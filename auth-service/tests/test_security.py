import secrets
import time
import jwt
import pytest
from sqlalchemy import select

from app.main import PH, User
from conftest import employee, headers, login


def test_creation_and_valid_login(env):
    app, c, pw = env
    uid, pwd, _ = employee(c, pw)
    response = login(c, 'empleado.lab', pwd)
    assert response.status_code == 200
    assert response.json()['expires_in'] == 900
    assert c.get('/me', headers=headers(response)).json()['id'] == uid


def test_invalid_and_unknown_are_generic(env):
    _, c, _ = env
    wrong = secrets.token_urlsafe(24)
    a, b = login(c, 'admin.lab', wrong), login(c, 'no.existe', wrong)
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json() == {'detail': 'Credenciales no válidas'}


def test_without_token(env):
    _, c, _ = env
    assert c.get('/me').status_code == 401
    assert c.post('/users', json={}).status_code == 401


def test_allowed_and_denied_roles(env):
    _, c, pw = env
    _, pwd, admin = employee(c, pw)
    user = headers(login(c, 'empleado.lab', pwd))
    assert c.get('/users', headers=admin).status_code == 200
    assert c.get('/me', headers=user).status_code == 200
    assert c.get('/users', headers=user).status_code == 403
    assert c.get('/audit', headers=user).status_code == 403


def test_no_self_promotion_or_registration(env):
    _, c, pw = env
    uid, pwd, admin = employee(c, pw)
    user = headers(login(c, 'empleado.lab', pwd))
    assert c.patch(f'/users/{uid}', headers=user, json={'role': 'ti'}).status_code == 403
    assert c.post('/users', headers=user, json={}).status_code == 403
    assert c.post('/users', headers=admin, json={'username': 'otra.lab', 'password': secrets.token_urlsafe(24),
                                               'role': 'superadmin', 'area': 'TI'}).status_code == 422


def test_argon2_salt_and_no_plaintext(env):
    app, c, pw = env
    _, pwd, admin = employee(c, pw)
    c.post('/users', headers=admin, json={'username': 'segunda.lab', 'password': pwd, 'area': 'ventas'})
    with app.state.db() as db:
        rows = list(db.scalars(select(User).where(User.role == 'empleado')))
        assert len(rows) == 2
        assert all(r.password_hash.startswith('$argon2id$v=19$m=19456,t=2,p=1$') for r in rows)
        assert rows[0].password_hash != rows[1].password_hash
        assert all(PH.verify(r.password_hash, pwd) and pwd not in r.password_hash for r in rows)
    assert 'password' not in c.get('/users', headers=admin).text


def test_logout_revokes_immediately(env):
    _, c, pw = env
    auth = headers(login(c, 'admin.lab', pw))
    assert c.post('/logout', headers=auth).status_code == 204
    assert c.get('/me', headers=auth).status_code == 401


def test_deactivation_revokes_all_sessions(env):
    _, c, pw = env
    uid, pwd, admin = employee(c, pw)
    sessions = [headers(login(c, 'empleado.lab', pwd)) for _ in range(2)]
    assert c.patch(f'/users/{uid}', headers=admin, json={'active': False}).status_code == 200
    assert all(c.get('/me', headers=s).status_code == 401 for s in sessions)
    assert login(c, 'empleado.lab', pwd).status_code == 401


@pytest.mark.parametrize('variant', ['expired', 'wrong_audience', 'wrong_issuer', 'missing_jti', 'unsigned'])
def test_invalid_tokens(env, variant):
    app, c, pw = env
    token = login(c, 'admin.lab', pw).json()['access_token']
    cfg = app.state.settings
    claims = jwt.decode(token, app.state.public_key, algorithms=['RS256'], audience=cfg.audience, issuer=cfg.issuer)
    if variant == 'expired':
        claims['exp'] = int(time.time())-1
    elif variant == 'wrong_audience':
        claims['aud'] = 'otra-aplicacion'
    elif variant == 'wrong_issuer':
        claims['iss'] = 'otro-emisor'
    elif variant == 'missing_jti':
        del claims['jti']
    bad = jwt.encode(claims, '' if variant == 'unsigned' else cfg.private_key,
                     algorithm='none' if variant == 'unsigned' else 'RS256')
    assert c.get('/me', headers={'Authorization': 'Bearer '+bad}).status_code == 401


def test_service_validation_requires_two_credentials(env):
    app, c, pw = env
    auth = headers(login(c, 'admin.lab', pw))
    assert c.post('/sessions/validate', headers=auth).status_code == 403
    combined = dict(auth, **{'X-Service-Key': app.state.settings.service_key})
    assert c.post('/sessions/validate', headers=combined).json()['active'] is True
    del combined['Authorization']
    assert c.post('/sessions/validate', headers=combined).status_code == 401


def test_login_limit_and_recovery(env):
    app, c, pw = env
    stamp = int(time.time())
    app.state.clock = lambda: stamp
    for _ in range(5):
        assert login(c, 'admin.lab', secrets.token_urlsafe(24)).status_code == 401
    assert login(c, 'admin.lab', pw).status_code == 429
    app.state.clock = lambda: stamp+301
    assert login(c, 'admin.lab', pw).status_code == 200


def test_audit_has_no_secrets(env):
    app, c, pw = env
    response = login(c, 'admin.lab', pw)
    token = response.json()['access_token']
    rows = c.get('/audit', headers=headers(response))
    assert rows.status_code == 200
    assert all(secret not in rows.text for secret in [pw, token, app.state.settings.service_key])
    assert all(set(r) == {'id', 'at', 'actor', 'action', 'resource', 'result'} for r in rows.json())


def test_validation_does_not_echo_password(env):
    _, c, pw = env
    response = c.post('/login', json={'username': 'x', 'password': pw, 'unexpected': pw})
    assert response.status_code == 422
    assert pw not in response.text


def test_duplicate_and_short_password(env):
    _, c, pw = env
    _, pwd, admin = employee(c, pw)
    data = {'username': 'empleado.lab', 'password': pwd, 'area': 'ventas'}
    assert c.post('/users', headers=admin, json=data).status_code == 409
    data.update(username='corta.lab', password='x')
    assert c.post('/users', headers=admin, json=data).status_code == 422


def test_headers_and_no_self_disable(env):
    _, c, pw = env
    response = c.get('/health')
    assert response.headers['cache-control'] == 'no-store'
    assert 'strict-transport-security' in response.headers
    auth = headers(login(c, 'admin.lab', pw))
    uid = c.get('/me', headers=auth).json()['id']
    assert c.patch(f'/users/{uid}', headers=auth, json={'active': False}).status_code == 409


def test_ip_limit(env):
    _, c, _ = env
    for _ in range(30):
        assert login(c, 'nadie.lab', secrets.token_urlsafe(24)).status_code == 401
    assert login(c, 'nadie.lab', secrets.token_urlsafe(24)).status_code == 429


def test_body_limit_and_bad_length(env):
    _, c, _ = env
    assert c.post('/login', content='x'*17000).status_code == 413
    assert c.post('/login', content='{}', headers={'Content-Length': 'oops'}).status_code == 400
