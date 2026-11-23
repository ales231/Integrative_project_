"""Compatibilidad del contrato compartido con la API oficial, usando secretos temporales."""
import json, sys, secrets
from pathlib import Path
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'auth-service'))
from app.main import Settings, User, PH, create_app
CONTRACT = json.loads((ROOT/'docs/integracion/contrato.json').read_text(encoding='utf-8'))

@pytest.fixture
def environment(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    cfg=Settings(f'sqlite:///{tmp_path/"contract.sqlite3"}',pem,secrets.token_urlsafe(48),True)
    app=create_app(cfg); password=secrets.token_urlsafe(24)
    with app.state.db.begin() as db:
        db.add(User(username='ti.contrato',password_hash=PH.hash(password),role='ti',area='TI'))
    with TestClient(app,base_url='https://localhost') as c:
        yield c,cfg,password

def test_routes_and_roles_match_implementation(environment):
    c,cfg,_=environment
    schema=c.app.openapi()
    actual={p:sorted(method for method in value if method in ('get','post','patch','delete')) for p,value in schema['paths'].items()}
    assert actual=={p:sorted(m.lower() for m in methods) for p,methods in CONTRACT['routes'].items()}
    assert schema['components']['schemas']['UserCreate']['properties']['role']['enum']==CONTRACT['identity']['roles']
    assert cfg.ttl==CONTRACT['session']['ttl_seconds']==900
    assert cfg.issuer==CONTRACT['session']['issuer'] and cfg.audience==CONTRACT['session']['audience']

def test_login_profile_and_service_validation_contract(environment):
    c,cfg,pw=environment
    r=c.post('/login',json={'username':'ti.contrato','password':pw})
    assert r.status_code==200 and set(r.json())==set(CONTRACT['login']['response'])
    assert r.json()['expires_in']==900
    auth={'Authorization':'Bearer '+r.json()['access_token']}
    profile=c.get('/me',headers=auth)
    assert set(profile.json())==set(CONTRACT['profile_fields'])
    assert c.post('/sessions/validate',headers=auth).status_code==403
    assert c.post('/sessions/validate',headers={**auth,'X-Service-Key':cfg.service_key}).json()==profile.json()
    assert c.post('/logout',headers=auth).status_code==204
    assert c.get('/me',headers=auth).status_code==401

def test_poo_account_workflow_and_revocation(environment):
    c,cfg,pw=environment
    ti={'Authorization':'Bearer '+c.post('/login',json={'username':'ti.contrato','password':pw}).json()['access_token']}
    password=secrets.token_urlsafe(24)
    data={'username':'ana.perez','password':password,'role':'empleado','area':'Ventas'}
    r=c.post('/users',headers=ti,json=data)
    assert r.status_code==201 and 'password' not in r.json()
    uid=r.json()['id']
    assert c.post('/users',headers=ti,json=data).status_code==409
    assert c.post('/users',headers=ti,json={**data,'username':'otra.persona','nombre':'Persona'}).status_code==422
    auth={'Authorization':'Bearer '+c.post('/login',json={'username':'ana.perez','password':password}).json()['access_token']}
    assert c.patch(f'/users/{uid}',headers=ti,json={'role':'admin'}).status_code==422
    assert c.patch(f'/users/{uid}',headers=ti,json={'role':'supervisor'}).status_code==200
    assert c.get('/me',headers=auth).status_code==401
    auth={'Authorization':'Bearer '+c.post('/login',json={'username':'ana.perez','password':password}).json()['access_token']}
    assert c.patch(f'/users/{uid}',headers=ti,json={'active':False}).status_code==200
    assert c.get('/me',headers=auth).status_code==401
    assert c.post('/login',json={'username':'ana.perez','password':password}).status_code==401

def test_username_is_identifier_not_email(environment):
    c,_,pw=environment
    assert c.post('/login',json={'username':'ana.perez@empresa.test','password':pw}).status_code==422
    r=c.post('/login',json={'username':' TI.CONTRATO ','password':pw})
    assert r.status_code==200
