import secrets
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import PH, Settings, User, create_app


@pytest.fixture
def env(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    cfg = Settings(f'sqlite:///{tmp_path / "test.sqlite3"}', pem, secrets.token_urlsafe(48), True)
    app = create_app(cfg)
    pwd = secrets.token_urlsafe(24)
    with app.state.db.begin() as db:
        db.add(User(username='admin.lab', password_hash=PH.hash(pwd), role='ti', area='TI'))
    with TestClient(app, base_url='https://localhost') as client:
        yield app, client, pwd


def login(client, name, password):
    return client.post('/login', json={'username': name, 'password': password})


def headers(response):
    return {'Authorization': 'Bearer '+response.json()['access_token']}


def employee(client, admin_password, name='empleado.lab', role='empleado'):
    admin = headers(login(client, 'admin.lab', admin_password))
    pwd = secrets.token_urlsafe(24)
    response = client.post('/users', headers=admin,
                           json={'username': name, 'password': pwd, 'role': role, 'area': 'ventas'})
    assert response.status_code == 201
    return response.json()['id'], pwd, admin
