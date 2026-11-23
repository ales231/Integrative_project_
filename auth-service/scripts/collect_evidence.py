"""Ejecuta peticiones HTTPS reales en loopback y guarda solo evidencia sanitizada."""
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.cli import init_lab
from app.main import PH, Settings, User, create_app


def main():
    output = Path(__file__).resolve().parents[2]/'evidence/seguridad/https-results.json'
    original = Path.cwd()
    results = []
    def record(code, action, expected, obtained, detail, requirement, control):
        results.append(dict(id=code, action=action, expected=expected, obtained=obtained,
                            passed=expected == obtained, evidence=detail,
                            requirement=requirement, control=control))
    with tempfile.TemporaryDirectory(prefix='uide-security-') as temp:
        try:
            os.chdir(temp)
            init_lab()
            service_key = Path('.secrets/service.key').read_text()
            cfg = Settings(f'sqlite:///{Path(temp)/"evidence.sqlite3"}',
                           Path('.secrets/jwt-private.pem').read_bytes(), service_key, True)
            app = create_app(cfg)
            admin_password = secrets.token_urlsafe(24)
            employee_password = secrets.token_urlsafe(24)
            with app.state.db.begin() as db:
                db.add(User(username='ti.laboratorio', password_hash=PH.hash(admin_password), role='ti', area='TI'))
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
            config = uvicorn.Config(app, host='127.0.0.1', port=port, log_level='critical',
                access_log=False, proxy_headers=False,
                ssl_keyfile=str(Path(temp)/'.secrets/tls-private.pem'),
                ssl_certfile=str(Path(temp)/'.secrets/tls-cert.pem'))
            server = uvicorn.Server(config)
            thread = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
            thread.start()
            deadline = time.monotonic()+10
            while not server.started and thread.is_alive() and time.monotonic()<deadline:
                time.sleep(.05)
            if not server.started:
                raise RuntimeError('No se pudo iniciar el laboratorio HTTPS')
            base = f'https://127.0.0.1:{port}'
            try:
                with httpx.Client(base_url=base, verify=str(Path(temp)/'.secrets/tls-cert.pem'),
                                  trust_env=False, timeout=5) as c:
                    response = c.post('/login', json={'username':'ti.laboratorio','password':admin_password})
                    response.raise_for_status()
                    admin = {'Authorization':'Bearer '+response.json()['access_token']}
                    data = {'username':'empleado.evidencia','password':employee_password,'role':'empleado','area':'ventas'}
                    response = c.post('/users', headers=admin, json=data)
                    record('E-01','Crear empleado como TI',201,response.status_code,response.json(),'RF-SEC-01','C-01')
                    uid = response.json()['id']
                    response = c.post('/login',json={'username':data['username'],'password':employee_password})
                    record('E-02','Iniciar sesión con credenciales válidas',200,response.status_code,
                           {'token_issued': 'access_token' in response.json(), 'expires_in':response.json().get('expires_in')},'RF-SEC-01','C-01')
                    token = response.json()['access_token']
                    user = {'Authorization':'Bearer '+token}
                    response = c.post('/login',json={'username':data['username'],'password':secrets.token_urlsafe(24)})
                    record('E-03','Rechazar contraseña incorrecta',401,response.status_code,response.json(),'RF-SEC-01','C-01')
                    response = c.get('/me',headers=user)
                    record('E-04','Consultar perfil propio autenticado',200,response.status_code,response.json(),'RF-SEC-02','C-02')
                    response = c.get('/users',headers=user)
                    record('E-05','Empleado intenta administrar usuarios',403,response.status_code,response.json(),'RF-SEC-02','C-02')
                    response = c.get('/me')
                    record('E-06','Consultar perfil sin autenticación',401,response.status_code,response.json(),'RF-SEC-01','C-01')
                    data['username'] = 'segunda.evidencia'
                    response = c.post('/users',headers=admin,json=data)
                    response.raise_for_status()
                    with app.state.db() as db:
                        accounts = list(db.scalars(select(User).where(User.role=='empleado')))
                        protected = len(accounts)==2 and accounts[0].password_hash != accounts[1].password_hash
                        protected = protected and all(PH.verify(u.password_hash,employee_password) and
                                  employee_password not in u.password_hash for u in accounts)
                        descriptor = '$'.join(accounts[0].password_hash.split('$')[:4])+'$[sal omitida]$[hash omitido]'
                    record('E-07','Inspeccionar almacenamiento de contraseñas',True,protected,
                           {'algorithm':'Argon2id','format':descriptor,'distinct_salts':True,
                            'plaintext_found':False,'storage':'security_users.password_hash'},'RF-SEC-03','C-03')
                    response = c.post('/sessions/validate',headers=user)
                    record('E-08','Validación interna sin clave de servicio',403,response.status_code,response.json(),'RF-SEC-05','C-05')
                    response = c.post('/sessions/validate',headers={**user,'X-Service-Key':service_key})
                    record('E-09','Validar sesión con credencial de servicio',200,response.status_code,response.json(),'RF-SEC-05','C-05')
                    response = c.post('/logout',headers=user)
                    response.raise_for_status()
                    response = c.get('/me',headers=user)
                    record('E-10','Reutilizar token después de cerrar sesión',401,response.status_code,response.json(),'RF-SEC-05','C-05')
                    response = c.get('/audit',headers=admin)
                    clean = all(secret not in response.text for secret in [admin_password,employee_password,token,service_key])
                    record('E-11','Consultar auditoría sin secretos',True,response.status_code==200 and clean,
                           {'event_count':len(response.json()),'secrets_found':not clean,
                            'sample':response.json()[:3]},'RF-SEC-08','C-08')
                    bad_tls_rejected = False
                    try:
                        with httpx.Client(verify=True,trust_env=False,timeout=5) as untrusted:
                            untrusted.get(base+'/health')
                    except httpx.ConnectError:
                        bad_tls_rejected = True
                    record('E-12','Conectar sin confiar en el certificado del laboratorio',True,bad_tls_rejected,
                           {'certificate_validation':'rechazo de CA no confiable'},'RF-SEC-04','C-04')
                    response = c.post('/login',json={'username':'empleado.evidencia','password':employee_password})
                    current_user = {'Authorization':'Bearer '+response.json()['access_token']}
                    response = c.patch(f'/users/{uid}',headers=admin,json={'active':False})
                    response.raise_for_status()
                    response = c.get('/me',headers=current_user)
                    record('E-13','Desactivar cuenta y rechazar sesión existente',401,response.status_code,response.json(),'RF-SEC-05','C-05')
                    claims = {'sub':str(uid),'jti':'invalid-demo','iss':cfg.issuer,'aud':cfg.audience,
                              'iat':int(time.time())-1000,'exp':int(time.time())-1}
                    expired = jwt.encode(claims,cfg.private_key,algorithm='RS256')
                    response = c.get('/me',headers={'Authorization':'Bearer '+expired})
                    record('E-14','Rechazar JWT vencido',401,response.status_code,response.json(),'RF-SEC-05','C-05')
            finally:
                server.should_exit = True
                thread.join(timeout=10)
                sock.close()
                app.state.db.kw['bind'].dispose()
            document = dict(executed_at=datetime.now(timezone.utc).isoformat(),
                            transport='HTTPS real sobre loopback con verificación de certificado',
                            database='SQLite temporal - laboratorio, no PostgreSQL desplegado',
                            total=len(results),passed=sum(r['passed'] for r in results),results=results)
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_text(json.dumps(document,ensure_ascii=False,indent=2),encoding='utf-8')
            print(f'Evidencias sanitizadas: {document["passed"]}/{document["total"]} correctas. {output}')
            if not all(r['passed'] for r in results):
                raise SystemExit(1)
        finally:
            os.chdir(original)


if __name__ == '__main__':
    main()
