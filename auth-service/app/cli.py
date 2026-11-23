"""Preparación explícita del laboratorio y alta inicial de TI, sin secretos impresos."""
import argparse
import getpass
import ipaddress
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from .main import PH, Settings, User, UserCreate, create_app


def init_lab():
    folder = Path('.secrets')
    folder.mkdir(mode=0o700, exist_ok=True)
    paths = [folder/p for p in ('jwt-private.pem', 'tls-private.pem', 'tls-cert.pem', 'service.key')]
    if any(p.exists() for p in paths):
        raise SystemExit('Ya existen claves: no se sobrescriben.')
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    tls = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    for key, path in [(signing, paths[0]), (tls, paths[1])]:
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        path.chmod(0o600)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    stamp = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tls.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(stamp-timedelta(minutes=1)).not_valid_after(stamp+timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(tls, hashes.SHA256()))
    paths[2].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths[3].write_text(secrets.token_urlsafe(48))
    paths[3].chmod(0o600)
    print('Claves y certificado de laboratorio creados en .secrets; no subirlos a Git.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init-lab', 'bootstrap'])
    args = parser.parse_args()
    if args.command == 'init-lab':
        init_lab()
        return
    app = create_app(Settings.from_env())
    username = input('Usuario inicial de TI: ').strip()
    password = getpass.getpass('Contraseña (mínimo 12 caracteres): ')
    if password != getpass.getpass('Repita la contraseña: '):
        raise SystemExit('Las contraseñas no coinciden.')
    data = UserCreate(username=username, password=password, role='ti', area='TI')
    with app.state.db.begin() as db:
        if db.scalar(select(User.id).limit(1)) is not None:
            raise SystemExit('Ya existen usuarios: use el alta administrativa autenticada.')
        db.add(User(username=data.username, password_hash=PH.hash(password), role='ti', area='TI'))
    print('Cuenta inicial creada. No se imprimió ni almacenó la contraseña en claro.')


if __name__ == '__main__':
    main()
