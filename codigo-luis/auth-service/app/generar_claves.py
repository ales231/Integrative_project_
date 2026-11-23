"""Genera el par de claves RSA para firmar (FastAPI) y verificar (servidor Go) los tokens.

Uso, desde auth-service:   python -m app.generar_claves
La clave privada queda en keys/privada.pem (excluida de Git); el servidor Go solo
recibe keys/publica.pem (C-05 / RF-SEC-05).
"""
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generar(directorio: Path) -> None:
    directorio.mkdir(parents=True, exist_ok=True)
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (directorio / "privada.pem").write_bytes(privada.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directorio / "publica.pem").write_bytes(privada.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


if __name__ == "__main__":
    destino = Path(__file__).resolve().parent.parent / "keys"
    if (destino / "privada.pem").exists():
        print(f"Ya existen claves en {destino}; no se sobrescriben.")
    else:
        generar(destino)
        print(f"Claves creadas en {destino} (privada.pem queda fuera de Git).")
