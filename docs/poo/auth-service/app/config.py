"""Configuración del servicio de autenticación (FastAPI).

Valores tomados del diseño de la Fase 2 de Fundamentos de Seguridad:
  RF-SEC-05 / C-05  JWT de 15 minutos, firmado con RS256 (clave privada solo en FastAPI).
  RF-SEC-07 / C-07  5 fallos en 5 minutos bloquean el acceso 5 minutos.
  RF-SEC-03 / C-03  Argon2id, 19 MiB, 2 iteraciones, paralelismo 1, sal individual.
Ningún secreto se escribe en el código: las rutas de las claves y la clave del
administrador inicial llegan por el entorno (.env local, excluido de Git).
"""
import os
from dataclasses import dataclass
from pathlib import Path

ROLES = ("empleado", "supervisor", "admin")
AREAS = ("Ventas", "Soporte", "Administración", "Finanzas", "TI", "Atención")


@dataclass(frozen=True)
class Config:
    clave_privada: str                  # PEM de la clave RSA privada (firma de tokens)
    clave_publica: str                  # PEM de la clave pública (la recibe el servidor Go)
    emisor: str = "auth.chat-grupo10"
    audiencia: str = "chat-empresarial"
    minutos_sesion: int = 15
    db_path: str = "auth.db"
    max_intentos: int = 5
    ventana_minutos: int = 5
    bloqueo_minutos: int = 5
    argon2_memoria_kib: int = 19456     # 19 MiB
    argon2_iteraciones: int = 2
    argon2_paralelismo: int = 1
    admin_correo: str | None = None
    admin_clave: str | None = None

    @staticmethod
    def desde_entorno() -> "Config":
        base = Path(__file__).resolve().parent.parent
        priv = Path(os.environ.get("JWT_CLAVE_PRIVADA", base / "keys" / "privada.pem"))
        pub = Path(os.environ.get("JWT_CLAVE_PUBLICA", base / "keys" / "publica.pem"))
        if not priv.exists() or not pub.exists():
            raise RuntimeError("No se encontraron las claves RSA. Genérelas con: python -m app.generar_claves")
        return Config(
            clave_privada=priv.read_text(),
            clave_publica=pub.read_text(),
            emisor=os.environ.get("JWT_EMISOR", "auth.chat-grupo10"),
            audiencia=os.environ.get("JWT_AUDIENCIA", "chat-empresarial"),
            minutos_sesion=int(os.environ.get("MINUTOS_SESION", "15")),
            db_path=os.environ.get("AUTH_DB_PATH", str(base / "auth.db")),
            admin_correo=os.environ.get("ADMIN_CORREO") or None,
            admin_clave=os.environ.get("ADMIN_CLAVE") or None,
        )
