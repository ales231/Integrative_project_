"""Controles criptográficos y de intentos del diseño de la Fase 2.

C-03 (RF-SEC-03): Argon2id con sal individual; se guarda hash, sal y parámetros.
C-05 (RF-SEC-05): JWT RS256 de 15 minutos con emisor, audiencia, usuario y sesión.
C-07 (RF-SEC-07): 5 fallos en 5 minutos bloquean el acceso de esa cuenta 5 minutos.
"""
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

ALGORITMO = "RS256"
LARGO_MIN, LARGO_MAX = 10, 128


class Hasher:
    def __init__(self, memoria_kib: int, iteraciones: int, paralelismo: int):
        self.ph = PasswordHasher(time_cost=iteraciones, memory_cost=memoria_kib,
                                 parallelism=paralelismo, hash_len=32, salt_len=16)
        # Hash de una clave aleatoria: se verifica cuando la cuenta no existe, para
        # que el rechazo tarde lo mismo y no revele si el usuario existe (C-01).
        self.simulado = self.ph.hash(secrets.token_urlsafe(16))

    def hash(self, clave: str) -> str:
        return self.ph.hash(clave)

    def verificar(self, hash_guardado: str | None, clave: str) -> bool:
        try:
            return self.ph.verify(hash_guardado or self.simulado, clave) and hash_guardado is not None
        except (VerificationError, InvalidHashError):
            return False

    def necesita_rehash(self, hash_guardado: str) -> bool:
        return self.ph.check_needs_rehash(hash_guardado)


def errores_politica(clave: str) -> list[str]:
    faltan = []
    if not LARGO_MIN <= len(clave) <= LARGO_MAX:
        faltan.append(f"entre {LARGO_MIN} y {LARGO_MAX} caracteres")
    if not re.search(r"[a-záéíóúñ]", clave):
        faltan.append("una minúscula")
    if not re.search(r"[A-ZÁÉÍÓÚÑ]", clave):
        faltan.append("una mayúscula")
    if not re.search(r"\d", clave):
        faltan.append("un número")
    return faltan


def clave_temporal() -> str:
    while True:
        c = secrets.token_urlsafe(12)
        if not errores_politica(c):
            return c


def crear_token(uid: int, sid: str, privada: str, emisor: str, audiencia: str, minutos: int) -> tuple[str, datetime]:
    """El token lleva usuario, sesión, emisor, audiencia y vencimiento; no lleva rol ni contraseña."""
    ahora = datetime.now(timezone.utc)
    vence = ahora + timedelta(minutes=minutos)
    carga = {"sub": str(uid), "sid": sid, "iss": emisor, "aud": audiencia,
             "iat": int(ahora.timestamp()), "exp": int(vence.timestamp())}
    return jwt.encode(carga, privada, algorithm=ALGORITMO), vence


def leer_token(token: str, publica: str, emisor: str, audiencia: str) -> dict:
    """Algoritmo fijo (RS256): rechaza 'none', HS256 y tokens con otro emisor o audiencia."""
    return jwt.decode(token, publica, algorithms=[ALGORITMO], issuer=emisor, audience=audiencia,
                      options={"require": ["exp", "iat", "sub", "sid", "iss", "aud"]})


class Intentos:
    """Ventana deslizante por cuenta: `maximo` fallos en `ventana` segundos bloquean `bloqueo` segundos."""

    def __init__(self, maximo: int, ventana_min: int, bloqueo_min: int, reloj=time.monotonic):
        self.maximo, self.ventana, self.bloqueo = maximo, ventana_min * 60, bloqueo_min * 60
        self.reloj = reloj
        self._fallos: dict[str, list[float]] = {}
        self._hasta: dict[str, float] = {}
        self._lock = threading.Lock()

    def bloqueado(self, cuenta: str) -> bool:
        with self._lock:
            hasta = self._hasta.get(cuenta)
            if hasta is None:
                return False
            if self.reloj() >= hasta:
                del self._hasta[cuenta]
                self._fallos.pop(cuenta, None)
                return False
            return True

    def fallo(self, cuenta: str) -> bool:
        with self._lock:
            t = self.reloj()
            lista = [x for x in self._fallos.get(cuenta, []) if t - x < self.ventana] + [t]
            self._fallos[cuenta] = lista
            if len(lista) >= self.maximo:
                self._hasta[cuenta] = t + self.bloqueo
                return True
            return False

    def exito(self, cuenta: str) -> None:
        with self._lock:
            self._fallos.pop(cuenta, None)
