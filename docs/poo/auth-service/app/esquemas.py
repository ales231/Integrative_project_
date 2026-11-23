"""Validación de entradas (C-01): formato, tamaño y valores permitidos antes de tocar la base."""
import re
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from .config import AREAS, ROLES

PATRON_CORREO = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _correo(v: str) -> str:
    v = v.strip().lower()
    if len(v) > 120 or not PATRON_CORREO.match(v):
        raise ValueError("usuario corporativo con formato inválido")
    return v


class LoginIn(BaseModel):
    usuario: str = Field(max_length=120, description="Usuario corporativo (correo de la empresa)")
    clave: str = Field(min_length=1, max_length=128)

    @field_validator("usuario")
    @classmethod
    def v_usuario(cls, v):
        return _correo(v)


class TokenOut(BaseModel):
    token: str
    venceEn: datetime


class ValidarIn(BaseModel):
    token: str = Field(min_length=10, max_length=4096)


class SesionOut(BaseModel):
    usuarioID: int
    sesionID: str
    correo: str
    rol: str
    area: str
    venceEn: datetime


class CuentaIn(BaseModel):
    nombre: str = Field(min_length=2, max_length=80)
    usuario: str = Field(max_length=120)
    rol: str = "empleado"
    area: str
    clave: str | None = Field(default=None, max_length=128)   # si falta, se genera una temporal

    @field_validator("usuario")
    @classmethod
    def v_usuario(cls, v):
        return _correo(v)

    @field_validator("rol")
    @classmethod
    def v_rol(cls, v):
        if v not in ROLES:
            raise ValueError(f"rol debe ser uno de: {', '.join(ROLES)}")
        return v

    @field_validator("area")
    @classmethod
    def v_area(cls, v):
        if v not in AREAS:
            raise ValueError(f"área debe ser una de: {', '.join(AREAS)}")
        return v


class CuentaOut(BaseModel):
    id: int
    usuario: str
    rol: str
    area: str
    claveTemporal: str | None = None


class UsuarioOut(BaseModel):
    id: int
    nombre: str
    usuario: str
    rol: str
    area: str
    activo: bool
