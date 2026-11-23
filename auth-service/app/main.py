"""Identidad, sesiones revocables y autorización. Sin implementar el chat."""
from __future__ import annotations

import hmac
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

ROLES = Literal['empleado', 'supervisor', 'ti']
PH = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


@dataclass(frozen=True)
class Settings:
    database_url: str
    private_key: bytes
    service_key: str
    laboratory: bool = False
    issuer: str = 'uide-auth'
    audience: str = 'uide-chat'
    ttl: int = 900

    @classmethod
    def from_env(cls):
        return cls(
            database_url=os.environ['DATABASE_URL'],
            private_key=Path(os.environ['JWT_PRIVATE_KEY_FILE']).read_bytes(),
            service_key=Path(os.environ['SERVICE_KEY_FILE']).read_text().strip(),
            laboratory=os.environ.get('LABORATORY_MODE') == '1',
        )


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'security_users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(16))
    area: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    window_start: Mapped[int] = mapped_column(Integer, default=0)
    blocked_until: Mapped[int] = mapped_column(Integer, default=0)


class LoginSession(Base):
    __tablename__ = 'security_sessions'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('security_users.id'))
    expires: Mapped[int] = mapped_column(Integer)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Audit(Base):
    __tablename__ = 'security_audit'
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[int] = mapped_column(Integer)
    actor: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(40))
    resource: Mapped[str] = mapped_column(String(80))
    result: Mapped[str] = mapped_column(String(16))


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Login(Input):
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=128)

    @field_validator('username')
    @classmethod
    def normalize(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r'[a-z0-9._-]{3,64}', value):
            raise ValueError('Identificador inválido')
        return value


class UserCreate(Login):
    password: SecretStr = Field(min_length=12, max_length=128)
    role: ROLES = 'empleado'
    area: str = Field(min_length=1, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')


class UserUpdate(Input):
    role: ROLES | None = None
    active: bool | None = None


def view(user):
    return dict(id=user.id, username=user.username, role=user.role,
                area=user.area, active=user.active)


def create_app(settings: Settings | None = None):
    cfg = settings or Settings.from_env()
    if len(cfg.service_key) < 32 or not 60 <= cfg.ttl <= 900:
        raise ValueError('Configuración de seguridad inválida')
    if not cfg.laboratory and not cfg.database_url.startswith('postgresql+psycopg://'):
        raise ValueError('PostgreSQL es obligatorio fuera del laboratorio')
    key = serialization.load_pem_private_key(cfg.private_key, password=None)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
        raise ValueError('Se requiere clave RSA de al menos 2048 bits')
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    engine = create_engine(cfg.database_url, **(
        {'connect_args': {'check_same_thread': False}} if cfg.database_url.startswith('sqlite') else {}))
    db_factory = sessionmaker(engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    mutex = threading.RLock()
    # La primera versión se ejecuta con UN trabajador. Límite global además
    # del contador persistente por cuenta; no confiar en X-Forwarded-For.
    attempts = OrderedDict()
    dummy_hash = PH.hash(secrets.token_urlsafe(24))

    @asynccontextmanager
    async def lifespan(app):
        yield
        engine.dispose()

    app = FastAPI(title='UIDE - Servicio de Seguridad', version='0.1.0',
                  lifespan=lifespan, docs_url=None if not cfg.laboratory else '/docs',
                  redoc_url=None)
    app.state.db = db_factory
    app.state.settings = cfg
    app.state.public_key = public_key
    app.state.clock = time.time

    def now():
        return int(app.state.clock())

    def audit(db, actor, action, resource, result):
        # Solo campos construidos por el servidor. Nunca tokens o payloads.
        db.add(Audit(at=now(), actor=actor, action=action,
                     resource=resource, result=result))

    @app.middleware('http')
    async def guard(request, call_next):
        if not cfg.laboratory and request.url.scheme != 'https':
            return JSONResponse({'detail': 'HTTPS obligatorio'}, status_code=400)
        try:
            content_length = int(request.headers.get('content-length', '0'))
        except ValueError:
            return JSONResponse({'detail': 'Longitud inválida'}, status_code=400)
        if content_length < 0 or content_length > 16384:
            return JSONResponse({'detail': 'Solicitud demasiado grande'}, status_code=413)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                return JSONResponse({'detail': 'Solicitud demasiado grande'}, status_code=413)
        request._body = bytes(body)  # Caché de Request para el siguiente consumidor ASGI.
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        if request.url.scheme == 'https':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        # Los errores estándar de Pydantic pueden reproducir el input secreto.
        return JSONResponse({'detail': 'Datos de solicitud inválidos'}, status_code=422)

    bearer = HTTPBearer(auto_error=False)

    def identity(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if credentials is None or len(credentials.credentials) > 4096:
            raise HTTPException(401, 'Sesión no válida', headers={'WWW-Authenticate': 'Bearer'})
        try:
            claims = jwt.decode(credentials.credentials, public_key, algorithms=['RS256'],
                                issuer=cfg.issuer, audience=cfg.audience,
                                options={'require': ['sub', 'jti', 'iat', 'exp', 'iss', 'aud']})
            uid = int(claims['sub'])
            if not isinstance(claims['jti'], str):
                raise ValueError()
        except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
            raise HTTPException(401, 'Sesión no válida', headers={'WWW-Authenticate': 'Bearer'})
        with mutex, db_factory() as db:
            session = db.get(LoginSession, claims['jti'])
            user = db.get(User, uid)
            if (not session or session.user_id != uid or session.revoked or
                    session.expires <= now() or not user or not user.active):
                raise HTTPException(401, 'Sesión no válida')
            return {'user': view(user), 'session_id': session.id}

    def admin(subject=Depends(identity)):
        if subject['user']['role'] != 'ti':
            with mutex, db_factory.begin() as db:
                audit(db, subject['user']['id'], 'access_denied', 'administration', 'denied')
            raise HTTPException(403, 'Acceso denegado')
        return subject

    @app.get('/health')
    def health():
        return {'status': 'ok'}

    @app.get('/public-key')
    def public():
        return {'algorithm': 'RS256', 'issuer': cfg.issuer, 'audience': cfg.audience,
                'public_key': public_key.decode()}

    @app.post('/login')
    def login(data: Login, request: Request):
        error = None
        with mutex, db_factory.begin() as db:
            stamp = now()
            source = request.client.host if request.client else 'unknown'
            bucket = attempts.get(source, (stamp, 0))
            if stamp - bucket[0] >= 60:
                bucket = (stamp, 0)
            attempts[source] = (bucket[0], bucket[1]+1)
            if len(attempts) > 10000:
                attempts.popitem(last=False)
            if bucket[1] >= 30:
                audit(db, None, 'login_throttled', 'login', 'denied')
                error = HTTPException(429, 'Demasiados intentos', headers={'Retry-After': '60'})
            else:
                user = db.scalar(select(User).where(User.username == data.username).with_for_update())
                try:
                    valid = PH.verify(user.password_hash if user else dummy_hash,
                                      data.password.get_secret_value())
                except (VerificationError, InvalidHashError):
                    valid = False
                if user and user.blocked_until > stamp:
                    error = HTTPException(429, 'Demasiados intentos', headers={'Retry-After': '300'})
                elif not user or not valid or not user.active:
                    if user:
                        if stamp-user.window_start >= 300:
                            user.window_start = stamp
                            user.failures = 0
                        user.failures += 1
                        if user.failures >= 5:
                            user.blocked_until = stamp+300
                            user.failures = 0
                    audit(db, user.id if user else None, 'login', 'login', 'denied')
                    error = HTTPException(401, 'Credenciales no válidas')
                else:
                    user.failures = 0
                    user.blocked_until = 0
                    jti = secrets.token_urlsafe(32)
                    db.add(LoginSession(id=jti, user_id=user.id, expires=stamp+cfg.ttl))
                    claims = dict(sub=str(user.id), jti=jti, iat=stamp, exp=stamp+cfg.ttl,
                                  iss=cfg.issuer, aud=cfg.audience)
                    token = jwt.encode(claims, cfg.private_key, algorithm='RS256')
                    audit(db, user.id, 'login', 'login', 'allowed')
        if error:
            raise error
        return {'access_token': token, 'token_type': 'bearer', 'expires_in': cfg.ttl}

    @app.get('/me')
    def me(subject=Depends(identity)):
        return subject['user']

    @app.post('/logout', status_code=204)
    def logout(subject=Depends(identity)):
        with mutex, db_factory.begin() as db:
            db.get(LoginSession, subject['session_id']).revoked = True
            audit(db, subject['user']['id'], 'logout', 'session', 'allowed')

    @app.post('/users', status_code=201)
    def create_user(data: UserCreate, subject=Depends(admin)):
        try:
            with mutex, db_factory.begin() as db:
                user = User(username=data.username, password_hash=PH.hash(data.password.get_secret_value()),
                            role=data.role, area=data.area)
                db.add(user)
                db.flush()
                audit(db, subject['user']['id'], 'user_created', f'user:{user.id}', 'allowed')
                result = view(user)
        except IntegrityError:
            raise HTTPException(409, 'No se pudo crear la cuenta')
        return result

    @app.get('/users')
    def users(subject=Depends(admin)):
        with mutex, db_factory() as db:
            return [view(u) for u in db.scalars(select(User).order_by(User.id).limit(100))]

    @app.patch('/users/{uid}')
    def update_user(uid: int, data: UserUpdate, subject=Depends(admin)):
        with mutex, db_factory.begin() as db:
            user = db.get(User, uid)
            if not user:
                raise HTTPException(404, 'Cuenta no encontrada')
            # Evita eliminar accidentalmente la única vía administrativa propia.
            if uid == subject['user']['id'] and (data.active is False or data.role not in (None, 'ti')):
                raise HTTPException(409, 'No se permite deshabilitar la cuenta administrativa propia')
            if data.active is not None:
                user.active = data.active
            if data.role is not None:
                user.role = data.role
            for session in db.scalars(select(LoginSession).where(LoginSession.user_id == uid)):
                session.revoked = True
            audit(db, subject['user']['id'], 'user_updated', f'user:{uid}', 'allowed')
            return view(user)

    @app.get('/audit')
    def events(subject=Depends(admin)):
        with mutex, db_factory.begin() as db:
            result = [dict(id=e.id, at=e.at, actor=e.actor, action=e.action,
                           resource=e.resource, result=e.result) for e in
                      db.scalars(select(Audit).order_by(Audit.id.desc()).limit(100))]
            audit(db, subject['user']['id'], 'audit_read', 'audit', 'allowed')
            return result

    @app.post('/sessions/validate')
    def validate(subject=Depends(identity), x_service_key: str = Header(default='')):
        if not hmac.compare_digest(x_service_key.encode(), cfg.service_key.encode()):
            raise HTTPException(403, 'Acceso de servicio denegado')
        # El token NO se devuelve ni se registra. Los roles son los actuales.
        return {'active': True, **subject['user']}

    return app
