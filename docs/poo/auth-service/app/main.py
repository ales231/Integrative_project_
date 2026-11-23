"""Servicio de autenticación del chat empresarial (FastAPI).

Implementa los controles de la Fase 2 de Fundamentos de Seguridad que dependen de FastAPI:
  C-01 autenticación con rechazo genérico     C-03 Argon2id
  C-05 sesiones de 15 min con revocación       C-07 límite de intentos
  C-08 auditoría sin secretos                  C-10 gestión de cuentas solo para TI

Rutas (diseño de POO, Fase 3, Tabla 2, más las de sesión de la Fase 2 de Seguridad):
  POST   /login                      público   usuario y clave -> JWT RS256 de 15 min
  POST   /logout                     sesión    revoca la sesión actual
  POST   /validar                    servidor  token -> estado de la sesión, rol y área vigentes
  GET    /yo                         sesión    datos de la sesión
  POST   /credenciales               TI        crea una cuenta
  DELETE /credenciales/{usuario}     TI        desactiva la cuenta y revoca todas sus sesiones
  GET    /admin/usuarios             TI        cuentas, sin hashes
  GET    /admin/auditoria            TI        eventos de seguridad

Ejecutar:  uvicorn app.main:crear_app --factory --env-file .env --port 8000
"""
import time
import uuid
from datetime import datetime, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import seguridad as seg
from .config import Config
from .db import Almacen
from .esquemas import (CuentaIn, CuentaOut, LoginIn, SesionOut, TokenOut,
                       UsuarioOut, ValidarIn)

RECHAZO = "Credenciales inválidas"   # mismo mensaje para clave errada, usuario inexistente o cuenta inactiva


def crear_app(config: Config | None = None, reloj=time.monotonic) -> FastAPI:
    cfg = config or Config.desde_entorno()
    db = Almacen(cfg.db_path)
    hasher = seg.Hasher(cfg.argon2_memoria_kib, cfg.argon2_iteraciones, cfg.argon2_paralelismo)
    intentos = seg.Intentos(cfg.max_intentos, cfg.ventana_minutos, cfg.bloqueo_minutos, reloj)

    if cfg.admin_correo and cfg.admin_clave and not db.por_correo(cfg.admin_correo.lower()):
        if seg.errores_politica(cfg.admin_clave):
            raise RuntimeError("ADMIN_CLAVE no cumple la política de contraseñas")
        db.crear_usuario("Administrador de TI", cfg.admin_correo.lower(), hasher.hash(cfg.admin_clave), "admin", "TI")
        db.auditar("sistema", "cuenta:" + cfg.admin_correo.lower(), "crear_cuenta", "ok", "administrador inicial")

    app = FastAPI(title="Servicio de autenticación – Chat empresarial (Grupo 10)", version="0.3.0")
    bearer = HTTPBearer(auto_error=False)

    # ---------- C-05: validación de sesión ----------
    def sesion_de(token: str) -> dict:
        try:
            datos = seg.leer_token(token, cfg.clave_publica, cfg.emisor, cfg.audiencia)
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Sesión vencida")
        except jwt.InvalidTokenError:
            raise HTTPException(401, "Token inválido")
        s = db.sesion(datos["sid"])
        u = db.por_id(int(datos["sub"]))
        if s is None or s["revocada"] or u is None or not u["activo"] or s["usuario_id"] != u["id"]:
            raise HTTPException(401, "Sesión revocada o cuenta desactivada")
        # Rol y área se leen de la base en cada validación, no del token (RF-SEC-02).
        return {"usuarioID": u["id"], "sesionID": s["sid"], "correo": u["correo"], "rol": u["rol"],
                "area": u["area"], "venceEn": datetime.fromtimestamp(datos["exp"], timezone.utc)}

    def sesion_actual(cred: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
        if cred is None:
            raise HTTPException(401, "Falta el token de sesión", headers={"WWW-Authenticate": "Bearer"})
        return sesion_de(cred.credentials)

    def solo_ti(request: Request, s: dict = Depends(sesion_actual)) -> dict:
        # C-10: solo el administrador de TI gestiona cuentas, roles y auditoría.
        if s["rol"] != "admin":
            db.auditar(s["correo"], request.url.path, request.method, "denegado", f"rol {s['rol']}")
            raise HTTPException(403, "No tiene permiso para esta operación")
        return s

    # ---------- rutas ----------
    @app.get("/salud")
    def salud():
        return {"estado": "ok"}

    @app.post("/login", response_model=TokenOut)
    def login(datos: LoginIn):
        cuenta = datos.usuario
        if intentos.bloqueado(cuenta):
            db.auditar(cuenta, "/login", "iniciar_sesion", "bloqueado")
            raise HTTPException(429, f"Demasiados intentos. Espere {cfg.bloqueo_minutos} minutos.")
        u = db.por_correo(cuenta)
        ok = hasher.verificar(u["hash_clave"] if u else None, datos.clave) and bool(u and u["activo"])
        if not ok:
            quedo = intentos.fallo(cuenta)
            db.auditar(cuenta, "/login", "iniciar_sesion", "rechazado", "cuenta bloqueada" if quedo else "")
            raise HTTPException(401, RECHAZO)
        intentos.exito(cuenta)
        if hasher.necesita_rehash(u["hash_clave"]):
            db.actualizar_hash(u["id"], hasher.hash(datos.clave))
        sid = uuid.uuid4().hex
        token, vence = seg.crear_token(u["id"], sid, cfg.clave_privada, cfg.emisor, cfg.audiencia, cfg.minutos_sesion)
        db.crear_sesion(sid, u["id"], vence)
        db.auditar(cuenta, "/login", "iniciar_sesion", "ok", f"sesión {sid[:8]}")
        return TokenOut(token=token, venceEn=vence)

    @app.post("/logout", status_code=204)
    def logout(s: dict = Depends(sesion_actual)):
        db.revocar_sesion(s["sesionID"])
        db.auditar(s["correo"], "/logout", "cerrar_sesion", "ok", f"sesión {s['sesionID'][:8]}")
        return Response(status_code=204)

    @app.post("/validar", response_model=SesionOut)
    def validar(datos: ValidarIn):
        return SesionOut(**sesion_de(datos.token))

    @app.get("/yo", response_model=SesionOut)
    def yo(s: dict = Depends(sesion_actual)):
        return SesionOut(**s)

    @app.post("/credenciales", response_model=CuentaOut, status_code=201)
    def crear_cuenta(datos: CuentaIn, ti: dict = Depends(solo_ti)):
        if db.por_correo(datos.usuario):
            raise HTTPException(409, "El usuario ya existe")
        temporal = None
        clave = datos.clave
        if clave is None:
            clave = temporal = seg.clave_temporal()
        elif faltan := seg.errores_politica(clave):
            raise HTTPException(422, "La contraseña necesita: " + ", ".join(faltan))
        uid = db.crear_usuario(datos.nombre, datos.usuario, hasher.hash(clave), datos.rol, datos.area)
        db.auditar(ti["correo"], "cuenta:" + datos.usuario, "crear_cuenta", "ok", f"rol {datos.rol}, área {datos.area}")
        return CuentaOut(id=uid, usuario=datos.usuario, rol=datos.rol, area=datos.area, claveTemporal=temporal)

    @app.delete("/credenciales/{usuario}", status_code=204)
    def desactivar(usuario: str, ti: dict = Depends(solo_ti)):
        usuario = usuario.strip().lower()
        if usuario == ti["correo"]:
            raise HTTPException(400, "No puede desactivar su propia cuenta")
        if db.desactivar(usuario) is None:
            raise HTTPException(404, "La cuenta no existe")
        db.auditar(ti["correo"], "cuenta:" + usuario, "desactivar_cuenta", "ok", "sesiones revocadas")
        return Response(status_code=204)

    @app.get("/admin/usuarios", response_model=list[UsuarioOut])
    def usuarios(_: dict = Depends(solo_ti)):
        return [UsuarioOut(id=u["id"], nombre=u["nombre"], usuario=u["correo"], rol=u["rol"],
                           area=u["area"], activo=bool(u["activo"])) for u in db.listar()]

    @app.get("/admin/auditoria")
    def auditoria(ti: dict = Depends(solo_ti)):
        db.auditar(ti["correo"], "/admin/auditoria", "consultar_auditoria", "ok")
        return [dict(e) for e in db.eventos()]

    return app
