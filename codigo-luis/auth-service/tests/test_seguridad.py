"""Pruebas de seguridad del servicio de autenticación.

Los códigos PS-xx, RF-SEC-xx y C-xx son los del plan de pruebas de la Fase 2 de
Fundamentos de Seguridad (Tabla 5). Las pruebas de membresía y límites de mensajes
(PS-04, PS-05, PS-13) y de FastAPI caído (PS-17) están en app-go.

Ejecutar desde auth-service:   python -m pytest -v
Cada prueba usa una base temporal, claves RSA y contraseñas generadas al azar.
"""
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from app.config import Config
from app.generar_claves import generar
from app.main import RECHAZO, crear_app


def clave() -> str:
    return "Prueba" + secrets.token_hex(4) + "9"


class Reloj:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def e(tmp_path):
    generar(tmp_path / "keys")
    cfg = Config(clave_privada=(tmp_path / "keys/privada.pem").read_text(),
                 clave_publica=(tmp_path / "keys/publica.pem").read_text(),
                 db_path=str(tmp_path / "auth.db"), admin_correo="ti@empresa.test", admin_clave=clave())
    reloj = Reloj()
    c = TestClient(crear_app(cfg, reloj))
    t = c.post("/login", json={"usuario": cfg.admin_correo, "clave": cfg.admin_clave}).json()["token"]

    class E:
        pass
    x = E()
    x.c, x.cfg, x.reloj, x.ti = c, cfg, reloj, {"Authorization": f"Bearer {t}"}
    return x


def cuenta(e, usuario="ana.perez@empresa.test", rol="empleado", area="Ventas", pw=None):
    pw = pw or clave()
    r = e.c.post("/credenciales", headers=e.ti, json={"nombre": "Prueba", "usuario": usuario, "rol": rol, "area": area, "clave": pw})
    assert r.status_code == 201, r.text
    return pw


def login(e, usuario, pw):
    return e.c.post("/login", json={"usuario": usuario, "clave": pw})


def cab(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------- PS-01 (+) RF-SEC-01 / C-01 ----------------
def test_PS01_login_valido_emite_sesion_de_15_minutos(e):
    pw = cuenta(e)
    r = login(e, "ana.perez@empresa.test", pw)
    assert r.status_code == 200
    datos = jwt.decode(r.json()["token"], e.cfg.clave_publica, algorithms=["RS256"],
                       audience=e.cfg.audiencia, issuer=e.cfg.emisor)
    assert datos["exp"] - datos["iat"] == 15 * 60
    assert {"sub", "sid", "iss", "aud"} <= datos.keys() and "rol" not in datos and "clave" not in datos
    assert e.c.get("/yo", headers=cab(r.json()["token"])).json()["rol"] == "empleado"


# ---------------- PS-02 (-) RF-SEC-01 / C-01 ----------------
def test_PS02_rechazo_generico_en_los_tres_casos(e):
    pw = cuenta(e)
    cuenta(e, "inactiva@empresa.test", pw=pw)
    e.c.delete("/credenciales/inactiva@empresa.test", headers=e.ti)
    casos = [("ana.perez@empresa.test", "ClaveErrada123"),   # contraseña incorrecta
             ("nadie@empresa.test", pw),                      # usuario inexistente
             ("inactiva@empresa.test", pw)]                   # cuenta desactivada
    for usuario, intento in casos:
        r = login(e, usuario, intento)
        assert r.status_code == 401 and r.json() == {"detail": RECHAZO}


def test_C01_entradas_invalidas_rechazadas_sin_cambios(e):
    malos = [{"nombre": "X", "usuario": "no-es-correo", "area": "Ventas"},
             {"nombre": "Robert'); DROP TABLE usuarios;--", "usuario": "sql@empresa.test", "rol": "root", "area": "Ventas"},
             {"nombre": "Ana", "usuario": "ana2@empresa.test", "area": "Marketing"}]
    for cuerpo in malos:
        assert e.c.post("/credenciales", headers=e.ti, json=cuerpo).status_code == 422
    with sqlite3.connect(e.cfg.db_path) as con:
        assert con.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 1


# ---------------- PS-03 (-) RF-SEC-01, RF-SEC-05 / C-01, C-05 ----------------
def test_PS03_tokens_sin_alterados_vencidos_y_de_otro_emisor_o_audiencia(e):
    pw = cuenta(e)
    bueno = login(e, "ana.perez@empresa.test", pw).json()["token"]
    sid = jwt.decode(bueno, options={"verify_signature": False})["sid"]
    priv = e.cfg.clave_privada
    base = {"sub": "2", "sid": sid, "iss": e.cfg.emisor, "aud": e.cfg.audiencia,
            "iat": int(datetime.now(timezone.utc).timestamp())}
    pasado = datetime.now(timezone.utc) - timedelta(minutes=20)
    variantes = {
        "sin token": None,
        "alterado": bueno[:-6] + ("AAAAAA" if not bueno.endswith("AAAAAA") else "BBBBBB"),
        "vencido": jwt.encode({**base, "iat": int(pasado.timestamp()), "exp": int((pasado + timedelta(minutes=15)).timestamp())}, priv, "RS256"),
        "otro emisor": jwt.encode({**base, "iss": "atacante", "exp": base["iat"] + 900}, priv, "RS256"),
        "otra audiencia": jwt.encode({**base, "aud": "otro-servicio", "exp": base["iat"] + 900}, priv, "RS256"),
        "HS256 con la clave pública": jwt.api_jws.PyJWS().encode(
            b'{"sub":"2","sid":"x","iss":"auth.chat-grupo10","aud":"chat-empresarial","exp":9999999999,"iat":1}',
            key=b"cualquier-secreto-hmac-de-32-bytes!!", algorithm="HS256"),
    }
    for nombre, tok in variantes.items():
        r = e.c.get("/yo", headers=cab(tok) if tok else {})
        assert r.status_code == 401, nombre


# ---------------- PS-06 (+/-) RF-SEC-02, RF-SEC-10 / C-02, C-10 (parte de FastAPI) ----------------
def test_PS06_ti_gestiona_cuentas_y_supervisor_no(e):
    pw = cuenta(e, "sup.ventas@empresa.test", rol="supervisor")
    sup = cab(login(e, "sup.ventas@empresa.test", pw).json()["token"])
    r = e.c.post("/credenciales", headers=sup, json={"nombre": "Yo TI", "usuario": "falso.ti@empresa.test", "rol": "admin", "area": "TI"})
    assert r.status_code == 403                                   # el supervisor no se asigna TI
    assert e.c.delete("/credenciales/ana.perez@empresa.test", headers=sup).status_code == 403
    r = e.c.post("/credenciales", headers=e.ti, json={"nombre": "Nuevo", "usuario": "nuevo@empresa.test", "area": "Soporte"})
    assert r.status_code == 201 and r.json()["claveTemporal"]     # TI crea (con clave temporal)
    assert e.c.delete("/credenciales/nuevo@empresa.test", headers=e.ti).status_code == 204   # y desactiva
    eventos = e.c.get("/admin/auditoria", headers=e.ti).json()
    assert any(x["resultado"] == "denegado" and x["actor"] == "sup.ventas@empresa.test" for x in eventos)


# ---------------- PS-07 (+/-) RF-SEC-03 / C-03 ----------------
def test_PS07_argon2id_con_sal_individual(e):
    misma = clave()
    cuenta(e, "uno@empresa.test", pw=misma)
    cuenta(e, "dos@empresa.test", pw=misma)
    with sqlite3.connect(e.cfg.db_path) as con:
        h1, h2 = [r[0] for r in con.execute("SELECT hash_clave FROM usuarios WHERE correo IN ('uno@empresa.test','dos@empresa.test')")]
    assert h1 != h2                                                     # sal individual
    for h in (h1, h2):
        assert h.startswith("$argon2id$v=19$m=19456,t=2,p=1$") and misma not in h
    assert login(e, "uno@empresa.test", misma).status_code == 200       # solo coincide la correcta
    assert login(e, "uno@empresa.test", misma + "x").status_code == 401


# ---------------- PS-08 (-) RF-SEC-03, RF-SEC-08 / C-03, C-08 ----------------
def test_PS08_sin_secretos_en_respuestas_ni_auditoria(e):
    pw = cuenta(e)
    tok = login(e, "ana.perez@empresa.test", pw).json()["token"]
    login(e, "ana.perez@empresa.test", "ClaveErrada123")
    usuarios = e.c.get("/admin/usuarios", headers=e.ti).text
    auditoria = e.c.get("/admin/auditoria", headers=e.ti).text
    for texto in (usuarios, auditoria):
        assert pw not in texto and tok not in texto and "argon2" not in texto and "ClaveErrada123" not in texto


# ---------------- PS-10 (-) RF-SEC-05 / C-05 ----------------
def test_PS10_logout_y_desactivacion_revocan_la_sesion(e):
    pw = cuenta(e)
    t1 = login(e, "ana.perez@empresa.test", pw).json()["token"]
    assert e.c.post("/logout", headers=cab(t1)).status_code == 204
    assert e.c.post("/validar", json={"token": t1}).status_code == 401          # token tras cerrar sesión
    t2 = login(e, "ana.perez@empresa.test", pw).json()["token"]
    assert e.c.post("/validar", json={"token": t2}).status_code == 200
    e.c.delete("/credenciales/ana.perez@empresa.test", headers=e.ti)
    assert e.c.post("/validar", json={"token": t2}).status_code == 401          # sesión activa revocada
    assert login(e, "ana.perez@empresa.test", pw).status_code == 401            # no vuelve a autenticarse


# ---------------- PS-12 (+/-) RF-SEC-07 / C-07 ----------------
def test_PS12_bloqueo_tras_5_fallos_en_5_minutos(e):
    pw = cuenta(e)
    pw_otra = cuenta(e, "otra@empresa.test")
    for _ in range(5):
        e.reloj.t += 30                                                   # 5 fallos dentro de 5 minutos
        assert login(e, "ana.perez@empresa.test", "ClaveErrada123").status_code == 401
    assert login(e, "ana.perez@empresa.test", pw).status_code == 429     # el sexto queda bloqueado
    assert login(e, "otra@empresa.test", pw_otra).status_code == 200     # otra cuenta no se bloquea
    e.reloj.t += 5 * 60 + 1                                               # pasa la suspensión
    assert login(e, "ana.perez@empresa.test", pw).status_code == 200


# ---------------- PS-14 (+/-) RF-SEC-08 / C-08 ----------------
def test_PS14_auditoria_completa_solo_para_ti_e_inmutable(e):
    pw = cuenta(e)
    emp = cab(login(e, "ana.perez@empresa.test", pw).json()["token"])
    login(e, "ana.perez@empresa.test", "ClaveErrada123")
    assert e.c.get("/admin/auditoria", headers=emp).status_code == 403
    eventos = e.c.get("/admin/auditoria", headers=e.ti).json()
    assert all(x["fecha"] and x["actor"] and x["recurso"] and x["accion"] and x["resultado"] for x in eventos)
    assert {"rechazado", "denegado", "ok"} <= {x["resultado"] for x in eventos}
    with sqlite3.connect(e.cfg.db_path) as con:
        with pytest.raises(sqlite3.DatabaseError):
            con.execute("UPDATE auditoria SET resultado = 'ok'")
        with pytest.raises(sqlite3.DatabaseError):
            con.execute("DELETE FROM auditoria")
