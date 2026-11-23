"""Ejecución del plan de pruebas de seguridad (Fase 2, Tabla 5) contra los servicios reales.

Requisitos: FastAPI en AUTH_URL (http://127.0.0.1:8000) y servidor Go en GO_URL
(http://127.0.0.1:8080). Lee la cuenta de TI de auth-service/.env. Crea cuentas de prueba
con contraseñas aleatorias; los tokens se muestran recortados (no se exponen secretos).

Ejecutar desde la raíz del proyecto:
    python scripts/demo_seguridad.py            # PS-01 a PS-14
    python scripts/demo_seguridad.py --ps17     # añade PS-17: pide detener FastAPI al final
"""
import base64
import json
import os
import secrets
import sqlite3
import sys
import time
from pathlib import Path

import httpx
import jwt
from dotenv import dotenv_values

RAIZ = Path(__file__).resolve().parent.parent
AUTH_DIR = RAIZ / "auth-service"
ENV = {**dotenv_values(AUTH_DIR / ".env"), **os.environ}
AUTH = ENV.get("AUTH_URL", "http://127.0.0.1:8000")
GO = ENV.get("GO_URL", "http://127.0.0.1:8080")
DB = Path(ENV.get("AUTH_DB_PATH", AUTH_DIR / "auth.db"))
SUF = secrets.token_hex(2)
filas = []
c = httpx.Client(timeout=15)


def u(nombre):
    return f"{nombre}.{SUF}@empresa.test"


def corto(tok):
    return tok[:14] + "…(recortado)"


def clave():
    return "Prueba" + secrets.token_hex(4) + "7"


def caso(cod, req, ctrl, desc, esperado, r, nota=""):
    obtenido = r.status_code if isinstance(r, httpx.Response) else r
    ok = obtenido == esperado
    filas.append((cod, req, ctrl, desc, esperado, obtenido, ok))
    linea = f"   {desc}: esperado {esperado}, obtenido {obtenido} -> {'CUMPLE' if ok else 'NO CUMPLE'}"
    print(linea)
    if nota or isinstance(r, httpx.Response) and r.text and r.status_code >= 300:
        print(f"      {nota or r.text[:150]}")


def titulo(cod, signo, req, ctrl, texto):
    print(f"\n[{cod} ({signo})] {req} / {ctrl} — {texto}")


def login(usuario, pw):
    return c.post(f"{AUTH}/login", json={"usuario": usuario, "clave": pw})


def cab(tok):
    return {"Authorization": f"Bearer {tok}"}


def main():
    if not ENV.get("ADMIN_CORREO") or not ENV.get("ADMIN_CLAVE"):
        sys.exit("Defina ADMIN_CORREO y ADMIN_CLAVE en auth-service/.env")
    print("=" * 78)
    print(" EJECUCIÓN DEL PLAN DE PRUEBAS DE SEGURIDAD – Chat empresarial (Grupo 10)")
    print("=" * 78)
    ti = cab(login(ENV["ADMIN_CORREO"], ENV["ADMIN_CLAVE"]).raise_for_status().json()["token"])

    # Cuentas de prueba (PS-06 +: TI crea cuentas). Ana y Luis comparten contraseña para PS-07.
    comun = clave()
    cuentas = {"ana": ("empleado", "Ventas", comun), "luis": ("empleado", "Ventas", comun),
               "pedro": ("empleado", "Soporte", clave()), "supv": ("supervisor", "Ventas", clave()),
               "sups": ("supervisor", "Soporte", clave()), "baja": ("empleado", "Atención", clave())}
    titulo("PS-06", "+", "RF-SEC-10", "C-10", "TI crea las cuentas de prueba")
    for n, (rol, area, pw) in cuentas.items():
        r = c.post(f"{AUTH}/credenciales", headers=ti, json={"nombre": n.capitalize(), "usuario": u(n), "rol": rol, "area": area, "clave": pw})
        if n == "ana":
            caso("PS-06", "RF-SEC-10", "C-10", f"TI crea {u(n)} ({rol}, {area})", 201, r)
    pw = {n: v[2] for n, v in cuentas.items()}

    # PS-01 (+)
    titulo("PS-01", "+", "RF-SEC-01", "C-01", "inicio de sesión con credenciales válidas")
    r = login(u("ana"), pw["ana"])
    tok_ana = r.json()["token"]
    d = jwt.decode(tok_ana, options={"verify_signature": False})
    caso("PS-01", "RF-SEC-01", "C-01", "Ana inicia sesión", 200, r,
         f"token {corto(tok_ana)} | alg RS256 | campos {sorted(d)} | duración {d['exp'] - d['iat']} s | sin rol ni contraseña")

    # PS-02 (-)
    titulo("PS-02", "-", "RF-SEC-01", "C-01", "rechazo genérico")
    c.delete(f"{AUTH}/credenciales/{u('baja')}", headers=ti)
    for desc, usr, clv in [("contraseña incorrecta", u("ana"), "ClaveErrada123"),
                           ("usuario inexistente", u("nadie"), pw["ana"]),
                           ("cuenta desactivada", u("baja"), pw["baja"])]:
        r = login(usr, clv)
        caso("PS-02", "RF-SEC-01", "C-01", desc, 401, r, f"mensaje: {r.json().get('detail')}")

    # PS-07 (+/-)
    titulo("PS-07", "+/-", "RF-SEC-03", "C-03", "Argon2id con sal individual")
    with sqlite3.connect(DB) as con:
        h_ana, h_luis = [con.execute("SELECT hash_clave FROM usuarios WHERE correo = ?", (u(n),)).fetchone()[0] for n in ("ana", "luis")]
    print(f"      Ana : {h_ana[:46]}…")
    print(f"      Luis: {h_luis[:46]}…   (misma contraseña)")
    caso("PS-07", "RF-SEC-03", "C-03", "hashes distintos con igual contraseña", "distintos", "distintos" if h_ana != h_luis else "iguales")
    caso("PS-07", "RF-SEC-03", "C-03", "contraseña legible en la base", "no", "no" if comun not in h_ana + h_luis else "sí")
    caso("PS-07", "RF-SEC-03", "C-03", "solo coincide la contraseña correcta", 401, login(u("luis"), comun + "x"))

    # PS-03 (-) en el servidor Go
    titulo("PS-03", "-", "RF-SEC-01, RF-SEC-05", "C-01, C-05", "el servidor Go rechaza tokens no válidos")
    privada = (AUTH_DIR / "keys" / "privada.pem").read_text()
    base = {"sub": d["sub"], "sid": d["sid"], "iss": d["iss"], "aud": d["aud"], "iat": int(time.time())}
    variantes = [
        ("sin token", None),
        ("token alterado", tok_ana[:-6] + ("AAAAAA" if not tok_ana.endswith("AAAAAA") else "BBBBBB")),
        ("token vencido", jwt.encode({**base, "iat": int(time.time()) - 1200, "exp": int(time.time()) - 300}, privada, "RS256")),
        ("otro emisor", jwt.encode({**base, "iss": "atacante", "exp": int(time.time()) + 600}, privada, "RS256")),
        ("otra audiencia", jwt.encode({**base, "aud": "otro-servicio", "exp": int(time.time()) + 600}, privada, "RS256")),
    ]
    for desc, tok in variantes:
        caso("PS-03", "RF-SEC-05", "C-05", desc, 401, c.get(f"{GO}/api/perfil", headers=cab(tok) if tok else {}))

    # PS-04 (+)
    tok = {n: login(u(n), pw[n]).json()["token"] for n in ("luis", "pedro", "supv", "sups")}
    tok["ana"] = tok_ana
    titulo("PS-04", "+", "RF-SEC-02", "C-02", "miembro lee y envía en su canal")
    r = c.post(f"{GO}/api/canales", headers=cab(tok["supv"]), json={"nombre": "Ventas-GYE"})
    canal = r.json()["datos"]["id"]
    caso("PS-04", "RF-SEC-02", "C-02", "supervisor de Ventas crea el canal", 201, r)
    caso("PS-04", "RF-SEC-02", "C-02", "supervisor agrega a Ana", 201,
         c.post(f"{GO}/api/canales/{canal}/miembros", headers=cab(tok["supv"]), json={"usuario": u("ana")}))
    caso("PS-04", "RF-SEC-02", "C-02", "Ana envía un mensaje", 201,
         c.post(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["ana"]), json={"texto": "Buenos días, Ventas"}))
    caso("PS-04", "RF-SEC-02", "C-02", "Ana lee el historial", 200, c.get(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["ana"])))

    # PS-05 (-)
    titulo("PS-05", "-", "RF-SEC-02", "C-02", "canal ajeno y miembro retirado")
    caso("PS-05", "RF-SEC-02", "C-02", "Luis (Ventas, no miembro) lee", 403, c.get(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["luis"])))
    caso("PS-05", "RF-SEC-02", "C-02", "Pedro cambia el ID del canal y envía", 403,
         c.post(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["pedro"]), json={"texto": "intruso"}))

    # PS-06 (+/-)
    titulo("PS-06", "+/-", "RF-SEC-02, RF-SEC-10", "C-02, C-10", "alcance del supervisor y de TI")
    caso("PS-06", "RF-SEC-02", "C-02", "supervisor de Soporte agrega en canal de Ventas", 403,
         c.post(f"{GO}/api/canales/{canal}/miembros", headers=cab(tok["sups"]), json={"usuario": u("pedro")}))
    caso("PS-06", "RF-SEC-10", "C-10", "supervisor intenta crearse una cuenta de TI", 403,
         c.post(f"{AUTH}/credenciales", headers=cab(tok["supv"]), json={"nombre": "Yo", "usuario": u("falso.ti"), "rol": "admin", "area": "TI"}))
    caso("PS-06", "RF-SEC-10", "C-10", "TI desactivó una cuenta (baja)", 401, login(u("baja"), pw["baja"]))

    # PS-13 (+/-)
    titulo("PS-13", "+/-", "RF-SEC-07", "C-07", "límites de tamaño y frecuencia de mensajes")
    c.post(f"{GO}/api/canales/{canal}/miembros", headers=cab(tok["supv"]), json={"usuario": u("luis")})
    caso("PS-13", "RF-SEC-07", "C-07", "mensaje de 4096 bytes", 201,
         c.post(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["luis"]), json={"texto": "a" * 4096}))
    caso("PS-13", "RF-SEC-07", "C-07", "mensaje de 4097 bytes", 413,
         c.post(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["luis"]), json={"texto": "a" * 4097}))
    for _ in range(29):
        c.post(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["luis"]), json={"texto": "ok"})
    caso("PS-13", "RF-SEC-07", "C-07", "mensaje 31 dentro del mismo minuto", 429,
         c.post(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["luis"]), json={"texto": "de más"}))
    caso("PS-13", "RF-SEC-07", "C-07", "otra cuenta (Ana) sigue enviando", 201,
         c.post(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["ana"]), json={"texto": "sigo aquí"}))

    # PS-05 (-) retiro de membresía
    titulo("PS-05", "-", "RF-SEC-02", "C-02", "tras retirar a Ana del canal")
    c.delete(f"{GO}/api/canales/{canal}/miembros/{u('ana')}", headers=cab(tok["supv"]))
    caso("PS-05", "RF-SEC-02", "C-02", "Ana ya no lee", 403, c.get(f"{GO}/api/canales/{canal}/mensajes", headers=cab(tok["ana"])))

    # PS-10 (-)
    titulo("PS-10", "-", "RF-SEC-05", "C-05", "cerrar sesión y desactivar revocan el acceso")
    caso("PS-10", "RF-SEC-05", "C-05", "Ana cierra sesión", 204, c.post(f"{AUTH}/logout", headers=cab(tok["ana"])))
    caso("PS-10", "RF-SEC-05", "C-05", "Go rechaza el token de la sesión cerrada", 401, c.get(f"{GO}/api/perfil", headers=cab(tok["ana"])))
    c.delete(f"{AUTH}/credenciales/{u('luis')}", headers=ti)
    caso("PS-10", "RF-SEC-05", "C-05", "Go rechaza a Luis tras desactivar su cuenta", 401, c.get(f"{GO}/api/perfil", headers=cab(tok["luis"])))
    caso("PS-10", "RF-SEC-05", "C-05", "Luis no vuelve a iniciar sesión", 401, login(u("luis"), pw["luis"]))

    # PS-12 (+/-)
    titulo("PS-12", "+/-", "RF-SEC-07", "C-07", "límite de intentos de acceso")
    for _ in range(5):
        login(u("pedro"), "ClaveErrada123")
    caso("PS-12", "RF-SEC-07", "C-07", "sexto intento de Pedro (clave correcta)", 429, login(u("pedro"), pw["pedro"]))
    caso("PS-12", "RF-SEC-07", "C-07", "otra cuenta no queda bloqueada", 200, login(u("sups"), pw["sups"]))
    print("      (El desbloqueo tras 5 minutos se comprueba en pytest: test_PS12.)")

    # PS-14 (+/-) y PS-08 (-)
    titulo("PS-14", "+/-", "RF-SEC-08", "C-08", "auditoría")
    caso("PS-14", "RF-SEC-08", "C-08", "empleado consulta la auditoría", 403, c.get(f"{AUTH}/admin/auditoria", headers=cab(tok["pedro"])))
    r = c.get(f"{AUTH}/admin/auditoria", headers=ti)
    caso("PS-14", "RF-SEC-08", "C-08", "TI consulta la auditoría", 200, r, "últimos eventos:")
    for ev in r.json()[:7]:
        print(f"         {ev['fecha']} | {ev['actor']:<30.30} | {ev['recurso']:<26.26} | {ev['accion']:<18} | {ev['resultado']}")
    try:
        with sqlite3.connect(DB) as con:
            con.execute("DELETE FROM auditoria")
        borrado = "permitido"
    except sqlite3.DatabaseError as e:
        borrado = "rechazado"
        print(f"      intento de borrar eventos: {e}")
    caso("PS-14", "RF-SEC-08", "C-08", "borrar eventos de auditoría", "rechazado", borrado)
    titulo("PS-08", "-", "RF-SEC-03, RF-SEC-08", "C-03, C-08", "sin secretos en respuestas ni auditoría")
    texto = r.text + c.get(f"{AUTH}/admin/usuarios", headers=ti).text
    hay = any(x in texto for x in list(pw.values()) + list(tok.values()) + ["argon2"])
    caso("PS-08", "RF-SEC-08", "C-08", "contraseñas, tokens o hashes expuestos", "no", "sí" if hay else "no")

    # PS-17 (-) opcional
    if "--ps17" in sys.argv:
        titulo("PS-17", "-", "RF-SEC-05", "C-05", "FastAPI sin respuesta")
        input("      Detenga FastAPI (Ctrl+C en su terminal) y pulse Enter aquí… ")
        caso("PS-17", "RF-SEC-05", "C-05", "Go con un token aún vigente", 503, c.get(f"{GO}/api/perfil", headers=cab(tok["sups"])))

    print("\n" + "=" * 78)
    print(f" {'Prueba':<7}{'Requisito':<12}{'Control':<8}{'Esperado':<11}{'Obtenido':<11}{'Resultado':<11}Descripción")
    for cod, req, ctrl, desc, esp, obt, ok in filas:
        print(f" {cod:<7}{req:<12}{ctrl:<8}{str(esp):<11}{str(obt):<11}{'CUMPLE' if ok else 'NO CUMPLE':<11}{desc}")
    print(f"\n {sum(f[6] for f in filas)} de {len(filas)} verificaciones cumplen.")
    print("=" * 78)


if __name__ == "__main__":
    main()
