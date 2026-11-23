"""Almacén de identidad (SQLite): usuarios, sesiones y auditoría.

- usuarios.hash_clave guarda el hash Argon2id con su sal y parámetros (C-03), nunca la contraseña.
- sesiones permite revocar al cerrar sesión o al desactivar la cuenta (C-05).
- auditoria solo admite inserciones: los triggers impiden editar o borrar eventos (C-08).
"""
import sqlite3
from datetime import datetime, timezone

ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre      TEXT NOT NULL,
    correo      TEXT NOT NULL UNIQUE,
    hash_clave  TEXT NOT NULL,
    rol         TEXT NOT NULL CHECK (rol IN ('empleado', 'supervisor', 'admin')),
    area        TEXT NOT NULL,
    activo      INTEGER NOT NULL DEFAULT 1,
    creado_en   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sesiones (
    sid         TEXT PRIMARY KEY,
    usuario_id  INTEGER NOT NULL REFERENCES usuarios(id),
    creada_en   TEXT NOT NULL,
    vence_en    TEXT NOT NULL,
    revocada    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS auditoria (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha       TEXT NOT NULL,
    actor       TEXT,
    recurso     TEXT NOT NULL,
    accion      TEXT NOT NULL,
    resultado   TEXT NOT NULL,
    detalle     TEXT
);
CREATE TRIGGER IF NOT EXISTS auditoria_sin_update BEFORE UPDATE ON auditoria
BEGIN SELECT RAISE(ABORT, 'la auditoría no se puede modificar'); END;
CREATE TRIGGER IF NOT EXISTS auditoria_sin_delete BEFORE DELETE ON auditoria
BEGIN SELECT RAISE(ABORT, 'la auditoría no se puede borrar'); END;
"""


def ahora() -> datetime:
    return datetime.now(timezone.utc)


def iso(d: datetime) -> str:
    return d.isoformat(timespec="seconds")


class Almacen:
    def __init__(self, ruta: str):
        self.ruta = ruta
        with self.con() as c:
            c.executescript(ESQUEMA)

    def con(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.ruta)
        c.row_factory = sqlite3.Row
        return c

    # ---------- usuarios ----------
    def crear_usuario(self, nombre, correo, hash_clave, rol, area) -> int:
        with self.con() as c:
            return c.execute(
                "INSERT INTO usuarios (nombre, correo, hash_clave, rol, area, creado_en) VALUES (?, ?, ?, ?, ?, ?)",
                (nombre, correo, hash_clave, rol, area, iso(ahora()))).lastrowid

    def por_correo(self, correo):
        with self.con() as c:
            return c.execute("SELECT * FROM usuarios WHERE correo = ?", (correo,)).fetchone()

    def por_id(self, uid):
        with self.con() as c:
            return c.execute("SELECT * FROM usuarios WHERE id = ?", (uid,)).fetchone()

    def actualizar_hash(self, uid, nuevo_hash):
        with self.con() as c:
            c.execute("UPDATE usuarios SET hash_clave = ? WHERE id = ?", (nuevo_hash, uid))

    def desactivar(self, correo) -> int | None:
        with self.con() as c:
            fila = c.execute("SELECT id FROM usuarios WHERE correo = ?", (correo,)).fetchone()
            if fila is None:
                return None
            c.execute("UPDATE usuarios SET activo = 0 WHERE id = ?", (fila["id"],))
            c.execute("UPDATE sesiones SET revocada = 1 WHERE usuario_id = ?", (fila["id"],))
            return fila["id"]

    def listar(self):
        with self.con() as c:
            return c.execute("SELECT id, nombre, correo, rol, area, activo FROM usuarios ORDER BY id").fetchall()

    # ---------- sesiones ----------
    def crear_sesion(self, sid, uid, vence: datetime):
        with self.con() as c:
            c.execute("INSERT INTO sesiones (sid, usuario_id, creada_en, vence_en) VALUES (?, ?, ?, ?)",
                      (sid, uid, iso(ahora()), iso(vence)))

    def sesion(self, sid):
        with self.con() as c:
            return c.execute("SELECT * FROM sesiones WHERE sid = ?", (sid,)).fetchone()

    def revocar_sesion(self, sid):
        with self.con() as c:
            c.execute("UPDATE sesiones SET revocada = 1 WHERE sid = ?", (sid,))

    # ---------- auditoría (C-08): sin contraseñas, tokens ni cuerpos de mensajes ----------
    def auditar(self, actor, recurso, accion, resultado, detalle=""):
        with self.con() as c:
            c.execute("INSERT INTO auditoria (fecha, actor, recurso, accion, resultado, detalle) VALUES (?, ?, ?, ?, ?, ?)",
                      (iso(ahora()), actor, recurso, accion, resultado, detalle))

    def eventos(self, limite=50):
        with self.con() as c:
            return c.execute("SELECT * FROM auditoria ORDER BY id DESC LIMIT ?", (limite,)).fetchall()
