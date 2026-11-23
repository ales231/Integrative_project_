# Controles de seguridad – Chat empresarial (Grupo 10)

Código de la **Fase 3 de Fundamentos de la Seguridad** («Implementación de controles»). Implementa los controles diseñados en `docs/seguridad/fase2-diseno-seguridad.pdf` (rama `avances`). Usa sus mismos códigos: riesgos **R-01 a R-08**, requisitos **RF-SEC-01 a RF-SEC-10**, controles **C-01 a C-10** y pruebas **PS-01 a PS-17**.

También sigue el diseño de POO (Fase 3): rutas `/login`, `/validar` y `/credenciales`; clases `Autenticador`, `ClienteAuth`, `Sesion` y `ServidorChat`; y la estructura `app-go/` y `auth-service/` de `PI_TERCER_NIVEL`.

```
auth-service/                 Servicio de identidad (FastAPI)
  app/main.py                 rutas y controles C-01, C-05, C-07, C-08, C-10
  app/seguridad.py            Argon2id (C-03), JWT RS256 de 15 min (C-05), límite de intentos (C-07)
  app/db.py                   usuarios (solo hash), sesiones revocables, auditoría inmutable
  app/generar_claves.py       genera el par RSA (la privada nunca sale de FastAPI)
  tests/test_seguridad.py     pruebas PS-01, 02, 03, 06, 07, 08, 10, 12, 14 y C-01
app-go/                       Servidor de chat (Go, sin dependencias externas)
  internal/sesion/            verificación RS256 local y consulta de sesión a FastAPI (C-05)
  internal/servidor/          autorización por rol, área y membresía (C-02), límites (C-07), registro (C-08)
  cmd/servidor/               programa principal
scripts/demo_seguridad.py     ejecuta el plan de pruebas contra los servicios y muestra los resultados
```

## 1. Qué se implementó de la Fase 2

| Control | Requisito | Implementado en esta fase | Dónde |
|---|---|---|---|
| C-01 | RF-SEC-01 | Login con usuario corporativo y contraseña. Rechazo genérico idéntico para clave errada, usuario inexistente o cuenta inactiva, con verificación equivalente. Validación de entradas y SQL parametrizado | `auth-service/app/main.py`, `esquemas.py` |
| C-02 | RF-SEC-02 | Denegación por defecto. Cada operación comprueba rol, área y membresía vigentes; el ID del canal enviado por el cliente no prueba membresía. Al retirar a un miembro se bloquean sus nuevas lecturas y envíos | `app-go/internal/servidor` |
| C-03 | RF-SEC-03 | Argon2id con sal individual (m=19456 KiB, t=2, p=1). Se guardan hash, sal y parámetros; no hay recuperación reversible. Secretos fuera de Git | `auth-service/app/seguridad.py`, `.gitignore` |
| C-05 | RF-SEC-05 | JWT RS256 de 15 minutos con `sub`, `sid`, `iss`, `aud` y `exp`, sin rol ni contraseña. Go fija el algoritmo y valida firma, emisor, audiencia y vigencia con la clave pública, y además consulta el estado de la sesión en FastAPI. Cerrar sesión revoca la sesión; desactivar la cuenta revoca todas. Si FastAPI no responde, se deniega | `seguridad.py`, `main.py`, `app-go/internal/sesion` |
| C-07 | RF-SEC-07 | 5 fallos en 5 minutos bloquean el acceso 5 minutos, sin afectar a otras cuentas. Mensajes de hasta 4096 bytes (medidos en bytes) y 30 por minuto por cuenta | `seguridad.py` (intentos), `servidor.go` (mensajes) |
| C-08 | RF-SEC-08 | Auditoría con hora, actor, recurso, acción y resultado, sin contraseñas, tokens ni cuerpos de mensajes. Solo TI consulta. La tabla no admite UPDATE ni DELETE (triggers). Go registra cada acceso con el mismo criterio | `db.py`, `main.py`, `servidor.go` |
| C-10 | RF-SEC-10 | Solo TI crea y desactiva cuentas y asigna roles. Go no modifica roles ni hashes, y FastAPI no maneja mensajes | `main.py` (`solo_ti`) |

No implementados en esta fase (ver la sección 7): C-04 (TLS), C-06 (firewall y PostgreSQL), C-09 (respaldos) y las partes de C-05 y C-07 que dependen del canal WSS.

## 2. Requisitos
- Python 3.11 o superior
- Go 1.22 o superior

## 3. Preparar el servicio de identidad
En `auth-service`:

```bash
python -m venv venv
```

```bash
venv\Scripts\activate
```
(En Linux o Codespaces: `source venv/bin/activate`.)

```bash
pip install -r requirements.txt
```

```bash
python -m app.generar_claves
```

Copie `.env.example` como `.env` y escriba una `ADMIN_CLAVE` propia (10+ caracteres, mayúscula, minúscula y número). `.env` y `keys/` están en `.gitignore`: **no se suben ni deben aparecer en las capturas**.

## 4. Pruebas automáticas
En `auth-service`, con el entorno activado:

```bash
python -m pytest -v
```

Debe mostrar `10 passed`. En `app-go`:

```bash
go test ./... -v
```

Debe mostrar `PASS` en las 10 pruebas (`TestPS01` a `TestPS17`).

## 5. Ejecutar el plan de pruebas con los servicios
**Terminal 1** (en `auth-service`, con el entorno activado):

```bash
uvicorn app.main:crear_app --factory --env-file .env --port 8000
```

**Terminal 2** (en `app-go`):

```bash
go run ./cmd/servidor
```

**Terminal 3** (en la raíz, con el entorno de `auth-service` activado):

```bash
python scripts/demo_seguridad.py --ps17
```

El script recorre PS-01 a PS-14 y muestra al final una tabla *Prueba / Requisito / Control / Esperado / Obtenido / Resultado* (37 verificaciones). Con `--ps17` pide detener FastAPI (Ctrl+C en la terminal 1) para comprobar que Go deniega con `503`. La terminal 2 muestra el registro de Go (`actor=… resultado=denegado`).

## 6. Evidencias para cada apartado del informe

| Apartado | Captura sugerida |
|---|---|
| 1. Controles implementados | Tabla de la sección 1 |
| 2. Autenticación | Demo: PS-06 (TI crea la cuenta), PS-01 (login válido, token RS256 de 900 s) y PS-02 (tres rechazos con el mismo mensaje) |
| 2. Autorización | Demo: PS-04 (permitidos) y PS-05 y PS-06 (denegados); terminal 2 con las líneas `resultado=denegado` |
| 3. Protección de credenciales | Demo: PS-07 (dos hashes `$argon2id$v=19$m=19456,t=2,p=1$…` distintos con igual contraseña); función `Hasher` de `app/seguridad.py` |
| 4. Pruebas y resultados | Salida de `pytest -v`, de `go test ./... -v` y tabla final de la demo |
| 5. Trazabilidad | Tabla de la sección 7 |
| 6. Pendientes | Sección 8 |

## 7. Trazabilidad actualizada (Riesgo → Requisito → Control → Prueba → Resultado)
Filas tomadas de la Tabla 6 de la Fase 2. Los resultados corresponden a la ejecución de `pytest`, `go test` y la demo.

| Riesgo | Requisito | Control | Prueba | Resultado |
|---|---|---|---|---|
| R-01. Suplantación | RF-SEC-01 | C-01 | PS-01, PS-02, PS-03 | Cumple |
| R-01. Acceso residual | RF-SEC-05 | C-05 | PS-03, PS-10, PS-17 | Cumple; el cierre de conexiones ociosas en 60 s queda pendiente (WSS) |
| R-01. Intentos repetidos | RF-SEC-07 | C-07 | PS-12 | Cumple |
| R-02. Acceso ajeno | RF-SEC-02 | C-02 | PS-04, PS-05, PS-06 | Cumple; falta validar el área de la persona agregada |
| R-02. Privilegio excesivo | RF-SEC-10 | C-10 | PS-06, PS-16 | Parcial: PS-06 cumple; PS-16 pendiente |
| R-03. Interceptación | RF-SEC-04 | C-04 | PS-09 | Pendiente (TLS) |
| R-04. Secretos expuestos | RF-SEC-03 | C-03 | PS-07, PS-08 | Cumple |
| R-04. Secretos en logs | RF-SEC-08 | C-08 | PS-08, PS-14 | Cumple |
| R-04. Copias expuestas | RF-SEC-09 | C-09 | PS-15 | Pendiente |
| R-05. Acceso directo | RF-SEC-06 | C-06 | PS-11 | Pendiente (firewall, PostgreSQL y VLAN 99) |
| R-05. Abuso técnico | RF-SEC-10 | C-10 | PS-16 | Pendiente |
| R-06. Saturación | RF-SEC-07 | C-07 | PS-12, PS-13 | Parcial: intentos, tamaño y frecuencia cumplen; límite de 5 conexiones pendiente (WSS) |
| R-07. Pérdida de datos | RF-SEC-09 | C-09 | PS-15 | Pendiente |
| R-08. Sin evidencia | RF-SEC-08 | C-08 | PS-08, PS-14 | Cumple |
| R-08. Cambios indebidos | RF-SEC-02 / 10 | C-02 / C-10 | PS-06, PS-16 | Parcial: PS-06 cumple; PS-16 pendiente |

## 8. Pendientes para la Fase 4
- **C-04 / PS-09:** HTTPS y WSS con certificados de la CA interna; ahora los servicios corren por HTTP en `localhost`.
- **C-06 / PS-11:** reglas de firewall, acceso a PostgreSQL solo desde Go y FastAPI, y administración desde VLAN 99.
- **C-09 / PS-15:** respaldo diario cifrado con AES-256-GCM y prueba de restauración en 4 horas.
- **C-10 / PS-16:** cuentas técnicas separadas en PostgreSQL. Esta fase usa SQLite para la identidad.
- **C-05:** revisión de conexiones ociosas cada 30 s, y **C-07:** límite de 5 conexiones por cuenta. Ambos se implementan cuando el chat pase a WSS.
- **C-02:** validar el área de la persona que se agrega a un canal (requiere el directorio de usuarios en PostgreSQL).
- **C-07:** los contadores de intentos y mensajes están en memoria de un solo proceso; con varios procesos deben compartirse.
