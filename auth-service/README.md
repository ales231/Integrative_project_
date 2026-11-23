# Componente de Seguridad - Fase 3

Servicio FastAPI de Arthur Brayan Beltran Hernandez, preparado para la integracion con el chat Go del equipo. **No implementa ni reemplaza el chat de POO.**

## Funcionalidad implementada

- Creacion administrativa de cuentas y asignacion de rol (`empleado`, `supervisor`, `ti`). No hay registro publico que permita autoasignarse TI.
- Login mediante usuario y contrasena; rechazo generico de usuario inexistente, inactivo o contrasena incorrecta.
- Hash Argon2id, sal individual, 19 MiB, 2 iteraciones y paralelismo 1. No existe cifrado reversible de contrasenas.
- JWT RS256 de 15 minutos, validacion de firma/emisor/audiencia/tiempo, sesiones persistidas y revocacion inmediata en logout o desactivacion.
- `/me` permitido a personas autenticadas; `/users` y `/audit` restringidos a TI. Un servicio necesita token de persona y `X-Service-Key` para validar sesiones.
- Bloqueo por cuenta despues de 5 fallos en 5 minutos, durante 5 minutos; limite adicional de 30 intentos por IP y minuto.
- Auditoria de acciones sin contrasenas, tokens ni claves. Errores de validacion sanitizados, consultas parametrizadas y limite de cuerpo de 16 KiB.
- Certificado HTTPS local con validacion; fuera de laboratorio se rechaza HTTP y se requiere PostgreSQL.

## Instalar (desde la raiz del repositorio, PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r auth-service/requirements.lock.txt
Set-Location auth-service
..\.venv\Scripts\python.exe -m app.cli init-lab
$env:DATABASE_URL = 'sqlite:///./laboratorio.sqlite3'
$env:LABORATORY_MODE = '1'
$env:JWT_PRIVATE_KEY_FILE = '.secrets/jwt-private.pem'
$env:SERVICE_KEY_FILE = '.secrets/service.key'
..\.venv\Scripts\python.exe -m app.cli bootstrap
..\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers --ssl-keyfile .secrets/tls-private.pem --ssl-certfile .secrets/tls-cert.pem
```

`bootstrap` pide una contrasena privada por consola y solo funciona si no existen cuentas. Las claves se generan localmente y no se imprimen ni se suben. El certificado de `init-lab` es para localhost/127.0.0.1 y dura 30 dias; no es el certificado del despliegue entre sedes. Proteja `.secrets` mediante permisos del sistema; en Windows compruebe sus ACL.

Para el entorno final: quite `LABORATORY_MODE`, use una URL `postgresql+psycopg://...` y credenciales limitadas configuradas localmente, certificado emitido por la CA interna y DNS apropiados. La configuracion SQL de permisos separados debe validarse en PostgreSQL; no se acredita con el laboratorio SQLite. Ejecute **un solo trabajador** hasta sustituir el limitador de IP local por almacenamiento compartido. No active proxy headers sin un proxy de confianza configurado.

## Contrato de API

| Metodo / ruta | Acceso | Funcion |
|---|---|---|
| POST `/login` | Publico limitado | JSON `username`, `password`; devuelve JWT en cuerpo. No imprimirlo ni guardarlo en URL o logs. |
| GET `/me` | Bearer valido | Perfil propio sin hash. |
| POST `/logout` | Bearer valido | Revoca la sesion actual. |
| POST `/users` | TI | Crear cuenta, rol y area; contrasena de 12 a 128 caracteres. |
| GET `/users` | TI | Listado limitado a 100 registros, sin credenciales. |
| PATCH `/users/{id}` | TI | Cambiar rol o estado; revoca las sesiones del usuario. |
| GET `/audit` | TI | Ultimos 100 eventos; sin payloads secretos. |
| POST `/sessions/validate` | Bearer + clave de servicio | Identidad activa y rol actual para Go. |
| GET `/public-key` | Publico | Clave publica RS256 y metadatos; nunca clave privada. |

El token se mantiene en memoria. Estos endpoints usan encabezados Bearer, no cookies. Un cliente web futuro necesitara definir su modelo de cookies/CSRF y no debe persistir tokens en localStorage.

## Pruebas y evidencia real

```powershell
..\.venv\Scripts\python.exe -m pytest -q --junitxml=../evidence/seguridad/pytest-results.xml
..\.venv\Scripts\python.exe scripts/collect_evidence.py
```

La segunda orden inicia temporalmente un servidor HTTPS real de loopback, genera datos sinteticos privados, ejecuta los escenarios y guarda `evidence/seguridad/https-results.json`. No publica contrasenas, JWT, claves, sales o hashes completos. Las cuentas del laboratorio se eliminan junto con su carpeta temporal. El informe debe distinguir estas pruebas de un despliegue integrado entre Quito y Guayaquil.

## Integracion y pendientes honestos

Use el adaptador de `../security-go` antes de aceptar la conexion WSS y antes de acciones protegidas. El chat debera consultar de nuevo cada 30 segundos para cerrar sesiones revocadas antes de 60 segundos. **El adaptador no crea automaticamente ese bucle ni cierra las conexiones de un chat que aun no esta integrado.**

Pendientes: membresias y canales del chat Go, limites de mensajes/conexiones de C-07, PostgreSQL y roles separados C-10, reglas entre VLAN de C-06, respaldos cifrados C-09 y auditoria con escritor SQL sin UPDATE/DELETE C-08. El servicio actual aplica acceso a auditoria por API, pero no acredita inmutabilidad frente al propietario de la base. Una averia de FastAPI debe producir denegacion, no bypass.

Fuentes tecnicas: [FastAPI](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/), [PyJWT](https://pyjwt.readthedocs.io/en/latest/usage.html), [SQLAlchemy](https://docs.sqlalchemy.org/en/20/orm/session_basics.html).
