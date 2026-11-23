# Contrato compartido de integración — versión 1.0.0

22 de noviembre de 2026. Misma revisión en `main`, `beltranfuego`, `luis-novillo` y `alex-alban`.
Este documento y `contrato.json` resuelven las diferencias entre POO, Seguridad y Redes.
La implementación de identidad de referencia es `auth-service/` y el adaptador es `security-go/`.
No se ha confirmado la entrega en la plataforma ni aprobación docente de estos ajustes.

## Identidad y permisos

`username` es el identificador corporativo, por ejemplo `ana.perez`: entre 3 y 64 caracteres
de `[a-z0-9._-]`, normalizados a minúsculas y sin espacios exteriores. No es el correo y no admite `@`.
Los formularios de POO deben pedir «Usuario corporativo» para login, destinatarios y membresía.
No se debe quitar automáticamente el dominio de un correo: podrían colisionar dos cuentas.
El `id` numérico de FastAPI es la clave estable para relacionar perfiles, salas, mensajes y métricas.
Nombre, correo de contacto y sede pueden ser datos del perfil del chat; no son campos aceptados por `/users`.
`area` es un código ASCII sin espacios (`Ventas`, `Soporte`, `TI`, etc.); el chat no cambia su valor por su cuenta.
Los únicos roles son `empleado`, `supervisor` y `ti`. «Administrador de TI» es una etiqueta de interfaz para `ti`.

FastAPI es la autoridad de cuentas, roles, áreas, contraseñas y sesiones. El servidor de chat no escribe
esas tablas ni hashes. El cliente de TI envía altas/cambios directamente a FastAPI con su Bearer de TI;
el servidor Go no recibe contraseñas. Un posible GestorCuentas es una fachada del cliente para esa API,
no un administrador de identidades dentro del servidor ni un método de `security-go`.
`GET /users` es exclusivo de TI y devuelve como máximo 100 filas; no se ofrece a supervisores.
El futuro repositorio del chat debe disponer de perfiles provisionados asociados a `id` para comprobar
el área y estado del miembro destino. No autorizar por un correo inventado ni tratar ese listado limitado
como un directorio público completo. Esa provisión todavía requiere implementación y pruebas.

## API implementada

Todas las llamadas se hacen por HTTPS. JSON usa estos nombres exactos, no las traducciones del diseño antiguo.

| Método y ruta | Entrada / autorización | Resultado |
|---|---|---|
| GET `/health` | Público | Estado del servicio, sin secretos |
| POST `/login` | JSON `username`, `password` | 200: `access_token`, `token_type`, `expires_in` (=900); rechazo genérico 401 o límite 429 |
| GET `/me` | Bearer | `id`, `username`, `role`, `area`, `active` |
| POST `/logout` | Bearer | 204; revoca la sesión |
| POST `/users` | Bearer TI; JSON `username`, `password`, `role`, `area` | 201: perfil; duplicado 409; validación 422 |
| GET `/users` | Bearer TI | Perfiles, máximo 100 |
| PATCH `/users/{uid}` | Bearer TI; JSON `active` y/o `role` | Perfil actualizado y revocación de todas sus sesiones; inexistente 404 |
| GET `/audit` | Bearer TI | Últimos 100 eventos, sin contraseñas ni tokens |
| GET `/public-key` | Público | Clave pública y metadatos, nunca clave privada |
| POST `/sessions/validate` | Bearer + `X-Service-Key`; sin cuerpo | Perfil activo; token rechazado 401, clave de servicio incorrecta 403 |

La contraseña de alta tiene 12 a 128 caracteres. TI la establece y no se devuelve ni se genera una
clave temporal en la respuesta. Campos adicionales como `nombre` o `sede` se rechazan con 422.
Desactivar significa `PATCH /users/{uid}` con `{"active":false}`, no DELETE.
Los cambios de rol revocan sesiones: el usuario vuelve a iniciar sesión; no sigue con el mismo JWT.
La propia cuenta de TI no puede desactivarse ni quitarse su rol mediante esa operación (409).
`/validar` y `/credenciales` no pertenecen a la API oficial.

## Sesiones, TLS y configuración

JWT RS256: duración 900 s, `iss=uide-auth`, `aud=uide-chat`; campos `sub`, `jti`, `iat`, `exp`, `iss`, `aud`.
El token no es fuente de rol ni área: `Validate(ctx, token)` consulta su estado y obtiene el perfil vigente.
El token permanece en memoria; no viaja en URL ni se registra. Cerrar sesión llama `/logout`, además de
cerrar WSS y limpiar memoria. Desactivar o cambiar rol invalida sesiones existentes.

El adaptador se configura con `New(urlHTTPS, publicPEM, caPEM, serviceKey)`. Verifica firma y TLS,
rechaza redirecciones y usa un timeout HTTP de 5 s. No obtiene confianza por descargar `/public-key`
desde un origen sin verificar. La clave privada RSA permanece únicamente en FastAPI.

Para el arranque futuro de `app-go` se define esta convención: `AUTH_URL` (HTTPS),
`AUTH_PUBLIC_KEY_FILE`, `AUTH_CA_FILE` y `AUTH_SERVICE_KEY_FILE`. El arranque deberá leer esos archivos,
recortar el salto final de la clave de servicio y pasar los contenidos a `New`. Esta carga de variables
en `app-go` es una especificación pendiente; no se afirma que ya esté programada.
FastAPI ya lee `DATABASE_URL`, `JWT_PRIVATE_KEY_FILE` y `SERVICE_KEY_FILE`.
Usar el mismo archivo de clave de servicio en ambos procesos, con permisos limitados.
Nunca reutilizar el archivo de clave privada de TLS como clave pública de firma JWT.

Laboratorio: FastAPI HTTPS en `127.0.0.1:8000`, certificado local, SQLite temporal y un trabajador.
Diseño entre sedes: FastAPI HTTPS tcp/8000 en servidor autorizado de VLAN 20 Quito;
chat WSS tcp/443; PostgreSQL con TLS tcp/5432. El puerto 443 del chat no implica que FastAPI use 443.
Direcciones/DNS y certificados de la CA interna deben provisionarse y comprobarse en el despliegue.
No está implementado un proxy que cambie 443 a 8000 ni se acredita ese despliegue con el laboratorio.

## Obligaciones pendientes del chat

Antes de aceptar WSS y antes de cada operación: ejecutar `Validate` y comprobar rol, área,
membresía o participación vigentes. Revalidar también conexiones ociosas cada 30 s y cerrarlas
como máximo 60 s después de una revocación; ante error o autenticación no disponible, denegar/cerrar.
El adaptador devuelve un error común: el chat no debe inventar que distingue revocación de caída del servicio.
Solo el supervisor del área administra canales de esa área; el miembro añadido debe existir, estar activo
y pertenecer al área. Leer, enviar, consultar historial y difundir requieren autorización vigente.
TI no recibe permiso automático para leer todos los mensajes por administrar cuentas.

Aplicar simultáneamente 2000 caracteres Unicode y 4096 bytes UTF-8 por texto, 30 mensajes/minuto
y 5 conexiones por cuenta. Un mensaje de 2000 emojis puede incumplir el límite en bytes.
Las pruebas de rendimiento de 1000 mensajes deben repartir carga entre cuentas/tiempo para no violar
el límite individual; 135 conexiones se prueban con 135 cuentas, no con una sola.
Métricas: una sesión autenticada dura como máximo 15 min; una jornada con varios logins es otra medida.
No usar ejemplos de 96 min o 2 h 14 min como duración de una única sesión autenticada.

## Redes y base de datos

Se conserva el direccionamiento de `network/week9/data/addressing_table.csv`: Quito 10.10.0.0/22,
Guayaquil 10.10.4.0/22; usuarios VLAN 10, servidores VLAN 20, invitados VLAN 30, administración VLAN 99.
En el prototipo de semana 9 siguen activos VLAN 1 sin segmentación y rutas estáticas; VLANs, OSPF,
ACL, NAT/firewall y controles SQL no se presentan como ya ejecutados.
Objetivo: permitir a usuarios autorizados llegar a HTTPS/WSS, impedir acceso de invitados a servicios
internos, permitir PostgreSQL solo desde Go/FastAPI con identidades y permisos distintos y restringir
administración a TI desde VLAN 99. La ubicación en una VLAN no sustituye autenticar ni autorizar.
Auditoría de solo inserción, respaldo cifrado diario, RPO 24 h, RTO 4 h y pruebas de restauración
permanecen pendientes en PostgreSQL. Los triggers de SQLite de la versión paralela no los acreditan.

## Cómo se interpretan los documentos previos

Las fases entregadas previamente son antecedentes fechados. La adenda incluida en los PDF actuales
de POO y Redes y este contrato sustituyen sus valores discrepantes para el desarrollo siguiente.
No se atribuye aprobación docente a estos cambios. No se modifica retroactivamente el resultado
de las pruebas ni se agregan firmas a la adenda.
El archivo histórico de Luis queda en `historico/codigo-luis-referencia.zip`, fuera de las rutas activas;
su autenticación paralela no debe arrancarse ni integrarse.
La versión del PDF que se suba a la plataforma debe ser exactamente la misma que la del repositorio.
