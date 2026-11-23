# Alineación de las entregas del Proyecto Integrador

## Alcance y responsables

Arthur: **Fundamentos de Seguridad** (`beltranfuego`). Luis: **Go / POO** (`luis-novillo`).
Alex: **Redes** (`alex-alban`). Las entregas corresponden al mismo chat empresarial Quito–Guayaquil,
pero cada materia conserva su alcance, documentos, código y evidencias. No deben copiarse todos los
archivos de una materia a las otras ramas para demostrar alineación.

La revisión anterior mezcló las ramas. Esta corrección recupera los archivos propios anteriores y
limita los cambios nuevos a esta nota y a las aclaraciones de los informes afectados. Los diagramas
completos y el código original de Luis se conservan. El código paralelo de identidad dentro de
codigo-luis/ sigue siendo referencia histórica, no reemplaza el servicio de Arthur.

## Correcciones que deben leerse en las entregas

| Tema | POO / Go de Luis | Seguridad de Arthur | Redes de Alex |
|---|---|---|---|
| Sesión | RNF-03 y CP-30 pasan de 8 h a 15 min | JWT RS256, 900 s | No define una duración distinta de sesión de aplicación |
| Roles | El valor del administrador TI es `ti`, no `admin` | empleado, supervisor, ti | Usuarios locales SSH de equipos son otra identidad |
| Cuentas | El cliente TI llama a FastAPI; el chat no escribe hashes ni roles | /users crea; PATCH /users/{uid} cambia rol o estado | Restringir acceso de administración; no gestionar roles del chat en routers |
| Identidad | Pedir usuario corporativo, por ejemplo ana.perez; usar ID estable | username acepta [a-z0-9._-], no @ | Direcciones IP y VLAN no reemplazan identidad de aplicación |
| Login | JSON username/password; leer access_token/token_type/expires_in | POST /login, expires_in=900 | HTTPS; no enviar credenciales en claro |
| Validación | Usar security-go.Validate por operación; revisar ociosas cada 30 s | POST /sessions/validate; Bearer + X-Service-Key, sin cuerpo | Permitir solo las comunicaciones autorizadas |
| Cierre y cambios | Cerrar WSS, borrar token; tras cambio de rol se requiere nuevo login | POST /logout revoca; PATCH revoca sesiones | No confundir caída de red con autorización concedida |
| Alta | CP-18: TI fija contraseña de 12–128; 201 perfil, duplicado 409 | No devuelve clave temporal | Sin efecto sobre el direccionamiento |
| Mensajes | Cumplir simultáneamente 2000 caracteres y 4096 bytes UTF-8 | Máximo 30 mensajes/min y 5 conexiones por cuenta como requisitos del chat | Dimensionar y probar sin afirmar que límites de aplicación son ACL |

No quitar automáticamente el dominio de un correo para convertirlo a username: podría crear colisiones.
Nombre y sede pertenecen al perfil del chat; no son campos de /users. El área usa códigos sin espacios.
Para agregar un miembro se comprueba que existe, está activo y pertenece al área; consultar o difundir
también exige membresía vigente. TI no obtiene acceso general a mensajes por administrar cuentas.

## Diseño, laboratorio y pruebas

FastAPI ya se probó por HTTPS en **8000 de loopback**. POO plantea acceso HTTPS en 443 para
el despliegue; se conserva como diseño, que deberá definir terminación TLS/proxy antes de probarlo.
No existe aún una publicación 443→8000 acreditada. Chat WSS 443 y PostgreSQL TLS 5432 son objetivos.
La CA, clave pública y clave de servicio se pasan por contenido a New; el arranque futuro de Go
deberá leer archivos protegidos. La clave privada de firma permanece en FastAPI.

El VLSM de Alex se conserva: Quito 10.10.0.0/22 y Guayaquil 10.10.4.0/22; VLAN diseñadas
10 usuarios, 20 servidores, 30 invitados y 99 administración. Su evidencia de semana 9 usa VLAN 1
y rutas estáticas. VLAN, ACL, firewall y OSPF no se acreditan como implementados por el laboratorio
de Arthur. Del mismo modo, hashes y sesiones correctos no prueban el chat WSS completo.

CP-19: desactivar mediante PATCH active=false y cerrar la conexión antes de 60 s. CP-20: PATCH role,
revocación y nuevo login; rol inválido 422. CP-22: POST /logout y rechazo de reutilización. CP-29:
comprobar TLS por servicio y ausencia de texto plano; los hashes Argon2id de FastAPI sí deben existir.
CP-30: expiración 15 min y errores de API según contrato (incluye 422). Las cargas CP-27/CP-33 deben
repartirse entre cuentas/tiempo para respetar las cuotas. Una única sesión no dura 96 min ni 2 h 14 min;
esa duración solo podría representar una jornada con varios inicios de sesión.

Las 21 pruebas FastAPI, 6 del adaptador y 14 escenarios HTTPS son evidencias de Seguridad.
Los CP de POO siguen siendo un plan hasta ejecutar el chat; las pruebas de Alex acreditan únicamente
su prototipo. Auditoría SQL de solo inserción, permisos PostgreSQL, respaldos y restauración siguen pendientes.
No se modifica el reparto de trabajo ni se atribuye aprobación docente a esta revisión.
