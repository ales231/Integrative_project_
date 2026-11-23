# Guía para continuar el Proyecto Integrador

**Grupo 10 · UIDE · Actualizada el 22 de noviembre de 2026.**

El proyecto es el mismo chat empresarial entre Quito y Guayaquil. Cada materia conserva
su alcance y sus evidencias. Las entregas anteriores quedan como antecedentes; las próximas
deben incorporar directamente las correcciones acordadas en textos, tablas, diagramas y código.
La nota de alineación no demuestra por sí sola que toda la implementación ya sea compatible.

## 1. Responsables y ramas

| Responsable | Área | Rama |
|---|---|---|
| Arthur Brayan Beltran Hernández | Fundamentos de Seguridad: autenticación, sesiones, permisos y contrato de API | `beltranfuego` |
| Luis Angel Novillo Cruz | Go / POO: servidor, cliente y diseño del chat | `luis-novillo` |
| Alex Fernando Alban Torres | Redes: direccionamiento, conectividad, segmentación y restricciones de acceso | `alex-alban` |

`main` conserva la documentación general. Las ramas personales no necesitan contener los
mismos archivos: deben describir decisiones compatibles y conservar el trabajo de su responsable.
No copiar carpetas de otra materia ni reemplazar sus componentes para aparentar alineación.
Las dependencias entre áreas se coordinan antes de integrar.

## 2. Criterios de referencia para las próximas entregas

| Tema | Qué debemos mantener coherente |
|---|---|
| Identificación | La API actual usa `username`, por ejemplo `ana.perez`, sin `@`; admite entre 3 y 64 caracteres de `[a-z0-9._-]` y normaliza a minúsculas. El ID numérico de FastAPI es la clave estable. |
| Correo | Si queremos iniciar sesión con correo, primero se acuerda, implementa y prueba el cambio. No quitar el dominio automáticamente ni presentar el correo como admitido actualmente. |
| Roles | Valores de API: `empleado`, `supervisor`, `ti`. «Administrador de TI» puede ser la etiqueta visible de `ti`. Las cuentas SSH de los routers son distintas. |
| Sesiones | JWT RS256 de 15 minutos (900 s). Logout revoca la sesión; desactivar o cambiar rol revoca las sesiones del usuario. Tras cambio de rol se requiere nuevo login. |
| Cuentas | FastAPI administra usuarios, contraseñas y roles. El cliente de TI llama a esa API. El servidor de chat no recibe contraseñas ni escribe hashes o roles. |
| Login | `POST /login`, JSON `username`, `password`; respuesta `access_token`, `token_type`, `expires_in`. |
| Validación | Go usa `security-go.Validate(ctx, token)`: firma local y `POST /sessions/validate` con Bearer y `X-Service-Key`, sin cuerpo. No usar `/validar` ni `/credenciales` del diseño anterior como API vigente. |
| Administración | Alta: `POST /users`. Cambios: `PATCH /users/{uid}` con `active` y/o `role`. Contraseña de alta definida por TI, de 12 a 128 caracteres; no hay clave temporal en la respuesta. |
| Mensajes | Aplicar simultáneamente un máximo de 2000 caracteres Unicode y 4096 bytes UTF-8. Son unidades distintas. |
| Cuotas del chat | Objetivos: 30 mensajes por minuto y 5 conexiones por cuenta. Las pruebas de carga deben repartir cuentas/tiempo para respetarlas. |
| Transporte | Distinguir laboratorio y despliegue. FastAPI está probado por HTTPS en loopback:8000; HTTPS 443 para publicación requiere definir y probar su configuración. Chat WSS 443 y PostgreSQL TLS 5432 son objetivos del diseño. |
| Evidencias | Las pruebas de autenticación no acreditan el chat integrado; los pings no acreditan roles, TLS o membresía; las VLAN diseñadas no se presentan como ya configuradas. |

Detalles y diferencias frente a las entregas anteriores: [ALINEACION-PROYECTO.md](ALINEACION-PROYECTO.md).

## 3. Siguiente trabajo por área

### Arthur — Seguridad

- Mantener documentados campos, rutas, roles, errores y comportamiento de revocación de la API.
- Coordinar con Luis cómo recibe Go la URL HTTPS, la clave pública, la CA y la clave de servicio.
  El adaptador recibe contenidos en `New`; la lectura de archivos corresponde al arranque que lo integre.
- Comunicar cualquier cambio de API antes de que otra entrega dependa de él; actualizar contrato y pruebas.
- Comprobar con Luis la revocación y la denegación cuando no se puede validar una sesión.
- Coordinar con Alex los certificados y restricciones de acceso del despliegue.

### Luis — Go / POO

- Integrar el cliente y servidor con la API oficial de Arthur, sin crear otra autenticación paralela.
- Adaptar los próximos diagramas, formularios y casos de prueba a los nombres y valores de esta guía.
- Validar antes de aceptar WSS y antes de cada operación protegida; revisar conexiones ociosas cada
  30 segundos y cerrar las revocadas antes de 60 segundos. Ante error de validación, denegar o cerrar.
- Comprobar rol, área, membresía o participación vigentes en cada operación. Al agregar miembros,
  comprobar existencia, estado activo y área del destinatario; no basta con que el supervisor esté autorizado.
- Implementar y probar límites de conexiones, frecuencia y tamaño. La administración de cuentas
  no concede a TI lectura general de mensajes.
- Relacionar perfiles del chat con el ID de FastAPI. Nombre y sede no son campos aceptados por `/users`.

### Alex — Redes

- Mantener el direccionamiento documentado para Quito y Guayaquil, con sus VLAN y gateways.
- Diferenciar la red diseñada del prototipo realmente configurado: semana 9 demuestra VLAN 1 y
  rutas estáticas; VLAN, ACL, firewall y OSPF requieren sus propias configuraciones y evidencias.
- Coordinar los flujos necesarios para HTTPS/WSS y la restricción del acceso directo a PostgreSQL.
- Verificar aislamiento de invitados, administración desde VLAN 99 e identidades autorizadas;
  pertenecer a una VLAN no reemplaza la autenticación de aplicación.
- Registrar pruebas de conectividad y de accesos rechazados, además del funcionamiento permitido.

## 4. Orden para avanzar hacia el cierre

1. **Revisar el contrato:** los tres consultan esta guía y la API actual antes de la siguiente fase.
   Cualquier decisión pendiente se acuerda antes de implementar o documentar una versión distinta.
2. **Integrar Go con Seguridad:** login, conexión, operación autorizada, rechazo por falta de permisos,
   logout, cambio de rol y desactivación. Probar también sesión vencida y servicio no disponible.
3. **Probar en la red prevista:** verificar direcciones, certificados y puertos reales, flujos permitidos
   y bloqueados. No presentar la prueba local como conectividad Quito–Guayaquil.
4. **Validar lo pendiente:** persistencia, permisos separados, auditoría protegida, respaldo cifrado
   y restauración necesitan responsables coordinados y pruebas propias antes de darse por terminados.
5. **Preparar la entrega:** actualizar los documentos de cada materia con la versión probada y usar
   exactamente ese PDF tanto en el repositorio como en la plataforma.

No se fijan fechas nuevas aquí: cada próxima presentación debe seguir el enunciado y la rúbrica
de su materia. Esta guía no sustituye requisitos docentes ni acredita aprobación de los ajustes.

## 5. Revisión antes de cada presentación

- [ ] Revisamos el nuevo enunciado y la rúbrica de la materia.
- [ ] Confirmamos los últimos avances de las ramas de los otros dos integrantes.
- [ ] Textos, tablas, diagramas, pantallas y código usan las mismas decisiones de integración.
- [ ] Indicamos la versión o commit al que corresponden las pruebas y capturas.
- [ ] Distinguimos «diseñado», «implementado», «probado en laboratorio» y «probado integrado».
- [ ] Ejecutamos las comprobaciones que acreditan lo que vamos a presentar y anotamos los pendientes.
- [ ] Si cambió una ruta, campo, rol, puerto o límite, coordinamos el cambio y actualizamos las referencias afectadas.
- [ ] Verificamos el formato exigido por esa materia y que el PDF de la plataforma sea el del repositorio.
- [ ] Cada responsable conserva su autoría y alcance: Arthur Seguridad, Luis Go, Alex Redes.

Actualizar esta guía cuando una decisión cambie o un pendiente quede realmente probado.
