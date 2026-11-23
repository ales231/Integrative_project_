# Contexto del proyecto – rama de Luis Novillo

Esta rama contiene **solo lo de Luis**: las entregas de POO (Fases 1 a 3, con las correcciones de la Fase 3) y esta carpeta `contexto/`, que resume en qué estado está cada parte del proyecto integrador (Grupo 10, chat empresarial) y qué le toca a cada uno. Los archivos de Redes (Alex) siguen en `main` y los de Seguridad (Arthur) en `beltranfuego`.

Estado al 22 de noviembre de 2026.

## 1. Ramas del repositorio

| Rama | Responsable | Qué contiene |
|---|---|---|
| `main` | Equipo | Entregas de POO (Fases 1, 2 y 3, con las correcciones de la Fase 3), diagramas editables y archivos de Redes de Alex (`network/`, `evidence/`) |
| `beltranfuego` | Arthur | Fundamentos de Seguridad: Fases 1, 2 y 3, servicio `auth-service/` (FastAPI), adaptador `security-go/` y evidencias |
| `luis-novillo` | Luis | Entregas de POO (Fases 1 a 3), esta carpeta de contexto y `codigo-luis/` (código de referencia) |

La rama `avances` ya no existe: Arthur la reemplazó por `beltranfuego`. El commit `3764449` que Luis subió por error (una segunda implementación de autenticación dentro de `docs/poo/`) ya lo quitó Arthur en `99c4f2b`, así que no hay nada que revertir.

## 2. Programación Orientada a Objetos (Luis)

| Fase | Documento en `main` | Estado |
|---|---|---|
| 1 | `docs/01-contexto-y-seleccion.pdf`, `docs/matriz-actores-roles.pdf`, `docs/contrato-comunicacion.pdf` | Entregada |
| 2 | `docs/Fase2_POO_Grupo10.pdf` | Entregada |
| 3 | `docs/Fase3_POO_Grupo10.pdf` y `docs/diagramas/` | Entregada; correcciones ya subidas a `main` (commit `3499a53`) |

### Retroalimentación de la Fase 3 y qué se corrigió en `main`

| Observación de la profesora | Estado |
|---|---|
| En la Figura 2 faltaban tres dependencias de la Tabla 3 (por ejemplo, Manejadores → Protocolo) | Corregido: se agregaron Manejadores → Protocolo, Gestión de cuentas → Dominio y Almacenamiento → Protocolo |
| El README enlazaba `docs/diagrama-clases-uml.png`, que está en `docs/diagramas/` | Corregido |
| Los métodos reciben un ID, pero las pantallas piden el correo | Corregido: todo se identifica por correo; el servidor lo traduce con `Repositorio.BuscarUsuario` |
| Agregar y quitar miembro no tenían método en `ServidorChat` | Corregido: `ServidorChat.AgregarMiembro` y `QuitarMiembro` |
| El PDF de Canvas (20 páginas) no era el del repositorio (16) | Para próximas entregas: subir a Canvas exactamente el PDF del repositorio |
| Siguen pendientes el video y el tablero de la Fase 2 | **Pendiente** (ver la sección 5) |

### Siguiente: Fase 4 de POO
El enunciado todavía no está habilitado. Por el documento del proyecto (`PI_TERCER_NIVEL`), la Fase 4 es «Prototipo y desarrollo inicial»: código de `app-go` (servidor y cliente). El plan es construir el servidor de chat **usando el adaptador `security-go` de Arthur**, sin reimplementar la autenticación ni tocar `auth-service/` o `security-go/`. Ahí van los pendientes de Seguridad que dependen del chat:

- llamar a `Validate` antes de aceptar la conexión WSS y antes de cada operación;
- comprobar membresía del canal, área y rol en cada operación;
- volver a validar la sesión cada 30 segundos y cerrar las revocadas antes de 60;
- limitar a 5 conexiones por cuenta, 30 mensajes por minuto y 4096 bytes por mensaje.

### Código de referencia en `codigo-luis/`
Código generado con Claude en paralelo al de Arthur, probado localmente (10 pruebas de FastAPI, 10 de Go y una demostración de 37 verificaciones). **No es la versión oficial de Seguridad.**
- `codigo-luis/app-go/`: servidor de chat con canales, membresía, área, límites de mensajes y validación de sesión. Es la **base para la Fase 4 de POO**; se adaptará para usar `security-go` de Arthur.
- `codigo-luis/auth-service/`: versión paralela del servicio de autenticación. **No se usa**: el oficial es el de Arthur en `beltranfuego`.
- Instrucciones en `codigo-luis/LEEME.md`. No contiene claves, `.env` ni bases de datos.

El mensaje que explica a Arthur lo que pasó y las diferencias está en `contexto/mensaje-arthur.md`.

## 3. Fundamentos de Seguridad (Arthur)

La Fase 3 ya está entregada en `beltranfuego`: informe `docs/seguridad/fase3-aplicacion-controles-seguridad.pdf`, servicio FastAPI, adaptador Go y evidencias. Luis ejecutó sus pruebas: **21 de 21 en FastAPI y 6 de 6 en Go**, con `go vet` limpio, y coinciden con lo que declara el informe.

Pendientes de su informe para la Fase 4: TLS del chat y de la base (C-04), firewall y PostgreSQL con permisos separados (C-06, C-10), respaldos cifrados (C-09), auditoría de solo inserción en PostgreSQL (C-08) y la integración con el chat (sección 2).

## 4. Incoherencias entre POO y Seguridad

Las Fases 3 de POO y de Seguridad no coinciden en nueve puntos. La propuesta es **ajustar POO a lo que Arthur ya implementó**, porque son requisitos de seguridad. Detalle en las imágenes `incoherencias-POO-seguridad-1de2.png` y `incoherencias-POO-seguridad-2de2.png`.

| # | Tema | POO (Fase 3) | Seguridad | Propuesta |
|---|---|---|---|---|
| 1 | Duración de la sesión | 8 horas (RNF-03) | 15 minutos (RF-SEC-05) | POO pasa a 15 min. **Avisar a los profesores** |
| 2 | Cuentas y roles | En el servidor Go (`GestorCuentas`) | En FastAPI; Go no modifica roles (RF-SEC-10) | `GestorCuentas` llama a FastAPI con la sesión de TI. **Avisar a los profesores** |
| 3 | Validación de la sesión | Al conectar y luego solo la hora | Firma local y consulta a FastAPI en cada operación y cada 30 s | Actualizar la secuencia y `validarSesion` |
| 4 | Rutas | `/validar`, `/credenciales` | `/sessions/validate`, `/users`, `/logout` | Usar las de Arthur |
| 5 | Rol de administrador | `admin` | `ti` | Usar `ti` |
| 6 | Cerrar sesión | El cliente descarta el token | `POST /logout` revoca la sesión | Agregar `/logout` |
| 7 | Crear cuenta | Clave temporal | TI define una contraseña de 12 a 128 caracteres | Cambiar CU-02.10 |
| 8 | Puerto de FastAPI | 443 | 8000 con TLS | Ajustar un documento |
| 9 | Tamaño de mensajes | 2000 caracteres | 4096 bytes | Aplicar ambos límites |

Los puntos 1 y 2 cambian requisitos y arquitectura ya calificados en POO, por eso conviene consultarlo con la profesora Salazar (POO) y el profesor López Tito (Seguridad). Los demás se explican en el apartado de cambios de la Fase 4.

## 5. Qué le toca a cada uno

### Arthur
1. Confirmar si `username` es el correo corporativo (por ejemplo `ana.perez@empresa.test`). En POO se identifica a los usuarios por correo.
2. Definir cómo recibe el servidor Go la clave pública, el certificado de la CA y la clave de servicio en el despliegue (¿rutas de archivos en variables de entorno?).
3. Avisar si cambia la API (rutas, campos o roles), para mantener POO alineado.
4. Revisar la tabla de incoherencias (sección 4) y decir si está de acuerdo con la propuesta.

### Alex
1. **Crear el tablero en GitHub Projects** (es dueño del repositorio): pestaña *Projects* › *New project* › plantilla *Board*; columnas *Por hacer*, *En progreso*, *En revisión* y *Hecho*; cargar las tareas de `docs/tablero-tareas.md`; y en *Settings* › *Visibility* ponerlo **público**. Lo pide la profesora desde la Fase 1.
2. **Publicar el video de la Fase 1** (YouTube, no listado) y pasar el enlace para ponerlo en el README. También está pendiente desde la Fase 1.
3. Para Seguridad (C-06): reglas de firewall y acceso desde la VLAN 99, en coordinación con Arthur, porque es parte de Redes.

### Luis
1. Hacer la Fase 4 de POO cuando se habilite el enunciado (sección 2).
2. Ajustar el diseño de POO según la tabla de incoherencias.
3. Consultar a los profesores los puntos 1 y 2 de la tabla.

### Todo el equipo
- Definir si las ramas personales (`beltranfuego`, `luis-novillo`) se unen a `main` antes de cada entrega, y quién lo hace.
- En cada entrega, subir a Canvas exactamente el mismo PDF que está en el repositorio.
