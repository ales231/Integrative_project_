# Chat empresarial entre sedes – Proyecto Integrador UIDE

Plataforma de chat interno para una empresa con dos sedes: la **matriz en Quito** (~100 empleados) y la **sucursal en Guayaquil** (~35 empleados). Un **servidor central en Go** recibe, guarda y reenvía los mensajes por WebSocket; los empleados se conectan desde un cliente de consola en Go después de iniciar sesión con un token emitido por un servicio FastAPI.

> **Grupo 10** · **Fase actual:** Fase 3 – Diseño de la solución.

## Fase 3

Documento de la entrega: [Fase3_POO_Grupo10.pdf](docs/Fase3_POO_Grupo10.pdf)

Incluye arquitectura cliente-servidor, diagrama de componentes, diagrama de clases actualizado, paquetes de Go, secuencia de la autenticación, matriz de trazabilidad, plan de pruebas, prototipo de la interfaz de consola con criterios de accesibilidad, cambios respecto a la Fase 2 y declaración de uso de IA.

Archivos editables de los diagramas (draw.io):

| Diagrama | Archivo |
| --- | --- |
| Arquitectura cliente-servidor | [fase3-arquitectura.drawio](docs/diagramas/fase3-arquitectura.drawio) |
| Componentes | [fase3-componentes.drawio](docs/diagramas/fase3-componentes.drawio) |
| Clases | [fase3-clases.drawio](docs/diagramas/fase3-clases.drawio) |
| Secuencia de la autenticación | [fase3-secuencia-autenticacion.drawio](docs/diagramas/fase3-secuencia-autenticacion.drawio) |

El diagrama de clases también está como imagen en [PNG](docs/diagramas/diagrama-clases-uml.png) y [PDF](docs/diagramas/diagrama-clases-uml.pdf). Los `.drawio` se abren en [app.diagrams.net](https://app.diagrams.net) con *Archivo › Abrir desde › Dispositivo*.

## Fase 2

Documento de la entrega: [Fase2_POO_Grupo10.pdf](docs/Fase2_POO_Grupo10.pdf)

## Video de presentación

El video de la Fase 1 todavía no tiene un enlace publicado; se agregará en este apartado.

## Equipo y roles

| Integrante | Rol | Responsabilidades principales |
| --- | --- | --- |
| Luis Angel Novillo Cruz | Líder del proyecto y del servidor Go | Coordinación, diagramas UML, servidor de chat |
| Arthur Brayan Beltran Hernández | Cliente y seguridad | Cliente de chat, inicio de sesión con token, contrato de comunicación |
| Alex Fernando Alban Torres | Repositorio, datos y pruebas | Repositorio y tablero, base de datos, métricas para Estadística, pruebas |

## Problema que resuelve

Hoy las sedes se comunican por llamadas, correo personal y grupos de WhatsApp: la información queda dispersa, las respuestas entre sedes tardan y la empresa no controla sus datos. El chat empresarial centraliza la comunicación en canales por área y mensajes directos, con historial guardado y acceso solo para usuarios autenticados.

## Arquitectura (resumen)

```
[Cliente Go] ── WSS, tcp/443, JSON ──► [Servidor Go] ── SQL ──► [PostgreSQL]
     │                                       │
     └── HTTPS: POST /login ──► [FastAPI] ◄──┘ HTTPS: POST /validar
```

El servidor Go, PostgreSQL y FastAPI se ubican en la matriz de Quito. La aplicación Go no guarda contraseñas.

## Estructura prevista del código

```
app-go/
├── cmd/
│   ├── cliente/      # main del cliente de consola
│   └── servidor/     # main del servidor de chat
└── internal/
    ├── cliente/      # Consola, ClienteChat
    ├── protocolo/    # Mensaje, Peticion, Respuesta, ResumenUso
    ├── servidor/     # ServidorChat, Conexion
    ├── sesion/       # Autenticador, ClienteAuth, Sesion
    ├── cuentas/      # GestorCuentas
    ├── almacen/      # Repositorio, RepositorioPostgres
    └── dominio/      # Usuario, Sala, Sede
```

El código se agregará en las siguientes fases.

## Datos para Estadística

Mensajes por hora y por sede, tiempo de respuesta entre sedes, latencia de entrega, longitud de los mensajes, usuarios conectados y duración de las sesiones. Se usarán datos simulados o de pruebas internas.

## Documentación (carpeta `docs/`)

### Programación Orientada a Objetos

| Entregable | Archivo |
| --- | --- |
| Fase 1: contexto y selección del sistema, cronograma, integridad, licencia y uso de IA | [01-contexto-y-seleccion.pdf](docs/01-contexto-y-seleccion.pdf) |
| Fase 1: matriz de actores, roles y responsabilidades | [matriz-actores-roles.pdf](docs/matriz-actores-roles.pdf) |
| Fase 1: contrato de comunicación del equipo | [contrato-comunicacion.pdf](docs/contrato-comunicacion.pdf) |
| Fase 2: definición de la aplicación | [Fase2_POO_Grupo10.pdf](docs/Fase2_POO_Grupo10.pdf) |
| Fase 3: diseño de la solución | [Fase3_POO_Grupo10.pdf](docs/Fase3_POO_Grupo10.pdf) |
| Fase 3: diagramas editables | [docs/diagramas/](docs/diagramas/) |
| Fase 3: diagrama de clases | [PNG](docs/diagramas/diagrama-clases-uml.png) y [PDF](docs/diagramas/diagrama-clases-uml.pdf) |
| Fases 1 a 3: tablero de tareas | [tablero-tareas.md](docs/tablero-tareas.md) |

### Otras materias

Esta rama contiene solo las entregas de POO de Luis. Los archivos de Tecnologías de Comunicación en Red (Alex) están en la rama `main` y los de Fundamentos de Seguridad (Arthur) en la rama `beltranfuego`.

## Tablero de tareas

La lista de tareas y su estado están en [`docs/tablero-tareas.md`](docs/tablero-tareas.md). El tablero en GitHub Projects se creará a partir de esa lista.

## Tecnologías

- **Go** – servidor y cliente de chat (WebSocket, goroutines)
- **FastAPI** – servicio de autenticación y emisión de tokens
- **PostgreSQL** – usuarios, canales, mensajes y métricas
- **draw.io** – diagramas UML editables
- **Git y GitHub** – control de versiones

## Licencia

Licencia preliminar **MIT**. Ver [`LICENSE`](LICENSE).

## Uso de herramientas de IA

El equipo usó Claude (Anthropic) como apoyo en la documentación de cada fase. El detalle está en la declaración de uso de IA de cada documento: sección 6 del documento de contexto de la Fase 1, apartado 10 de la Fase 2 y apartado 11 de la Fase 3.
