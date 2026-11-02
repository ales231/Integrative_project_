# Chat empresarial entre sedes – Proyecto Integrador UIDE

Plataforma de chat interno para una empresa con dos sedes: la **matriz en Quito** (~100 empleados) y la **sucursal en Guayaquil** (~35 empleados). Un **servidor central en Go** recibe, guarda y reenvía los mensajes por WebSocket; los empleados se conectan desde un cliente después de iniciar sesión con un token.

> **Grupo 10** · **Fase actual:** Fase 2 – Definición de la aplicación cliente-servidor.

## Fase 2

Documento de la entrega: [Fase2_POO_Grupo10.pdf](docs/Fase2_POO_Grupo10.pdf)

Incluye objetivo, actores, alcance, requisitos, diagrama y fichas de casos de uso, matriz de trazabilidad, cambios respecto a la Fase 1 y declaración de uso de IA. El diagrama de clases corregido está en [PNG](docs/diagrama-clases-uml.png) y [PDF](docs/diagrama-clases-uml.pdf).

## Video de presentación

El video de la Fase 1 todavía no tiene un enlace publicado; se agregará en este apartado.

## Equipo y roles

| Integrante | Rol | Responsabilidades principales |
| --- | --- | --- |
| Luis Angel Novillo Cruz | Líder del proyecto y del servidor Go | Coordinación, diagrama UML, servidor de chat |
| Arthur Brayan Beltran Hernández | Cliente y seguridad | Cliente de chat, inicio de sesión con token, contrato de comunicación |
| Alex Fernando Alban Torres | Repositorio, datos y pruebas | Repositorio y tablero, base de datos, métricas para Estadística, pruebas |

## Problema que resuelve

Hoy las sedes se comunican por llamadas, correo personal y grupos de WhatsApp: la información queda dispersa, las respuestas entre sedes tardan y la empresa no controla sus datos. El chat empresarial centraliza la comunicación en canales por área y mensajes directos, con historial guardado y acceso solo para usuarios autenticados.

## Arquitectura (resumen)

```
[Cliente Quito] ─┐
                 ├── WebSocket (tcp/443) ──► [Servidor de chat Go] ──► [PostgreSQL]
[Cliente GYE] ───┘                                   │
                                                     └── valida token ──► [Autenticación FastAPI]
```

Los servicios se ubican en la matriz de Quito.

## Datos para Estadística

Mensajes por hora y por sede, tiempo de respuesta entre sedes, latencia de entrega, longitud de los mensajes, usuarios conectados y duración de las sesiones. Se usarán datos simulados o de pruebas internas.

## Documentación (carpeta `docs/`)

### Programación Orientada a Objetos

| Entregable | Archivo |
| --- | --- |
| Fase 1: contexto y selección del sistema, cronograma, integridad, licencia y uso de IA | [01-contexto-y-seleccion.pdf](docs/01-contexto-y-seleccion.pdf) |
| Fase 1: matriz de actores, roles y responsabilidades | [matriz-actores-roles.pdf](docs/matriz-actores-roles.pdf) |
| Fase 1: contrato de comunicación del equipo | [contrato-comunicacion.pdf](docs/contrato-comunicacion.pdf) |
| Fases 1 y 2: tablero de tareas | [tablero-tareas.md](docs/tablero-tareas.md) |
| Fase 2: documento de la entrega | [Fase2_POO_Grupo10.pdf](docs/Fase2_POO_Grupo10.pdf) |
| Fase 2: diagrama de clases UML corregido | [PNG](docs/diagrama-clases-uml.png) y [PDF](docs/diagrama-clases-uml.pdf) |

### Otras materias

Estos informes son de Tecnologías de Comunicación en Red y no forman parte de las entregas de POO.

| Informe | Archivo |
| --- | --- |
| Planificación de la red (español) | [Informe_Fase1_Planificacion_Red_Chat_Empresarial.pdf](docs/Informe_Fase1_Planificacion_Red_Chat_Empresarial.pdf) |
| Planificación de la red (inglés) | [Phase1_Network_Planning_Report_Enterprise_Chat.pdf](docs/Phase1_Network_Planning_Report_Enterprise_Chat.pdf) |

## Tablero de tareas

La lista de tareas y su estado están en [`docs/tablero-tareas.md`](docs/tablero-tareas.md). El tablero en GitHub Projects se creará a partir de esa lista.

## Tecnologías

- **Go** – servidor y cliente de chat (WebSocket, goroutines)
- **FastAPI** – servicio de autenticación y emisión de tokens
- **PostgreSQL** – usuarios, canales, mensajes y métricas
- **Git y GitHub** – control de versiones

## Estructura del repositorio

```
├── README.md
├── LICENSE
└── docs/
    ├── 01-contexto-y-seleccion.pdf
    ├── matriz-actores-roles.pdf
    ├── contrato-comunicacion.pdf
    ├── tablero-tareas.md
    ├── Fase2_POO_Grupo10.pdf
    ├── diagrama-clases-uml.png
    ├── diagrama-clases-uml.pdf
    ├── Informe_Fase1_Planificacion_Red_Chat_Empresarial.pdf
    └── Phase1_Network_Planning_Report_Enterprise_Chat.pdf
```

El código se agregará en las siguientes fases.

## Licencia

Licencia preliminar **MIT**. Ver [`LICENSE`](LICENSE).

## Uso de herramientas de IA

El equipo usó Claude (Anthropic) para ordenar ideas y redactar borradores de la documentación, y en la Fase 2 también para proponer requisitos y casos de uso, dibujar los diagramas y maquetar el PDF. El detalle de la Fase 2 está en el apartado 10 de su documento.