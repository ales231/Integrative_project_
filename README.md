# Chat empresarial entre Quito y Guayaquil — Grupo 10, UIDE

Base común de POO, Fundamentos de Seguridad y Tecnologías de Comunicación en Red.
`main`, `beltranfuego`, `luis-novillo` y `alex-alban` comparten esta revisión de integración.
Los aportes y responsables se conservan; las ramas personales pueden continuar a partir de esta base.

**Estado real:** autenticación y adaptador de Seguridad probados en laboratorio; diseño de POO
con correcciones; prototipo de red de semana 9. El chat WSS integrado, VLAN/ACL, permisos PostgreSQL
y restauración de respaldos todavía requieren implementación y pruebas. No se acredita entrega en la plataforma.

## Referencia común

- [Contrato exacto de API, identidad, sesiones y despliegue](docs/integracion/CONTRATO.md).
- [Resolución de discrepancias y cambios de pruebas](docs/integracion/RESOLUCIONES.md).
- [Contrato legible por herramientas](docs/integracion/contrato.json).
- [Adenda de alineación y diagramas vigentes](docs/integracion/alineacion-proyecto.pdf).
- [Estado y pendientes por responsable](docs/tablero-tareas.md).

Identidad: `username` como `ana.perez`, sin `@`; clave estable `id`; roles `empleado`, `supervisor`, `ti`.
Login: HTTPS `/login` con `username` y `password`; JWT RS256 de 15 minutos.
Go usa `security-go.Validate` y `/sessions/validate` con Bearer y clave de servicio.
FastAPI administra cuentas y roles; Go administra salas, mensajes y perfiles vinculados al ID.

## Entregables y componentes

| Área | Responsable | Archivos |
|---|---|---|
| POO | Luis; cliente con Arthur | [Fase 1](docs/01-contexto-y-seleccion.pdf), [Fase 2](docs/Fase2_POO_Grupo10.pdf), [Fase 3 con adenda](docs/Fase3_POO_Grupo10.pdf), [diagramas vigentes](docs/diagramas/README.md) |
| Seguridad | Arthur | [Fases 1–3](docs/seguridad/README.md), [FastAPI](auth-service/README.md), [adaptador Go](security-go/README.md), [evidencias](evidence/seguridad/README.md) |
| Redes | Alex | [Plan de red](docs/Phase1_Network_Planning_Report_Enterprise_Chat.pdf), [semana 9](docs/Week9_Prototype_Report.pdf), [configuraciones y datos](network/week9/), [capturas](evidence/week9/) |

Los informes previos se conservan como antecedentes; los PDF actuales de POO y Redes incluyen
la adenda que explica los valores corregidos. Originales sin alterar en `docs/historico/`.
El código paralelo de Luis se conserva como referencia histórica comprimida, no es una segunda API activa.

## Arquitectura objetivo

Cliente Go → WSS tcp/443 → servidor de chat Go → PostgreSQL con TLS tcp/5432.
Cliente Go → HTTPS tcp/8000 → FastAPI para login, perfil y administración de TI.
Servidor Go → HTTPS tcp/8000 → FastAPI mediante `security-go` para comprobar identidad y revocación.
Servicios en Quito; usuarios en Quito y Guayaquil. Certificados y reglas de red del despliegue pendientes.
El laboratorio de Seguridad usa loopback, certificado local y SQLite temporal; no prueba la WAN.

## Comprobaciones reproducibles

Desde `auth-service/`, con las dependencias documentadas: `python -m pytest -q`.
Desde `security-go/`: `go test -count=1 ./...` y `go vet ./...`.
Contrato adicional: `python -m pytest -q ../tests/integracion` desde `auth-service/`.
Resultados de revisión en `evidence/integracion/`; no confundirlos con la implementación del chat.

## Equipo y pendientes externos

Luis Angel Novillo Cruz: diseño y servidor Go. Arthur Brayan Beltran Hernández: Seguridad y cliente.
Alex Fernando Alban Torres: redes, repositorio y persistencia/métricas.
Video y GitHub Projects siguen pendientes de enlace verificable. No hay URL de entrega o aprobación docente confirmada.
Licencia MIT: [LICENSE](LICENSE). Las declaraciones históricas se conservan en los documentos originales.
