> **Próximas entregas:** consultar la [guía de continuidad del proyecto](CONTINUIDAD-PROYECTO.md): responsables, criterios comunes, siguientes pasos y revisión antes de presentar.

> **Responsable: Arthur. Alcance de esta rama: Seguridad.**
> Las correcciones entre entregas están en [ALINEACION-PROYECTO.md](ALINEACION-PROYECTO.md) y [su nota PDF](docs/alineacion-entregas.pdf). Cada materia conserva sus archivos y evidencias.

# Seguridad — Arthur Brayan Beltran Hernández

Rama `beltranfuego` del Proyecto Integrador UIDE. Contiene únicamente los avances de Fundamentos de Seguridad de Arthur.

- [Servicio de autenticación FastAPI](auth-service/README.md): cuentas, roles, Argon2id, JWT RS256, revocación y controles de acceso.
- [Adaptador de Seguridad para Go](security-go/README.md): validación de identidad y sesiones mediante HTTPS.
- [Informes de Seguridad, fases 1 a 3](docs/seguridad/README.md).
- [Pruebas y evidencias de laboratorio](evidence/seguridad/README.md).

Base de implementación: commit `0e889a78202f2c169f3779009fef1742ed029e17`. Las pruebas registradas son de laboratorio; los pendientes de integración se describen en los informes y en los README de cada componente.

La documentación de POO, los prototipos de redes y la implementación paralela de `docs/poo/` no forman parte del contenido actual de esta rama. Los archivos de entrega que se están preparando localmente se mantienen separados.
