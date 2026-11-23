# Evidencias de Seguridad, Fase 3

- `https-results.json`: 14 escenarios ejecutados mediante un servidor HTTPS real de loopback; almacena accion, resultado esperado, obtenido, evidencia sanitizada, requisito y control.
- `pytest-results.xml`: 21 pruebas del servicio FastAPI con base SQLite temporal y cliente ASGI de laboratorio.
- `go-tests.jsonl`: 6 pruebas del adaptador Go contra servidores TLS de prueba; no equivalen al servidor de chat del equipo.

No hay contrasenas, JWT, claves privadas ni hashes completos en estos artefactos. Todos los usuarios y secretos de las pruebas se generan en memoria o carpetas temporales, no se reutilizan para despliegue.

Estos resultados NO acreditan PostgreSQL desplegado, conectividad Quito-Guayaquil, membresias de canales, cierre real de conexiones WSS del chat, firewall por VLAN ni restauracion cifrada. Se documentan como pendientes, no como pruebas aprobadas.
