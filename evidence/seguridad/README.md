# Evidencias de Seguridad, Fase 3

- `https-results.json`: 14 escenarios ejecutados mediante un servidor HTTPS real de loopback; almacena accion, resultado esperado, obtenido, evidencia sanitizada, requisito y control.
- `pytest-results.xml`: 21 pruebas del servicio FastAPI con base SQLite temporal y cliente ASGI de laboratorio.
- `go-tests.jsonl`: 6 pruebas del adaptador Go contra servidores TLS de prueba; no equivalen al servidor de chat del equipo.

No hay contrasenas, JWT, claves privadas ni hashes completos en estos artefactos. Todos los usuarios y secretos de las pruebas se generan en memoria o carpetas temporales, no se reutilizan para despliegue.

Estos resultados NO acreditan PostgreSQL desplegado, conectividad Quito-Guayaquil, membresias de canales, cierre real de conexiones WSS del chat, firewall por VLAN ni restauracion cifrada. Se documentan como pendientes, no como pruebas aprobadas.

## Capturas de pantalla

La carpeta `capturas/` contiene cinco capturas originales del navegador mostrando los visores locales de resultados: autenticacion, autorizacion, proteccion, sesiones y pruebas automaticas. No son capturas de la interfaz del chat ni montajes de una terminal. Los visores leen los artefactos reales de la ejecucion y muestran sus fuentes y huellas SHA-256. No se retocaron las imagenes; los secretos se excluyen del resultado antes de mostrarlo.

Los archivos HTML se reproducen con `python auth-service/scripts/build_evidence_viewer.py` desde la raiz, despues de ejecutar las pruebas y recopilar la evidencia. `pytest-console.txt` contiene la salida real, incluida una advertencia de compatibilidad que no impidio aprobar las 21 pruebas.
