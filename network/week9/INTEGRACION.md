# Integración con POO y Seguridad

Se preservan el .pkt, configuraciones, matriz y capturas originales de semana 9 sin atribuirles controles nuevos.
En esta evidencia se usan VLAN 1 y rutas estáticas; las VLAN del VLSM son un plan.
El diseño común usa WSS 443, FastAPI HTTPS 8000 y PostgreSQL TLS 5432.
La política de acceso objetivo y el estado pendiente están en ../../docs/integracion/CONTRATO.md.
Las cuentas locales de administración de equipos de red no son los roles de aplicación:
un usuario SSH llamado admin en un router no implica que el rol de FastAPI se llame admin (se llama ti).
Las credenciales de práctica de las configuraciones históricas no deben reutilizarse en despliegue;
la propia matriz pending_tests.csv mantiene pendiente sustituirlas y repetir las pruebas.
