# Discrepancias resueltas y trazabilidad

| Tema | Valor anterior | Valor común / efecto |
|---|---|---|
| Identidad | Correo en POO | `username` corporativo sin `@`; `id` de FastAPI como clave estable |
| Sesión RNF-03 / CP-30 | 8 horas | 15 minutos; expiración, logout y cambios de rol/estado revocan |
| Rol TI | `admin` | `ti`; etiqueta visible Administrador de TI |
| Login | `correo`, `clave`; `token`, `venceEn` | `username`, `password`; `access_token`, `token_type`, `expires_in` |
| Validación | `/validar` con JSON | `/sessions/validate`, Bearer + X-Service-Key, sin cuerpo |
| JWT | `sid` en referencia | `jti`, `uide-auth`, `uide-chat`, RS256 |
| Cuentas | Go escribe roles/credenciales | Cliente TI llama FastAPI; Go chat solo perfiles y datos de chat |
| Alta CU-02.10 / CP-18 | Clave temporal en respuesta | Contraseña definida por TI, 12–128; 201 perfil; repetido 409 |
| Baja CU-02.11 / CP-19 | DELETE por correo | PATCH por ID con active=false; cerrar WSS antes de 60 s |
| Rol CU-02.12 / CP-20 | Rol nuevo con token anterior | PATCH role; revoca; requiere nuevo login; inválido 422 |
| Cierre CU-02.14 / CP-22 | Descartar token | POST /logout, cierre WSS y limpieza; reutilización 401 |
| Revalidación | Solo comprobar reloj local | Firma + consulta por operación y cada 30 s incluso sin tráfico |
| Transporte | FastAPI 443 / ejemplo HTTP | Auth HTTPS 8000; chat WSS 443; PostgreSQL TLS 5432 como objetivo |
| Mensaje | 2000 caracteres o 4 KiB | Ambos: máximo 2000 caracteres y 4096 bytes UTF-8 |
| Carga CP-27/CP-33 | 1000 envíos sin considerar cuotas | Distribuir cuentas/tiempo; respetar 30/min y 5 conexiones por cuenta |
| Estadísticas de sesión | 96 min / 2 h 14 min | Máximo 15 min por login; jornada acumulada es otra métrica |
| Prueba CP-29 | Solo puerto 443 y cero columnas de contraseña | HTTPS/WSS según servicio; sin texto plano; hashes Argon2id solo en FastAPI |
| Estados HTTP CP-30 | Todo inválido 400/404 | API FastAPI usa 422 para validación; 401/403/404/409 según contrato |
| Red | Confundir VLSM diseñado con VLAN activas | Semana 9: VLAN 1 y rutas estáticas; segmentación y firewall pendientes |
| Entrega / aprobación | «Fase 3 ya entregada» sin confirmar | Preparada/probada en laboratorio; entrega y aprobación no verificadas |
| Ramas | Cada una elimina carpetas de las otras | Base común con todos los aportes y contrato idéntico |

Los CP de POO siguen siendo un plan, no resultados del chat integrado. CP-01 a CP-34 se leen con
estas sustituciones; los demás criterios funcionales y de accesibilidad conservan su propósito.
Los 21 tests FastAPI, 6 tests del adaptador y 14 escenarios HTTPS de Arthur conservan sus evidencias
y alcance de laboratorio. Las verificaciones adicionales del contrato se registran por separado.
Fuentes originales: main 3499a53, luis-novillo c0385b3, alex-alban 4b9bdc8, beltranfuego 99c4f2b.
