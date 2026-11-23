# Adaptador de Seguridad para Go

Este modulo solo valida identidad y sesiones; no implementa el servidor ni el cliente de chat de los otros integrantes. No tiene dependencias externas.

`New(urlHTTPS, clavePublicaPEM, certificadoCAPEM, claveServicio)` configura un cliente con validacion de TLS, clave publica RS256 fijada y timeout de 5 segundos. `Validate(ctx, token)` comprueba firma, emisor, audiencia, duracion y revocacion; retorna el rol actual del usuario desde FastAPI.

Llamar antes de aceptar WSS y antes de cada operacion protegida. El chat debe comprobar tambien rol/area/membresia para cada recurso y repetir `Validate` cada 30 segundos incluso en conexiones ociosas. Ante error, denegar y cerrar la conexion. No guardar ni registrar el token o la clave de servicio. No descargar la clave publica sin validar su origen.

```powershell
go test -v ./...
```

Se prueban HTTPS confiable, revocacion, indisponibilidad, firma alterada, certificado no confiable y entradas invalidas. Las pruebas usan un servidor TLS de laboratorio, no el chat integrado.
