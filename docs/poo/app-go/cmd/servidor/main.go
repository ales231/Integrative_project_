// Servidor de chat (etapa de controles de seguridad).
//
// Variables de entorno:
//
//	AUTH_URL           servicio FastAPI (por defecto http://127.0.0.1:8000)
//	JWT_CLAVE_PUBLICA  clave pública RSA de FastAPI (por defecto ../auth-service/keys/publica.pem)
//	JWT_EMISOR         emisor esperado del token (por defecto auth.chat-grupo10)
//	JWT_AUDIENCIA      audiencia esperada (por defecto chat-empresarial)
//	PUERTO             puerto del servidor Go (por defecto 8080)
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ales231/Integrative_project_/app-go/internal/servidor"
	"github.com/ales231/Integrative_project_/app-go/internal/sesion"
)

func valor(nombre, defecto string) string {
	if v := os.Getenv(nombre); v != "" {
		return v
	}
	return defecto
}

func main() {
	registro := log.New(os.Stdout, "[servidor] ", log.LstdFlags)
	rutaPublica := valor("JWT_CLAVE_PUBLICA", "../auth-service/keys/publica.pem")
	pemPublica, err := os.ReadFile(rutaPublica)
	if err != nil {
		log.Fatalf("no se pudo leer la clave pública %s: %v", rutaPublica, err)
	}
	verificador, err := sesion.NuevoVerificador(pemPublica, valor("JWT_EMISOR", "auth.chat-grupo10"), valor("JWT_AUDIENCIA", "chat-empresarial"))
	if err != nil {
		log.Fatal(err)
	}
	authURL := valor("AUTH_URL", "http://127.0.0.1:8000")
	auth := sesion.NuevoClienteAuth(authURL, verificador, 10*time.Second)
	puerto := valor("PUERTO", "8080")
	srv := &http.Server{
		Addr:              ":" + puerto,
		Handler:           servidor.NuevoServidor(auth, registro).Rutas(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	registro.Printf("escuchando en :%s; valida sesiones con %s", puerto, authURL)
	log.Fatal(srv.ListenAndServe())
}
