package servidor

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ales231/Integrative_project_/app-go/internal/sesion"
)

// authFalso reemplaza a FastAPI: cada token de prueba representa una sesión vigente.
type authFalso map[string]sesion.Sesion

func (a authFalso) ValidarToken(t string) (sesion.Sesion, error) {
	switch t {
	case "caido":
		return sesion.Sesion{}, sesion.ErrAuthNoDisponible
	case "revocado":
		return sesion.Sesion{}, sesion.ErrSesionRevocada
	}
	if s, ok := a[t]; ok {
		return s, nil
	}
	return sesion.Sesion{}, sesion.ErrTokenInvalido
}

type prueba struct {
	t *testing.T
	h http.Handler
	s *ServidorChat
}

func nuevo(t *testing.T) *prueba {
	v := time.Now().Add(15 * time.Minute)
	a := authFalso{
		"ana":     {Correo: "ana@empresa.test", Rol: RolEmpleado, Area: "Ventas", VenceEn: v},
		"luis":    {Correo: "luis@empresa.test", Rol: RolEmpleado, Area: "Ventas", VenceEn: v},
		"pedro":   {Correo: "pedro@empresa.test", Rol: RolEmpleado, Area: "Soporte", VenceEn: v},
		"supV":    {Correo: "sup.ventas@empresa.test", Rol: RolSupervisor, Area: "Ventas", VenceEn: v},
		"supS":    {Correo: "sup.soporte@empresa.test", Rol: RolSupervisor, Area: "Soporte", VenceEn: v},
		"ti":      {Correo: "ti@empresa.test", Rol: RolAdmin, Area: "TI", VenceEn: v},
		"vencido": {Correo: "ana@empresa.test", Rol: RolEmpleado, Area: "Ventas", VenceEn: time.Now().Add(-time.Second)},
	}
	s := NuevoServidor(a, log.New(io.Discard, "", 0))
	return &prueba{t: t, h: s.Rutas(), s: s}
}

func (p *prueba) pedir(metodo, ruta, token, cuerpo string) (int, string) {
	r := httptest.NewRequest(metodo, ruta, strings.NewReader(cuerpo))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func (p *prueba) esperar(nombre string, esperado int, metodo, ruta, token, cuerpo string) {
	p.t.Helper()
	if got, body := p.pedir(metodo, ruta, token, cuerpo); got != esperado {
		p.t.Errorf("%s: esperaba %d, obtuve %d (%s)", nombre, esperado, got, body)
	}
}

// El supervisor de Ventas crea el canal 1 y agrega a Ana.
func (p *prueba) canalVentasConAna() {
	p.t.Helper()
	p.esperar("supervisor crea canal de su área", 201, "POST", "/api/canales", "supV", `{"nombre":"Ventas-GYE"}`)
	p.esperar("supervisor agrega a Ana", 201, "POST", "/api/canales/1/miembros", "supV", `{"usuario":"ana@empresa.test"}`)
}

// PS-03 (-) RF-SEC-01, RF-SEC-05 / C-01, C-05
func TestPS03_SinSesionValidaNoHayAcceso(t *testing.T) {
	p := nuevo(t)
	p.canalVentasConAna()
	for _, tok := range []string{"", "falso", "vencido", "revocado"} {
		p.esperar("token "+tok, 401, "GET", "/api/canales/1/mensajes", tok, "")
	}
}

// PS-04 (+) RF-SEC-02 / C-02
func TestPS04_MiembroLeeYEnviaEnSuCanal(t *testing.T) {
	p := nuevo(t)
	p.canalVentasConAna()
	p.esperar("Ana envía", 201, "POST", "/api/canales/1/mensajes", "ana", `{"texto":"Hola Ventas"}`)
	_, body := p.pedir("GET", "/api/canales/1/mensajes", "ana", "")
	if !strings.Contains(body, "Hola Ventas") {
		t.Fatalf("Ana debía leer su mensaje: %s", body)
	}
}

// PS-05 (-) RF-SEC-02 / C-02
func TestPS05_CanalAjenoYMiembroRetirado(t *testing.T) {
	p := nuevo(t)
	p.canalVentasConAna()
	p.esperar("Luis (misma área, no miembro) lee", 403, "GET", "/api/canales/1/mensajes", "luis", "")
	p.esperar("Pedro cambia el ID y envía", 403, "POST", "/api/canales/1/mensajes", "pedro", `{"texto":"intruso"}`)
	p.esperar("supervisor retira a Ana", 200, "DELETE", "/api/canales/1/miembros/ana@empresa.test", "supV", "")
	p.esperar("Ana ya no lee", 403, "GET", "/api/canales/1/mensajes", "ana", "")
	p.esperar("Ana ya no envía", 403, "POST", "/api/canales/1/mensajes", "ana", `{"texto":"hola"}`)
	_, body := p.pedir("GET", "/api/canales/1/mensajes", "supV", "")
	if strings.Contains(body, "intruso") {
		t.Fatal("el envío indebido no debía guardarse")
	}
}

// PS-06 (+/-) RF-SEC-02, RF-SEC-10 / C-02, C-10
func TestPS06_SupervisorSoloGestionaSuArea(t *testing.T) {
	p := nuevo(t)
	p.canalVentasConAna()
	p.esperar("supervisor de Soporte agrega en canal de Ventas", 403, "POST", "/api/canales/1/miembros", "supS", `{"usuario":"pedro@empresa.test"}`)
	p.esperar("supervisor de Soporte quita en canal de Ventas", 403, "DELETE", "/api/canales/1/miembros/ana@empresa.test", "supS", "")
	p.esperar("empleado crea canal", 403, "POST", "/api/canales", "ana", `{"nombre":"Mi canal"}`)
	p.esperar("TI gestiona miembros sin ser supervisor del área", 403, "POST", "/api/canales/1/miembros", "ti", `{"usuario":"x@empresa.test"}`)
	p.esperar("supervisor pide estadísticas", 403, "GET", "/api/estadisticas", "supV", "")
	p.esperar("TI pide estadísticas", 200, "GET", "/api/estadisticas", "ti", "")
}

// PS-13 (+/-) RF-SEC-07 / C-07
func TestPS13_LimitesDeTamanoYFrecuencia(t *testing.T) {
	p := nuevo(t)
	p.canalVentasConAna()
	p.esperar("supervisor agrega a Luis", 201, "POST", "/api/canales/1/miembros", "supV", `{"usuario":"luis@empresa.test"}`)
	cuerpo := func(n int) string {
		b, _ := json.Marshal(map[string]string{"texto": strings.Repeat("a", n)})
		return string(b)
	}
	p.esperar("4096 bytes", 201, "POST", "/api/canales/1/mensajes", "ana", cuerpo(4096))
	p.esperar("4097 bytes", 413, "POST", "/api/canales/1/mensajes", "ana", cuerpo(4097))
	for i := 2; i <= 30; i++ {
		p.esperar("mensaje dentro del límite", 201, "POST", "/api/canales/1/mensajes", "ana", `{"texto":"ok"}`)
	}
	p.esperar("mensaje 31 en el minuto", 429, "POST", "/api/canales/1/mensajes", "ana", `{"texto":"de más"}`)
	p.esperar("otra cuenta sigue enviando", 201, "POST", "/api/canales/1/mensajes", "luis", `{"texto":"sigo"}`)
	p.s.ahora = func() time.Time { return time.Now().Add(61 * time.Second) }
	p.esperar("pasado el minuto Ana vuelve a enviar", 201, "POST", "/api/canales/1/mensajes", "ana", `{"texto":"de nuevo"}`)
}

// PS-17 (-) RF-SEC-05 / C-05
func TestPS17_SinFastAPISeDeniega(t *testing.T) {
	p := nuevo(t)
	p.canalVentasConAna()
	p.esperar("FastAPI caído", 503, "POST", "/api/canales/1/mensajes", "caido", `{"texto":"hola"}`)
}
