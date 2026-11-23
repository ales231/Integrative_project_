// Package servidor contiene el servidor de chat con los controles de la Fase 2 de Seguridad
// que le corresponden a Go:
//
//	C-02 / RF-SEC-02  autorización por rol, área y membresía en cada operación, con denegación por defecto
//	C-05 / RF-SEC-05  sesión validada antes de cada operación; si FastAPI no responde, se deniega
//	C-07 / RF-SEC-07  mensajes de hasta 4 KiB y 30 por minuto por cuenta
//	C-08 / RF-SEC-08  registro de accesos sin tokens ni cuerpos de mensajes
//
// En esta etapa las operaciones se exponen por HTTP para demostrar los controles;
// en la Fase 4 se trasladan al canal WSS del diseño.
package servidor

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ales231/Integrative_project_/app-go/internal/sesion"
)

const (
	RolEmpleado     = "empleado"
	RolSupervisor   = "supervisor"
	RolAdmin        = "admin"
	MaxBytesMensaje = 4096 // RF-SEC-07
	MaxMensajesMin  = 30   // RF-SEC-07
)

// Canal es una sala de un área; solo sus miembros leen y envían.
type Canal struct {
	ID       int      `json:"id"`
	Nombre   string   `json:"nombre"`
	Area     string   `json:"area"`
	Miembros []string `json:"miembros"`
	mensajes []Mensaje
}

// Mensaje sigue el formato de protocolo.Mensaje del diseño.
type Mensaje struct {
	Autor     string    `json:"autor"`
	Texto     string    `json:"texto"`
	EnviadoEn time.Time `json:"enviadoEn"`
}

// ServidorChat atiende las operaciones y valida la sesión en cada una.
type ServidorChat struct {
	auth    sesion.Autenticador
	ahora   func() time.Time
	log     *log.Logger
	mu      sync.Mutex
	canales map[int]*Canal
	sigID   int
	envios  map[string][]time.Time // mensajes por cuenta en el último minuto
}

// NuevoServidor crea el servidor.
func NuevoServidor(auth sesion.Autenticador, registro *log.Logger) *ServidorChat {
	return &ServidorChat{auth: auth, ahora: time.Now, log: registro, canales: map[int]*Canal{}, sigID: 1, envios: map[string][]time.Time{}}
}

// Respuesta sigue el formato de protocolo.Respuesta del diseño.
type Respuesta struct {
	Codigo int    `json:"codigo"`
	Error  string `json:"error,omitempty"`
	Datos  any    `json:"datos,omitempty"`
}

func escribir(w http.ResponseWriter, codigo int, r Respuesta) {
	r.Codigo = codigo
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(codigo)
	json.NewEncoder(w).Encode(r)
}

// Rutas: cualquier ruta no listada responde 404 (denegación por defecto).
func (s *ServidorChat) Rutas() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/salud", func(w http.ResponseWriter, _ *http.Request) { escribir(w, 200, Respuesta{Datos: "ok"}) })
	m.Handle("GET /api/perfil", s.conSesion(s.perfil))
	m.Handle("POST /api/canales", s.conSesion(s.crearCanal))
	m.Handle("POST /api/canales/{id}/miembros", s.conSesion(s.agregarMiembro))
	m.Handle("DELETE /api/canales/{id}/miembros/{usuario}", s.conSesion(s.quitarMiembro))
	m.Handle("GET /api/canales/{id}/mensajes", s.conSesion(s.leerMensajes))
	m.Handle("POST /api/canales/{id}/mensajes", s.conSesion(s.enviarMensaje))
	m.Handle("GET /api/estadisticas", s.conSesion(s.estadisticas))
	return m
}

type manejador func(w http.ResponseWriter, r *http.Request, ses sesion.Sesion)

// conSesion es validarSesion del diseño: token presente, verificado y vigente antes de operar.
func (s *ServidorChat) conSesion(h manejador) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || strings.TrimSpace(token) == "" {
			s.registrar(r, "-", "rechazado", "sin token")
			escribir(w, 401, Respuesta{Error: "falta el token de sesión"})
			return
		}
		ses, err := s.auth.ValidarToken(token)
		switch {
		case errors.Is(err, sesion.ErrAuthNoDisponible):
			s.registrar(r, "-", "rechazado", "autenticación no disponible")
			escribir(w, 503, Respuesta{Error: "autenticación no disponible; intente más tarde"})
			return
		case err != nil:
			s.registrar(r, "-", "rechazado", err.Error())
			escribir(w, 401, Respuesta{Error: err.Error()})
			return
		case !ses.Vigente(s.ahora()):
			s.registrar(r, ses.Correo, "rechazado", "sesión vencida")
			escribir(w, 401, Respuesta{Error: "sesión vencida"})
			return
		}
		h(w, r, ses)
	})
}

// registrar (C-08): hora, actor, recurso, acción y resultado; nunca tokens ni textos de mensajes.
func (s *ServidorChat) registrar(r *http.Request, actor, resultado, detalle string) {
	s.log.Printf("actor=%s recurso=%s accion=%s resultado=%s %s", actor, r.URL.Path, r.Method, resultado, detalle)
}

func (s *ServidorChat) denegar(w http.ResponseWriter, r *http.Request, ses sesion.Sesion, motivo string) {
	s.registrar(r, ses.Correo, "denegado", motivo)
	escribir(w, 403, Respuesta{Error: "no tiene permiso para esta operación"})
}

func (s *ServidorChat) canal(r *http.Request) *Canal {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		return nil
	}
	return s.canales[id]
}

// ---------- operaciones ----------

func (s *ServidorChat) perfil(w http.ResponseWriter, r *http.Request, ses sesion.Sesion) {
	s.registrar(r, ses.Correo, "ok", "")
	escribir(w, 200, Respuesta{Datos: ses})
}

// crearCanal: solo un supervisor, y el canal queda en su área (Tabla 2 de la Fase 2).
func (s *ServidorChat) crearCanal(w http.ResponseWriter, r *http.Request, ses sesion.Sesion) {
	if ses.Rol != RolSupervisor {
		s.denegar(w, r, ses, "solo un supervisor crea canales")
		return
	}
	var p struct{ Nombre string }
	if json.NewDecoder(r.Body).Decode(&p) != nil || utf8.RuneCountInString(strings.TrimSpace(p.Nombre)) < 3 || utf8.RuneCountInString(p.Nombre) > 40 {
		escribir(w, 400, Respuesta{Error: "el nombre debe tener entre 3 y 40 caracteres"})
		return
	}
	s.mu.Lock()
	c := &Canal{ID: s.sigID, Nombre: strings.TrimSpace(p.Nombre), Area: ses.Area, Miembros: []string{ses.Correo}}
	s.canales[c.ID] = c
	s.sigID++
	s.mu.Unlock()
	s.registrar(r, ses.Correo, "ok", "canal "+strconv.Itoa(c.ID))
	escribir(w, 201, Respuesta{Datos: c})
}

// gestionaArea: solo el supervisor del área del canal gestiona sus miembros.
func gestionaArea(ses sesion.Sesion, c *Canal) bool {
	return ses.Rol == RolSupervisor && ses.Area == c.Area
}

func (s *ServidorChat) agregarMiembro(w http.ResponseWriter, r *http.Request, ses sesion.Sesion) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.canal(r)
	if c == nil {
		escribir(w, 404, Respuesta{Error: "el canal no existe"})
		return
	}
	if !gestionaArea(ses, c) {
		s.denegar(w, r, ses, "no es supervisor del área "+c.Area)
		return
	}
	var p struct{ Usuario string }
	if json.NewDecoder(r.Body).Decode(&p) != nil || !strings.Contains(p.Usuario, "@") || len(p.Usuario) > 120 {
		escribir(w, 400, Respuesta{Error: "usuario corporativo inválido"})
		return
	}
	u := strings.ToLower(strings.TrimSpace(p.Usuario))
	if !slices.Contains(c.Miembros, u) {
		c.Miembros = append(c.Miembros, u)
	}
	s.registrar(r, ses.Correo, "ok", "agrega "+u)
	escribir(w, 201, Respuesta{Datos: c})
}

func (s *ServidorChat) quitarMiembro(w http.ResponseWriter, r *http.Request, ses sesion.Sesion) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.canal(r)
	if c == nil {
		escribir(w, 404, Respuesta{Error: "el canal no existe"})
		return
	}
	if !gestionaArea(ses, c) {
		s.denegar(w, r, ses, "no es supervisor del área "+c.Area)
		return
	}
	u := strings.ToLower(r.PathValue("usuario"))
	c.Miembros = slices.DeleteFunc(c.Miembros, func(m string) bool { return m == u })
	s.registrar(r, ses.Correo, "ok", "quita "+u)
	escribir(w, 200, Respuesta{Datos: c})
}

// leerMensajes: solo los miembros; el ID del canal enviado por el cliente no prueba membresía.
func (s *ServidorChat) leerMensajes(w http.ResponseWriter, r *http.Request, ses sesion.Sesion) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.canal(r)
	if c == nil {
		escribir(w, 404, Respuesta{Error: "el canal no existe"})
		return
	}
	if !slices.Contains(c.Miembros, ses.Correo) {
		s.denegar(w, r, ses, "no es miembro del canal")
		return
	}
	s.registrar(r, ses.Correo, "ok", "")
	escribir(w, 200, Respuesta{Datos: c.mensajes})
}

// enviarMensaje: miembro, máximo 4 KiB y 30 mensajes por minuto por cuenta (C-07).
func (s *ServidorChat) enviarMensaje(w http.ResponseWriter, r *http.Request, ses sesion.Sesion) {
	var p struct{ Texto string }
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Texto == "" {
		escribir(w, 400, Respuesta{Error: "mensaje vacío o cuerpo inválido"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.canal(r)
	if c == nil {
		escribir(w, 404, Respuesta{Error: "el canal no existe"})
		return
	}
	if !slices.Contains(c.Miembros, ses.Correo) {
		s.denegar(w, r, ses, "no es miembro del canal")
		return
	}
	if len(p.Texto) > MaxBytesMensaje { // medido en bytes, antes de guardar o difundir
		s.registrar(r, ses.Correo, "rechazado", "mensaje de "+strconv.Itoa(len(p.Texto))+" bytes")
		escribir(w, 413, Respuesta{Error: "el mensaje supera 4096 bytes"})
		return
	}
	ahora := s.ahora()
	recientes := slices.DeleteFunc(s.envios[ses.Correo], func(t time.Time) bool { return ahora.Sub(t) >= time.Minute })
	if len(recientes) >= MaxMensajesMin {
		s.envios[ses.Correo] = recientes
		s.registrar(r, ses.Correo, "rechazado", "límite de 30 mensajes por minuto")
		escribir(w, 429, Respuesta{Error: "límite de 30 mensajes por minuto"})
		return
	}
	s.envios[ses.Correo] = append(recientes, ahora)
	c.mensajes = append(c.mensajes, Mensaje{Autor: ses.Correo, Texto: p.Texto, EnviadoEn: ahora})
	s.registrar(r, ses.Correo, "ok", strconv.Itoa(len(p.Texto))+" bytes")
	escribir(w, 201, Respuesta{Datos: "mensaje enviado"})
}

// estadisticas: solo el administrador de TI.
func (s *ServidorChat) estadisticas(w http.ResponseWriter, r *http.Request, ses sesion.Sesion) {
	if ses.Rol != RolAdmin {
		s.denegar(w, r, ses, "solo TI consulta estadísticas")
		return
	}
	s.mu.Lock()
	total := 0
	for _, c := range s.canales {
		total += len(c.mensajes)
	}
	canales := len(s.canales)
	s.mu.Unlock()
	s.registrar(r, ses.Correo, "ok", "")
	escribir(w, 200, Respuesta{Datos: map[string]int{"canales": canales, "mensajes": total}})
}
