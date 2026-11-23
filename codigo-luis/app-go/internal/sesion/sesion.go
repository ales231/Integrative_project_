// Package sesion valida las sesiones del chat (C-05 / RF-SEC-05 de la Fase 2 de Seguridad).
//
// Flujo del diseño (sección 3.1): Go verifica localmente la firma RS256, el emisor, la
// audiencia y la vigencia del token, y además consulta a FastAPI el estado de la sesión
// y el rol y área vigentes. Si FastAPI no responde, se deniega la operación (PS-17).
// El servidor Go nunca recibe contraseñas.
package sesion

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	ErrTokenInvalido    = errors.New("token inválido")
	ErrTokenVencido     = errors.New("sesión vencida")
	ErrSesionRevocada   = errors.New("sesión revocada o cuenta desactivada")
	ErrAuthNoDisponible = errors.New("el servicio de autenticación no responde")
)

// Sesion son los datos vigentes de una sesión validada (rol y área vienen de FastAPI, no del token).
type Sesion struct {
	UsuarioID int       `json:"usuarioID"`
	SesionID  string    `json:"sesionID"`
	Correo    string    `json:"correo"`
	Rol       string    `json:"rol"`
	Area      string    `json:"area"`
	VenceEn   time.Time `json:"venceEn"`
}

// Vigente indica si la sesión sigue activa en el instante dado.
func (s Sesion) Vigente(ahora time.Time) bool { return ahora.Before(s.VenceEn) }

// Autenticador es lo que el servidor necesita del servicio de identidad.
type Autenticador interface {
	ValidarToken(token string) (Sesion, error)
}

// ClienteAuth implementa Autenticador: verificación local RS256 más consulta a POST /validar.
type ClienteAuth struct {
	baseURL     string
	http        *http.Client
	verificador *VerificadorJWT
}

// NuevoClienteAuth crea el cliente; espera es el tiempo máximo de respuesta de FastAPI.
func NuevoClienteAuth(baseURL string, verificador *VerificadorJWT, espera time.Duration) *ClienteAuth {
	return &ClienteAuth{baseURL: baseURL, http: &http.Client{Timeout: espera}, verificador: verificador}
}

// ValidarToken rechaza primero lo que falla localmente y después consulta el estado en FastAPI.
func (c *ClienteAuth) ValidarToken(token string) (Sesion, error) {
	if _, err := c.verificador.Verificar(token); err != nil {
		return Sesion{}, err
	}
	cuerpo, _ := json.Marshal(map[string]string{"token": token})
	resp, err := c.http.Post(c.baseURL+"/validar", "application/json", bytes.NewReader(cuerpo))
	if err != nil {
		return Sesion{}, fmt.Errorf("%w: %v", ErrAuthNoDisponible, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var s Sesion
		if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
			return Sesion{}, fmt.Errorf("%w: respuesta ilegible", ErrAuthNoDisponible)
		}
		return s, nil
	case http.StatusUnauthorized:
		return Sesion{}, ErrSesionRevocada
	default:
		return Sesion{}, fmt.Errorf("%w: código %d", ErrAuthNoDisponible, resp.StatusCode)
	}
}
