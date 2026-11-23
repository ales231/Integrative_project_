package sesion

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const emisor, audiencia = "auth.chat-grupo10", "chat-empresarial"

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// firmar crea un token RS256 como lo haría FastAPI.
func firmar(t *testing.T, k *rsa.PrivateKey, alg string, r Reclamos) string {
	t.Helper()
	cab, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	carga, _ := json.Marshal(r)
	base := b64(cab) + "." + b64(carga)
	h := sha256.Sum256([]byte(base))
	switch alg {
	case "RS256":
		f, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		return base + "." + b64(f)
	case "HS256":
		m := hmac.New(sha256.New, []byte("secreto-hmac-de-prueba"))
		m.Write([]byte(base))
		return base + "." + b64(m.Sum(nil))
	}
	return base + "."
}

func entorno(t *testing.T) (*rsa.PrivateKey, *VerificadorJWT) {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	v, err := NuevoVerificador(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), emisor, audiencia)
	if err != nil {
		t.Fatal(err)
	}
	return k, v
}

func reclamos() Reclamos {
	now := time.Now()
	return Reclamos{Sub: "2", Sid: "abc123", Iss: emisor, Aud: audiencia, Iat: now.Unix(), Exp: now.Add(15 * time.Minute).Unix()}
}

// PS-01 / PS-03 (RF-SEC-01, RF-SEC-05 / C-05): el servidor Go acepta solo tokens RS256 válidos.
func TestPS03_VerificadorRS256(t *testing.T) {
	k, v := entorno(t)
	if _, err := v.Verificar(firmar(t, k, "RS256", reclamos())); err != nil {
		t.Fatalf("token válido rechazado: %v", err)
	}
	otraK, _ := rsa.GenerateKey(rand.Reader, 2048)
	vencido, otroEmisor, otraAud := reclamos(), reclamos(), reclamos()
	vencido.Exp = time.Now().Add(-time.Minute).Unix()
	otroEmisor.Iss = "atacante"
	otraAud.Aud = "otro-servicio"
	bueno := firmar(t, k, "RS256", reclamos())
	casos := map[string]string{
		"alterado":               bueno[:len(bueno)-6] + "AAAAAA",
		"vencido":                firmar(t, k, "RS256", vencido),
		"otro emisor":            firmar(t, k, "RS256", otroEmisor),
		"otra audiencia":         firmar(t, k, "RS256", otraAud),
		"firmado con otra clave": firmar(t, otraK, "RS256", reclamos()),
		"alg none":               firmar(t, k, "none", reclamos()),
		"alg HS256":              firmar(t, k, "HS256", reclamos()),
		"basura":                 "no.es.un-token",
	}
	for nombre, tok := range casos {
		if _, err := v.Verificar(tok); err == nil {
			t.Errorf("%s: debía rechazarse", nombre)
		}
	}
}

// PS-10 (RF-SEC-05 / C-05): una sesión revocada en FastAPI se rechaza aunque la firma sea válida.
func TestPS10_SesionRevocadaEnFastAPI(t *testing.T) {
	k, v := entorno(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := NuevoClienteAuth(srv.URL, v, time.Second).ValidarToken(firmar(t, k, "RS256", reclamos()))
	if !errors.Is(err, ErrSesionRevocada) {
		t.Fatalf("esperaba ErrSesionRevocada, obtuve %v", err)
	}
}

// PS-17 (RF-SEC-05 / C-05): si FastAPI no responde, no se valida la sesión.
func TestPS17_FastAPISinRespuesta(t *testing.T) {
	k, v := entorno(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()
	_, err := NuevoClienteAuth(srv.URL, v, 100*time.Millisecond).ValidarToken(firmar(t, k, "RS256", reclamos()))
	if !errors.Is(err, ErrAuthNoDisponible) {
		t.Fatalf("esperaba ErrAuthNoDisponible, obtuve %v", err)
	}
}

// PS-01 (RF-SEC-01 / C-01): con FastAPI disponible se obtiene la sesión con rol y área vigentes.
func TestPS01_SesionValidaConRolYArea(t *testing.T) {
	k, v := entorno(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Sesion{UsuarioID: 2, SesionID: "abc123", Correo: "ana@empresa.test", Rol: "empleado", Area: "Ventas", VenceEn: time.Now().Add(15 * time.Minute)})
	}))
	defer srv.Close()
	s, err := NuevoClienteAuth(srv.URL, v, time.Second).ValidarToken(firmar(t, k, "RS256", reclamos()))
	if err != nil || s.Rol != "empleado" || s.Area != "Ventas" || !s.Vigente(time.Now()) {
		t.Fatalf("sesión inesperada %+v, %v", s, err)
	}
}
