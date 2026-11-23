package security

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, status int) (*Client, string, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	service := strings.Repeat("s", 48) // Solo valor sintético del test; no es secreto de despliegue.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sessions/validate" || r.Header.Get("X-Service-Key") != service || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(status)
		if status == 200 {
			_, _ = w.Write([]byte(`{"active":true,"id":1,"role":"empleado","area":"ventas"}`))
		}
	}))
	t.Cleanup(srv.Close)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	client, err := New(srv.URL, pub, ca, service)
	if err != nil {
		t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	b, _ := json.Marshal(map[string]any{"sub": "1", "jti": "test-session", "iss": "uide-auth", "aud": "uide-chat", "iat": time.Now().Unix(), "exp": time.Now().Unix() + 900})
	unsigned := h + "." + base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return client, unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), srv
}

func TestValidSession(t *testing.T) {
	c, token, _ := fixture(t, 200)
	u, err := c.Validate(context.Background(), token)
	if err != nil || u.ID != 1 || u.Role != "empleado" {
		t.Fatal("sesión válida rechazada")
	}
}

func TestRevokedSession(t *testing.T) {
	c, token, _ := fixture(t, 401)
	if _, err := c.Validate(context.Background(), token); err == nil {
		t.Fatal("se aceptó revocación")
	}
}

func TestUnavailableFailsClosed(t *testing.T) {
	c, token, _ := fixture(t, 503)
	if _, err := c.Validate(context.Background(), token); err == nil {
		t.Fatal("fallback inseguro")
	}
}

func TestTamperedToken(t *testing.T) {
	c, token, _ := fixture(t, 200)
	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"2"}`))
	if _, err := c.Validate(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("firma no verificada")
	}
}

func TestUntrustedCertificate(t *testing.T) {
	c, token, _ := fixture(t, 200)
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer other.Close()
	c.http.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
	if _, err := c.Validate(context.Background(), token); err == nil {
		t.Fatal("certificado no verificado")
	}
}

func TestRejectCleartextAndMalformed(t *testing.T) {
	if _, err := New("http://localhost:8000", nil, nil, strings.Repeat("s", 48)); err == nil {
		t.Fatal("HTTP aceptado")
	}
	c, _, _ := fixture(t, 200)
	for _, token := range []string{"", "x.y.z", strings.Repeat("a", 4097)} {
		if _, err := c.Validate(context.Background(), token); err == nil {
			t.Fatal("token inválido aceptado")
		}
	}
}
