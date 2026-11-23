// Package security implementa el adaptador de identidad para el futuro chat Go.
// No reemplaza su control de membresías ni implementa el servidor de mensajes.
package security

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrDenied = errors.New("sesión no válida o servicio no disponible")

type User struct {
	Active   bool   `json:"active"`
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Area     string `json:"area"`
}

type Client struct {
	baseURL    string
	serviceKey string
	key        *rsa.PublicKey
	http       *http.Client
}

// New exige HTTPS, una CA confiable y clave pública RSA fijada localmente.
// No sigue redirecciones que pudieran exponer los encabezados de identidad.
func New(baseURL string, publicPEM, caPEM []byte, serviceKey string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(serviceKey) < 32 {
		return nil, ErrDenied
	}
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		return nil, ErrDenied
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrDenied
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, ErrDenied
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, ErrDenied
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), serviceKey: serviceKey, key: key,
		http: &http.Client{Transport: transport, Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Validate debe ejecutarse antes de aceptar una conexión y antes de cada
// operación protegida. En conexiones ociosas, invocar al menos cada 30 s.
// Un error obliga al chat a denegar/cerrar; nunca hay fallback permisivo.
func (c *Client) Validate(ctx context.Context, token string) (User, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 4096 {
		return User{}, ErrDenied
	}
	var header struct {
		Alg string `json:"alg"`
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(h, &header) != nil || header.Alg != "RS256" {
		return User{}, ErrDenied
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return User{}, ErrDenied
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(c.key, crypto.SHA256, digest[:], sig) != nil {
		return User{}, ErrDenied
	}
	var claims struct {
		Sub      string `json:"sub"`
		JTI      string `json:"jti"`
		Issuer   string `json:"iss"`
		Audience string `json:"aud"`
		Expires  int64  `json:"exp"`
		Issued   int64  `json:"iat"`
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(body, &claims) != nil {
		return User{}, ErrDenied
	}
	now := time.Now().Unix()
	uid, err := strconv.Atoi(claims.Sub)
	if err != nil || uid <= 0 || claims.JTI == "" || claims.Issuer != "uide-auth" || claims.Audience != "uide-chat" || claims.Expires <= now || claims.Issued <= 0 || claims.Issued > now || claims.Expires-claims.Issued > 900 {
		return User{}, ErrDenied
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/sessions/validate", bytes.NewReader(nil))
	if err != nil {
		return User{}, ErrDenied
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Service-Key", c.serviceKey)
	response, err := c.http.Do(req)
	if err != nil {
		return User{}, ErrDenied
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return User{}, ErrDenied
	}
	var user User
	if json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&user) != nil || !user.Active || user.ID != uid {
		return User{}, ErrDenied
	}
	if user.Role != "empleado" && user.Role != "supervisor" && user.Role != "ti" {
		return User{}, ErrDenied
	}
	return user, nil
}
