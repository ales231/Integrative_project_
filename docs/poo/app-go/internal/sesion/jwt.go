package sesion

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Reclamos son los campos del token definidos en la Fase 2 (sección 3.1): usuario,
// sesión, emisor, audiencia y vencimiento. El token no lleva rol ni contraseña.
type Reclamos struct {
	Sub string `json:"sub"`
	Sid string `json:"sid"`
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

// VerificadorJWT valida localmente la firma RS256 con la clave pública de FastAPI (C-05).
// El algoritmo es fijo: se rechazan "none", HS256 y cualquier otro.
type VerificadorJWT struct {
	publica   *rsa.PublicKey
	emisor    string
	audiencia string
	ahora     func() time.Time
}

// NuevoVerificador lee la clave pública en formato PEM.
func NuevoVerificador(pemPublica []byte, emisor, audiencia string) (*VerificadorJWT, error) {
	bloque, _ := pem.Decode(pemPublica)
	if bloque == nil {
		return nil, errors.New("clave pública PEM inválida")
	}
	clave, err := x509.ParsePKIXPublicKey(bloque.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clave pública: %w", err)
	}
	pub, ok := clave.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("la clave pública no es RSA")
	}
	return &VerificadorJWT{publica: pub, emisor: emisor, audiencia: audiencia, ahora: time.Now}, nil
}

// Verificar comprueba algoritmo, firma, emisor, audiencia y vigencia.
func (v *VerificadorJWT) Verificar(token string) (Reclamos, error) {
	partes := strings.Split(token, ".")
	if len(partes) != 3 {
		return Reclamos{}, ErrTokenInvalido
	}
	var cab struct {
		Alg string `json:"alg"`
	}
	if b, err := base64.RawURLEncoding.DecodeString(partes[0]); err != nil || json.Unmarshal(b, &cab) != nil || cab.Alg != "RS256" {
		return Reclamos{}, ErrTokenInvalido
	}
	firma, err := base64.RawURLEncoding.DecodeString(partes[2])
	if err != nil {
		return Reclamos{}, ErrTokenInvalido
	}
	resumen := sha256.Sum256([]byte(partes[0] + "." + partes[1]))
	if rsa.VerifyPKCS1v15(v.publica, crypto.SHA256, resumen[:], firma) != nil {
		return Reclamos{}, ErrTokenInvalido
	}
	var r Reclamos
	if b, err := base64.RawURLEncoding.DecodeString(partes[1]); err != nil || json.Unmarshal(b, &r) != nil {
		return Reclamos{}, ErrTokenInvalido
	}
	switch {
	case r.Iss != v.emisor, r.Aud != v.audiencia, r.Sub == "", r.Sid == "":
		return Reclamos{}, ErrTokenInvalido
	case !v.ahora().Before(time.Unix(r.Exp, 0)):
		return Reclamos{}, ErrTokenVencido
	}
	return r, nil
}
