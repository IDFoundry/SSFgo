// Package clientassertion builds the signed JWTs a client presents to an
// OAuth 2.0 token endpoint instead of a client secret (RFC 7523 §2.2,
// OpenID Connect Core §9: client_secret_jwt and private_key_jwt).
//
// HS256 lives here rather than in internal/jose on purpose: a shared-secret
// MAC is acceptable for authenticating a client to its own authorization
// server, but must never be usable to sign or verify a SET.
package clientassertion

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/jose"
)

// Type is the client_assertion_type for JWT client assertions
// (RFC 7523 §2.2).
const Type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Lifetime is how long an assertion is valid. It only needs to survive
// one token request.
const Lifetime = time.Minute

// minSecretBytes is the smallest HS256 key RFC 7518 §3.2 allows: at least
// as long as the hash output.
const minSecretBytes = 32

// Options describe one assertion. Set Secret for client_secret_jwt, or
// Signer and Algorithm for private_key_jwt.
type Options struct {
	ClientID string
	// Audience identifies the authorization server; the token endpoint
	// URL is the conventional choice (RFC 7523 §3).
	Audience string
	Now      time.Time

	Secret []byte

	Signer    crypto.Signer
	Algorithm ssf.SignatureAlgorithm
	KeyID     string
}

type claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// Build returns a signed client assertion.
func Build(o Options) (string, error) {
	if o.ClientID == "" || o.Audience == "" {
		return "", errors.New("clientassertion: ClientID and Audience are required")
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	payload, err := json.Marshal(claims{
		Iss: o.ClientID,
		Sub: o.ClientID,
		Aud: o.Audience,
		Jti: hex.EncodeToString(jti),
		Iat: o.Now.Unix(),
		Exp: o.Now.Add(Lifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	switch {
	case o.Secret != nil && o.Signer != nil:
		return "", errors.New("clientassertion: set either Secret or Signer, not both")
	case o.Secret != nil:
		return signHS256(o.Secret, payload)
	case o.Signer != nil:
		return jose.Sign(o.Signer, jose.Header{Algorithm: o.Algorithm, Type: "JWT", KeyID: o.KeyID}, payload)
	default:
		return "", errors.New("clientassertion: a Secret or a Signer is required")
	}
}

func signHS256(secret, payload []byte) (string, error) {
	if len(secret) < minSecretBytes {
		return "", fmt.Errorf("clientassertion: HS256 needs a secret of at least %d bytes, got %d", minSecretBytes, len(secret))
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	input := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
