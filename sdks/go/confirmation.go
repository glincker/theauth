package theauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
)

var thumbprintPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

var errBadThumbprint = errors.New("theauth: a SHA-256 thumbprint is 43 base64url characters")

// DPoPConfirmation is the cnf binding a token to a DPoP key: {"jkt": thumbprint}
// (RFC 7800, RFC 9449 section 6).
func DPoPConfirmation(p *DPoPProver) map[string]string {
	return map[string]string{"jkt": p.Thumbprint()}
}

// JKTConfirmation builds the cnf from a JWK thumbprint you already hold.
func JKTConfirmation(thumbprint string) (map[string]string, error) {
	if !thumbprintPattern.MatchString(thumbprint) {
		return nil, errBadThumbprint
	}
	return map[string]string{"jkt": thumbprint}, nil
}

// MTLSConfirmation is the cnf binding a token to a client certificate: the
// base64url SHA-256 of the DER certificate (RFC 8705 section 3.1).
func MTLSConfirmation(certDER []byte) map[string]string {
	sum := sha256.Sum256(certDER)
	return map[string]string{"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:])}
}

// X5tConfirmation builds the cnf from a certificate thumbprint you already hold.
func X5tConfirmation(thumbprint string) (map[string]string, error) {
	if !thumbprintPattern.MatchString(thumbprint) {
		return nil, errBadThumbprint
	}
	return map[string]string{"x5t#S256": thumbprint}, nil
}
