package theauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DeviceAssertionTyp is the typ header of a device assertion JWT.
const DeviceAssertionTyp = "device-assertion+jwt"

// DefaultDeviceAudience is the aud the server expects unless devices.audience is set.
const DefaultDeviceAudience = "theauth"

// MaxDeviceAssertionLifetime is the longest exp minus iat the server accepts.
const MaxDeviceAssertionLifetime = 300 * time.Second

// DeviceAuth is a credential a device presents as itself: a pre shared key
// (DevicePSK), a ready made assertion (DeviceToken) or a DeviceAssertionSigner
// that signs a fresh assertion for every call.
type DeviceAuth interface {
	// AuthorizationValue returns the Authorization header value.
	AuthorizationValue() (string, error)
}

// DevicePSK is a tdk_ pre shared key.
type DevicePSK string

// AuthorizationValue implements DeviceAuth.
func (k DevicePSK) AuthorizationValue() (string, error) { return bearerOf(string(k)) }

// DeviceToken is a ready assertion JWT. The server accepts each jti once, so a
// DeviceToken works for one call. Use a DeviceAssertionSigner for more.
type DeviceToken string

// AuthorizationValue implements DeviceAuth.
func (t DeviceToken) AuthorizationValue() (string, error) { return bearerOf(string(t)) }

func bearerOf(v string) (string, error) {
	if v == "" {
		return "", errors.New("theauth: a device credential is required")
	}
	return "Bearer " + v, nil
}

// DeviceAssertionOption configures a DeviceAssertionSigner.
type DeviceAssertionOption func(*DeviceAssertionSigner)

// WithDeviceKey reuses an existing ECDSA P-256 key instead of generating one.
func WithDeviceKey(key *ecdsa.PrivateKey) DeviceAssertionOption {
	return func(s *DeviceAssertionSigner) { s.key = key }
}

// WithDeviceAudience sets aud. It must equal the server's devices.audience.
func WithDeviceAudience(aud string) DeviceAssertionOption {
	return func(s *DeviceAssertionSigner) { s.audience = aud }
}

// WithDeviceLifetime sets the time between iat and exp, 1 to 300 seconds. The default is 60.
func WithDeviceLifetime(d time.Duration) DeviceAssertionOption {
	return func(s *DeviceAssertionSigner) { s.lifetime = d }
}

// WithDeviceClock overrides the clock used for iat and exp.
func WithDeviceClock(now func() time.Time) DeviceAssertionOption {
	return func(s *DeviceAssertionSigner) { s.now = now }
}

// DeviceAssertionSigner owns a device P-256 key and signs device assertions
// (iot-device-identity.md D3, RFC 7523 section 3 with the RFC 9449 replay
// rules). It is safe for concurrent use. Register PublicJWK with JWKCredential.
type DeviceAssertionSigner struct {
	mu       sync.RWMutex
	deviceID string
	audience string
	lifetime time.Duration
	now      func() time.Time
	key      *ecdsa.PrivateKey
	jwk      map[string]string
	kid      string
}

// NewDeviceAssertionSigner creates a signer for deviceID. ES256 (P-256) only;
// the server also accepts ES384 and EdDSA keys. Pass "" to create the key first
// (you need PublicJWK to register), then call Bind with the id you get back.
func NewDeviceAssertionSigner(deviceID string, opts ...DeviceAssertionOption) (*DeviceAssertionSigner, error) {
	s := &DeviceAssertionSigner{deviceID: deviceID, audience: DefaultDeviceAudience, lifetime: 60 * time.Second, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	if s.lifetime < time.Second || s.lifetime > MaxDeviceAssertionLifetime {
		return nil, fmt.Errorf("theauth: lifetime must be 1 to %d seconds", int(MaxDeviceAssertionLifetime/time.Second))
	}
	if s.key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("theauth: generate device key: %w", err)
		}
		s.key = key
	}
	if s.key.Curve != elliptic.P256() {
		return nil, errors.New("theauth: the device key must be an ECDSA P-256 key")
	}
	s.jwk = map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64url(s.key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   b64url(s.key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
	s.kid = sha256URL(fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, s.jwk["crv"], s.jwk["kty"], s.jwk["x"], s.jwk["y"]))
	return s, nil
}

// Bind sets the device id after registration. Sign fails until an id is set.
func (s *DeviceAssertionSigner) Bind(deviceID string) error {
	if deviceID == "" {
		return errors.New("theauth: deviceID must not be empty")
	}
	s.mu.Lock()
	s.deviceID = deviceID
	s.mu.Unlock()
	return nil
}

// PublicJWK returns a copy of the public key to register with JWKCredential.
func (s *DeviceAssertionSigner) PublicJWK() map[string]string {
	out := make(map[string]string, len(s.jwk))
	for k, v := range s.jwk {
		out[k] = v
	}
	return out
}

// KeyID is the RFC 7638 SHA-256 thumbprint of the public key. The server looks
// the credential up by it.
func (s *DeviceAssertionSigner) KeyID() string { return s.kid }

// Sign returns a new signed assertion with a fresh jti.
func (s *DeviceAssertionSigner) Sign() (string, error) {
	s.mu.RLock()
	deviceID := s.deviceID
	s.mu.RUnlock()
	if deviceID == "" {
		return "", errors.New("theauth: Bind a device id before signing")
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("theauth: generate jti: %w", err)
	}
	iat := s.now().Unix()
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": DeviceAssertionTyp, "kid": s.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]interface{}{
		"iss": deviceID,
		"sub": deviceID,
		"aud": s.audience,
		"iat": iat,
		"exp": iat + int64(s.lifetime/time.Second),
		"jti": b64url(jti),
	})
	if err != nil {
		return "", err
	}
	signingInput := b64url(header) + "." + b64url(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("theauth: sign device assertion: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return signingInput + "." + b64url(sig), nil
}

// AuthorizationValue implements DeviceAuth with a new assertion per call.
func (s *DeviceAssertionSigner) AuthorizationValue() (string, error) {
	jwt, err := s.Sign()
	if err != nil {
		return "", err
	}
	return "Bearer " + jwt, nil
}
