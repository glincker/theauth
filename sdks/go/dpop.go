package theauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DPoPPublicJWK is the public half of the proof key as carried in the
// proof header (RFC 9449 section 4.2).
type DPoPPublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// DPoPProofInput is the input to DPoPProver.CreateProof.
type DPoPProofInput struct {
	// Method is the HTTP method of the request the proof is for.
	Method string
	// URL is the absolute request URL. Query and fragment are dropped from htu.
	URL string
	// AccessToken, when set, binds the proof to a resource request (ath).
	AccessToken string
	// Nonce is a server provided nonce, when one is known for the origin.
	Nonce string
}

// DPoPOption configures a DPoPProver or DPoPTransport.
type DPoPOption func(*dpopConfig)

type dpopConfig struct {
	key         *ecdsa.PrivateKey
	now         func() time.Time
	accessToken string
}

// WithDPoPKey reuses an existing ECDSA P-256 key instead of generating one.
func WithDPoPKey(key *ecdsa.PrivateKey) DPoPOption {
	return func(c *dpopConfig) { c.key = key }
}

// WithDPoPClock overrides the clock used for the iat claim.
func WithDPoPClock(now func() time.Time) DPoPOption {
	return func(c *dpopConfig) { c.now = now }
}

// WithDPoPAccessToken sets the access token used for the DPoP authorization
// scheme and ath claim, overriding any Bearer token on the request.
func WithDPoPAccessToken(token string) DPoPOption {
	return func(c *dpopConfig) { c.accessToken = token }
}

// DPoPProver owns an ES256 key pair, builds DPoP proofs and caches the
// server provided nonce per origin. It is safe for concurrent use.
type DPoPProver struct {
	key       *ecdsa.PrivateKey
	jwk       DPoPPublicJWK
	now       func() time.Time
	mu        sync.Mutex
	nonces    map[string]string
	thumbOnce sync.Once
	thumb     string
}

// NewDPoPProver creates a prover. A P-256 key is generated unless
// WithDPoPKey is given.
func NewDPoPProver(opts ...DPoPOption) (*DPoPProver, error) {
	cfg := &dpopConfig{}
	for _, o := range opts {
		o(cfg)
	}
	key := cfg.key
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("theauth: generate dpop key: %w", err)
		}
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("theauth: DPoP key must be an ECDSA P-256 key")
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	return &DPoPProver{
		key: key,
		jwk: DPoPPublicJWK{
			Kty: "EC",
			Crv: "P-256",
			X:   b64url(key.PublicKey.X.FillBytes(make([]byte, 32))),
			Y:   b64url(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		},
		now:    now,
		nonces: make(map[string]string),
	}, nil
}

// PublicJWK returns the public key as it appears in proof headers.
func (p *DPoPProver) PublicJWK() DPoPPublicJWK { return p.jwk }

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint (the jkt value).
func (p *DPoPProver) Thumbprint() string {
	p.thumbOnce.Do(func() {
		canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, p.jwk.Crv, p.jwk.Kty, p.jwk.X, p.jwk.Y)
		p.thumb = sha256URL(canonical)
	})
	return p.thumb
}

// CreateProof builds and signs a dpop+jwt for the given request.
func (p *DPoPProver) CreateProof(in DPoPProofInput) (string, error) {
	htu, err := NormalizeHTU(in.URL)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("theauth: generate jti: %w", err)
	}
	claims := map[string]interface{}{
		"htm": strings.ToUpper(in.Method),
		"htu": htu,
		"iat": p.now().Unix(),
		"jti": b64url(jti),
	}
	if in.AccessToken != "" {
		claims["ath"] = sha256URL(in.AccessToken)
	}
	if in.Nonce != "" {
		claims["nonce"] = in.Nonce
	}
	header, err := json.Marshal(map[string]interface{}{"typ": "dpop+jwt", "alg": "ES256", "jwk": p.jwk})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64url(header) + "." + b64url(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("theauth: sign dpop proof: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64url(sig), nil
}

// Nonce returns the cached nonce for the origin of rawURL, or "".
func (p *DPoPProver) Nonce(rawURL string) string {
	origin, err := originOf(rawURL)
	if err != nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nonces[origin]
}

// SetNonce caches a nonce for the origin of rawURL.
func (p *DPoPProver) SetNonce(rawURL, nonce string) {
	origin, err := originOf(rawURL)
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nonces[origin] = nonce
}

// NormalizeHTU returns the htu form of a URL: scheme, host and path only,
// with the scheme and host lowercased and default ports dropped.
func NormalizeHTU(raw string) (string, error) {
	origin, err := originOf(raw)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(raw)
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return origin + path, nil
}

func originOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("theauth: invalid url %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("theauth: url %q is not absolute", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sha256URL(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64url(sum[:])
}

// DPoPTransport is an http.RoundTripper that attaches a DPoP proof to every
// request, switches a Bearer token to the DPoP scheme (adding ath), caches the
// DPoP-Nonce response header per origin and retries once on use_dpop_nonce.
type DPoPTransport struct {
	// Prover signs the proofs and holds the nonce cache.
	Prover *DPoPProver
	// Base is the underlying transport. http.DefaultTransport when nil.
	Base http.RoundTripper
	// AccessToken overrides the token taken from the Authorization header.
	AccessToken string
}

// NewDPoPTransport wraps base (http.DefaultTransport when nil).
func NewDPoPTransport(prover *DPoPProver, base http.RoundTripper, opts ...DPoPOption) *DPoPTransport {
	cfg := &dpopConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return &DPoPTransport{Prover: prover, Base: base, AccessToken: cfg.accessToken}
}

// DPoPHTTPClient returns a copy of hc (a fresh client when nil) whose
// transport is wrapped with DPoP. The input client is not modified.
func DPoPHTTPClient(hc *http.Client, prover *DPoPProver, opts ...DPoPOption) *http.Client {
	var cp http.Client
	if hc != nil {
		cp = *hc
	}
	cp.Transport = NewDPoPTransport(prover, cp.Transport, opts...)
	return &cp
}

func (t *DPoPTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// RoundTrip implements http.RoundTripper.
func (t *DPoPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token := t.AccessToken
	if token == "" {
		auth := req.Header.Get("Authorization")
		switch {
		case strings.HasPrefix(auth, "Bearer "):
			token = strings.TrimPrefix(auth, "Bearer ")
		case strings.HasPrefix(auth, "DPoP "):
			token = strings.TrimPrefix(auth, "DPoP ")
		}
	}

	// Buffer the body once so the nonce retry can replay it.
	getBody := req.GetBody
	if getBody == nil && req.Body != nil && req.Body != http.NoBody {
		data, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		getBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	}

	resp, err := t.send(req, getBody, token)
	if err != nil || !isNonceChallenge(resp) {
		return resp, err
	}
	// Drain and close the challenge response, then retry once with its nonce
	// (already cached by send).
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return t.send(req, getBody, token)
}

func (t *DPoPTransport) send(orig *http.Request, getBody func() (io.ReadCloser, error), token string) (*http.Response, error) {
	req := orig.Clone(orig.Context())
	if getBody != nil {
		body, err := getBody()
		if err != nil {
			return nil, err
		}
		req.Body = body
		req.GetBody = getBody
	}
	target := req.URL.String()
	proof, err := t.Prover.CreateProof(DPoPProofInput{
		Method:      req.Method,
		URL:         target,
		AccessToken: token,
		Nonce:       t.Prover.Nonce(target),
	})
	if err != nil {
		return nil, err
	}
	req.Header.Set("DPoP", proof)
	if token != "" {
		req.Header.Set("Authorization", "DPoP "+token)
	}
	resp, err := t.base().RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if nonce := resp.Header.Get("DPoP-Nonce"); nonce != "" {
		t.Prover.SetNonce(target, nonce)
	}
	return resp, nil
}

// isNonceChallenge reports a use_dpop_nonce challenge. The response body is
// restored when it had to be inspected.
func isNonceChallenge(resp *http.Response) bool {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	if resp.Header.Get("DPoP-Nonce") == "" {
		return false
	}
	if strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
		return true
	}
	if resp.StatusCode != http.StatusBadRequest {
		return false
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		return false
	}
	var body struct {
		Error interface{} `json:"error"`
	}
	if json.Unmarshal(data, &body) != nil {
		return false
	}
	s, ok := body.Error.(string)
	return ok && s == "use_dpop_nonce"
}
