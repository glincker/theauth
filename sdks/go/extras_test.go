package theauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

// -------------------------------------------------------------------------
// MCP
// -------------------------------------------------------------------------

func TestMCP_RegisterListGet(t *testing.T) {
	srvFixture := theauth.McpServer{ID: "m1", Name: "gh", Endpoint: "https://mcp.test", Tools: []string{"a"}, AuthRequired: true, CreatedAt: "2024-01-01T00:00:00Z"}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/mcp/servers":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			rl, _ := body["rateLimit"].(map[string]interface{})
			if body["name"] != "gh" || rl["rpm"] != float64(60) {
				t.Errorf("unexpected body: %v", body)
			}
			writeJSON(w, 201, srvFixture)
		case r.Method == "GET" && r.URL.Path == "/mcp/servers":
			writeJSON(w, 200, []theauth.McpServer{srvFixture})
		case r.URL.Path == "/mcp/servers/m1":
			writeJSON(w, 200, srvFixture)
		default:
			writeJSON(w, 404, map[string]interface{}{"error": map[string]string{"code": "NOT_FOUND", "message": "nope"}})
		}
	}))
	defer ts.Close()
	c := theauth.NewClient(ts.URL)
	ctx := context.Background()

	got, err := c.MCP.Register(ctx, theauth.RegisterMcpServerInput{Name: "gh", Endpoint: "https://mcp.test", Tools: []string{"a"}, AuthRequired: true, RateLimitRPM: ptr(60)})
	if err != nil || got.ID != "m1" {
		t.Fatalf("register: %v %+v", err, got)
	}
	list, err := c.MCP.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", err, list)
	}
	one, err := c.MCP.Get(ctx, "m1")
	if err != nil || one == nil || one.Name != "gh" {
		t.Fatalf("get: %v %+v", err, one)
	}
	missing, err := c.MCP.Get(ctx, "zzz")
	if err != nil || missing != nil {
		t.Fatalf("expected nil,nil for missing, got %v %v", missing, err)
	}
}

// -------------------------------------------------------------------------
// Do / Request and errors
// -------------------------------------------------------------------------

func TestDo_QueryBodyAndOut(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/team/t%201/invite" && r.URL.EscapedPath() != "/auth/team/t%201/invite" {
			t.Errorf("path: %s", r.URL.EscapedPath())
		}
		if r.URL.Query().Get("dry") != "1" || r.Method != "POST" {
			t.Errorf("bad request %s %s", r.Method, r.URL)
		}
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"email":"a@b.c"`) {
			t.Errorf("body: %s", b)
		}
		writeJSON(w, 200, map[string]string{"id": "inv1"})
	}))
	defer ts.Close()
	c := theauth.NewClient(ts.URL)
	var out struct{ ID string }
	err := c.Request(context.Background(), theauth.RequestOptions{
		Method: "post", Path: "/auth/team/:id/invite",
		Params: map[string]string{"id": "t 1"},
		Query:  map[string]string{"dry": "1"},
		Body:   map[string]string{"email": "a@b.c"},
	}, &out)
	if err != nil || out.ID != "inv1" {
		t.Fatalf("%v %+v", err, out)
	}
	if err := c.Request(context.Background(), theauth.RequestOptions{Method: "GET", Path: "/x/:id"}, nil); err == nil {
		t.Fatal("expected missing path parameter error")
	}
}

func TestDo_ValidationIssues(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 400, map[string]interface{}{"error": map[string]interface{}{
			"code": "VALIDATION_ERROR", "message": "bad input",
			"issues": []map[string]interface{}{{"path": []string{"email"}, "message": "Invalid"}},
		}})
	}))
	defer ts.Close()
	err := theauth.NewClient(ts.URL).Do(context.Background(), "POST", "/p", nil, map[string]string{}, nil)
	e, ok := err.(*theauth.TheAuthError)
	if !ok || e.Code != "VALIDATION_ERROR" || e.StatusCode != 400 {
		t.Fatalf("unexpected: %#v", err)
	}
	issues, ok := e.Issues.([]interface{})
	if !ok || len(issues) != 1 || theauth.ValidationIssues(err) == nil {
		t.Fatalf("issues: %#v", e.Issues)
	}
}

func TestErrors_RateLimitedAndCSRF(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rl" {
			w.Header().Set("Retry-After", "7")
			writeJSON(w, 429, map[string]interface{}{"error": map[string]string{"code": "RATE_LIMITED", "message": "slow"}})
			return
		}
		writeJSON(w, 403, map[string]interface{}{"error": map[string]string{"code": "CSRF_REJECTED", "message": "csrf"}})
	}))
	defer ts.Close()
	c := theauth.NewClient(ts.URL)
	err := c.Do(context.Background(), "GET", "/rl", nil, nil, nil)
	if secs, ok := theauth.IsRateLimited(err); !ok || secs != 7 || !theauth.IsRateLimit(err) {
		t.Fatalf("rate limit: %v", err)
	}
	err = c.Do(context.Background(), "POST", "/csrf", nil, nil, nil)
	if !theauth.IsCSRFRejected(err) || !theauth.IsPermission(err) {
		t.Fatalf("csrf: %v", err)
	}
}

// -------------------------------------------------------------------------
// DPoP
// -------------------------------------------------------------------------

func parseProof(t *testing.T, jwt string) (header, payload map[string]interface{}) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("bad jwt: %s", jwt)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := json.Unmarshal(dec(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(dec(parts[1]), &payload); err != nil {
		t.Fatal(err)
	}
	sig := dec(parts[2])
	jwk := header["jwk"].(map[string]interface{})
	x := new(big.Int).SetBytes(dec(jwk["x"].(string)))
	y := new(big.Int).SetBytes(dec(jwk["y"].(string)))
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("proof signature does not verify")
	}
	return header, payload
}

func sha256URL(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestNormalizeHTU(t *testing.T) {
	got, err := theauth.NormalizeHTU("https://Example.COM:443/a/b?x=1#f")
	if err != nil || got != "https://example.com/a/b" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := theauth.NormalizeHTU("/relative"); err == nil {
		t.Fatal("expected error for relative url")
	}
}

func TestDPoPProver_Proof(t *testing.T) {
	p, err := theauth.NewDPoPProver(theauth.WithDPoPClock(func() time.Time { return time.Unix(1_700_000_000, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := p.CreateProof(theauth.DPoPProofInput{Method: "post", URL: "https://as.test/token?a=b", AccessToken: "tok-123", Nonce: "n-1"})
	if err != nil {
		t.Fatal(err)
	}
	h, c := parseProof(t, jwt)
	if h["typ"] != "dpop+jwt" || h["alg"] != "ES256" {
		t.Fatalf("header: %v", h)
	}
	if len(h["jwk"].(map[string]interface{})) != 4 {
		t.Fatalf("jwk must only carry public members: %v", h["jwk"])
	}
	if c["htm"] != "POST" || c["htu"] != "https://as.test/token" || c["iat"] != float64(1_700_000_000) ||
		c["ath"] != sha256URL("tok-123") || c["nonce"] != "n-1" {
		t.Fatalf("claims: %v", c)
	}
	jwt2, _ := p.CreateProof(theauth.DPoPProofInput{Method: "GET", URL: "https://rs.test/x"})
	_, c2 := parseProof(t, jwt2)
	if _, has := c2["ath"]; has {
		t.Fatal("ath must be absent without token")
	}
	jwt3, _ := p.CreateProof(theauth.DPoPProofInput{Method: "GET", URL: "https://rs.test/x"})
	if _, c3 := parseProof(t, jwt3); c3["jti"] == c2["jti"] {
		t.Fatal("jti must be unique per proof")
	}
}

func TestDPoPProver_ThumbprintAndNonce(t *testing.T) {
	p, _ := theauth.NewDPoPProver()
	j := p.PublicJWK()
	canonical := `{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `","y":"` + j.Y + `"}`
	if p.Thumbprint() != sha256URL(canonical) {
		t.Fatal("thumbprint mismatch")
	}
	p.SetNonce("https://as.test/token", "n1")
	if p.Nonce("https://as.test/other") != "n1" || p.Nonce("https://rs.test/") != "" {
		t.Fatal("nonce cache is per origin")
	}
}

func TestDPoPTransport_NonceRetry(t *testing.T) {
	var calls int32
	var bodies []string
	var nonces []interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if r.Header.Get("Authorization") != "DPoP AT" {
			t.Errorf("authorization: %q", r.Header.Get("Authorization"))
		}
		_, c := parseProof(t, r.Header.Get("DPoP"))
		nonces = append(nonces, c["nonce"])
		if c["ath"] != sha256URL("AT") {
			t.Errorf("ath: %v", c["ath"])
		}
		if n == 1 {
			w.Header().Set("DPoP-Nonce", "srv-1")
			writeJSON(w, 400, map[string]string{"error": "use_dpop_nonce"})
			return
		}
		w.Header().Set("DPoP-Nonce", "srv-2")
		writeJSON(w, 200, map[string]string{"ok": "yes"})
	}))
	defer ts.Close()

	c := theauth.NewClient(ts.URL, theauth.WithToken("AT"))
	p, _ := theauth.NewDPoPProver()
	c.UseDPoP(p)
	var out map[string]string
	if err := c.Do(context.Background(), "POST", "/thing", nil, map[string]string{"a": "b"}, &out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != "yes" || calls != 2 {
		t.Fatalf("out=%v calls=%d", out, calls)
	}
	if nonces[0] != nil || nonces[1] != "srv-1" {
		t.Fatalf("nonces: %v", nonces)
	}
	if bodies[0] != bodies[1] || bodies[1] == "" {
		t.Fatalf("body not replayed: %v", bodies)
	}
	if p.Nonce(ts.URL) != "srv-2" {
		t.Fatal("latest nonce should be cached")
	}
}

func TestDPoPTransport_RetriesOnlyOnce(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("DPoP-Nonce", "n")
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		writeJSON(w, 401, map[string]string{"error": "x"})
	}))
	defer ts.Close()
	p, _ := theauth.NewDPoPProver()
	hc := theauth.DPoPHTTPClient(nil, p, theauth.WithDPoPAccessToken("AT"))
	resp, err := hc.Get(ts.URL + "/r")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls != 2 || resp.StatusCode != 401 {
		t.Fatalf("calls=%d status=%d", calls, resp.StatusCode)
	}
}
