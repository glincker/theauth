package theauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

var deviceWire = map[string]interface{}{
	"id": "dev_1", "agentId": "agt_1", "ownerId": "user_1", "name": "Pump 4", "kind": "sensor", "hardwareId": "hw-77",
	"status": "active", "groups": []string{"plant-a"},
	"permissions": []map[string]interface{}{{"resource": "mqtt:plant/a/#", "actions": []string{"publish"}}},
	"metadata":    map[string]interface{}{}, "expiresAt": nil, "lastSeenAt": nil,
	"createdAt": "2030-01-01T00:00:00.000Z", "updatedAt": "2030-01-01T00:00:00.000Z",
}

var credWire = map[string]interface{}{
	"id": "cred_1", "deviceId": "dev_1", "kind": "psk", "lookup": "abc", "status": "active",
	"expiresAt": nil, "lastUsedAt": nil, "createdAt": "2030-01-01T00:00:00.000Z",
}

func withSecret(secret string) map[string]interface{} {
	m := map[string]interface{}{"secret": secret}
	for k, v := range credWire {
		m[k] = v
	}
	return m
}

func TestDevices_RegisterAndEnroll(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /devices":       {201, data(map[string]interface{}{"device": deviceWire, "credential": withSecret("tdk_abc")}), nil},
		"POST /device/enroll": {201, data(map[string]interface{}{"device": deviceWire}), nil},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin-token"))
	ctx := context.Background()
	reg, err := c.Devices.Register(ctx, theauth.RegisterDeviceInput{
		OwnerID: "user_1", Name: "Pump 4", Kind: "sensor", HardwareID: "hw-77", Groups: []string{"plant-a"},
		Permissions: []theauth.Permission{{Resource: "mqtt:plant/a/#", Actions: []string{"publish"}}},
		Credential:  ptr(theauth.PSKCredential()),
	})
	if err != nil {
		t.Fatal(err)
	}
	sent := rec.body(t)
	cred, _ := sent["credential"].(map[string]interface{})
	if len(cred) != 1 || cred["kind"] != "psk" || sent["hardwareId"] != "hw-77" {
		t.Fatalf("sent %v", sent)
	}
	if reg.Device.AgentID != "agt_1" || reg.Device.Permissions[0].Resource != "mqtt:plant/a/#" || reg.Credential == nil || reg.Credential.Secret != "tdk_abc" {
		t.Fatalf("decoded %+v", reg)
	}

	enrolled, err := c.Device.Enroll(ctx, theauth.EnrollDeviceInput{
		Token: "ABCDE-FGHJK", Name: "Pump 4", Credential: theauth.PSKCredential(), HardwareID: "hw-77", Evidence: "ev", Nonce: "n1",
	})
	if err != nil || enrolled.Credential != nil || enrolled.Device.ID != "dev_1" {
		t.Fatalf("%+v %v", enrolled, err)
	}
	b, _ := json.Marshal(rec.body(t))
	if string(b) != `{"credential":{"kind":"psk"},"evidence":"ev","hardwareId":"hw-77","name":"Pump 4","nonce":"n1","token":"ABCDE-FGHJK"}` {
		t.Fatalf("enroll body %s", b)
	}
}

func TestDevices_Lifecycle(t *testing.T) {
	suspended := map[string]interface{}{"status": "suspended"}
	for k, v := range deviceWire {
		if k != "status" {
			suspended[k] = v
		}
	}
	srv, rec := serve(t, map[string]w9reply{
		"GET /devices":                {200, data([]interface{}{deviceWire}), nil},
		"GET /devices/dev_1":          {200, data(deviceWire), nil},
		"GET /devices/nope":           {404, map[string]interface{}{"error": map[string]string{"code": "NOT_FOUND", "message": "no"}}, nil},
		"PATCH /devices/dev_1":        {200, data(deviceWire), nil},
		"POST /devices/dev_1/suspend": {200, data(suspended), nil},
		"POST /devices/dev_1/resume":  {200, data(deviceWire), nil},
		"DELETE /devices/dev_1":       {200, data(map[string]interface{}{"revokedDelegations": []string{"d1", "d2"}}), nil},
		"GET /devices/a%2Fb%3Fc":      {200, data(deviceWire), nil},
	})
	c := theauth.NewClient(srv.URL)
	ctx := context.Background()

	list, err := c.Devices.List(ctx, &theauth.DeviceFilters{OwnerID: "user_1", Status: theauth.DeviceActive, Limit: ptr(10)})
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	if q := rec.last(t).RawQuery; q != "limit=10&ownerId=user_1&status=active" {
		t.Fatalf("query %s", q)
	}
	if d, err := c.Devices.Get(ctx, "dev_1"); err != nil || d == nil {
		t.Fatalf("%v %v", d, err)
	}
	if d, err := c.Devices.Get(ctx, "nope"); err != nil || d != nil {
		t.Fatalf("a missing device is nil, nil: %v %v", d, err)
	}
	if _, err := c.Devices.Get(ctx, "a/b?c"); err != nil {
		t.Fatalf("path escaping: %v", err)
	}
	if _, err := c.Devices.Update(ctx, "dev_1", theauth.UpdateDeviceInput{Name: ptr("Pump 5"), Groups: []string{"b"}}); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t).Body; got != `{"name":"Pump 5","groups":["b"]}` {
		t.Fatalf("patch body %s", got)
	}
	d, err := c.Devices.Suspend(ctx, "dev_1", "stolen")
	if err != nil || d.Status != theauth.DeviceSuspended || rec.last(t).Body != `{"reason":"stolen"}` {
		t.Fatalf("%+v %v %s", d, err, rec.last(t).Body)
	}
	if _, err := c.Devices.Suspend(ctx, "dev_1", ""); err != nil || rec.last(t).Body != "" {
		t.Fatalf("no reason sends no body: %q %v", rec.last(t).Body, err)
	}
	if d, err := c.Devices.Resume(ctx, "dev_1"); err != nil || d.Status != theauth.DeviceActive {
		t.Fatalf("%+v %v", d, err)
	}
	ids, err := c.Devices.Revoke(ctx, "dev_1")
	if err != nil || !reflect.DeepEqual(ids, []string{"d1", "d2"}) {
		t.Fatalf("%v %v", ids, err)
	}
}

func TestDevices_CredentialsBundleStatsAndTokens(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /devices/dev_1/credentials":          {201, data(map[string]interface{}{"id": "cred_2", "deviceId": "dev_1", "kind": "x509", "lookup": "t", "status": "active", "expiresAt": nil, "lastUsedAt": nil, "createdAt": "x"}), nil},
		"DELETE /devices/dev_1/credentials/cred_1": {204, nil, nil},
		"POST /devices/dev_1/bundle":               {200, data(map[string]interface{}{"token": "a.b.c", "claims": map[string]interface{}{"exp": 1}}), nil},
		"GET /devices/stats":                       {200, data(map[string]interface{}{"total": 5, "active": 3, "suspended": 1, "revoked": 1, "seenLastHour": 2, "seenLastDay": 3, "neverSeen": 1}), nil},
		"POST /devices/enrollment-tokens":          {201, data(map[string]interface{}{"id": "e1", "kind": "bulk", "token": "tde_x", "ownerId": "user_1", "maxUses": 50, "expiresAt": "2030-01-02T00:00:00.000Z"}), nil},
		"DELETE /devices/enrollment-tokens/e1":     {204, nil, nil},
	})
	c := theauth.NewClient(srv.URL)
	ctx := context.Background()

	cred, err := c.Devices.AddCredential(ctx, "dev_1", theauth.X509Credential(strings.Repeat("T", 43)))
	if err != nil || cred.Kind != theauth.DeviceCredentialX509 || rec.last(t).Body != `{"kind":"x509","thumbprint":"`+strings.Repeat("T", 43)+`"}` {
		t.Fatalf("%+v %v %s", cred, err, rec.last(t).Body)
	}
	if err := c.Devices.RevokeCredential(ctx, "dev_1", "cred_1"); err != nil {
		t.Fatal(err)
	}
	bundle, err := c.Devices.IssueBundle(ctx, "dev_1", ptr(600))
	if err != nil || bundle.Token != "a.b.c" || rec.last(t).Body != `{"ttlSeconds":600}` {
		t.Fatalf("%+v %v %s", bundle, err, rec.last(t).Body)
	}
	st, err := c.Devices.Stats(ctx, "user_1")
	if err != nil || st.Total != 5 || st.SeenLastHour != 2 || st.NeverSeen != 1 || rec.last(t).RawQuery != "ownerId=user_1" {
		t.Fatalf("%+v %v %s", st, err, rec.last(t).RawQuery)
	}
	tok, err := c.Devices.CreateEnrollmentToken(ctx, theauth.EnrollmentTokenInput{
		OwnerID: "user_1", Kind: theauth.EnrollmentBulk, MaxUses: ptr(50), TTLSeconds: ptr(3600), Groups: []string{"g"},
	})
	if err != nil || tok.Token != "tde_x" || tok.MaxUses != 50 {
		t.Fatalf("%+v %v", tok, err)
	}
	if got := rec.last(t).Body; got != `{"ownerId":"user_1","kind":"bulk","maxUses":50,"ttlSeconds":3600,"groups":["g"]}` {
		t.Fatalf("token body %s", got)
	}
	if err := c.Devices.RevokeEnrollmentToken(ctx, "e1"); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceAPI_AuthorizeUsesTheDeviceCredential(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /device/authorize": {403, data(map[string]interface{}{"allowed": false, "auditId": "au1", "code": "device_suspended"}), nil},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin-token"))
	res, err := c.Device.Authorize(context.Background(), theauth.DevicePSK("tdk_secret"), theauth.AuthorizeRequest{
		Action: "publish", Resource: "mqtt:plant/a/t1", Inputs: []theauth.ProvenanceInput{{Kind: theauth.ProvenanceAgent}},
	})
	if err != nil || res.Allowed || res.Code != theauth.DecisionDeviceSuspended {
		t.Fatalf("%+v %v", res, err)
	}
	if got := rec.last(t).Header.Get("Authorization"); got != "Bearer tdk_secret" {
		t.Fatalf("the device credential must replace the client token, got %q", got)
	}
	if _, has := rec.body(t)["agentId"]; has {
		t.Fatal("a device never sends an agentId")
	}
}

func TestDeviceAPI_BadCredentialIsA401Result(t *testing.T) {
	srv, _ := serve(t, map[string]w9reply{
		"POST /device/authorize": {401, data(map[string]interface{}{"allowed": false, "auditId": "", "code": "invalid_token"}), nil},
	})
	c := theauth.NewClient(srv.URL)
	res, err := c.Device.Authorize(context.Background(), theauth.DevicePSK("tdk_bad"), theauth.AuthorizeRequest{Action: "a", Resource: "b"})
	if err != nil || res.Allowed {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestDeviceAPI_EmptyCredentialsFailBeforeTheRequest(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{})
	c := theauth.NewClient(srv.URL)
	if _, err := c.Device.Bundle(context.Background(), theauth.DevicePSK("")); err == nil {
		t.Fatal("empty credential must fail")
	}
	if _, err := c.Device.Bundle(context.Background(), nil); err == nil {
		t.Fatal("nil credential must fail")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 0 {
		t.Fatalf("no request expected, got %d", len(rec.calls))
	}
}

func TestDeviceAPI_NonceBundleJWKS(t *testing.T) {
	srv, _ := serve(t, map[string]w9reply{
		"POST /device/attestation-nonce": {200, data(map[string]interface{}{"nonce": "n1", "expiresAt": "2030-01-01T00:05:00.000Z"}), nil},
		"GET /device/bundle":             {200, data(map[string]interface{}{"token": "h.p.s", "claims": map[string]interface{}{}}), nil},
		"GET /device/jwks":               {200, map[string]interface{}{"keys": []map[string]string{{"kty": "EC"}}}, nil},
	})
	c := theauth.NewClient(srv.URL)
	ctx := context.Background()
	n, err := c.Device.AttestationNonce(ctx)
	if err != nil || n.Nonce != "n1" {
		t.Fatalf("%+v %v", n, err)
	}
	b, err := c.Device.Bundle(ctx, theauth.DeviceToken("a.b.c"))
	if err != nil || b.Token != "h.p.s" {
		t.Fatalf("%+v %v", b, err)
	}
	raw, err := c.Device.JWKS(ctx)
	if err != nil || string(raw) != `{"keys":[{"kty":"EC"}]}` && !strings.Contains(string(raw), `"keys"`) {
		t.Fatalf("%s %v", raw, err)
	}
}

func decodeJWT(t *testing.T, jwt string) (header, payload map[string]interface{}, signingInput string, sig []byte) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %s", jwt)
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
	return header, payload, parts[0] + "." + parts[1], dec(parts[2])
}

func TestDeviceAssertion_LayoutAndSignature(t *testing.T) {
	signer, err := theauth.NewDeviceAssertionSigner("dev_1", theauth.WithDeviceClock(func() time.Time { return time.Unix(1_800_000_000, 900_000_000) }))
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := signer.Sign()
	if err != nil {
		t.Fatal(err)
	}
	header, payload, input, sig := decodeJWT(t, jwt)
	if header["alg"] != "ES256" || header["typ"] != "device-assertion+jwt" || header["kid"] != signer.KeyID() || len(header) != 3 {
		t.Fatalf("header %v", header)
	}
	if payload["iss"] != "dev_1" || payload["sub"] != "dev_1" || payload["aud"] != "theauth" {
		t.Fatalf("payload %v", payload)
	}
	if payload["iat"].(float64) != 1_800_000_000 || payload["exp"].(float64) != 1_800_000_060 {
		t.Fatalf("times %v", payload)
	}
	if jti, _ := payload["jti"].(string); len(jti) < 16 || len(jti) > 256 {
		t.Fatalf("jti %q", jti)
	}

	jwk := signer.PublicJWK()
	xb, _ := base64.RawURLEncoding.DecodeString(jwk["x"])
	yb, _ := base64.RawURLEncoding.DecodeString(jwk["y"])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	digest := sha256.Sum256([]byte(input))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify with the public JWK")
	}
	canonical := `{"crv":"P-256","kty":"EC","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `"}`
	sum := sha256.Sum256([]byte(canonical))
	if signer.KeyID() != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("kid is not the RFC 7638 thumbprint")
	}
}

func TestDeviceAssertion_FreshJTIsAndBounds(t *testing.T) {
	signer, _ := theauth.NewDeviceAssertionSigner("dev_1")
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		jwt, _ := signer.Sign()
		_, p, _, _ := decodeJWT(t, jwt)
		seen[p["jti"].(string)] = true
	}
	if len(seen) != 50 {
		t.Fatalf("jti reused: %d unique of 50", len(seen))
	}
	custom, err := theauth.NewDeviceAssertionSigner("dev_1", theauth.WithDeviceAudience("fleet"), theauth.WithDeviceLifetime(300*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	jwt, _ := custom.Sign()
	_, p, _, _ := decodeJWT(t, jwt)
	if p["aud"] != "fleet" || p["exp"].(float64)-p["iat"].(float64) != 300 {
		t.Fatalf("%v", p)
	}
	for _, bad := range []time.Duration{0, 500 * time.Millisecond, 301 * time.Second, -time.Second} {
		if _, err := theauth.NewDeviceAssertionSigner("dev_1", theauth.WithDeviceLifetime(bad)); err == nil {
			t.Fatalf("lifetime %v must fail", bad)
		}
	}
	unbound, err := theauth.NewDeviceAssertionSigner("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unbound.Sign(); err == nil {
		t.Fatal("an unbound signer must not sign")
	}
	if err := unbound.Bind(""); err == nil {
		t.Fatal("binding an empty id must fail")
	}
	jwkBefore := unbound.PublicJWK()
	if err := unbound.Bind("dev_9"); err != nil {
		t.Fatal(err)
	}
	signed, err := unbound.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if _, p, _, _ := decodeJWT(t, signed); p["iss"] != "dev_9" || unbound.PublicJWK()["x"] != jwkBefore["x"] {
		t.Fatalf("bind must set iss and keep the key: %v", p)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), strings.NewReader(strings.Repeat("k", 4096)))
	if p384 != nil {
		if _, err := theauth.NewDeviceAssertionSigner("dev_1", theauth.WithDeviceKey(p384)); err == nil {
			t.Fatal("a P-384 key must be refused")
		}
	}
}

func TestDeviceAssertion_SignerAsCredentialAndPrivateJWKRefused(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /device/authorize": {200, data(map[string]interface{}{"allowed": true, "auditId": "au1", "code": "allowed"}), nil},
	})
	signer, _ := theauth.NewDeviceAssertionSigner("dev_1")
	c := theauth.NewClient(srv.URL)
	ctx := context.Background()
	_, _ = c.Device.Authorize(ctx, signer, theauth.AuthorizeRequest{Action: "read", Resource: "x"})
	first := rec.last(t).Header.Get("Authorization")
	_, _ = c.Device.Authorize(ctx, signer, theauth.AuthorizeRequest{Action: "read", Resource: "x"})
	second := rec.last(t).Header.Get("Authorization")
	if !strings.HasPrefix(first, "Bearer ") || first == second {
		t.Fatal("every call needs a new assertion")
	}

	if _, err := theauth.JWKCredential(map[string]string{"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "secret"}); err == nil {
		t.Fatal("a private JWK must be refused")
	}
	spec, err := theauth.JWKCredential(signer.PublicJWK())
	if err != nil || spec.Kind != theauth.DeviceCredentialJWK || spec.JWK["x"] != signer.PublicJWK()["x"] {
		t.Fatalf("%+v %v", spec, err)
	}
	if _, has := signer.PublicJWK()["d"]; has {
		t.Fatal("the public JWK never carries d")
	}
}

// Every route the new calls use must exist in the generated OpenAPI document.
func TestWave9RoutesExistInOpenAPIDocument(t *testing.T) {
	raw, err := os.ReadFile("../openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ok := w9reply{200, map[string]interface{}{}, nil}
	routes := map[string]w9reply{}
	for _, k := range []string{
		"POST /devices", "GET /devices", "GET /devices/x", "PATCH /devices/x", "POST /devices/x/suspend", "POST /devices/x/resume",
		"DELETE /devices/x", "POST /devices/x/credentials", "DELETE /devices/x/credentials/y", "POST /devices/x/bundle",
		"GET /devices/stats", "POST /devices/enrollment-tokens", "DELETE /devices/enrollment-tokens/x",
		"POST /device/enroll", "POST /device/attestation-nonce", "POST /device/authorize", "GET /device/bundle", "GET /device/jwks",
		"POST /agents/x/rotate",
	} {
		routes[k] = ok
	}
	srv, rec := serve(t, routes)
	c := theauth.NewClient(srv.URL)
	ctx := context.Background()
	psk := theauth.DevicePSK("tdk_x")
	cred := theauth.PSKCredential()
	_, _ = c.Devices.Register(ctx, theauth.RegisterDeviceInput{})
	_, _ = c.Devices.List(ctx, nil)
	_, _ = c.Devices.Get(ctx, "x")
	_, _ = c.Devices.Update(ctx, "x", theauth.UpdateDeviceInput{})
	_, _ = c.Devices.Suspend(ctx, "x", "")
	_, _ = c.Devices.Resume(ctx, "x")
	_, _ = c.Devices.Revoke(ctx, "x")
	_, _ = c.Devices.AddCredential(ctx, "x", cred)
	_ = c.Devices.RevokeCredential(ctx, "x", "y")
	_, _ = c.Devices.IssueBundle(ctx, "x", nil)
	_, _ = c.Devices.Stats(ctx, "")
	_, _ = c.Devices.CreateEnrollmentToken(ctx, theauth.EnrollmentTokenInput{})
	_ = c.Devices.RevokeEnrollmentToken(ctx, "x")
	_, _ = c.Device.Enroll(ctx, theauth.EnrollDeviceInput{Credential: cred})
	_, _ = c.Device.AttestationNonce(ctx)
	_, _ = c.Device.Authorize(ctx, psk, theauth.AuthorizeRequest{})
	_, _ = c.Device.Bundle(ctx, psk)
	_, _ = c.Device.JWKS(ctx)
	_, _ = c.Agents.RotateWith(ctx, "x", theauth.RotateOptions{Unbind: true})

	type route struct {
		method  string
		pattern *regexp.Regexp
	}
	var table []route
	for path, methods := range doc.Paths {
		parts := strings.Split(path, "/")
		for i, p := range parts {
			if strings.HasPrefix(p, "{") {
				parts[i] = "[^/]+"
			} else {
				parts[i] = regexp.QuoteMeta(p)
			}
		}
		pattern := regexp.MustCompile("^" + strings.Join(parts, "/") + "$")
		for method := range methods {
			table = append(table, route{strings.ToUpper(method), pattern})
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != len(routes) {
		t.Fatalf("expected %d calls, got %d", len(routes), len(rec.calls))
	}
	for _, call := range rec.calls {
		found := false
		for _, r := range table {
			if r.method == call.Method && r.pattern.MatchString(call.Path) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("client calls %s %s, which openapi.json does not describe", call.Method, call.Path)
		}
	}
}

func TestIntrospectionReadsBothCnfMembers(t *testing.T) {
	var r theauth.IntrospectionResponse
	if err := json.Unmarshal([]byte(`{"active":true,"cnf":{"jkt":"J","x5t#S256":"X"}}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Cnf == nil || r.Cnf.Jkt != "J" || r.Cnf.X5tS256 != "X" {
		t.Fatalf("%+v", r.Cnf)
	}
}
