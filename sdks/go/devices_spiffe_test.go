package theauth_test

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
)

const spiffeRobot = "spiffe://example.org/ns/prod/sa/robot"

var spiffeVerified = map[string]interface{}{
	"ok": true, "code": "ok", "spiffeId": spiffeRobot,
	"svid":      map[string]interface{}{"kind": "x509", "expiresAt": "2030-01-01T00:00:00.000Z", "thumbprint": "abc"},
	"principal": map[string]interface{}{"type": "device", "id": "dev_1", "name": "Pump 4"},
}

var spiffeCred = map[string]interface{}{
	"id": "cred_1", "deviceId": "dev_1", "kind": "spiffe", "lookup": spiffeRobot, "status": "active",
	"expiresAt": nil, "lastUsedAt": nil, "createdAt": "2030-01-01T00:00:00.000Z",
}

func TestSPIFFE_VerifyAndToken(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /devices/spiffe/verify": {200, data(spiffeVerified), nil},
		"POST /devices/spiffe/token": {201, data(map[string]interface{}{
			"agentId": "agt_1", "token": "ta_x", "cnf": map[string]string{"x5t#S256": "t"},
		}), nil},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin"))
	ctx := context.Background()

	out, err := c.Devices.SPIFFEVerify(ctx, theauth.SPIFFEX509("PEM"))
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t).Body; got != `{"kind":"x509","chain":"PEM"}` {
		t.Fatalf("sent %s", got)
	}
	if !out.OK || out.SpiffeID != spiffeRobot || out.Svid == nil || out.Svid.Thumbprint != "abc" || out.Principal == nil || out.Principal.Type != "device" {
		t.Fatalf("%+v", out)
	}
	if _, err := c.Devices.SPIFFEVerify(ctx, theauth.SPIFFEJWT("a.b.c")); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t).Body; got != `{"kind":"jwt","token":"a.b.c"}` {
		t.Fatalf("sent %s", got)
	}

	tok, err := c.Devices.SPIFFEToken(ctx, "PEM")
	if err != nil {
		t.Fatal(err)
	}
	if rec.last(t).Body != `{"chain":"PEM"}` || tok.AgentID != "agt_1" || tok.Token != "ta_x" || tok.CNF["x5t#S256"] != "t" {
		t.Fatalf("%+v body %s", tok, rec.last(t).Body)
	}
}

func TestSPIFFE_FailedVerificationIsAResult(t *testing.T) {
	srv, _ := serve(t, map[string]w9reply{
		"POST /devices/spiffe/verify": {200, data(map[string]interface{}{"ok": false, "code": "unknown_workload", "reason": "none"}), nil},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin"))
	out, err := c.Devices.SPIFFEVerify(context.Background(), theauth.SPIFFEJWT("x"))
	if err != nil || out.OK || out.Code != "unknown_workload" || out.Principal != nil {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestSPIFFE_Link(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /devices/dev%2F1/spiffe": {201, data(spiffeCred), nil},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin"))
	ctx := context.Background()
	cred, err := c.Devices.LinkSPIFFEID(ctx, "dev/1", spiffeRobot)
	if err != nil {
		t.Fatal(err)
	}
	if rec.last(t).Body != `{"spiffeId":"`+spiffeRobot+`"}` || cred.Kind != theauth.DeviceCredentialSPIFFE || cred.Lookup != spiffeRobot {
		t.Fatalf("%+v body %s", cred, rec.last(t).Body)
	}
	if _, err := c.Devices.LinkSPIFFEPresentation(ctx, "dev/1", theauth.SPIFFEX509("PEM")); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t).Body; got != `{"presentation":{"kind":"x509","chain":"PEM"}}` {
		t.Fatalf("sent %s", got)
	}
	if _, err := c.Devices.LinkSPIFFEID(ctx, "dev/1", ""); err == nil {
		t.Fatal("an empty id must fail before the request")
	}
}

func TestSPIFFE_DeviceSideUsesBearerSVID(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /device/spiffe/verify": {200, data(spiffeVerified), nil},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin"))
	ctx := context.Background()
	out, err := c.Device.SPIFFEVerify(ctx, "a.b.c")
	if err != nil || !out.OK {
		t.Fatalf("%+v %v", out, err)
	}
	last := rec.last(t)
	if last.Header.Get("Authorization") != "Bearer a.b.c" || last.Body != "" {
		t.Fatalf("auth %q body %q", last.Header.Get("Authorization"), last.Body)
	}
	if _, err := c.Device.SPIFFEVerify(ctx, ""); err == nil {
		t.Fatal("an empty SVID must fail before the request")
	}
}

func TestSPIFFE_RefusedSVIDCarriesTheCode(t *testing.T) {
	srv, _ := serve(t, map[string]w9reply{
		"POST /device/spiffe/verify": {401, map[string]interface{}{"error": map[string]string{"code": "wrong_audience", "message": "audience"}}, nil},
	})
	c := theauth.NewClient(srv.URL)
	_, err := c.Device.SPIFFEVerify(context.Background(), "a.b.c")
	if !theauth.IsAuthentication(err) {
		t.Fatalf("want an authentication error, got %v", err)
	}
	if !strings.Contains(err.Error(), "wrong_audience") {
		t.Fatalf("code missing: %v", err)
	}
}

func TestSPIFFE_RoutesExistInOpenAPIDocument(t *testing.T) {
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
	srv, rec := serve(t, map[string]w9reply{
		"POST /devices/spiffe/verify": ok, "POST /devices/spiffe/token": ok,
		"POST /devices/x/spiffe": ok, "POST /device/spiffe/verify": ok,
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("t"))
	ctx := context.Background()
	_, _ = c.Devices.SPIFFEVerify(ctx, theauth.SPIFFEJWT("x"))
	_, _ = c.Devices.SPIFFEToken(ctx, "PEM")
	_, _ = c.Devices.LinkSPIFFEID(ctx, "x", spiffeRobot)
	_, _ = c.Device.SPIFFEVerify(ctx, "a.b.c")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 4 {
		t.Fatalf("expected 4 calls, got %d", len(rec.calls))
	}
	for _, call := range rec.calls {
		found := false
		for path, methods := range doc.Paths {
			parts := strings.Split(path, "/")
			for i, p := range parts {
				if strings.HasPrefix(p, "{") {
					parts[i] = "[^/]+"
				} else {
					parts[i] = regexp.QuoteMeta(p)
				}
			}
			re := regexp.MustCompile("^" + strings.Join(parts, "/") + "$")
			for m := range methods {
				if strings.ToUpper(m) == call.Method && re.MatchString(call.Path) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("client calls %s %s, which openapi.json does not describe", call.Method, call.Path)
		}
	}
}
