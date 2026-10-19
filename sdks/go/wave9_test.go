package theauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

// w9reply is a canned answer, with headers.
type w9reply struct {
	status  int
	body    interface{}
	headers map[string]string
}

type w9call struct {
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   string
}

type w9server struct {
	mu    sync.Mutex
	calls []w9call
}

func serve(t *testing.T, routes map[string]w9reply) (*httptest.Server, *w9server) {
	t.Helper()
	rec := &w9server{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.calls = append(rec.calls, w9call{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Clone(), string(b)})
		rec.mu.Unlock()
		rp, ok := routes[r.Method+" "+r.URL.EscapedPath()]
		if !ok {
			writeJSON(w, 404, map[string]interface{}{"error": map[string]string{"code": "NOT_FOUND", "message": "no route"}})
			return
		}
		for k, v := range rp.headers {
			w.Header().Set(k, v)
		}
		if rp.body == nil {
			w.WriteHeader(rp.status)
			return
		}
		writeJSON(w, rp.status, rp.body)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func (s *w9server) last(t *testing.T) w9call {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("no request reached the server")
	}
	return s.calls[len(s.calls)-1]
}

func (s *w9server) body(t *testing.T) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s.last(t).Body), &m); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, s.last(t).Body)
	}
	return m
}

const stepUpHeader = `Bearer error="insufficient_user_authentication", error_description="A stronger authentication is required", ` +
	`acr_values="urn:theauth:acr:mfa urn:theauth:acr:phishing-resistant", max_age="300", ` +
	`resource_metadata="https://api.example.org/.well-known/oauth-protected-resource"`

func TestParseStepUpChallenge(t *testing.T) {
	c := theauth.ParseStepUpChallenge(stepUpHeader)
	if c == nil || c.Scheme != "Bearer" || c.MaxAge == nil || *c.MaxAge != 300 {
		t.Fatalf("unexpected challenge %+v", c)
	}
	if !reflect.DeepEqual(c.ACRValues, []string{theauth.ACRMFA, theauth.ACRPhishingResistant}) {
		t.Fatalf("acr values %v", c.ACRValues)
	}
	if c.ErrorDescription != "A stronger authentication is required" || c.ResourceMetadata == "" {
		t.Fatalf("unexpected fields %+v", c)
	}
	want := map[string]string{"acr_values": "urn:theauth:acr:mfa urn:theauth:acr:phishing-resistant", "max_age": "300"}
	if got := c.AuthorizeParams(); !reflect.DeepEqual(got, want) {
		t.Fatalf("params %v", got)
	}
}

func TestParseStepUpChallenge_Edges(t *testing.T) {
	multi := theauth.ParseStepUpChallenge(`Basic realm="x", DPoP error="insufficient_user_authentication", max_age=60`)
	if multi == nil || multi.Scheme != "DPoP" || multi.MaxAge == nil || *multi.MaxAge != 60 || len(multi.ACRValues) != 0 {
		t.Fatalf("multi %+v", multi)
	}
	// Several header lines.
	if c := theauth.ParseStepUpChallenge(`Basic realm="x"`, stepUpHeader); c == nil {
		t.Fatal("second header line was not searched")
	}
	for _, h := range []string{"", "Bearer", `Bearer error="invalid_token"`} {
		if c := theauth.ParseStepUpChallenge(h); c != nil {
			t.Fatalf("%q must not be a step-up challenge", h)
		}
	}
	for _, raw := range []string{"-5", "1.5", "abc", "", "99999999999999999999999"} {
		c := theauth.ParseStepUpChallenge(`Bearer error="insufficient_user_authentication", max_age="` + raw + `"`)
		if c == nil || c.MaxAge != nil {
			t.Fatalf("max_age %q must be dropped, got %+v", raw, c)
		}
	}
	q := theauth.ParseStepUpChallenge(`Bearer error_description="a, b \"c\"", error="insufficient_user_authentication"`)
	if q == nil || q.ErrorDescription != `a, b "c"` {
		t.Fatalf("quoted value %+v", q)
	}
	ci := theauth.ParseStepUpChallenge(`Bearer Error="insufficient_user_authentication", MAX_AGE="0"`)
	if ci == nil || ci.MaxAge == nil || *ci.MaxAge != 0 {
		t.Fatalf("case insensitive names %+v", ci)
	}
}

func TestStepUpParamsValidate(t *testing.T) {
	p, err := theauth.StepUpParams([]string{"a", "b"}, ptr(0))
	if err != nil || p["acr_values"] != "a b" || p["max_age"] != "0" {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := theauth.StepUpParams(nil, ptr(-1)); err == nil {
		t.Fatal("negative max_age must fail")
	}
	for _, bad := range []string{"", "has space", "tab\t"} {
		if _, err := theauth.StepUpParams([]string{bad}, nil); err == nil {
			t.Fatalf("acr value %q must fail", bad)
		}
	}
}

func TestACRSatisfiesAndFreshness(t *testing.T) {
	if !theauth.ACRSatisfies(theauth.ACRPhishingResistant, theauth.ACRMFA) || !theauth.ACRSatisfies(theauth.ACRMFA, theauth.ACRMFA) {
		t.Fatal("stronger or equal must satisfy")
	}
	if theauth.ACRSatisfies(theauth.ACRMFA, theauth.ACRPhishingResistant) {
		t.Fatal("weaker must not satisfy")
	}
	if !theauth.ACRSatisfies(theauth.ACRMFA, theauth.ACRPhishingResistant, theauth.ACRMFA) {
		t.Fatal("any one of the wanted classes is enough")
	}
	if theauth.ACRSatisfies("", theauth.ACRMFA) || theauth.ACRSatisfies("urn:other:strong", theauth.ACRMFA) || theauth.ACRSatisfies(theauth.ACRPhishingResistant, "urn:other:strong") {
		t.Fatal("unknown classes never satisfy")
	}
	now := time.Unix(1300, 0)
	if !theauth.AuthIsFresh(1000, 300*time.Second, now, 0) || theauth.AuthIsFresh(1000, 299*time.Second, now, 0) {
		t.Fatal("age boundary")
	}
	if theauth.AuthIsFresh(0, time.Hour, now, 0) {
		t.Fatal("a missing auth_time is never fresh")
	}
	if theauth.AuthIsFresh(2000, time.Hour, now, 0) || !theauth.AuthIsFresh(1305, time.Hour, now, 10*time.Second) {
		t.Fatal("future auth_time handling")
	}
}

func TestStepUpRequiredError(t *testing.T) {
	srv, _ := serve(t, map[string]w9reply{
		"POST /approvals/a1/approve": {401, map[string]interface{}{"error": map[string]string{"code": "STEP_UP_REQUIRED", "message": "stronger sign-in"}},
			map[string]string{"WWW-Authenticate": stepUpHeader}},
		"POST /approvals/a2/approve": {401, map[string]interface{}{"error": map[string]string{"code": "STEP_UP_REQUIRED", "message": "again"}}, nil},
		"POST /approvals/a3/approve": {401, map[string]interface{}{"error": "insufficient_user_authentication", "error_description": "older than max_age"},
			map[string]string{"WWW-Authenticate": stepUpHeader}},
		"POST /approvals/a4/approve": {401, map[string]interface{}{"error": map[string]string{"code": "UNAUTHORIZED", "message": "no"}},
			map[string]string{"WWW-Authenticate": `Bearer error="invalid_token"`}},
	})
	c := theauth.NewClient(srv.URL)
	ctx := context.Background()

	_, err := c.Approvals.Approve(ctx, "a1")
	su, ok := err.(*theauth.ErrStepUpRequired)
	if !ok || su.Challenge == nil || su.Challenge.MaxAge == nil || *su.Challenge.MaxAge != 300 || su.StatusCode != 401 || su.Code != "STEP_UP_REQUIRED" {
		t.Fatalf("expected ErrStepUpRequired with a challenge, got %T %+v", err, err)
	}
	if !theauth.IsStepUpRequired(err) || !theauth.IsAuthentication(err) {
		t.Fatal("step-up must also read as an authentication error")
	}

	_, err = c.Approvals.Approve(ctx, "a2")
	if su, ok := err.(*theauth.ErrStepUpRequired); !ok || su.Challenge != nil {
		t.Fatalf("code without a header must give a nil challenge, got %T %+v", err, err)
	}

	_, err = c.Approvals.Approve(ctx, "a3")
	su, ok = err.(*theauth.ErrStepUpRequired)
	if !ok || su.Code != theauth.InsufficientUserAuthentication || su.Message != "older than max_age" {
		t.Fatalf("OAuth style string error, got %T %+v", err, err)
	}

	_, err = c.Approvals.Approve(ctx, "a4")
	if _, ok := err.(*theauth.ErrAuthentication); !ok || theauth.IsStepUpRequired(err) {
		t.Fatalf("a plain 401 must stay ErrAuthentication, got %T", err)
	}
}

func agentWire(cnf interface{}) map[string]interface{} {
	return map[string]interface{}{
		"id": "a1", "ownerId": "u1", "name": "bot", "type": "autonomous", "token": "ta_x",
		"permissions": []interface{}{}, "status": "active", "expiresAt": nil, "cnf": cnf,
		"createdAt": "2030-01-01T00:00:00.000Z", "updatedAt": "2030-01-01T00:00:00.000Z",
	}
}

func TestCreateAgentSendsCnfAndReadsItBack(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /agents": {201, data(agentWire(map[string]string{"jkt": strings.Repeat("A", 43)})), nil},
	})
	prover, err := theauth.NewDPoPProver()
	if err != nil {
		t.Fatal(err)
	}
	c := theauth.NewClient(srv.URL)
	agent, err := c.Agents.Create(context.Background(), theauth.CreateAgentInput{
		OwnerID: "u1", Name: "bot", Type: theauth.AgentTypeAutonomous,
		Permissions: []theauth.Permission{{Resource: "db:*", Actions: []string{"read"}}},
		Cnf:         theauth.DPoPConfirmation(prover),
	})
	if err != nil {
		t.Fatal(err)
	}
	cnf, _ := rec.body(t)["cnf"].(map[string]interface{})
	if cnf["jkt"] != prover.Thumbprint() || len(cnf) != 1 {
		t.Fatalf("sent cnf %v", cnf)
	}
	if agent.Cnf["jkt"] != strings.Repeat("A", 43) {
		t.Fatalf("read cnf %v", agent.Cnf)
	}
}

func TestCreateAgentWithoutCnfSendsNone(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{"POST /agents": {201, data(agentWire(nil)), nil}})
	c := theauth.NewClient(srv.URL)
	agent, err := c.Agents.Create(context.Background(), theauth.CreateAgentInput{OwnerID: "u1", Name: "bot", Type: theauth.AgentTypeAutonomous})
	if err != nil {
		t.Fatal(err)
	}
	if _, has := rec.body(t)["cnf"]; has || agent.Cnf != nil {
		t.Fatalf("cnf must be absent both ways: %v %v", rec.body(t), agent.Cnf)
	}
}

func TestRotateWith(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{"POST /agents/a1/rotate": {200, data(agentWire(nil)), nil}})
	c := theauth.NewClient(srv.URL)
	ctx := context.Background()
	if _, err := c.Agents.Rotate(ctx, "a1"); err != nil || rec.last(t).Body != "" {
		t.Fatalf("plain rotate sends no body: %q %v", rec.last(t).Body, err)
	}
	if _, err := c.Agents.RotateWith(ctx, "a1", theauth.RotateOptions{}); err != nil || rec.last(t).Body != "" {
		t.Fatalf("zero options keep the binding and send no body: %q %v", rec.last(t).Body, err)
	}
	b := strings.Repeat("B", 43)
	if _, err := c.Agents.RotateWith(ctx, "a1", theauth.RotateOptions{Confirmation: map[string]string{"jkt": b}}); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t).Body; got != `{"cnf":{"jkt":"`+b+`"}}` {
		t.Fatalf("rebind body %s", got)
	}
	if _, err := c.Agents.RotateWith(ctx, "a1", theauth.RotateOptions{Unbind: true}); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t).Body; got != `{"cnf":null}` {
		t.Fatalf("unbind body %s", got)
	}
	if _, err := c.Agents.RotateWith(ctx, "a1", theauth.RotateOptions{Unbind: true, Confirmation: map[string]string{"jkt": b}}); err == nil {
		t.Fatal("unbind together with a confirmation must fail")
	}
}

func TestConfirmationHelpers(t *testing.T) {
	prover, _ := theauth.NewDPoPProver()
	j := prover.PublicJWK()
	canonical := `{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `","y":"` + j.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	if got := theauth.DPoPConfirmation(prover)["jkt"]; got != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("jkt %s is not the RFC 7638 thumbprint", got)
	}
	der := []byte("not a real certificate, only bytes")
	dsum := sha256.Sum256(der)
	if got := theauth.MTLSConfirmation(der)["x5t#S256"]; got != base64.RawURLEncoding.EncodeToString(dsum[:]) {
		t.Fatalf("x5t#S256 %s", got)
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 44), strings.Repeat("A", 42) + "="} {
		if _, err := theauth.JKTConfirmation(bad); err == nil {
			t.Fatalf("jkt %q must fail", bad)
		}
		if _, err := theauth.X5tConfirmation(bad); err == nil {
			t.Fatalf("x5t %q must fail", bad)
		}
	}
	if m, err := theauth.JKTConfirmation(strings.Repeat("A", 43)); err != nil || m["jkt"] == "" {
		t.Fatal("a valid thumbprint passes")
	}
}

func TestAuthorizeSendsInputs(t *testing.T) {
	srv, rec := serve(t, map[string]w9reply{
		"POST /authorize": {200, data(map[string]interface{}{"allowed": true, "auditId": "au1", "code": "allowed"}), nil},
	})
	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.Authorize(context.Background(), "a1", theauth.AuthorizeRequest{
		Action: "execute", Resource: "mcp:x:y",
		Inputs: []theauth.ProvenanceInput{
			{Kind: theauth.ProvenanceUserMessage, ID: "m1", Content: "hello"},
			{Kind: theauth.ProvenanceToolOutput, Hash: strings.Repeat("a", 64), HashVersion: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []interface{}{
		map[string]interface{}{"kind": "user_message", "id": "m1", "content": "hello"},
		map[string]interface{}{"kind": "tool_output", "hash": strings.Repeat("a", 64), "hashVersion": float64(2)},
	}
	if got := rec.body(t)["inputs"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("inputs %v", got)
	}
	_, _ = c.Agents.Authorize(context.Background(), "a1", theauth.AuthorizeRequest{Action: "read", Resource: "x"})
	if _, has := rec.body(t)["inputs"]; has {
		t.Fatal("no inputs means no key")
	}
}

func TestEncodeInputsHeader(t *testing.T) {
	v, err := theauth.EncodeInputsHeader([]theauth.ProvenanceInput{{Kind: theauth.ProvenanceRetrievedDocument, ID: "https://e.org/ü"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(v, "=+/") {
		t.Fatalf("not base64url without padding: %s", v)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || string(raw) != `[{"kind":"retrieved_document","id":"https://e.org/ü"}]` {
		t.Fatalf("decoded %q %v", raw, err)
	}
	if _, err := theauth.EncodeInputsHeader(make([]theauth.ProvenanceInput, 33)); err == nil {
		t.Fatal("33 inputs must fail")
	}
	if _, err := theauth.EncodeInputsHeader(make([]theauth.ProvenanceInput, 32)); err != nil {
		t.Fatalf("32 inputs fit: %v", err)
	}
	if _, err := theauth.EncodeInputsHeader([]theauth.ProvenanceInput{{Kind: theauth.ProvenanceUserMessage, Content: strings.Repeat("x", 7000)}}); err == nil {
		t.Fatal("an oversize header must fail")
	}
}

func TestDecisionCodesMatchOpenAPI(t *testing.T) {
	raw, err := os.ReadFile("../openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Enum []string `json:"enum"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, c := range []theauth.DecisionCode{
		theauth.DecisionAllowed, theauth.DecisionApprovalConsumed, theauth.DecisionNoPermission, theauth.DecisionRateLimited,
		theauth.DecisionIPNotAllowed, theauth.DecisionTimeRestricted, theauth.DecisionArgumentRejected, theauth.DecisionApprovalRequired,
		theauth.DecisionApprovalInvalid, theauth.DecisionApprovalNotFound, theauth.DecisionApprovalPending, theauth.DecisionApprovalDenied,
		theauth.DecisionApprovalExpired, theauth.DecisionApprovalAlreadyUsed, theauth.DecisionApprovalMismatch,
		theauth.DecisionApprovalArgumentsMismatch, theauth.DecisionApprovalStepUpInsufficient, theauth.DecisionApprovalGranted,
		theauth.DecisionAgentNotFound, theauth.DecisionAgentRevoked, theauth.DecisionAgentExpired, theauth.DecisionInvalidToken,
		theauth.DecisionConfirmationRequired, theauth.DecisionConfirmationFailed, theauth.DecisionDeviceNotFound,
		theauth.DecisionDeviceSuspended, theauth.DecisionDeviceRevoked, theauth.DecisionDeviceExpired, theauth.DecisionOwnerMismatch,
		theauth.DecisionHookDenied, theauth.DecisionHookTimeout, theauth.DecisionHookError, theauth.DecisionTaintViolation,
		theauth.DecisionRiskEscalation, theauth.DecisionPolicyIndeterminate,
	} {
		have[string(c)] = true
	}
	server := doc.Components.Schemas["DecisionCode"].Enum
	if len(server) == 0 {
		t.Fatal("DecisionCode enum missing from openapi.json")
	}
	for _, c := range server {
		if !have[c] {
			t.Errorf("server code %q has no constant", c)
		}
		delete(have, c)
	}
	for c := range have {
		t.Errorf("constant %q is not a server code", c)
	}
}
