package theauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/glincker/theauth-go"
)

// recorder is a fake server that answers from a table and remembers each call.
type recorder struct {
	mu    sync.Mutex
	calls []recorded
}

type recorded struct {
	Method string
	Path   string
	Header http.Header
	Body   string
}

type reply struct {
	status int
	body   interface{}
}

func newRecorder(t *testing.T, routes map[string]reply) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.calls = append(rec.calls, recorded{r.Method, r.URL.Path, r.Header.Clone(), string(b)})
		rec.mu.Unlock()
		rp, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			writeJSON(w, 404, map[string]interface{}{"error": map[string]string{"code": "NOT_FOUND", "message": "no route"}})
			return
		}
		writeJSON(w, rp.status, rp.body)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func (r *recorder) last(t *testing.T) recorded {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatal("no request reached the server")
	}
	return r.calls[len(r.calls)-1]
}

func data(v interface{}) map[string]interface{} { return map[string]interface{}{"data": v} }

func TestAuthorize_CarriesCodeAndSendsAgentIDAndApprovalID(t *testing.T) {
	srv, rec := newRecorder(t, map[string]reply{
		"POST /authorize": {200, data(map[string]interface{}{"allowed": true, "auditId": "aud_1", "code": "approval_consumed"})},
	})
	c := theauth.NewClient(srv.URL)
	res, err := c.Agents.Authorize(context.Background(), "agent-1", theauth.AuthorizeRequest{
		Action: "write", Resource: "db:orders", ApprovalID: "apr_9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed || res.Code != theauth.DecisionApprovalConsumed || !res.Code.Allowed() {
		t.Fatalf("unexpected result %+v", res)
	}
	var body map[string]interface{}
	_ = json.Unmarshal([]byte(rec.last(t).Body), &body)
	if body["agentId"] != "agent-1" || body["approvalId"] != "apr_9" || body["action"] != "write" {
		t.Fatalf("unexpected body %v", body)
	}
}

func TestAuthorize_DenialIsAResultNotAnError(t *testing.T) {
	srv, _ := newRecorder(t, map[string]reply{
		"POST /authorize": {403, data(map[string]interface{}{
			"allowed": false, "auditId": "aud_2", "code": "approval_required", "reason": "needs a human",
		})},
	})
	c := theauth.NewClient(srv.URL)
	res, err := c.Agents.Authorize(context.Background(), "agent-1", theauth.AuthorizeRequest{Action: "write", Resource: "db:orders"})
	if err != nil {
		t.Fatalf("a denial must not be an error: %v", err)
	}
	if res.Allowed || res.Code != theauth.DecisionApprovalRequired || res.Reason == nil || *res.Reason != "needs a human" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestAuthorize_ScopeRefusalStaysAnError(t *testing.T) {
	srv, _ := newRecorder(t, map[string]reply{
		"POST /authorize": {403, map[string]interface{}{"error": map[string]string{"code": "FORBIDDEN", "message": "not your agent"}}},
	})
	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.Authorize(context.Background(), "agent-1", theauth.AuthorizeRequest{Action: "read", Resource: "x"})
	if _, ok := err.(*theauth.ErrPermission); !ok {
		t.Fatalf("expected ErrPermission, got %T %v", err, err)
	}
}

func TestAuthorizeByToken_InvalidTokenIs401Result(t *testing.T) {
	srv, rec := newRecorder(t, map[string]reply{
		"POST /authorize/token": {401, data(map[string]interface{}{"allowed": false, "auditId": "aud_3", "code": "invalid_token"})},
	})
	c := theauth.NewClient(srv.URL)
	res, err := c.Auth.AuthorizeByToken(context.Background(), "ta_bad", theauth.AuthorizeRequest{Action: "read", Resource: "x"})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if res.Allowed || res.Code != theauth.DecisionInvalidToken {
		t.Fatalf("unexpected result %+v", res)
	}
	if got := rec.last(t).Header.Get("Authorization"); got != "Bearer ta_bad" {
		t.Fatalf("authorization header %q", got)
	}
}

func TestExplain_DecodesChainAndConstraints(t *testing.T) {
	srv, rec := newRecorder(t, map[string]reply{
		"POST /explain": {200, data(map[string]interface{}{
			"decision": "escalate", "allowed": false, "code": "approval_required", "reason": "approval needed",
			"agent": map[string]interface{}{"id": "a2", "name": "worker", "ownerId": "u1", "status": "active", "expiresAt": nil},
			"delegation": map[string]interface{}{
				"rootOwnerId": "u1",
				"path":        []string{"a1", "a2"},
				"links": []map[string]interface{}{{
					"delegationId": "d1", "fromAgent": "a1", "toAgent": "a2", "depth": 1, "maxDepth": 3,
					"permissions": []map[string]interface{}{{"resource": "db:*", "actions": []string{"write"}}},
					"expiresAt":   "2030-01-01T00:00:00.000Z", "createdAt": "2029-01-01T00:00:00.000Z",
				}},
				"inbound": []interface{}{},
			},
			"matchedGrant": map[string]interface{}{
				"source": "delegation", "index": 0, "resourceMatch": "wildcard:prefix", "actionMatch": "exact",
				"permission": map[string]interface{}{"resource": "db:*", "actions": []string{"write"}},
			},
			"constraints": []map[string]interface{}{{"constraint": "requireApproval", "outcome": "approval", "detail": "needs a human"}},
			"attempts":    []map[string]interface{}{{"source": "delegation", "rulesChecked": 1, "outcome": "escalate", "code": "approval_required"}},
			"hook":        map[string]interface{}{"configured": false, "evaluated": false},
			"nearMisses": []map[string]interface{}{{
				"source": "own", "grant": map[string]interface{}{"resource": "db:orders", "actions": []string{"read"}},
				"mismatch": []string{"action"}, "hint": "action read does not cover write", "score": 0.6,
			}},
			"trace":       []map[string]interface{}{{"stage": "constraint", "outcome": "approval", "detail": "held"}},
			"evaluatedAt": "2029-06-01T00:00:00.000Z",
		})},
	})
	c := theauth.NewClient(srv.URL)
	res, err := c.Agents.Explain(context.Background(), theauth.ExplainRequest{AgentID: "a2", Action: "write", Resource: "db:orders"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != "escalate" || res.Code != theauth.DecisionApprovalRequired {
		t.Fatalf("unexpected %+v", res)
	}
	if res.Delegation == nil || *res.Delegation.RootOwnerID != "u1" || len(res.Delegation.Path) != 2 || res.Delegation.Links[0].MaxDepth != 3 {
		t.Fatalf("delegation not decoded: %+v", res.Delegation)
	}
	if res.MatchedGrant == nil || res.MatchedGrant.ResourceMatch != "wildcard:prefix" {
		t.Fatalf("matched grant: %+v", res.MatchedGrant)
	}
	if res.Constraints[0].Outcome != "approval" || res.NearMisses[0].Grant.Resource != "db:orders" || res.Trace[0].Stage != "constraint" {
		t.Fatalf("details not decoded: %+v", res)
	}
	if !strings.Contains(rec.last(t).Body, `"agentId":"a2"`) {
		t.Fatalf("body %s", rec.last(t).Body)
	}
}

func TestDelegation_ListChainsCarriesRootOwnerAndPath(t *testing.T) {
	srv, _ := newRecorder(t, map[string]reply{
		"GET /delegations/a2": {200, data([]map[string]interface{}{{
			"id": "d1", "fromAgent": "a1", "toAgent": "a2", "depth": 1, "permissions": []interface{}{},
			"expiresAt": "x", "createdAt": "y", "rootOwnerId": "u1", "path": []string{"a1", "a2"},
		}})},
	})
	chains, err := theauth.NewClient(srv.URL).Delegation.ListChains(context.Background(), "a2")
	if err != nil || len(chains) != 1 {
		t.Fatalf("%v %v", err, chains)
	}
	if chains[0].RootOwnerID == nil || *chains[0].RootOwnerID != "u1" || len(chains[0].Path) != 2 {
		t.Fatalf("%+v", chains[0])
	}
}

func TestApprovals_FullFlow(t *testing.T) {
	srv, rec := newRecorder(t, map[string]reply{
		"POST /approvals": {201, data(map[string]interface{}{"id": "apr_1", "status": "pending", "action": "admin:rotate", "resource": "agent:a1", "expiresAt": "t"})},
		"GET /approvals": {200, data([]map[string]interface{}{{
			"id": "apr_1", "action": "admin:rotate", "resource": "agent:a1", "requestedBy": "u1",
			"createdAt": "c", "expiresAt": "e", "arguments": "{}", "argumentsTruncated": false,
		}})},
		"GET /approvals/apr_1":          {200, data(map[string]interface{}{"id": "apr_1", "status": "approved", "action": "admin:rotate", "resource": "agent:a1", "expiresAt": "e", "respondedAt": "r"})},
		"POST /approvals/apr_1/approve": {200, data(map[string]interface{}{"id": "apr_1", "status": "approved", "respondedAt": "r"})},
		"POST /approvals/apr_1/deny":    {200, data(map[string]interface{}{"id": "apr_1", "status": "denied", "respondedAt": "r"})},
		"POST /approvals/apr_1/consume": {200, data(map[string]interface{}{"consumed": true, "approvalId": "apr_1"})},
	})
	ctx := context.Background()
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin_token"))

	opened, err := c.Approvals.Open(ctx, theauth.OpenApprovalInput{Action: "admin:rotate", Resource: "agent:a1"})
	if err != nil || opened.ID != "apr_1" || opened.Status != theauth.ApprovalPending {
		t.Fatalf("open: %v %+v", err, opened)
	}
	limit := 10
	pending, err := c.Approvals.ListPending(ctx, &limit)
	if err != nil || len(pending) != 1 || pending[0].RequestedBy != "u1" {
		t.Fatalf("list: %v %+v", err, pending)
	}
	state, err := c.Approvals.Get(ctx, "apr_1")
	if err != nil || state == nil || state.Status != theauth.ApprovalApproved || state.RespondedAt == nil {
		t.Fatalf("get: %v %+v", err, state)
	}
	if dec, err := c.Approvals.Approve(ctx, "apr_1"); err != nil || dec.Status != theauth.ApprovalApproved {
		t.Fatalf("approve: %v %+v", err, dec)
	}
	if dec, err := c.Approvals.Deny(ctx, "apr_1"); err != nil || dec.Status != theauth.ApprovalDenied {
		t.Fatalf("deny: %v %+v", err, dec)
	}
	spent, err := c.Approvals.Consume(ctx, "apr_1", theauth.ConsumeApprovalInput{Action: "admin:rotate", Resource: "agent:a1"})
	if err != nil || !spent {
		t.Fatalf("consume: %v %v", err, spent)
	}
	missing, err := c.Approvals.Get(ctx, "nope")
	if err != nil || missing != nil {
		t.Fatalf("missing approval should be nil, nil: %v %v", err, missing)
	}
	if got := rec.last(t).Header.Get("Authorization"); got != "Bearer admin_token" {
		t.Fatalf("authorization %q", got)
	}
}

func TestApprovals_ConflictIsAnError(t *testing.T) {
	srv, _ := newRecorder(t, map[string]reply{
		"POST /approvals/apr_1/approve": {409, map[string]interface{}{"error": map[string]string{"code": "APPROVAL_NOT_PENDING", "message": "Request is no longer pending"}}},
	})
	_, err := theauth.NewClient(srv.URL).Approvals.Approve(context.Background(), "apr_1")
	var base *theauth.TheAuthError
	if e, ok := err.(*theauth.TheAuthError); ok {
		base = e
	}
	if base == nil || base.Code != "APPROVAL_NOT_PENDING" || base.StatusCode != 409 {
		t.Fatalf("got %T %v", err, err)
	}
}

func TestIntrospect_FormBasicAuthAndClaims(t *testing.T) {
	srv, rec := newRecorder(t, map[string]reply{
		"POST /mcp/introspect": {200, map[string]interface{}{
			"active": true, "scope": "read write", "client_id": "cli", "sub": "u1", "exp": 1900000000,
			"aud": []string{"https://api.example.com"}, "token_type": "Bearer", "agent_id": "a2",
			"act":         map[string]interface{}{"sub": "a2", "act": map[string]interface{}{"sub": "a1"}},
			"theauth_dlg": map[string]interface{}{"v": 1, "agt": []string{"a1", "a2"}, "lnk": []string{"d1"}},
		}},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("ignored_bearer"))
	res, err := c.MCP.Introspect(context.Background(), theauth.IntrospectInput{
		Token: "tok", TokenTypeHint: "access_token", ClientID: "rs 1", ClientSecret: "s3cret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Active || res.AgentID != "a2" || len(res.Aud) != 1 || res.Act == nil || res.Act.Act.Sub != "a1" {
		t.Fatalf("unexpected %+v", res)
	}
	if res.Delegation == nil || res.Delegation.V != 1 || res.Delegation.Lnk[0] != "d1" {
		t.Fatalf("delegation binding %+v", res.Delegation)
	}
	call := rec.last(t)
	if call.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("content type %q", call.Header.Get("Content-Type"))
	}
	if !strings.Contains(call.Body, "token=tok") || !strings.Contains(call.Body, "token_type_hint=access_token") {
		t.Fatalf("form body %q", call.Body)
	}
	if !strings.HasPrefix(call.Header.Get("Authorization"), "Basic ") {
		t.Fatalf("expected client basic auth, got %q", call.Header.Get("Authorization"))
	}
}

func TestIntrospect_InactiveAndStringAudience(t *testing.T) {
	srv, _ := newRecorder(t, map[string]reply{
		"POST /mcp/introspect": {200, map[string]interface{}{"active": false, "aud": "https://api.example.com", "theauth_inactive_reason": "delegation_revoked"}},
	})
	res, err := theauth.NewClient(srv.URL).MCP.Introspect(context.Background(), theauth.IntrospectInput{Token: "t", ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Active || res.InactiveReason != "delegation_revoked" || len(res.Aud) != 1 || res.Aud[0] != "https://api.example.com" {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestIntrospect_OAuthErrorBody(t *testing.T) {
	srv, _ := newRecorder(t, map[string]reply{
		"POST /mcp/introspect": {401, map[string]interface{}{"error": "invalid_client", "error_description": "Client authentication failed"}},
	})
	_, err := theauth.NewClient(srv.URL).MCP.Introspect(context.Background(), theauth.IntrospectInput{Token: "t", ClientID: "c", ClientSecret: "bad"})
	e, ok := err.(*theauth.ErrAuthentication)
	if !ok || e.Code != "invalid_client" {
		t.Fatalf("got %T %v", err, err)
	}
}

func TestAudit_EntryDecodesCodeAndEvent(t *testing.T) {
	srv, _ := newRecorder(t, map[string]reply{
		"GET /audit": {200, data([]map[string]interface{}{{
			"id": "e1", "agentId": "a", "userId": "u", "action": "write", "resource": "r", "parameters": map[string]interface{}{},
			"result": "escalated", "durationMs": 3, "timestamp": "t", "code": "approval_required", "event": "authorize",
		}})},
	})
	entries, err := theauth.NewClient(srv.URL).Audit.Query(context.Background(), nil)
	if err != nil || len(entries) != 1 {
		t.Fatalf("%v %v", err, entries)
	}
	e := entries[0]
	if e.Result != theauth.AuditResultEscalated || e.Code == nil || *e.Code != theauth.DecisionApprovalRequired || e.Event == nil || *e.Event != "authorize" {
		t.Fatalf("%+v", e)
	}
}

// Every route the typed calls use must exist in the generated OpenAPI document.
func TestClientRoutesExistInOpenAPIDocument(t *testing.T) {
	raw, err := os.ReadFile("../openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ok := reply{200, map[string]interface{}{}}
	srv, rec := newRecorder(t, map[string]reply{
		"POST /authorize": ok, "POST /authorize/token": ok, "POST /explain": ok, "POST /mcp/introspect": ok,
		"POST /approvals": ok, "GET /approvals": ok, "GET /approvals/x": ok,
		"POST /approvals/x/approve": ok, "POST /approvals/x/deny": ok, "POST /approvals/x/consume": ok,
		"GET /delegations/x": ok,
	})
	ctx := context.Background()
	c := theauth.NewClient(srv.URL)
	_, _ = c.Agents.Authorize(ctx, "x", theauth.AuthorizeRequest{})
	_, _ = c.Auth.AuthorizeByToken(ctx, "ta_x", theauth.AuthorizeRequest{})
	_, _ = c.Agents.Explain(ctx, theauth.ExplainRequest{AgentID: "x"})
	_, _ = c.MCP.Introspect(ctx, theauth.IntrospectInput{Token: "t"})
	_, _ = c.Approvals.Open(ctx, theauth.OpenApprovalInput{})
	_, _ = c.Approvals.ListPending(ctx, nil)
	_, _ = c.Approvals.Get(ctx, "x")
	_, _ = c.Approvals.Approve(ctx, "x")
	_, _ = c.Approvals.Deny(ctx, "x")
	_, _ = c.Approvals.Consume(ctx, "x", theauth.ConsumeApprovalInput{})
	_, _ = c.Delegation.ListChains(ctx, "x")

	type route struct {
		method  string
		pattern *regexp.Regexp
	}
	var routes []route
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
			routes = append(routes, route{strings.ToUpper(method), pattern})
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 11 {
		t.Fatalf("expected 11 calls, got %d", len(rec.calls))
	}
	for _, call := range rec.calls {
		found := false
		for _, r := range routes {
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
