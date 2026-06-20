package theauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

// helpers

func ptr[T any](v T) *T { return &v }

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func agentFixture() theauth.Agent {
	return theauth.Agent{
		ID:      "agent-1",
		OwnerID: "user-1",
		Name:    "test-agent",
		Type:    theauth.AgentTypeAutonomous,
		Token:   "kv_abc123",
		Permissions: []theauth.Permission{
			{Resource: "mcp:github:*", Actions: []string{"read"}},
		},
		Status:    theauth.AgentStatusActive,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}
}

// -------------------------------------------------------------------------
// Client creation
// -------------------------------------------------------------------------

func TestNewClient_Defaults(t *testing.T) {
	c := theauth.NewClient("https://example.com/api/kavach")
	if c.Agents == nil {
		t.Fatal("expected Agents resource to be non-nil")
	}
	if c.Auth == nil {
		t.Fatal("expected Auth resource to be non-nil")
	}
	if c.Audit == nil {
		t.Fatal("expected Audit resource to be non-nil")
	}
	if c.Delegation == nil {
		t.Fatal("expected Delegation resource to be non-nil")
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kv_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Custom") != "hello" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(w, 200, agentFixture())
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL,
		theauth.WithToken("kv_test"),
		theauth.WithTimeout(5*time.Second),
		theauth.WithHeader("X-Custom", "hello"),
	)
	agent, err := c.Agents.Get(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent == nil || agent.ID != "agent-1" {
		t.Fatalf("expected agent-1, got %v", agent)
	}
}

func TestNewClient_WithHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, agentFixture())
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL, theauth.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	agent, err := c.Agents.Get(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent == nil {
		t.Fatal("expected agent, got nil")
	}
}

// -------------------------------------------------------------------------
// Agents
// -------------------------------------------------------------------------

func TestAgents_Create(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/agents" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body theauth.CreateAgentInput
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Name != "my-agent" {
			t.Errorf("expected name my-agent, got %s", body.Name)
		}
		writeJSON(w, 201, agentFixture())
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	agent, err := c.Agents.Create(context.Background(), theauth.CreateAgentInput{
		OwnerID: "user-1",
		Name:    "my-agent",
		Type:    theauth.AgentTypeAutonomous,
		Permissions: []theauth.Permission{
			{Resource: "mcp:github:*", Actions: []string{"read"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent.Token != "kv_abc123" {
		t.Errorf("expected token kv_abc123, got %s", agent.Token)
	}
}

func TestAgents_List(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("userId") != "user-1" {
			t.Errorf("expected userId query param, got %s", r.URL.RawQuery)
		}
		writeJSON(w, 200, []theauth.Agent{agentFixture()})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	agents, err := c.Agents.List(context.Background(), &theauth.AgentFilters{UserID: ptr("user-1")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
}

func TestAgents_List_NoFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []theauth.Agent{agentFixture(), agentFixture()})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	agents, err := c.Agents.List(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
}

func TestAgents_Get(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/agent-1") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		writeJSON(w, 200, agentFixture())
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	agent, err := c.Agents.Get(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent == nil || agent.ID != "agent-1" {
		t.Fatalf("expected agent-1, got %v", agent)
	}
}

func TestAgents_Get_NotFound_ReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]string{"code": "NOT_FOUND", "message": "agent not found"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	agent, err := c.Agents.Get(context.Background(), "missing")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if agent != nil {
		t.Fatalf("expected nil agent, got %+v", agent)
	}
}

func TestAgents_Update(t *testing.T) {
	updated := agentFixture()
	updated.Name = "renamed"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		writeJSON(w, 200, updated)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	agent, err := c.Agents.Update(context.Background(), "agent-1", theauth.UpdateAgentInput{Name: ptr("renamed")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent.Name != "renamed" {
		t.Errorf("expected renamed, got %s", agent.Name)
	}
}

func TestAgents_Revoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	if err := c.Agents.Revoke(context.Background(), "agent-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAgents_Rotate(t *testing.T) {
	rotated := agentFixture()
	rotated.Token = "kv_new_token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/rotate") {
			t.Errorf("expected /rotate path, got %s", r.URL.Path)
		}
		writeJSON(w, 200, rotated)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	agent, err := c.Agents.Rotate(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent.Token != "kv_new_token" {
		t.Errorf("expected kv_new_token, got %s", agent.Token)
	}
}

func TestAgents_Authorize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/authorize") {
			t.Errorf("expected /authorize path")
		}
		writeJSON(w, 200, theauth.AuthorizeResult{
			Allowed: true,
			AuditID: "aud_123",
		})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Agents.Authorize(context.Background(), "agent-1", theauth.AuthorizeRequest{
		Action:   "read",
		Resource: "mcp:github:repos",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed=true")
	}
	if result.AuditID != "aud_123" {
		t.Errorf("expected aud_123, got %s", result.AuditID)
	}
}

func TestClient_Authorize_Convenience(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, theauth.AuthorizeResult{Allowed: false, AuditID: "aud_456"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Authorize(context.Background(), "agent-1", theauth.AuthorizeRequest{
		Action:   "write",
		Resource: "mcp:github:repos",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected allowed=false")
	}
}

// -------------------------------------------------------------------------
// Auth
// -------------------------------------------------------------------------

func TestAuth_SignIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign-in/email" || r.Method != "POST" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["email"] != "test@example.com" {
			t.Errorf("unexpected email: %s", body["email"])
		}
		writeJSON(w, 200, map[string]interface{}{
			"user":    theauth.User{ID: "user-1", Email: "test@example.com", CreatedAt: "2024-01-01T00:00:00Z"},
			"session": theauth.Session{ID: "sess-1", UserID: "user-1", Token: "tok_abc", ExpiresAt: "2025-01-01T00:00:00Z", CreatedAt: "2024-01-01T00:00:00Z"},
		})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	resp, err := c.Auth.SignIn(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.User.Email != "test@example.com" {
		t.Errorf("expected test@example.com, got %s", resp.User.Email)
	}
	if resp.Session.Token != "tok_abc" {
		t.Errorf("expected tok_abc, got %s", resp.Session.Token)
	}
}

func TestAuth_SignUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign-up/email" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "Alice" {
			t.Errorf("expected name=Alice, got %v", body["name"])
		}
		writeJSON(w, 201, map[string]interface{}{
			"user":    theauth.User{ID: "user-2", Email: "alice@example.com", Name: ptr("Alice"), CreatedAt: "2024-01-01T00:00:00Z"},
			"session": theauth.Session{ID: "sess-2", UserID: "user-2", Token: "tok_xyz", ExpiresAt: "2025-01-01T00:00:00Z", CreatedAt: "2024-01-01T00:00:00Z"},
		})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	resp, err := c.Auth.SignUp(context.Background(), "alice@example.com", "secret", "Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.User.Name == nil || *resp.User.Name != "Alice" {
		t.Errorf("expected name Alice")
	}
}

func TestAuth_SignUp_NoName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["name"]; ok {
			t.Error("expected no name field")
		}
		writeJSON(w, 201, map[string]interface{}{
			"user":    theauth.User{ID: "user-3", Email: "bob@example.com", CreatedAt: "2024-01-01T00:00:00Z"},
			"session": theauth.Session{ID: "sess-3", UserID: "user-3", Token: "tok_no_name", ExpiresAt: "2025-01-01T00:00:00Z", CreatedAt: "2024-01-01T00:00:00Z"},
		})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	resp, err := c.Auth.SignUp(context.Background(), "bob@example.com", "secret", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Session.Token != "tok_no_name" {
		t.Errorf("unexpected token: %s", resp.Session.Token)
	}
}

func TestAuth_SignOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign-out" || r.Method != "POST" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	if err := c.Auth.SignOut(context.Background(), ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuth_GetSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, theauth.Session{ID: "sess-1", UserID: "user-1", Token: "tok_abc", ExpiresAt: "2025-01-01T00:00:00Z", CreatedAt: "2024-01-01T00:00:00Z"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	sess, err := c.Auth.GetSession(context.Background(), "tok_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess == nil || sess.ID != "sess-1" {
		t.Fatalf("expected sess-1, got %v", sess)
	}
}

func TestAuth_GetSession_Expired_ReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]string{"code": "UNAUTHORIZED", "message": "token expired"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	sess, err := c.Auth.GetSession(context.Background(), "expired_token")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if sess != nil {
		t.Fatalf("expected nil session")
	}
}

func TestAuth_AuthorizeByToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authorize" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer kv_") {
			t.Errorf("expected agent bearer token")
		}
		writeJSON(w, 200, theauth.AuthorizeResult{Allowed: true, AuditID: "aud_789"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Auth.AuthorizeByToken(context.Background(), "kv_agent_token", theauth.AuthorizeRequest{
		Action:   "read",
		Resource: "mcp:github:repos",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed=true")
	}
}

// -------------------------------------------------------------------------
// Audit
// -------------------------------------------------------------------------

func TestAudit_Query_List(t *testing.T) {
	entries := []theauth.AuditEntry{
		{ID: "aud-1", AgentID: "agent-1", UserID: "user-1", Action: "read", Resource: "mcp:github:repos", Result: theauth.AuditResultAllowed, DurationMs: 50, Timestamp: "2024-01-01T00:00:00Z", Parameters: map[string]interface{}{}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, entries)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Audit.Query(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 || result[0].ID != "aud-1" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestAudit_Query_Paginated(t *testing.T) {
	total := 100
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("agentId") != "agent-1" {
			t.Errorf("expected agentId query param")
		}
		writeJSON(w, 200, theauth.PaginatedAuditLogs{
			Entries: []theauth.AuditEntry{
				{ID: "aud-1", AgentID: "agent-1", UserID: "user-1", Action: "read", Resource: "res", Result: theauth.AuditResultAllowed, DurationMs: 10, Timestamp: "2024-01-01T00:00:00Z", Parameters: map[string]interface{}{}},
			},
			Total: &total,
		})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Audit.QueryPaginated(context.Background(), &theauth.AuditFilters{AgentID: ptr("agent-1")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *result.Total != 100 {
		t.Errorf("expected total 100, got %d", *result.Total)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
}

func TestAudit_Export(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") != "csv" {
			t.Errorf("expected format=csv, got %s", r.URL.Query().Get("format"))
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("id,action\naud-1,read"))
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	raw, err := c.Audit.Export(context.Background(), &theauth.ExportOptions{Format: theauth.ExportFormatCSV})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(raw, "aud-1") {
		t.Errorf("expected csv content, got %s", raw)
	}
}

// -------------------------------------------------------------------------
// Delegation
// -------------------------------------------------------------------------

func TestDelegation_Create(t *testing.T) {
	chain := theauth.DelegationChain{
		ID:        "del-1",
		FromAgent: "agent-1",
		ToAgent:   "agent-2",
		Permissions: []theauth.Permission{
			{Resource: "mcp:github:*", Actions: []string{"read"}},
		},
		ExpiresAt: "2025-01-01T00:00:00Z",
		Depth:     1,
		CreatedAt: "2024-01-01T00:00:00Z",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/delegations" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 201, chain)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Delegation.Create(context.Background(), theauth.DelegateInput{
		FromAgent:   "agent-1",
		ToAgent:     "agent-2",
		Permissions: []theauth.Permission{{Resource: "mcp:github:*", Actions: []string{"read"}}},
		ExpiresAt:   "2025-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "del-1" {
		t.Errorf("expected del-1, got %s", result.ID)
	}
}

func TestDelegation_ListChains(t *testing.T) {
	chains := []theauth.DelegationChain{
		{ID: "del-1", FromAgent: "agent-1", ToAgent: "agent-2", Permissions: []theauth.Permission{{Resource: "res", Actions: []string{"read"}}}, ExpiresAt: "2025-01-01T00:00:00Z", Depth: 1, CreatedAt: "2024-01-01T00:00:00Z"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/agent-1") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		writeJSON(w, 200, chains)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Delegation.ListChains(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(result))
	}
}

func TestDelegation_Revoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	if err := c.Delegation.Revoke(context.Background(), "del-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelegation_GetEffectivePermissions(t *testing.T) {
	perms := []theauth.Permission{
		{Resource: "mcp:github:*", Actions: []string{"read", "write"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/permissions") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		writeJSON(w, 200, perms)
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	result, err := c.Delegation.GetEffectivePermissions(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 || result[0].Resource != "mcp:github:*" {
		t.Fatalf("unexpected permissions: %v", result)
	}
}

// -------------------------------------------------------------------------
// Error handling
// -------------------------------------------------------------------------

func TestError_401_Authentication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]string{"code": "UNAUTHORIZED", "message": "invalid token"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !theauth.IsAuthentication(err) {
		t.Errorf("expected ErrAuthentication, got %T: %v", err, err)
	}
}

func TestError_403_Permission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]string{"code": "FORBIDDEN", "message": "access denied"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.List(context.Background(), nil)
	if !theauth.IsPermission(err) {
		t.Errorf("expected ErrPermission, got %T: %v", err, err)
	}
}

func TestError_404_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]string{"code": "NOT_FOUND", "message": "not found"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.Rotate(context.Background(), "missing-agent")
	if !theauth.IsNotFound(err) {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestError_429_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, 429, map[string]string{"code": "RATE_LIMITED", "message": "too many requests"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.List(context.Background(), nil)
	if !theauth.IsRateLimit(err) {
		t.Errorf("expected ErrRateLimit, got %T: %v", err, err)
	}
	rlErr, _ := err.(*theauth.ErrRateLimit)
	if rlErr.RetryAfter == nil || *rlErr.RetryAfter != 60 {
		t.Errorf("expected RetryAfter=60, got %v", rlErr.RetryAfter)
	}
}

func TestError_500_Server(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 500, map[string]string{"code": "INTERNAL", "message": "server exploded"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.List(context.Background(), nil)
	if !theauth.IsServer(err) {
		t.Errorf("expected ErrServer, got %T: %v", err, err)
	}
}

func TestError_ErrorEnvelope(t *testing.T) {
	// Some endpoints wrap errors as { error: { code, message } }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]interface{}{
			"error": map[string]string{"code": "FORBIDDEN", "message": "nope"},
		})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.List(context.Background(), nil)
	if !theauth.IsPermission(err) {
		t.Errorf("expected ErrPermission from error envelope, got %T: %v", err, err)
	}
}

func TestError_Message(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]string{"code": "UNAUTHORIZED", "message": "custom message"})
	}))
	defer srv.Close()

	c := theauth.NewClient(srv.URL)
	_, err := c.Agents.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "UNAUTHORIZED") {
		t.Errorf("expected UNAUTHORIZED in error message, got: %s", err.Error())
	}
}

func TestError_NetworkError(t *testing.T) {
	// Point at a port that refuses connections
	c := theauth.NewClient("http://127.0.0.1:1", theauth.WithTimeout(1*time.Second))
	_, err := c.Agents.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected network error")
	}
	if _, ok := err.(*theauth.ErrNetwork); !ok {
		t.Errorf("expected ErrNetwork, got %T: %v", err, err)
	}
}
