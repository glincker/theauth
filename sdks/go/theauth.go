// Package theauth provides a Go client for the TheAuth REST API.
//
// TheAuth is an auth OS for AI agents: agent identity, permissions, delegation,
// audit logs, and human authentication.
//
// Basic usage:
//
//	client := theauth.NewClient("https://your-app.com/api/kavach",
//	    theauth.WithToken("kv_..."),
//	    theauth.WithTimeout(10*time.Second),
//	)
//
//	agent, err := client.Agents.Create(ctx, theauth.CreateAgentInput{
//	    OwnerID: "user-123",
//	    Name:    "github-reader",
//	    Type:    theauth.AgentTypeAutonomous,
//	    Permissions: []theauth.Permission{
//	        {Resource: "mcp:github:*", Actions: []string{"read"}},
//	    },
//	})
package theauth

import (
	"context"
	"net/http"
	"time"
)

// Client is the TheAuth API client. Create one with NewClient.
type Client struct {
	// Agents manages agent identity CRUD and authorization.
	Agents *AgentsResource
	// Auth handles human authentication (sign-in, sign-up, sessions).
	Auth *AuthResource
	// Audit provides access to audit log queries and exports.
	Audit *AuditResource
	// Delegation manages delegation chains between agents.
	Delegation *DelegationResource

	tp *transport
}

// Option is a functional option for configuring a Client.
type Option func(*clientConfig)

type clientConfig struct {
	token        string
	timeout      time.Duration
	httpClient   *http.Client
	extraHeaders map[string]string
}

// WithToken sets the bearer token sent with every request.
// This can be a user session token or an agent token.
func WithToken(token string) Option {
	return func(c *clientConfig) {
		c.token = token
	}
}

// WithTimeout sets the HTTP request timeout. Defaults to 30 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

// WithHTTPClient replaces the default http.Client with a custom one.
// When provided, WithTimeout is ignored.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *clientConfig) {
		c.httpClient = hc
	}
}

// WithHeader adds a custom HTTP header sent with every request.
func WithHeader(key, value string) Option {
	return func(c *clientConfig) {
		if c.extraHeaders == nil {
			c.extraHeaders = make(map[string]string)
		}
		c.extraHeaders[key] = value
	}
}

// NewClient creates a new TheAuth client.
//
// baseURL is the base URL of your TheAuth deployment, e.g.
// "https://your-app.com/api/kavach". Apply options with the With* helpers.
func NewClient(baseURL string, opts ...Option) *Client {
	cfg := &clientConfig{
		timeout: 30 * time.Second,
	}
	for _, o := range opts {
		o(cfg)
	}

	hc := cfg.httpClient
	if hc == nil {
		hc = &http.Client{Timeout: cfg.timeout}
	}

	tp := &transport{
		baseURL:      baseURL,
		token:        cfg.token,
		extraHeaders: cfg.extraHeaders,
		httpClient:   hc,
	}

	return &Client{
		Agents:     &AgentsResource{tp: tp},
		Auth:       &AuthResource{tp: tp},
		Audit:      &AuditResource{tp: tp},
		Delegation: &DelegationResource{tp: tp},
		tp:         tp,
	}
}

// Authorize checks whether an agent may perform an action.
// This is a convenience method that delegates to client.Agents.Authorize.
func (c *Client) Authorize(ctx context.Context, agentID string, req AuthorizeRequest) (*AuthorizeResult, error) {
	return c.Agents.Authorize(ctx, agentID, req)
}
