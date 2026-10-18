package theauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
)

// IntrospectInput is a token introspection request (RFC 7662). The caller
// authenticates as an OAuth client with ClientID and ClientSecret (HTTP Basic).
type IntrospectInput struct {
	Token string
	// TokenTypeHint is advisory: "access_token" or "refresh_token".
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
}

// Audience is the aud claim, which the server sends as a string or a list.
type Audience []string

// UnmarshalJSON accepts both forms of aud.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = Audience(many)
	return nil
}

// ActorClaim is the RFC 8693 act claim: the actor, with earlier hops nested.
type ActorClaim struct {
	Sub      string      `json:"sub,omitempty"`
	ClientID string      `json:"client_id,omitempty"`
	Act      *ActorClaim `json:"act,omitempty"`
}

// DelegationBinding is the theauth_dlg claim: the authority path the token rests on.
type DelegationBinding struct {
	V int `json:"v"`
	// Agt lists agent ids on the authority path, root first.
	Agt []string `json:"agt"`
	// Lnk lists the delegation chain id for each consecutive pair in Agt.
	Lnk []string `json:"lnk"`
}

// IntrospectionResponse is the RFC 7662 answer. A caller that is not entitled
// to the token always gets Active false and nothing else.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Exp       *int64   `json:"exp,omitempty"`
	Iat       *int64   `json:"iat,omitempty"`
	Aud       Audience `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Jti       string   `json:"jti,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Cnf       *struct {
		Jkt string `json:"jkt"`
	} `json:"cnf,omitempty"`
	Act     *ActorClaim `json:"act,omitempty"`
	AgentID string      `json:"agent_id,omitempty"`
	// Delegation is set for tokens bound to a delegation chain.
	Delegation *DelegationBinding `json:"theauth_dlg,omitempty"`
	// InactiveReason is set only for entitled callers, and only when Active is false.
	InactiveReason string `json:"theauth_inactive_reason,omitempty"`
}

// Introspect asks the server whether a token is live and what it carries,
// including the agent id and the delegation binding. The endpoint is off
// unless the server enables introspection, in which case it answers 404.
func (r *MCPResource) Introspect(ctx context.Context, input IntrospectInput) (*IntrospectionResponse, error) {
	form := url.Values{"token": {input.Token}}
	if input.TokenTypeHint != "" {
		form.Set("token_type_hint", input.TokenTypeHint)
	}
	headers := map[string]string{}
	if input.ClientID != "" {
		basic := url.QueryEscape(input.ClientID) + ":" + url.QueryEscape(input.ClientSecret)
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(basic))
	}
	var out IntrospectionResponse
	if err := r.tp.doForm(ctx, "/mcp/introspect", form, headers, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
