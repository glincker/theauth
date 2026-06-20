package theauth

import (
	"context"
	"encoding/json"
	"fmt"
)

// AuthResource handles human authentication operations.
type AuthResource struct {
	tp *transport
}

type signInBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type signUpBody struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	Name     *string `json:"name,omitempty"`
}

// SignIn authenticates a user with email and password.
func (r *AuthResource) SignIn(ctx context.Context, email, password string) (*AuthResponse, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/sign-in/email", signInBody{Email: email, Password: password}, nil, &raw); err != nil {
		return nil, err
	}
	return decodeAuthResponse(unwrapAPIData(raw))
}

// SignUp creates a new user account with email and password.
// name is optional; pass an empty string to omit it.
func (r *AuthResource) SignUp(ctx context.Context, email, password, name string) (*AuthResponse, error) {
	body := signUpBody{Email: email, Password: password}
	if name != "" {
		body.Name = &name
	}
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/sign-up/email", body, nil, &raw); err != nil {
		return nil, err
	}
	return decodeAuthResponse(unwrapAPIData(raw))
}

// SignOut revokes the current session. If token is non-empty it overrides the
// client's default token for this call.
func (r *AuthResource) SignOut(ctx context.Context, token string) error {
	var extraHeaders map[string]string
	if token != "" {
		extraHeaders = map[string]string{"Authorization": "Bearer " + token}
	}
	return r.tp.doJSONWithHeaders(ctx, "POST", "/sign-out", nil, nil, extraHeaders, nil)
}

// GetSession retrieves the session for the given token.
// If token is empty, the client's configured token is used.
// Returns nil, nil when the session does not exist or has expired.
func (r *AuthResource) GetSession(ctx context.Context, token string) (*Session, error) {
	var extraHeaders map[string]string
	if token != "" {
		extraHeaders = map[string]string{"Authorization": "Bearer " + token}
	}
	var raw json.RawMessage
	err := r.tp.doJSONWithHeaders(ctx, "GET", "/session", nil, nil, extraHeaders, &raw)
	if err != nil {
		if IsAuthentication(err) || IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var session Session
	if err := json.Unmarshal(unwrapAPIData(raw), &session); err != nil {
		return nil, fmt.Errorf("theauth: decode session: %w", err)
	}
	return &session, nil
}

// AuthorizeByToken checks whether an action is permitted using an agent bearer
// token directly (when you have the token rather than the agent ID).
func (r *AuthResource) AuthorizeByToken(ctx context.Context, agentToken string, req AuthorizeRequest) (*AuthorizeResult, error) {
	extraHeaders := map[string]string{"Authorization": "Bearer " + agentToken}
	var raw json.RawMessage
	if err := r.tp.doJSONWithHeaders(ctx, "POST", "/authorize", req, nil, extraHeaders, &raw); err != nil {
		return nil, err
	}
	var result AuthorizeResult
	if err := json.Unmarshal(unwrapAPIData(raw), &result); err != nil {
		return nil, fmt.Errorf("theauth: decode authorize result: %w", err)
	}
	return &result, nil
}

func decodeAuthResponse(data json.RawMessage) (*AuthResponse, error) {
	var ar AuthResponse
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("theauth: decode auth response: %w", err)
	}
	return &ar, nil
}
