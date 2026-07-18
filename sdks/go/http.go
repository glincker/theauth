package theauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// transport is the internal HTTP client used by all resource types.
type transport struct {
	baseURL      string
	token        string
	extraHeaders map[string]string
	httpClient   *http.Client
}

// doJSON performs an authenticated JSON request and decodes the response into dst.
// Pass nil for dst when no response body is expected (e.g. DELETE/sign-out).
func (t *transport) doJSON(ctx context.Context, method, path string, body interface{}, params map[string]string, dst interface{}) error {
	return t.doJSONWithHeaders(ctx, method, path, body, params, nil, dst)
}

// doJSONWithHeaders performs a JSON request with optional per-call header overrides.
func (t *transport) doJSONWithHeaders(ctx context.Context, method, path string, body interface{}, params map[string]string, extraHeaders map[string]string, dst interface{}) error {
	// Build URL
	rawURL := strings.TrimRight(t.baseURL, "/") + path
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		rawURL += "?" + q.Encode()
	}

	// Marshal body
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("theauth: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
	if err != nil {
		return &ErrNetwork{TheAuthError{Code: "NETWORK_ERROR", Message: err.Error()}}
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	for k, v := range t.extraHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return &ErrNetwork{TheAuthError{Code: "NETWORK_ERROR", Message: err.Error()}}
	}
	defer resp.Body.Close()

	// No content
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	// Error responses
	if resp.StatusCode >= 400 {
		return parseErrorResponse(resp)
	}

	// Successful but caller doesn't want a body
	if dst == nil {
		return nil
	}

	// Decode response
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("theauth: decode response: %w", err)
	}
	return nil
}

// doRaw performs a request and returns the raw response body as a string.
// Used for CSV / raw export endpoints.
func (t *transport) doRaw(ctx context.Context, method, path string, params map[string]string) (string, error) {
	rawURL := strings.TrimRight(t.baseURL, "/") + path
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		rawURL += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return "", &ErrNetwork{TheAuthError{Code: "NETWORK_ERROR", Message: err.Error()}}
	}

	req.Header.Set("Accept", "text/plain, application/json")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	for k, v := range t.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return "", &ErrNetwork{TheAuthError{Code: "NETWORK_ERROR", Message: err.Error()}}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", parseErrorResponse(resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("theauth: read response: %w", err)
	}
	return string(data), nil
}

// parseErrorResponse maps an HTTP error response to a typed TheAuthError.
func parseErrorResponse(resp *http.Response) error {
	var apiErr struct {
		Code    string                 `json:"code"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details"`
		Error   *struct {
			Code    string                 `json:"code"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details"`
		} `json:"error"`
	}

	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &apiErr)

	code := apiErr.Code
	message := apiErr.Message
	details := apiErr.Details

	// Support { error: { code, message } } envelope
	if apiErr.Error != nil {
		if apiErr.Error.Code != "" {
			code = apiErr.Error.Code
		}
		if apiErr.Error.Message != "" {
			message = apiErr.Error.Message
		}
		if apiErr.Error.Details != nil {
			details = apiErr.Error.Details
		}
	}

	if code == "" {
		code = "API_ERROR"
	}
	if message == "" {
		message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	base := TheAuthError{
		Code:       code,
		Message:    message,
		StatusCode: resp.StatusCode,
		Details:    details,
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &ErrAuthentication{base}
	case http.StatusForbidden:
		return &ErrPermission{base}
	case http.StatusNotFound:
		return &ErrNotFound{base}
	case http.StatusTooManyRequests:
		e := &ErrRateLimit{TheAuthError: base}
		if raw := resp.Header.Get("Retry-After"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				e.RetryAfter = &n
			}
		}
		return e
	}

	if resp.StatusCode >= 500 {
		return &ErrServer{base}
	}

	return &base
}

// unwrapAPIData handles the { success: true, data: T } envelope that some endpoints use.
// If the JSON has a "data" key, it returns the value of that key; otherwise the original.
func unwrapAPIData(raw json.RawMessage) json.RawMessage {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && len(envelope.Data) > 0 {
		return envelope.Data
	}
	return raw
}
