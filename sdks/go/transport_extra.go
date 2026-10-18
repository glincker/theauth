package theauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// send builds and performs a request. The caller closes the response body.
func (t *transport) send(ctx context.Context, method, path, contentType string, body []byte, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(t.baseURL, "/")+path, reader)
	if err != nil {
		return nil, &ErrNetwork{TheAuthError{Code: "NETWORK_ERROR", Message: err.Error()}}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	for k, v := range t.extraHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, &ErrNetwork{TheAuthError{Code: "NETWORK_ERROR", Message: err.Error()}}
	}
	return resp, nil
}

// doDecision performs a JSON request to an authorize endpoint. A denial comes
// back as 403 (or 401 for an identity failure) with the same { data: result }
// body as an allowed call, so a 401 or 403 that carries a result is returned as
// a result, not an error. Any other error status is parsed as usual.
func (t *transport) doDecision(ctx context.Context, path string, body interface{}, headers map[string]string) (*AuthorizeResult, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("theauth: marshal request: %w", err)
	}
	resp, err := t.send(ctx, "POST", path, "application/json", payload, headers)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("theauth: read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if result, ok := decodeDecision(data); ok {
				return result, nil
			}
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		return nil, parseErrorResponse(resp)
	}
	result, ok := decodeDecision(data)
	if !ok {
		return nil, fmt.Errorf("theauth: decode authorize result: unexpected body")
	}
	return result, nil
}

// decodeDecision reads an AuthorizeResult from a bare or { data } body. It
// reports false when the body has no "allowed" field, as an error body has not.
func decodeDecision(data []byte) (*AuthorizeResult, bool) {
	inner := unwrapAPIData(json.RawMessage(data))
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(inner, &probe); err != nil {
		return nil, false
	}
	if _, ok := probe["allowed"]; !ok {
		return nil, false
	}
	var result AuthorizeResult
	if err := json.Unmarshal(inner, &result); err != nil {
		return nil, false
	}
	return &result, true
}

// doForm posts an application/x-www-form-urlencoded body and decodes the JSON
// response as is, without looking for a { data } envelope (OAuth endpoints).
func (t *transport) doForm(ctx context.Context, path string, form url.Values, headers map[string]string, dst interface{}) error {
	resp, err := t.send(ctx, "POST", path, "application/x-www-form-urlencoded", []byte(form.Encode()), headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return parseOAuthError(resp)
	}
	if dst == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("theauth: decode response: %w", err)
	}
	return nil
}

// parseOAuthError maps an RFC 6749 error body ({ error, error_description })
// onto the same typed errors as the rest of the client.
func parseOAuthError(resp *http.Response) error {
	data, _ := io.ReadAll(resp.Body)
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(data, &body); err == nil && body.Error != "" {
		wrapped, _ := json.Marshal(map[string]interface{}{
			"error": map[string]string{"code": body.Error, "message": body.Description},
		})
		resp.Body = io.NopCloser(bytes.NewReader(wrapped))
		return parseErrorResponse(resp)
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return parseErrorResponse(resp)
}
