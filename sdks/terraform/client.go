package main

// client.go provides a thin HTTP helper for TheAuth API endpoints that the Go SDK
// does not yet expose as typed methods (API keys, organizations).
//
// The Terraform provider uses the Go SDK (github.com/glincker/theauth-go) for all
// agent, audit, and delegation operations. For API keys and organizations we talk to
// the same REST API directly using this helper so the provider does not depend on
// an unreleased SDK build.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpClient is a minimal REST client for TheAuth endpoints not covered by the Go SDK.
type httpClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func newHTTPClient(baseURL, token string) *httpClient {
	return &httpClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// do executes an authenticated JSON request and decodes the response body into dst.
// Pass nil body for requests with no body (GET, DELETE).
// Pass nil dst when no response body is expected.
func (c *httpClient) do(ctx context.Context, method, path string, body interface{}, dst interface{}) error {
	rawURL := strings.TrimRight(c.baseURL, "/") + path

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("theauth: marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
	if err != nil {
		return fmt.Errorf("theauth: build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("theauth: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("theauth: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(respBody, &apiErr)

		code := apiErr.Code
		msg := apiErr.Message
		if apiErr.Error != nil {
			if apiErr.Error.Code != "" {
				code = apiErr.Error.Code
			}
			if apiErr.Error.Message != "" {
				msg = apiErr.Error.Message
			}
		}
		if code == "" {
			code = "API_ERROR"
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}

		return fmt.Errorf("theauth: [%s] %s (status %d)", code, msg, resp.StatusCode)
	}

	if dst == nil {
		return nil
	}

	if err := json.Unmarshal(respBody, dst); err != nil {
		// Try unwrapping { data: T } envelope.
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if jsonErr := json.Unmarshal(respBody, &envelope); jsonErr == nil && len(envelope.Data) > 0 {
			if err2 := json.Unmarshal(envelope.Data, dst); err2 == nil {
				return nil
			}
		}
		return fmt.Errorf("theauth: decode response: %w", err)
	}

	return nil
}

// isNotFound returns true when err looks like a 404 from the TheAuth API.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "status 404")
}
