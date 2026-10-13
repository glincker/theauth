package theauth

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// RequestOptions describes a call to a plugin route declared with the
// TypeScript server's defineEndpoint.
type RequestOptions struct {
	// Method is the HTTP method, e.g. "POST".
	Method string
	// Path is the route path relative to the base URL. ":name" segments are
	// filled from Params and URL escaped, e.g. "/auth/team/:id/invite".
	Path string
	// Params fills ":name" path segments.
	Params map[string]string
	// Query is sent as the URL query string.
	Query map[string]string
	// Body is JSON encoded when non-nil.
	Body interface{}
}

var pathParamRe = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

func fillPath(path string, params map[string]string) (string, error) {
	var missing string
	out := pathParamRe.ReplaceAllStringFunc(path, func(m string) string {
		name := m[1:]
		v, ok := params[name]
		if !ok {
			missing = name
			return m
		}
		return url.PathEscape(v)
	})
	if missing != "" {
		return "", fmt.Errorf("theauth: missing path parameter %q for %s", missing, path)
	}
	return out, nil
}

// Request calls a plugin route and decodes the JSON response into out
// (pass nil to discard it). Validation failures come back as a
// *TheAuthError whose Issues field carries the server's issue list.
func (c *Client) Request(ctx context.Context, opts RequestOptions, out interface{}) error {
	method := strings.ToUpper(opts.Method)
	if method == "" {
		return fmt.Errorf("theauth: request method is required")
	}
	if !strings.HasPrefix(opts.Path, "/") {
		return fmt.Errorf("theauth: request path must start with /, got %q", opts.Path)
	}
	path, err := fillPath(opts.Path, opts.Params)
	if err != nil {
		return err
	}
	return c.tp.doJSON(ctx, method, path, opts.Body, opts.Query, out)
}

// Do is shorthand for Request without path parameters.
func (c *Client) Do(ctx context.Context, method, path string, query map[string]string, body, out interface{}) error {
	return c.Request(ctx, RequestOptions{Method: method, Path: path, Query: query, Body: body}, out)
}
