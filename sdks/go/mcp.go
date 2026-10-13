package theauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// MCPResource manages MCP server registrations.
type MCPResource struct {
	tp *transport
}

// Register registers an MCP server.
func (r *MCPResource) Register(ctx context.Context, input RegisterMcpServerInput) (*McpServer, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/mcp/servers", input, nil, &raw); err != nil {
		return nil, err
	}
	var srv McpServer
	if err := json.Unmarshal(unwrapAPIData(raw), &srv); err != nil {
		return nil, fmt.Errorf("theauth: decode mcp server: %w", err)
	}
	return &srv, nil
}

// List returns all registered MCP servers.
func (r *MCPResource) List(ctx context.Context) ([]McpServer, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", "/mcp/servers", nil, nil, &raw); err != nil {
		return nil, err
	}
	var servers []McpServer
	if err := json.Unmarshal(unwrapAPIData(raw), &servers); err != nil {
		return nil, fmt.Errorf("theauth: decode mcp servers: %w", err)
	}
	return servers, nil
}

// Get retrieves an MCP server by ID. Returns nil, nil when not found.
func (r *MCPResource) Get(ctx context.Context, id string) (*McpServer, error) {
	var raw json.RawMessage
	err := r.tp.doJSON(ctx, "GET", "/mcp/servers/"+url.PathEscape(id), nil, nil, &raw)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var srv McpServer
	if err := json.Unmarshal(unwrapAPIData(raw), &srv); err != nil {
		return nil, fmt.Errorf("theauth: decode mcp server: %w", err)
	}
	return &srv, nil
}
