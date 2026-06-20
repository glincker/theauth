package theauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// AgentsResource manages agent identity operations.
type AgentsResource struct {
	tp *transport
}

// Create creates a new agent identity.
func (r *AgentsResource) Create(ctx context.Context, input CreateAgentInput) (*Agent, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/agents", input, nil, &raw); err != nil {
		return nil, err
	}
	var agent Agent
	if err := json.Unmarshal(unwrapAPIData(raw), &agent); err != nil {
		return nil, fmt.Errorf("theauth: decode agent: %w", err)
	}
	return &agent, nil
}

// List returns agent identities. Pass nil filters to list all agents.
func (r *AgentsResource) List(ctx context.Context, filters *AgentFilters) ([]Agent, error) {
	params := agentFiltersToParams(filters)
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", "/agents", nil, params, &raw); err != nil {
		return nil, err
	}
	data := unwrapAPIData(raw)
	var agents []Agent
	if err := json.Unmarshal(data, &agents); err != nil {
		return nil, fmt.Errorf("theauth: decode agents list: %w", err)
	}
	return agents, nil
}

// Get retrieves an agent by ID. Returns nil, nil when not found.
func (r *AgentsResource) Get(ctx context.Context, agentID string) (*Agent, error) {
	var raw json.RawMessage
	err := r.tp.doJSON(ctx, "GET", "/agents/"+url.PathEscape(agentID), nil, nil, &raw)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var agent Agent
	if err := json.Unmarshal(unwrapAPIData(raw), &agent); err != nil {
		return nil, fmt.Errorf("theauth: decode agent: %w", err)
	}
	return &agent, nil
}

// Update modifies an existing agent. All fields in input are optional.
func (r *AgentsResource) Update(ctx context.Context, agentID string, input UpdateAgentInput) (*Agent, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "PATCH", "/agents/"+url.PathEscape(agentID), input, nil, &raw); err != nil {
		return nil, err
	}
	var agent Agent
	if err := json.Unmarshal(unwrapAPIData(raw), &agent); err != nil {
		return nil, fmt.Errorf("theauth: decode agent: %w", err)
	}
	return &agent, nil
}

// Revoke deletes an agent identity.
func (r *AgentsResource) Revoke(ctx context.Context, agentID string) error {
	return r.tp.doJSON(ctx, "DELETE", "/agents/"+url.PathEscape(agentID), nil, nil, nil)
}

// Rotate issues a new bearer token for the agent and invalidates the previous one.
func (r *AgentsResource) Rotate(ctx context.Context, agentID string) (*Agent, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/agents/"+url.PathEscape(agentID)+"/rotate", nil, nil, &raw); err != nil {
		return nil, err
	}
	var agent Agent
	if err := json.Unmarshal(unwrapAPIData(raw), &agent); err != nil {
		return nil, fmt.Errorf("theauth: decode agent: %w", err)
	}
	return &agent, nil
}

// Authorize checks whether an agent is permitted to perform an action on a resource.
func (r *AgentsResource) Authorize(ctx context.Context, agentID string, req AuthorizeRequest) (*AuthorizeResult, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/agents/"+url.PathEscape(agentID)+"/authorize", req, nil, &raw); err != nil {
		return nil, err
	}
	var result AuthorizeResult
	if err := json.Unmarshal(unwrapAPIData(raw), &result); err != nil {
		return nil, fmt.Errorf("theauth: decode authorize result: %w", err)
	}
	return &result, nil
}

// GetEffectivePermissions returns the merged set of permissions for an agent,
// including any delegated permissions.
func (r *AgentsResource) GetEffectivePermissions(ctx context.Context, agentID string) ([]Permission, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", "/delegations/"+url.PathEscape(agentID)+"/permissions", nil, nil, &raw); err != nil {
		return nil, err
	}
	var perms []Permission
	if err := json.Unmarshal(unwrapAPIData(raw), &perms); err != nil {
		return nil, fmt.Errorf("theauth: decode permissions: %w", err)
	}
	return perms, nil
}

func agentFiltersToParams(f *AgentFilters) map[string]string {
	if f == nil {
		return nil
	}
	params := make(map[string]string)
	if f.UserID != nil {
		params["userId"] = *f.UserID
	}
	if f.Status != nil {
		params["status"] = string(*f.Status)
	}
	if f.Type != nil {
		params["type"] = string(*f.Type)
	}
	if len(params) == 0 {
		return nil
	}
	return params
}
