package theauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// DelegationResource manages delegation chains between agents.
type DelegationResource struct {
	tp *transport
}

// Create creates a new delegation from one agent to another.
// The target agent receives a subset of the granting agent's permissions,
// subject to the depth limit.
func (r *DelegationResource) Create(ctx context.Context, input DelegateInput) (*DelegationChain, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/delegations", input, nil, &raw); err != nil {
		return nil, err
	}
	var chain DelegationChain
	if err := json.Unmarshal(unwrapAPIData(raw), &chain); err != nil {
		return nil, fmt.Errorf("theauth: decode delegation chain: %w", err)
	}
	return &chain, nil
}

// ListChains returns all delegation chains where the given agent is a participant.
func (r *DelegationResource) ListChains(ctx context.Context, agentID string) ([]DelegationChain, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", "/delegations/"+url.PathEscape(agentID), nil, nil, &raw); err != nil {
		return nil, err
	}
	var chains []DelegationChain
	if err := json.Unmarshal(unwrapAPIData(raw), &chains); err != nil {
		return nil, fmt.Errorf("theauth: decode delegation chains: %w", err)
	}
	return chains, nil
}

// Revoke deletes a delegation chain by its ID.
func (r *DelegationResource) Revoke(ctx context.Context, delegationID string) error {
	return r.tp.doJSON(ctx, "DELETE", "/delegations/"+url.PathEscape(delegationID), nil, nil, nil)
}

// GetEffectivePermissions returns the merged permissions for an agent, including
// all delegated grants.
func (r *DelegationResource) GetEffectivePermissions(ctx context.Context, agentID string) ([]Permission, error) {
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
