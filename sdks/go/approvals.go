package theauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// ApprovalStatus is the state of an approval request.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalExpired  ApprovalStatus = "expired"
)

// OpenApprovalInput opens an approval request. Action must look like admin:<name>.
type OpenApprovalInput struct {
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ApprovalOpened is returned when a request is opened.
type ApprovalOpened struct {
	ID        string         `json:"id"`
	Status    ApprovalStatus `json:"status"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	ExpiresAt string         `json:"expiresAt"`
}

// PendingApproval is one entry of the pending list. Arguments is JSON text with
// secret looking keys redacted and cut at 2 KB.
type PendingApproval struct {
	ID                 string `json:"id"`
	Action             string `json:"action"`
	Resource           string `json:"resource"`
	RequestedBy        string `json:"requestedBy"`
	CreatedAt          string `json:"createdAt"`
	ExpiresAt          string `json:"expiresAt"`
	Arguments          string `json:"arguments"`
	ArgumentsTruncated bool   `json:"argumentsTruncated"`
}

// ApprovalState is the current state of one request.
type ApprovalState struct {
	ID          string         `json:"id"`
	Status      ApprovalStatus `json:"status"`
	Action      string         `json:"action"`
	Resource    string         `json:"resource"`
	ExpiresAt   string         `json:"expiresAt"`
	RespondedAt *string        `json:"respondedAt,omitempty"`
}

// ApprovalDecision is returned by Approve and Deny.
type ApprovalDecision struct {
	ID          string         `json:"id"`
	Status      ApprovalStatus `json:"status"`
	RespondedAt string         `json:"respondedAt"`
}

// ConsumeApprovalInput names the call an approved request is spent on.
type ConsumeApprovalInput struct {
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ApprovalsResource calls the approval routes of the admin API plugin. The
// plugin is off by default, and every route needs an admin user token.
type ApprovalsResource struct {
	tp *transport
}

func approvalPath(id, suffix string) string {
	return "/approvals/" + url.PathEscape(id) + suffix
}

func decodeData(raw json.RawMessage, dst interface{}, what string) error {
	if err := json.Unmarshal(unwrapAPIData(raw), dst); err != nil {
		return fmt.Errorf("theauth: decode %s: %w", what, err)
	}
	return nil
}

// Open creates a pending approval request.
func (r *ApprovalsResource) Open(ctx context.Context, input OpenApprovalInput) (*ApprovalOpened, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/approvals", input, nil, &raw); err != nil {
		return nil, err
	}
	var out ApprovalOpened
	if err := decodeData(raw, &out, "approval"); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListPending returns pending, unexpired requests, newest first. Pass nil limit
// for the server default (50, at most 100).
func (r *ApprovalsResource) ListPending(ctx context.Context, limit *int) ([]PendingApproval, error) {
	params := map[string]string{"status": "pending"}
	if limit != nil {
		params["limit"] = strconv.Itoa(*limit)
	}
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", "/approvals", nil, params, &raw); err != nil {
		return nil, err
	}
	var out []PendingApproval
	if err := decodeData(raw, &out, "pending approvals"); err != nil {
		return nil, err
	}
	return out, nil
}

// Get reads a request. Returns nil, nil when it does not exist.
func (r *ApprovalsResource) Get(ctx context.Context, id string) (*ApprovalState, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", approvalPath(id, ""), nil, nil, &raw); err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var out ApprovalState
	if err := decodeData(raw, &out, "approval"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Approve approves a pending request. The admin who opened it cannot approve
// it unless the server allows self approval. A request that is no longer
// pending answers 409.
func (r *ApprovalsResource) Approve(ctx context.Context, id string) (*ApprovalDecision, error) {
	return r.decide(ctx, approvalPath(id, "/approve"))
}

// Deny denies a pending request.
func (r *ApprovalsResource) Deny(ctx context.Context, id string) (*ApprovalDecision, error) {
	return r.decide(ctx, approvalPath(id, "/deny"))
}

func (r *ApprovalsResource) decide(ctx context.Context, path string) (*ApprovalDecision, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", path, nil, nil, &raw); err != nil {
		return nil, err
	}
	var out ApprovalDecision
	if err := decodeData(raw, &out, "approval decision"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Consume spends an approved request once, for the named call. Only the admin
// who opened the request may spend it. It returns true when the request was spent.
func (r *ApprovalsResource) Consume(ctx context.Context, id string, input ConsumeApprovalInput) (bool, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", approvalPath(id, "/consume"), input, nil, &raw); err != nil {
		return false, err
	}
	var out struct {
		Consumed bool `json:"consumed"`
	}
	if err := decodeData(raw, &out, "approval consume"); err != nil {
		return false, err
	}
	return out.Consumed, nil
}
