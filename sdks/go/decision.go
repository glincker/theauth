package theauth

import (
	"context"
	"encoding/json"
	"fmt"
)

// DecisionCode is the machine-readable outcome of an authorization decision.
type DecisionCode string

// Decision codes set by the server on AuthorizeResult.Code, ExplainResult.Code
// and audit entries. The server may add codes, so keep a default branch.
const (
	// BEGIN GENERATED decision-codes
	DecisionAllowed                    DecisionCode = "allowed"
	DecisionApprovalConsumed           DecisionCode = "approval_consumed"
	DecisionNoPermission               DecisionCode = "no_permission"
	DecisionRateLimited                DecisionCode = "rate_limited"
	DecisionIPNotAllowed               DecisionCode = "ip_not_allowed"
	DecisionTimeRestricted             DecisionCode = "time_restricted"
	DecisionArgumentRejected           DecisionCode = "argument_rejected"
	DecisionApprovalRequired           DecisionCode = "approval_required"
	DecisionApprovalInvalid            DecisionCode = "approval_invalid"
	DecisionApprovalNotFound           DecisionCode = "approval_not_found"
	DecisionApprovalPending            DecisionCode = "approval_pending"
	DecisionApprovalDenied             DecisionCode = "approval_denied"
	DecisionApprovalExpired            DecisionCode = "approval_expired"
	DecisionApprovalAlreadyUsed        DecisionCode = "approval_already_used"
	DecisionApprovalMismatch           DecisionCode = "approval_mismatch"
	DecisionApprovalArgumentsMismatch  DecisionCode = "approval_arguments_mismatch"
	DecisionApprovalStepUpInsufficient DecisionCode = "approval_step_up_insufficient"
	DecisionApprovalGranted            DecisionCode = "approval_granted"
	DecisionAgentNotFound              DecisionCode = "agent_not_found"
	DecisionAgentRevoked               DecisionCode = "agent_revoked"
	DecisionAgentExpired               DecisionCode = "agent_expired"
	DecisionInvalidToken               DecisionCode = "invalid_token"
	DecisionConfirmationRequired       DecisionCode = "confirmation_required"
	DecisionConfirmationFailed         DecisionCode = "confirmation_failed"
	DecisionDeviceNotFound             DecisionCode = "device_not_found"
	DecisionDeviceSuspended            DecisionCode = "device_suspended"
	DecisionDeviceRevoked              DecisionCode = "device_revoked"
	DecisionDeviceExpired              DecisionCode = "device_expired"
	DecisionOwnerMismatch              DecisionCode = "owner_mismatch"
	DecisionHookDenied                 DecisionCode = "hook_denied"
	DecisionHookTimeout                DecisionCode = "hook_timeout"
	DecisionHookError                  DecisionCode = "hook_error"
	DecisionTaintViolation             DecisionCode = "taint_violation"
	DecisionRiskEscalation             DecisionCode = "risk_escalation"
	DecisionPolicyIndeterminate        DecisionCode = "policy_indeterminate"
	// END GENERATED decision-codes
)

// Allowed reports whether the code means the call went through.
func (c DecisionCode) Allowed() bool {
	return c == DecisionAllowed || c == DecisionApprovalConsumed
}

// RequestContext is request metadata the server checks constraints against.
type RequestContext struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
}

// ExplainRequest asks why an agent would be allowed or denied an action.
// Nothing is recorded in the audit log.
type ExplainRequest struct {
	AgentID   string                 `json:"agentId"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
	Context   *RequestContext        `json:"context,omitempty"`
	// At evaluates time windows at this ISO 8601 instant. Defaults to now.
	At *string `json:"at,omitempty"`
	// RunHooks calls the beforeAuthorize hook in dry run mode.
	RunHooks *bool `json:"runHooks,omitempty"`
}

// DelegationLink is one grant on the path from the root agent to the acting agent.
type DelegationLink struct {
	DelegationID string       `json:"delegationId"`
	FromAgent    string       `json:"fromAgent"`
	ToAgent      string       `json:"toAgent"`
	Permissions  []Permission `json:"permissions"`
	Depth        int          `json:"depth"`
	MaxDepth     int          `json:"maxDepth"`
	ExpiresAt    string       `json:"expiresAt"`
	CreatedAt    string       `json:"createdAt"`
}

// DecisionDelegation says who stands behind the acting agent, root human first.
type DecisionDelegation struct {
	RootOwnerID *string `json:"rootOwnerId,omitempty"`
	// Path lists agent ids from the root agent to the acting agent.
	Path []string `json:"path"`
	// Links are the grants along Path, root first. Empty when not delegated.
	Links []DelegationLink `json:"links"`
	// Inbound is every active grant whose ToAgent is the acting agent.
	Inbound []DelegationLink `json:"inbound"`
}

// ExplainAgent is the agent an explanation is about.
type ExplainAgent struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	OwnerID   string      `json:"ownerId"`
	Status    AgentStatus `json:"status"`
	ExpiresAt *string     `json:"expiresAt"`
}

// MatchedGrant is the rule that decided, or came closest.
type MatchedGrant struct {
	Source        string          `json:"source"`
	Index         int             `json:"index"`
	Permission    Permission      `json:"permission"`
	ResourceMatch string          `json:"resourceMatch"`
	ActionMatch   string          `json:"actionMatch"`
	Link          *DelegationLink `json:"link,omitempty"`
}

// ConstraintStep is one constraint check on the matched grant.
type ConstraintStep struct {
	Constraint string      `json:"constraint"`
	Outcome    string      `json:"outcome"`
	Detail     string      `json:"detail"`
	Observed   interface{} `json:"observed,omitempty"`
	Configured interface{} `json:"configured,omitempty"`
}

// ExplainAttempt records how one permission set was tried.
type ExplainAttempt struct {
	Source       string       `json:"source"`
	RulesChecked int          `json:"rulesChecked"`
	Outcome      string       `json:"outcome"`
	Code         DecisionCode `json:"code"`
}

// ExplainHook reports the beforeAuthorize hook state.
type ExplainHook struct {
	Configured bool     `json:"configured"`
	Evaluated  bool     `json:"evaluated"`
	Outcome    *string  `json:"outcome,omitempty"`
	Reason     *string  `json:"reason,omitempty"`
	Guard      *string  `json:"guard,omitempty"`
	RuleID     *string  `json:"ruleId,omitempty"`
	ElapsedMs  *float64 `json:"elapsedMs,omitempty"`
}

// NearMiss is a grant that failed on resource or action, with a hint.
type NearMiss struct {
	Source       string `json:"source"`
	DelegationID string `json:"delegationId,omitempty"`
	Grant        struct {
		Resource string   `json:"resource"`
		Actions  []string `json:"actions"`
	} `json:"grant"`
	Mismatch []string `json:"mismatch"`
	Hint     string   `json:"hint"`
	Score    float64  `json:"score"`
}

// TraceStep is one step of the evaluation, in order.
type TraceStep struct {
	Stage   string                 `json:"stage"`
	Outcome string                 `json:"outcome"`
	Detail  string                 `json:"detail"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// ExplainResult is the full account of an authorization decision.
type ExplainResult struct {
	Decision     string              `json:"decision"`
	Allowed      bool                `json:"allowed"`
	Code         DecisionCode        `json:"code"`
	Reason       string              `json:"reason"`
	Agent        *ExplainAgent       `json:"agent"`
	Delegation   *DecisionDelegation `json:"delegation"`
	MatchedGrant *MatchedGrant       `json:"matchedGrant,omitempty"`
	Constraints  []ConstraintStep    `json:"constraints"`
	Attempts     []ExplainAttempt    `json:"attempts"`
	Hook         ExplainHook         `json:"hook"`
	NearMisses   []NearMiss          `json:"nearMisses"`
	Trace        []TraceStep         `json:"trace"`
	EvaluatedAt  string              `json:"evaluatedAt"`
}

// Explain evaluates an authorization request without recording it and returns
// the decision, the delegation chain behind the agent, the constraint checks
// and the closest grants that did not match.
func (r *AgentsResource) Explain(ctx context.Context, req ExplainRequest) (*ExplainResult, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "POST", "/explain", req, nil, &raw); err != nil {
		return nil, err
	}
	var result ExplainResult
	if err := json.Unmarshal(unwrapAPIData(raw), &result); err != nil {
		return nil, fmt.Errorf("theauth: decode explain result: %w", err)
	}
	return &result, nil
}
