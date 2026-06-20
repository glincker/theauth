package theauth

// AgentType represents the kind of agent identity.
type AgentType string

const (
	AgentTypeAutonomous AgentType = "autonomous"
	AgentTypeDelegated  AgentType = "delegated"
	AgentTypeService    AgentType = "service"
)

// AgentStatus represents the lifecycle state of an agent.
type AgentStatus string

const (
	AgentStatusActive  AgentStatus = "active"
	AgentStatusRevoked AgentStatus = "revoked"
	AgentStatusExpired AgentStatus = "expired"
)

// AuditResult represents the outcome of an authorization decision.
type AuditResult string

const (
	AuditResultAllowed     AuditResult = "allowed"
	AuditResultDenied      AuditResult = "denied"
	AuditResultRateLimited AuditResult = "rate_limited"
)

// ExportFormat specifies the format for audit log exports.
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
)

// PermissionConstraints holds optional limits on a permission grant.
type PermissionConstraints struct {
	MaxCallsPerHour    *int        `json:"maxCallsPerHour,omitempty"`
	AllowedArgPatterns []string    `json:"allowedArgPatterns,omitempty"`
	RequireApproval    *bool       `json:"requireApproval,omitempty"`
	TimeWindow         *TimeWindow `json:"timeWindow,omitempty"`
	IPAllowlist        []string    `json:"ipAllowlist,omitempty"`
}

// TimeWindow defines a start/end time range for a permission constraint.
type TimeWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Permission is a single permission grant: a resource pattern and allowed actions.
type Permission struct {
	Resource    string                 `json:"resource"`
	Actions     []string               `json:"actions"`
	Constraints *PermissionConstraints `json:"constraints,omitempty"`
}

// Agent is an agent identity returned by the TheAuth API.
type Agent struct {
	ID          string      `json:"id"`
	OwnerID     string      `json:"ownerId"`
	Name        string      `json:"name"`
	Type        AgentType   `json:"type"`
	Token       string      `json:"token"`
	Permissions []Permission `json:"permissions"`
	Status      AgentStatus `json:"status"`
	ExpiresAt   *string     `json:"expiresAt,omitempty"`
	CreatedAt   string      `json:"createdAt"`
	UpdatedAt   string      `json:"updatedAt"`
	TenantID    *string     `json:"tenantId,omitempty"`
}

// CreateAgentInput is the input for creating a new agent identity.
type CreateAgentInput struct {
	OwnerID     string                 `json:"ownerId"`
	Name        string                 `json:"name"`
	Type        AgentType              `json:"type"`
	Permissions []Permission           `json:"permissions"`
	ExpiresAt   *string                `json:"expiresAt,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateAgentInput is the input for updating an existing agent. All fields are optional.
type UpdateAgentInput struct {
	Name        *string                `json:"name,omitempty"`
	Permissions []Permission           `json:"permissions,omitempty"`
	ExpiresAt   *string                `json:"expiresAt,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AgentFilters are query parameters for listing agents.
type AgentFilters struct {
	UserID *string
	Status *AgentStatus
	Type   *AgentType
}

// AuthorizeRequest is a request to check whether an agent may perform an action.
type AuthorizeRequest struct {
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// AuthorizeResult is the result of an authorization check.
type AuthorizeResult struct {
	Allowed bool    `json:"allowed"`
	AuditID string  `json:"auditId"`
	Reason  *string `json:"reason,omitempty"`
}

// AuthorizeByTokenInput is used to authorize using an agent bearer token directly.
type AuthorizeByTokenInput struct {
	AgentToken string
	Request    AuthorizeRequest
}

// DelegateInput is the input for creating a delegation between agents.
type DelegateInput struct {
	FromAgent   string       `json:"fromAgent"`
	ToAgent     string       `json:"toAgent"`
	Permissions []Permission `json:"permissions"`
	ExpiresAt   string       `json:"expiresAt"`
	MaxDepth    *int         `json:"maxDepth,omitempty"`
}

// DelegationChain is a single delegation link between two agents.
type DelegationChain struct {
	ID          string       `json:"id"`
	FromAgent   string       `json:"fromAgent"`
	ToAgent     string       `json:"toAgent"`
	Permissions []Permission `json:"permissions"`
	ExpiresAt   string       `json:"expiresAt"`
	Depth       int          `json:"depth"`
	CreatedAt   string       `json:"createdAt"`
}

// AuditEntry is a single audit log record.
type AuditEntry struct {
	ID         string                 `json:"id"`
	AgentID    string                 `json:"agentId"`
	UserID     string                 `json:"userId"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	Parameters map[string]interface{} `json:"parameters"`
	Result     AuditResult            `json:"result"`
	DurationMs int                    `json:"durationMs"`
	Timestamp  string                 `json:"timestamp"`
	Reason     *string                `json:"reason,omitempty"`
	TokensCost *float64               `json:"tokensCost,omitempty"`
}

// AuditFilters are query parameters for the audit log.
type AuditFilters struct {
	AgentID *string
	UserID  *string
	Since   *string
	Until   *string
	Actions []string
	Result  *AuditResult
	Limit   *int
	Offset  *int
}

// PaginatedAuditLogs is the paginated response from the audit log endpoint.
type PaginatedAuditLogs struct {
	Entries []AuditEntry `json:"entries"`
	Total   *int         `json:"total,omitempty"`
}

// ExportOptions controls the audit log export format and date range.
type ExportOptions struct {
	Format ExportFormat
	Since  *string
	Until  *string
}

// User is a human user account.
type User struct {
	ID        string  `json:"id"`
	Email     string  `json:"email"`
	CreatedAt string  `json:"createdAt"`
	Name      *string `json:"name,omitempty"`
}

// Session is an active session for a human user.
type Session struct {
	ID        string `json:"id"`
	UserID    string `json:"userId"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	CreatedAt string `json:"createdAt"`
}

// AuthResponse is returned by sign-in and sign-up endpoints.
type AuthResponse struct {
	User    User    `json:"user"`
	Session Session `json:"session"`
}

// McpServer is a registered MCP server.
type McpServer struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Endpoint     string   `json:"endpoint"`
	Tools        []string `json:"tools"`
	AuthRequired bool     `json:"authRequired"`
	CreatedAt    string   `json:"createdAt"`
}

// RegisterMcpServerInput is the input for registering an MCP server.
type RegisterMcpServerInput struct {
	Name         string   `json:"name"`
	Endpoint     string   `json:"endpoint"`
	Tools        []string `json:"tools"`
	AuthRequired bool     `json:"authRequired"`
	RateLimitRPM *int     `json:"rateLimit,omitempty"`
}
