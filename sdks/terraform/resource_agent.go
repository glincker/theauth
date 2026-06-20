package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	theauth "github.com/glincker/theauth-go"
)

func resourceAgent() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a TheAuth agent identity. " +
			"Agents are the primary entity in TheAuth — " +
			"each AI agent, service account, or automated process gets its own identity " +
			"with cryptographic tokens and scoped permissions.",

		CreateContext: resourceAgentCreate,
		ReadContext:   resourceAgentRead,
		UpdateContext: resourceAgentUpdate,
		DeleteContext: resourceAgentDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"owner_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the user who owns this agent.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Human-readable name for the agent.",
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"autonomous", "delegated", "service"}, false),
				Description:  "Agent type: autonomous, delegated, or service.",
			},
			"permission": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Permission grants for this agent. Each block defines a resource pattern and allowed actions.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Resource pattern, e.g. mcp:github:* or mcp:deploy:production.",
						},
						"actions": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "List of allowed actions, e.g. [\"read\"] or [\"read\", \"write\"].",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"constraints": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "Optional constraints limiting how and when the permission may be used.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"require_approval": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     false,
										Description: "Require human approval before the action is executed.",
									},
									"max_calls_per_hour": {
										Type:         schema.TypeInt,
										Optional:     true,
										ValidateFunc: validation.IntAtLeast(1),
										Description:  "Maximum number of calls allowed per hour.",
									},
									"allowed_arg_patterns": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "Glob patterns restricting allowed argument values.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"ip_allowlist": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "CIDR blocks or IPs from which this permission may be exercised.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
								},
							},
						},
					},
				},
			},
			"expires_at": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.IsRFC3339Time,
				Description:  "RFC 3339 timestamp after which the agent token expires.",
			},
			// Computed fields
			"token": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
				Description: "Bearer token for this agent. Set on create and on token rotation. " +
					"Store securely — TheAuth does not store the raw token after creation.",
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current lifecycle status: active, revoked, or expired.",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RFC 3339 timestamp when this agent was created.",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RFC 3339 timestamp of the last update.",
			},
		},
	}
}

func resourceAgentCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	input := theauth.CreateAgentInput{
		OwnerID:     d.Get("owner_id").(string),
		Name:        d.Get("name").(string),
		Type:        theauth.AgentType(d.Get("type").(string)),
		Permissions: expandPermissions(d.Get("permission").([]interface{})),
	}

	if v, ok := d.GetOk("expires_at"); ok {
		s := v.(string)
		input.ExpiresAt = &s
	}

	agent, err := cfg.client.Agents.Create(ctx, input)
	if err != nil {
		return diag.Errorf("creating theauth_agent: %s", err)
	}

	d.SetId(agent.ID)
	return setAgentState(d, agent)
}

func resourceAgentRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	agent, err := cfg.client.Agents.Get(ctx, d.Id())
	if err != nil {
		return diag.Errorf("reading theauth_agent %s: %s", d.Id(), err)
	}
	if agent == nil {
		// Agent was deleted outside of Terraform.
		d.SetId("")
		return nil
	}

	return setAgentState(d, agent)
}

func resourceAgentUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	input := theauth.UpdateAgentInput{}

	if d.HasChange("name") {
		name := d.Get("name").(string)
		input.Name = &name
	}

	if d.HasChange("permission") {
		input.Permissions = expandPermissions(d.Get("permission").([]interface{}))
	}

	if d.HasChange("expires_at") {
		if v, ok := d.GetOk("expires_at"); ok {
			s := v.(string)
			input.ExpiresAt = &s
		}
	}

	agent, err := cfg.client.Agents.Update(ctx, d.Id(), input)
	if err != nil {
		return diag.Errorf("updating theauth_agent %s: %s", d.Id(), err)
	}

	return setAgentState(d, agent)
}

func resourceAgentDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	if err := cfg.client.Agents.Revoke(ctx, d.Id()); err != nil {
		if theauth.IsNotFound(err) {
			return nil
		}
		return diag.Errorf("deleting theauth_agent %s: %s", d.Id(), err)
	}

	return nil
}

// setAgentState writes a *theauth.Agent into Terraform state.
func setAgentState(d *schema.ResourceData, a *theauth.Agent) diag.Diagnostics {
	var diags diag.Diagnostics

	if err := d.Set("owner_id", a.OwnerID); err != nil {
		diags = append(diags, diagFromErr("owner_id", err))
	}
	if err := d.Set("name", a.Name); err != nil {
		diags = append(diags, diagFromErr("name", err))
	}
	if err := d.Set("type", string(a.Type)); err != nil {
		diags = append(diags, diagFromErr("type", err))
	}
	if err := d.Set("status", string(a.Status)); err != nil {
		diags = append(diags, diagFromErr("status", err))
	}
	if err := d.Set("created_at", a.CreatedAt); err != nil {
		diags = append(diags, diagFromErr("created_at", err))
	}
	if err := d.Set("updated_at", a.UpdatedAt); err != nil {
		diags = append(diags, diagFromErr("updated_at", err))
	}

	// Only set token if present — on Read it may be empty (TheAuth only returns it on Create/Rotate).
	if a.Token != "" {
		if err := d.Set("token", a.Token); err != nil {
			diags = append(diags, diagFromErr("token", err))
		}
	}

	if a.ExpiresAt != nil {
		if err := d.Set("expires_at", *a.ExpiresAt); err != nil {
			diags = append(diags, diagFromErr("expires_at", err))
		}
	}

	if err := d.Set("permission", flattenPermissions(a.Permissions)); err != nil {
		diags = append(diags, diagFromErr("permission", err))
	}

	return diags
}

// expandPermissions converts a Terraform list of permission blocks into []theauth.Permission.
func expandPermissions(raw []interface{}) []theauth.Permission {
	perms := make([]theauth.Permission, 0, len(raw))
	for _, item := range raw {
		m := item.(map[string]interface{})

		perm := theauth.Permission{
			Resource: m["resource"].(string),
			Actions:  expandStringList(m["actions"].([]interface{})),
		}

		if constraintList, ok := m["constraints"].([]interface{}); ok && len(constraintList) > 0 {
			c := constraintList[0].(map[string]interface{})
			constraints := &theauth.PermissionConstraints{}

			if v, ok := c["require_approval"].(bool); ok && v {
				constraints.RequireApproval = &v
			}
			if v, ok := c["max_calls_per_hour"].(int); ok && v > 0 {
				constraints.MaxCallsPerHour = &v
			}
			if v, ok := c["allowed_arg_patterns"].([]interface{}); ok && len(v) > 0 {
				constraints.AllowedArgPatterns = expandStringList(v)
			}
			if v, ok := c["ip_allowlist"].([]interface{}); ok && len(v) > 0 {
				constraints.IPAllowlist = expandStringList(v)
			}

			perm.Constraints = constraints
		}

		perms = append(perms, perm)
	}
	return perms
}

// flattenPermissions converts []theauth.Permission into a Terraform-compatible list.
func flattenPermissions(perms []theauth.Permission) []interface{} {
	result := make([]interface{}, 0, len(perms))
	for _, p := range perms {
		m := map[string]interface{}{
			"resource": p.Resource,
			"actions":  p.Actions,
		}

		if p.Constraints != nil {
			c := map[string]interface{}{}

			if p.Constraints.RequireApproval != nil {
				c["require_approval"] = *p.Constraints.RequireApproval
			} else {
				c["require_approval"] = false
			}
			if p.Constraints.MaxCallsPerHour != nil {
				c["max_calls_per_hour"] = *p.Constraints.MaxCallsPerHour
			}
			if len(p.Constraints.AllowedArgPatterns) > 0 {
				c["allowed_arg_patterns"] = p.Constraints.AllowedArgPatterns
			}
			if len(p.Constraints.IPAllowlist) > 0 {
				c["ip_allowlist"] = p.Constraints.IPAllowlist
			}

			m["constraints"] = []interface{}{c}
		}

		result = append(result, m)
	}
	return result
}

// expandStringList converts []interface{} of strings to []string.
func expandStringList(raw []interface{}) []string {
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// diagFromErr wraps a state-set error into a Terraform diagnostic.
func diagFromErr(attr string, err error) diag.Diagnostic {
	return diag.Diagnostic{
		Severity: diag.Error,
		Summary:  "Error setting " + attr,
		Detail:   err.Error(),
	}
}
