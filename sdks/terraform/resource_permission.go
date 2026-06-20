package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	theauth "github.com/glincker/theauth-go"
)

// resourcePermission manages a standalone permission grant attached to an existing agent.
//
// This is an alternative to the inline permission blocks on theauth_agent.
// Use this resource when permissions are managed separately from agent creation —
// for example, when a central permissions module grants access to resources
// owned by other modules.
//
// Note: The TheAuth API stores permissions as part of the agent, so this resource
// reads and updates the agent's permissions list. Concurrent updates to the same
// agent from multiple resources may conflict — prefer using the inline permission
// blocks on theauth_agent when all permissions are managed in one place.
func resourcePermission() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a single permission grant on a TheAuth agent. " +
			"For agents where all permissions are known up front, prefer inline permission blocks on theauth_agent. " +
			"Use this resource when permissions are granted by a separate Terraform module.",

		CreateContext: resourcePermissionCreate,
		ReadContext:   resourcePermissionRead,
		UpdateContext: resourcePermissionUpdate,
		DeleteContext: resourcePermissionDelete,

		Schema: map[string]*schema.Schema{
			"agent_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the agent to grant this permission to.",
			},
			"resource": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Resource pattern to grant access to, e.g. mcp:github:* or mcp:deploy:production.",
			},
			"actions": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Actions the agent is allowed to perform on the resource.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"require_approval": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Require human approval before the action is executed.",
			},
			"max_calls_per_hour": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum calls allowed per hour. 0 means unlimited.",
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
	}
}

// resourcePermissionCreate appends a permission to the agent's permission list.
func resourcePermissionCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)
	agentID := d.Get("agent_id").(string)

	agent, err := cfg.client.Agents.Get(ctx, agentID)
	if err != nil {
		return diag.Errorf("reading agent %s for permission grant: %s", agentID, err)
	}
	if agent == nil {
		return diag.Errorf("agent %s not found", agentID)
	}

	newPerm := buildPermissionFromState(d)
	updatedPerms := append(agent.Permissions, newPerm)

	updated, err := cfg.client.Agents.Update(ctx, agentID, theauth.UpdateAgentInput{
		Permissions: updatedPerms,
	})
	if err != nil {
		return diag.Errorf("granting permission on agent %s: %s", agentID, err)
	}

	// Use agent_id + resource as the synthetic ID.
	d.SetId(agentID + "/" + newPerm.Resource)

	return syncPermissionState(d, updated, newPerm.Resource)
}

func resourcePermissionRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)
	agentID := d.Get("agent_id").(string)

	agent, err := cfg.client.Agents.Get(ctx, agentID)
	if err != nil {
		return diag.Errorf("reading agent %s: %s", agentID, err)
	}
	if agent == nil {
		d.SetId("")
		return nil
	}

	return syncPermissionState(d, agent, d.Get("resource").(string))
}

func resourcePermissionUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)
	agentID := d.Get("agent_id").(string)
	resource := d.Get("resource").(string)

	agent, err := cfg.client.Agents.Get(ctx, agentID)
	if err != nil {
		return diag.Errorf("reading agent %s for permission update: %s", agentID, err)
	}
	if agent == nil {
		return diag.Errorf("agent %s not found", agentID)
	}

	// Replace the matching permission in the list.
	newPerm := buildPermissionFromState(d)
	updatedPerms := make([]theauth.Permission, 0, len(agent.Permissions))
	replaced := false
	for _, p := range agent.Permissions {
		if p.Resource == resource {
			updatedPerms = append(updatedPerms, newPerm)
			replaced = true
		} else {
			updatedPerms = append(updatedPerms, p)
		}
	}
	if !replaced {
		updatedPerms = append(updatedPerms, newPerm)
	}

	updated, err := cfg.client.Agents.Update(ctx, agentID, theauth.UpdateAgentInput{
		Permissions: updatedPerms,
	})
	if err != nil {
		return diag.Errorf("updating permission on agent %s: %s", agentID, err)
	}

	return syncPermissionState(d, updated, resource)
}

func resourcePermissionDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)
	agentID := d.Get("agent_id").(string)
	resource := d.Get("resource").(string)

	agent, err := cfg.client.Agents.Get(ctx, agentID)
	if err != nil {
		if theauth.IsNotFound(err) {
			return nil
		}
		return diag.Errorf("reading agent %s for permission revoke: %s", agentID, err)
	}
	if agent == nil {
		return nil
	}

	// Remove the matching permission.
	updatedPerms := make([]theauth.Permission, 0, len(agent.Permissions))
	for _, p := range agent.Permissions {
		if p.Resource != resource {
			updatedPerms = append(updatedPerms, p)
		}
	}

	if _, err := cfg.client.Agents.Update(ctx, agentID, theauth.UpdateAgentInput{
		Permissions: updatedPerms,
	}); err != nil {
		return diag.Errorf("revoking permission on agent %s: %s", agentID, err)
	}

	return nil
}

func buildPermissionFromState(d *schema.ResourceData) theauth.Permission {
	perm := theauth.Permission{
		Resource: d.Get("resource").(string),
		Actions:  expandStringList(d.Get("actions").([]interface{})),
	}

	hasConstraints := false
	constraints := &theauth.PermissionConstraints{}

	if v := d.Get("require_approval").(bool); v {
		constraints.RequireApproval = &v
		hasConstraints = true
	}
	if v := d.Get("max_calls_per_hour").(int); v > 0 {
		constraints.MaxCallsPerHour = &v
		hasConstraints = true
	}
	if v := expandStringList(d.Get("allowed_arg_patterns").([]interface{})); len(v) > 0 {
		constraints.AllowedArgPatterns = v
		hasConstraints = true
	}
	if v := expandStringList(d.Get("ip_allowlist").([]interface{})); len(v) > 0 {
		constraints.IPAllowlist = v
		hasConstraints = true
	}

	if hasConstraints {
		perm.Constraints = constraints
	}

	return perm
}

func syncPermissionState(d *schema.ResourceData, agent *theauth.Agent, resource string) diag.Diagnostics {
	for _, p := range agent.Permissions {
		if p.Resource == resource {
			if err := d.Set("actions", p.Actions); err != nil {
				return diag.FromErr(err)
			}
			if p.Constraints != nil {
				if p.Constraints.RequireApproval != nil {
					if err := d.Set("require_approval", *p.Constraints.RequireApproval); err != nil {
						return diag.FromErr(err)
					}
				}
				if p.Constraints.MaxCallsPerHour != nil {
					if err := d.Set("max_calls_per_hour", *p.Constraints.MaxCallsPerHour); err != nil {
						return diag.FromErr(err)
					}
				}
				if err := d.Set("allowed_arg_patterns", p.Constraints.AllowedArgPatterns); err != nil {
					return diag.FromErr(err)
				}
				if err := d.Set("ip_allowlist", p.Constraints.IPAllowlist); err != nil {
					return diag.FromErr(err)
				}
			}
			return nil
		}
	}

	// Permission was removed outside Terraform.
	d.SetId("")
	return nil
}
