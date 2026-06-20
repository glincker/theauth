package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	theauth "github.com/glincker/theauth-go"
)

func dataSourceAgent() *schema.Resource {
	return &schema.Resource{
		Description: "Reads a single TheAuth agent by ID. " +
			"Use this when you need to reference an agent that was not created by Terraform.",

		ReadContext: dataSourceAgentRead,

		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the agent to look up.",
			},
			"owner_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the user who owns this agent.",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Human-readable name of the agent.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Agent type: autonomous, delegated, or service.",
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current lifecycle status: active, revoked, or expired.",
			},
			"permission": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Permission grants assigned to this agent.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"actions": {
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"constraints": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"require_approval": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"max_calls_per_hour": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"allowed_arg_patterns": {
										Type:     schema.TypeList,
										Computed: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"ip_allowlist": {
										Type:     schema.TypeList,
										Computed: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
					},
				},
			},
			"expires_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RFC 3339 timestamp when the agent token expires, if set.",
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

func dataSourceAgentRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	id := d.Get("id").(string)

	agent, err := cfg.client.Agents.Get(ctx, id)
	if err != nil {
		return diag.Errorf("reading theauth_agent data source (id=%s): %s", id, err)
	}
	if agent == nil {
		return diag.Errorf("agent %s not found", id)
	}

	d.SetId(agent.ID)

	return setAgentDataState(d, agent)
}

// setAgentDataState writes a *theauth.Agent into a data source's Terraform state.
// Unlike setAgentState (resource), this never sets the token (not returned by read).
func setAgentDataState(d *schema.ResourceData, a *theauth.Agent) diag.Diagnostics {
	var diags diag.Diagnostics

	fields := map[string]interface{}{
		"owner_id":   a.OwnerID,
		"name":       a.Name,
		"type":       string(a.Type),
		"status":     string(a.Status),
		"created_at": a.CreatedAt,
		"updated_at": a.UpdatedAt,
	}
	for k, v := range fields {
		if err := d.Set(k, v); err != nil {
			diags = append(diags, diagFromErr(k, err))
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
