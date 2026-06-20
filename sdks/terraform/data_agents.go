package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	theauth "github.com/glincker/theauth-go"
)

func dataSourceAgents() *schema.Resource {
	return &schema.Resource{
		Description: "Lists TheAuth agents, optionally filtered by owner, status, or type.",

		ReadContext: dataSourceAgentsRead,

		Schema: map[string]*schema.Schema{
			// Optional filters
			"owner_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Filter agents by owner user ID.",
			},
			"status": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"active", "revoked", "expired"}, false),
				Description:  "Filter agents by status: active, revoked, or expired.",
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"autonomous", "delegated", "service"}, false),
				Description:  "Filter agents by type: autonomous, delegated, or service.",
			},
			// Computed result
			"agents": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of matching agents.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"owner_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"status": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"expires_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"updated_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceAgentsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	filters := &theauth.AgentFilters{}

	if v, ok := d.GetOk("owner_id"); ok {
		s := v.(string)
		filters.UserID = &s
	}
	if v, ok := d.GetOk("status"); ok {
		s := theauth.AgentStatus(v.(string))
		filters.Status = &s
	}
	if v, ok := d.GetOk("type"); ok {
		t := theauth.AgentType(v.(string))
		filters.Type = &t
	}

	agents, err := cfg.client.Agents.List(ctx, filters)
	if err != nil {
		return diag.Errorf("listing theauth_agents: %s", err)
	}

	// Use a deterministic ID based on the filter combination.
	filterID := buildFilterID(d)
	d.SetId(filterID)

	flat := flattenAgentList(agents)
	if err := d.Set("agents", flat); err != nil {
		return diag.Errorf("setting agents: %s", err)
	}

	return nil
}

func flattenAgentList(agents []theauth.Agent) []interface{} {
	result := make([]interface{}, 0, len(agents))
	for _, a := range agents {
		m := map[string]interface{}{
			"id":         a.ID,
			"owner_id":   a.OwnerID,
			"name":       a.Name,
			"type":       string(a.Type),
			"status":     string(a.Status),
			"created_at": a.CreatedAt,
			"updated_at": a.UpdatedAt,
		}
		if a.ExpiresAt != nil {
			m["expires_at"] = *a.ExpiresAt
		} else {
			m["expires_at"] = ""
		}
		result = append(result, m)
	}
	return result
}

// buildFilterID creates a stable synthetic ID from the active filter values.
func buildFilterID(d *schema.ResourceData) string {
	id := "agents"
	if v, ok := d.GetOk("owner_id"); ok {
		id += "/owner=" + v.(string)
	}
	if v, ok := d.GetOk("status"); ok {
		id += "/status=" + v.(string)
	}
	if v, ok := d.GetOk("type"); ok {
		id += "/type=" + v.(string)
	}
	return id
}
