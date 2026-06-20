package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// organizationResponse mirrors the TheAuth API response for organization operations.
type organizationResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Slug        string   `json:"slug"`
	Plan        string   `json:"plan,omitempty"`
	MemberCount int      `json:"memberCount,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
}

func resourceOrganization() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a TheAuth organization. " +
			"Organizations provide multi-tenant isolation: agents, API keys, and audit logs " +
			"are scoped to the organization that owns them.",

		CreateContext: resourceOrganizationCreate,
		ReadContext:   resourceOrganizationRead,
		UpdateContext: resourceOrganizationUpdate,
		DeleteContext: resourceOrganizationDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name for the organization, e.g. Engineering or Acme Corp.",
			},
			"slug": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringMatch(slugRegexp(), "must be lowercase alphanumeric with hyphens"),
				Description:  "URL-safe identifier, e.g. engineering or acme-corp. Cannot be changed after creation.",
			},
			"plan": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.StringInSlice([]string{"free", "pro", "enterprise"}, false),
				Description:  "Subscription plan: free, pro, or enterprise.",
			},
			"domains": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Verified domains associated with this organization.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			// Computed
			"member_count": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Number of members in this organization.",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RFC 3339 timestamp when this organization was created.",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RFC 3339 timestamp of the last update.",
			},
		},
	}
}

func resourceOrganizationCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	type createOrgInput struct {
		Name    string   `json:"name"`
		Slug    string   `json:"slug"`
		Plan    string   `json:"plan,omitempty"`
		Domains []string `json:"domains,omitempty"`
	}

	input := createOrgInput{
		Name: d.Get("name").(string),
		Slug: d.Get("slug").(string),
	}
	if v, ok := d.GetOk("plan"); ok {
		input.Plan = v.(string)
	}
	if v, ok := d.GetOk("domains"); ok {
		input.Domains = expandStringList(v.([]interface{}))
	}

	var org organizationResponse
	if err := cfg.http.do(ctx, "POST", "/organizations", input, &org); err != nil {
		return diag.Errorf("creating theauth_organization: %s", err)
	}

	d.SetId(org.ID)
	return setOrganizationState(d, &org)
}

func resourceOrganizationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	var org organizationResponse
	if err := cfg.http.do(ctx, "GET", fmt.Sprintf("/organizations/%s", d.Id()), nil, &org); err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.Errorf("reading theauth_organization %s: %s", d.Id(), err)
	}

	return setOrganizationState(d, &org)
}

func resourceOrganizationUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	type updateOrgInput struct {
		Name    *string  `json:"name,omitempty"`
		Plan    *string  `json:"plan,omitempty"`
		Domains []string `json:"domains,omitempty"`
	}

	input := updateOrgInput{}

	if d.HasChange("name") {
		name := d.Get("name").(string)
		input.Name = &name
	}
	if d.HasChange("plan") {
		plan := d.Get("plan").(string)
		input.Plan = &plan
	}
	if d.HasChange("domains") {
		input.Domains = expandStringList(d.Get("domains").([]interface{}))
	}

	var org organizationResponse
	if err := cfg.http.do(ctx, "PATCH", fmt.Sprintf("/organizations/%s", d.Id()), input, &org); err != nil {
		return diag.Errorf("updating theauth_organization %s: %s", d.Id(), err)
	}

	return setOrganizationState(d, &org)
}

func resourceOrganizationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	if err := cfg.http.do(ctx, "DELETE", fmt.Sprintf("/organizations/%s", d.Id()), nil, nil); err != nil {
		if isNotFound(err) {
			return nil
		}
		return diag.Errorf("deleting theauth_organization %s: %s", d.Id(), err)
	}

	return nil
}

func setOrganizationState(d *schema.ResourceData, org *organizationResponse) diag.Diagnostics {
	var diags diag.Diagnostics

	if err := d.Set("name", org.Name); err != nil {
		diags = append(diags, diagFromErr("name", err))
	}
	if err := d.Set("slug", org.Slug); err != nil {
		diags = append(diags, diagFromErr("slug", err))
	}
	if err := d.Set("plan", org.Plan); err != nil {
		diags = append(diags, diagFromErr("plan", err))
	}
	if err := d.Set("member_count", org.MemberCount); err != nil {
		diags = append(diags, diagFromErr("member_count", err))
	}
	if err := d.Set("created_at", org.CreatedAt); err != nil {
		diags = append(diags, diagFromErr("created_at", err))
	}
	if err := d.Set("updated_at", org.UpdatedAt); err != nil {
		diags = append(diags, diagFromErr("updated_at", err))
	}
	if len(org.Domains) > 0 {
		if err := d.Set("domains", org.Domains); err != nil {
			diags = append(diags, diagFromErr("domains", err))
		}
	}

	return diags
}
