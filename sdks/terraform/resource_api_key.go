package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// apiKeyResponse mirrors the TheAuth API response for API key operations.
type apiKeyResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Prefix    string   `json:"prefix"`
	Key       string   `json:"key,omitempty"` // Only present on creation.
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expiresAt,omitempty"`
	CreatedAt string   `json:"createdAt"`
	LastUsed  *string  `json:"lastUsed,omitempty"`
}

func resourceAPIKey() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a TheAuth API key. " +
			"API keys authenticate server-to-server requests. " +
			"The raw key value is only available immediately after creation — " +
			"store it in a secret manager rather than in Terraform state.",

		CreateContext: resourceAPIKeyCreate,
		ReadContext:   resourceAPIKeyRead,
		UpdateContext: resourceAPIKeyUpdate,
		DeleteContext: resourceAPIKeyDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Human-readable label for this API key, e.g. ci-pipeline or staging-worker.",
			},
			"scopes": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Permission scopes granted to this key, e.g. [\"agents:read\", \"agents:write\"].",
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{
						"agents:read",
						"agents:write",
						"audit:read",
						"delegation:read",
						"delegation:write",
						"organizations:read",
						"organizations:write",
						"admin",
					}, false),
				},
			},
			"expires_at": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.IsRFC3339Time,
				Description:  "RFC 3339 expiry timestamp. Omit to create a non-expiring key.",
			},
			// Computed
			"key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
				Description: "The raw API key value. Only populated immediately after creation. " +
					"This value is not recoverable — if lost, delete and recreate the key.",
			},
			"prefix": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Short prefix identifying this key (e.g. kv_live_abc123). Safe to log.",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RFC 3339 timestamp when this key was created.",
			},
			"last_used": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "RFC 3339 timestamp of last use, if available.",
			},
		},
	}
}

func resourceAPIKeyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	type createAPIKeyInput struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt *string  `json:"expiresAt,omitempty"`
	}

	input := createAPIKeyInput{
		Name:   d.Get("name").(string),
		Scopes: expandStringList(d.Get("scopes").([]interface{})),
	}
	if v, ok := d.GetOk("expires_at"); ok {
		s := v.(string)
		input.ExpiresAt = &s
	}

	var apiKey apiKeyResponse
	if err := cfg.http.do(ctx, "POST", "/api-keys", input, &apiKey); err != nil {
		return diag.Errorf("creating theauth_api_key: %s", err)
	}

	d.SetId(apiKey.ID)
	return setAPIKeyState(d, &apiKey)
}

func resourceAPIKeyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	var apiKey apiKeyResponse
	if err := cfg.http.do(ctx, "GET", fmt.Sprintf("/api-keys/%s", d.Id()), nil, &apiKey); err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.Errorf("reading theauth_api_key %s: %s", d.Id(), err)
	}

	return setAPIKeyState(d, &apiKey)
}

func resourceAPIKeyUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	type updateAPIKeyInput struct {
		Name      *string  `json:"name,omitempty"`
		Scopes    []string `json:"scopes,omitempty"`
		ExpiresAt *string  `json:"expiresAt,omitempty"`
	}

	input := updateAPIKeyInput{}

	if d.HasChange("name") {
		name := d.Get("name").(string)
		input.Name = &name
	}
	if d.HasChange("scopes") {
		input.Scopes = expandStringList(d.Get("scopes").([]interface{}))
	}
	if d.HasChange("expires_at") {
		if v, ok := d.GetOk("expires_at"); ok {
			s := v.(string)
			input.ExpiresAt = &s
		}
	}

	var apiKey apiKeyResponse
	if err := cfg.http.do(ctx, "PATCH", fmt.Sprintf("/api-keys/%s", d.Id()), input, &apiKey); err != nil {
		return diag.Errorf("updating theauth_api_key %s: %s", d.Id(), err)
	}

	return setAPIKeyState(d, &apiKey)
}

func resourceAPIKeyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cfg := meta.(*providerConfig)

	if err := cfg.http.do(ctx, "DELETE", fmt.Sprintf("/api-keys/%s", d.Id()), nil, nil); err != nil {
		if isNotFound(err) {
			return nil
		}
		return diag.Errorf("deleting theauth_api_key %s: %s", d.Id(), err)
	}

	return nil
}

func setAPIKeyState(d *schema.ResourceData, k *apiKeyResponse) diag.Diagnostics {
	var diags diag.Diagnostics

	if err := d.Set("name", k.Name); err != nil {
		diags = append(diags, diagFromErr("name", err))
	}
	if err := d.Set("scopes", k.Scopes); err != nil {
		diags = append(diags, diagFromErr("scopes", err))
	}
	if err := d.Set("prefix", k.Prefix); err != nil {
		diags = append(diags, diagFromErr("prefix", err))
	}
	if err := d.Set("created_at", k.CreatedAt); err != nil {
		diags = append(diags, diagFromErr("created_at", err))
	}
	if k.ExpiresAt != nil {
		if err := d.Set("expires_at", *k.ExpiresAt); err != nil {
			diags = append(diags, diagFromErr("expires_at", err))
		}
	}
	if k.LastUsed != nil {
		if err := d.Set("last_used", *k.LastUsed); err != nil {
			diags = append(diags, diagFromErr("last_used", err))
		}
	}
	// Only set raw key if present — returned only on create.
	if k.Key != "" {
		if err := d.Set("key", k.Key); err != nil {
			diags = append(diags, diagFromErr("key", err))
		}
	}

	return diags
}
