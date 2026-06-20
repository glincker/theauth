terraform {
  required_version = ">= 1.5"
  required_providers {
    theauth = {
      source  = "theauth/theauth"
      version = "~> 0.1"
    }
  }
}

# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------
# Pass credentials via environment variables in CI:
#   export THEAUTH_BASE_URL=https://your-app.com/api/kavach
#   export THEAUTH_TOKEN=kv_live_...
#
# Or explicitly (use variables rather than hardcoding):
provider "theauth" {
  base_url = var.theauth_base_url
  token    = var.theauth_token
}

variable "theauth_base_url" {
  type        = string
  description = "Base URL of the TheAuth deployment."
}

variable "theauth_token" {
  type        = string
  sensitive   = true
  description = "API token for TheAuth."
}

# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------
resource "theauth_organization" "engineering" {
  name = "Engineering"
  slug = "engineering"
  plan = "pro"
}

# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
resource "theauth_api_key" "ci_pipeline" {
  name   = "ci-pipeline"
  scopes = ["agents:read", "agents:write", "audit:read"]
}

resource "theauth_api_key" "readonly_monitor" {
  name       = "monitoring-read"
  scopes     = ["agents:read", "audit:read"]
  expires_at = "2027-01-01T00:00:00Z"
}

# Store the raw key in an output so it can be injected into CI secrets.
# In production, consider writing this to AWS Secrets Manager or Vault instead.
output "ci_api_key" {
  value     = theauth_api_key.ci_pipeline.key
  sensitive = true
}

# ---------------------------------------------------------------------------
# GitHub reader agent — read-only access to GitHub MCP tools
# ---------------------------------------------------------------------------
resource "theauth_agent" "github_reader" {
  owner_id = "user-123"
  name     = "github-reader"
  type     = "autonomous"

  permission {
    resource = "mcp:github:*"
    actions  = ["read"]
  }

  permission {
    resource = "mcp:github:repos:delete"
    actions  = ["execute"]
    constraints {
      require_approval = true
    }
  }
}

# ---------------------------------------------------------------------------
# Deploy agent — limited production access with rate limiting and approval
# ---------------------------------------------------------------------------
resource "theauth_agent" "deploy_bot" {
  owner_id   = "user-123"
  name       = "deploy-bot"
  type       = "autonomous"
  expires_at = "2026-12-31T23:59:59Z"

  permission {
    resource = "mcp:deploy:staging"
    actions  = ["execute"]
    constraints {
      max_calls_per_hour = 20
    }
  }

  permission {
    resource = "mcp:deploy:production"
    actions  = ["execute"]
    constraints {
      require_approval    = true
      max_calls_per_hour = 5
      ip_allowlist        = ["10.0.0.0/8", "172.16.0.0/12"]
    }
  }
}

# ---------------------------------------------------------------------------
# Service account for internal tooling — no expiry, narrow scope
# ---------------------------------------------------------------------------
resource "theauth_agent" "internal_analytics" {
  owner_id = "user-123"
  name     = "internal-analytics"
  type     = "service"

  permission {
    resource = "mcp:analytics:read"
    actions  = ["read", "export"]
    constraints {
      allowed_arg_patterns = ["report:*", "dashboard:*"]
    }
  }
}

# ---------------------------------------------------------------------------
# Data source examples
# ---------------------------------------------------------------------------

# Look up an agent that was not created by this config.
data "theauth_agent" "legacy_bot" {
  id = "agent-id-of-existing-bot"
}

output "legacy_bot_status" {
  value = data.theauth_agent.legacy_bot.status
}

# List all active autonomous agents owned by a specific user.
data "theauth_agents" "active_bots" {
  owner_id = "user-123"
  status   = "active"
  type     = "autonomous"
}

output "active_bot_count" {
  value = length(data.theauth_agents.active_bots.agents)
}

# ---------------------------------------------------------------------------
# Standalone permission grant (cross-module pattern)
# ---------------------------------------------------------------------------
# Use theauth_permission when one module creates the agent and another
# grants permissions. If you control both, use inline permission blocks instead.
resource "theauth_permission" "ops_deploy_access" {
  agent_id           = theauth_agent.deploy_bot.id
  resource           = "mcp:ops:restart"
  actions            = ["execute"]
  require_approval   = true
  max_calls_per_hour = 3
}
