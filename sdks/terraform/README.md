# terraform-provider-kavachos

Terraform provider for [KavachOS](https://kavachos.dev). Manages agent identities, permissions, API keys, and organizations as infrastructure.

## Why IaC for auth

Auth config drifts. An agent created by hand in a dashboard has no audit trail, no review process, and no rollback path. Treating agents and permissions as Terraform resources means every grant goes through code review, every change is versioned, and destroying the environment tears down the access alongside it.

## Requirements

- Terraform 1.5 or later
- Go 1.21 or later (to build from source)
- A running KavachOS deployment

## Build and install

```bash
git clone https://github.com/kavachos/terraform-provider-kavachos
cd terraform-provider-kavachos/sdks/terraform

go build -o terraform-provider-kavachos .

# Install into the local plugin cache
OS=$(go env GOOS)
ARCH=$(go env GOARCH)
PLUGIN_DIR=~/.terraform.d/plugins/registry.terraform.io/kavachos/kavachos/0.1.0/${OS}_${ARCH}
mkdir -p "$PLUGIN_DIR"
mv terraform-provider-kavachos "$PLUGIN_DIR/"
```

Add a dev override to your Terraform configuration:

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "kavachos/kavachos" = "/path/to/sdks/terraform"
  }
  direct {}
}
```

## Provider configuration

```hcl
terraform {
  required_providers {
    kavachos = {
      source  = "kavachos/kavachos"
      version = "~> 0.1"
    }
  }
}

provider "kavachos" {
  base_url = "https://your-app.com/api/kavach"
  token    = var.kavachos_token
}
```

Both arguments can be set via environment variables instead:

```bash
export KAVACHOS_BASE_URL=https://your-app.com/api/kavach
export KAVACHOS_TOKEN=kv_live_...
```

| Argument   | Env var              | Required | Description                              |
|------------|----------------------|----------|------------------------------------------|
| `base_url` | `KAVACHOS_BASE_URL`  | yes      | Base URL of your KavachOS deployment     |
| `token`    | `KAVACHOS_TOKEN`     | yes      | API token (admin scope recommended)      |

## Resources

### `kavachos_agent`

Manages a KavachOS agent identity.

```hcl
resource "kavachos_agent" "github_reader" {
  owner_id = "user-123"
  name     = "github-reader"
  type     = "autonomous"   # autonomous | delegated | service

  permission {
    resource = "mcp:github:*"
    actions  = ["read"]
  }

  permission {
    resource = "mcp:deploy:production"
    actions  = ["execute"]
    constraints {
      require_approval    = true
      max_calls_per_hour = 10
      ip_allowlist        = ["10.0.0.0/8"]
    }
  }

  expires_at = "2026-12-31T23:59:59Z"
}
```

**Arguments**

| Name          | Type   | Required | Description                                        |
|---------------|--------|----------|----------------------------------------------------|
| `owner_id`    | string | yes      | ID of the owning user                              |
| `name`        | string | yes      | Human-readable name                                |
| `type`        | string | yes      | `autonomous`, `delegated`, or `service`            |
| `permission`  | block  | no       | One or more permission grants (see below)          |
| `expires_at`  | string | no       | RFC 3339 expiry timestamp                          |

**Permission block**

| Name                   | Type         | Required | Description                               |
|------------------------|--------------|----------|-------------------------------------------|
| `resource`             | string       | yes      | Resource pattern, e.g. `mcp:github:*`    |
| `actions`              | list(string) | yes      | Allowed actions                           |
| `constraints`          | block        | no       | Optional usage constraints                |

**Constraints block**

| Name                   | Type         | Description                               |
|------------------------|--------------|-------------------------------------------|
| `require_approval`     | bool         | Require human approval before execution   |
| `max_calls_per_hour`   | number       | Rate limit per hour                       |
| `allowed_arg_patterns` | list(string) | Glob patterns for argument values         |
| `ip_allowlist`         | list(string) | CIDR blocks allowed to exercise the grant |

**Computed attributes**: `token` (sensitive), `status`, `created_at`, `updated_at`.

The `token` attribute is only populated on resource creation. Store it securely, read it with `terraform output -raw <name>`, and inject it into your agent's environment.

**Import**

```bash
terraform import kavachos_agent.github_reader <agent-id>
```

---

### `kavachos_permission`

Grants a single permission to an existing agent. Prefer inline `permission` blocks on `kavachos_agent` when you control both resources in the same module.

```hcl
resource "kavachos_permission" "extra_access" {
  agent_id           = kavachos_agent.github_reader.id
  resource           = "mcp:deploy:staging"
  actions            = ["execute"]
  require_approval   = true
  max_calls_per_hour = 5
}
```

**Arguments**

| Name                   | Type         | Required | Description                           |
|------------------------|--------------|----------|---------------------------------------|
| `agent_id`             | string       | yes      | ID of the target agent                |
| `resource`             | string       | yes      | Resource pattern                      |
| `actions`              | list(string) | yes      | Allowed actions                       |
| `require_approval`     | bool         | no       | Default `false`                       |
| `max_calls_per_hour`   | number       | no       |                                       |
| `allowed_arg_patterns` | list(string) | no       |                                       |
| `ip_allowlist`         | list(string) | no       |                                       |

---

### `kavachos_api_key`

Manages a KavachOS API key for server-to-server authentication.

```hcl
resource "kavachos_api_key" "ci_key" {
  name   = "ci-pipeline"
  scopes = ["agents:read", "agents:write"]
}

output "ci_key_value" {
  value     = kavachos_api_key.ci_key.key
  sensitive = true
}
```

**Arguments**

| Name         | Type         | Required | Description                                      |
|--------------|--------------|----------|--------------------------------------------------|
| `name`       | string       | yes      | Label for the key                                |
| `scopes`     | list(string) | yes      | Permission scopes (see valid values below)       |
| `expires_at` | string       | no       | RFC 3339 expiry timestamp                        |

**Valid scopes**: `agents:read`, `agents:write`, `audit:read`, `delegation:read`, `delegation:write`, `organizations:read`, `organizations:write`, `admin`.

**Computed attributes**: `key` (sensitive, only on create), `prefix`, `created_at`, `last_used`.

**Import**

```bash
terraform import kavachos_api_key.ci_key <key-id>
```

Note: the raw key value is not recoverable via import. Only the ID and metadata are restored.

---

### `kavachos_organization`

Manages a KavachOS organization for multi-tenant isolation.

```hcl
resource "kavachos_organization" "engineering" {
  name = "Engineering"
  slug = "engineering"
  plan = "pro"
}
```

**Arguments**

| Name      | Type         | Required | Description                                    |
|-----------|--------------|----------|------------------------------------------------|
| `name`    | string       | yes      | Display name                                   |
| `slug`    | string       | yes      | URL-safe ID, immutable after creation          |
| `plan`    | string       | no       | `free`, `pro`, or `enterprise`                 |
| `domains` | list(string) | no       | Verified domains                               |

**Computed attributes**: `member_count`, `created_at`, `updated_at`.

**Import**

```bash
terraform import kavachos_organization.engineering <org-id>
```

---

## Data sources

### `kavachos_agent`

Reads a single agent by ID.

```hcl
data "kavachos_agent" "existing" {
  id = "agent-id"
}

output "status" {
  value = data.kavachos_agent.existing.status
}
```

---

### `kavachos_agents`

Lists agents with optional filters.

```hcl
data "kavachos_agents" "active" {
  owner_id = "user-123"
  status   = "active"
  type     = "autonomous"
}

output "count" {
  value = length(data.kavachos_agents.active.agents)
}
```

**Filter arguments**: `owner_id`, `status` (`active` | `revoked` | `expired`), `type` (`autonomous` | `delegated` | `service`).

Each item in `agents` has: `id`, `owner_id`, `name`, `type`, `status`, `expires_at`, `created_at`, `updated_at`.

---

## Import existing resources

Resources provisioned outside Terraform can be imported:

```bash
# Import an agent
terraform import kavachos_agent.my_bot agent-abc123

# Import an API key (raw key value is not recoverable via import)
terraform import kavachos_api_key.ci kv_key_abc123

# Import an organization
terraform import kavachos_organization.eng org-xyz789
```

After importing, run `terraform plan` to verify state matches your configuration.

---

## GitOps workflow

A minimal setup for managing KavachOS configuration alongside application code:

```
.
├── infra/
│   ├── main.tf           # Provider + org
│   ├── agents.tf         # All agent definitions
│   ├── api_keys.tf       # CI and service API keys
│   └── variables.tf
└── .github/workflows/
    └── terraform.yml
```

```yaml
# .github/workflows/terraform.yml
name: Terraform

on:
  push:
    branches: [main]
    paths: ['infra/**']
  pull_request:
    paths: ['infra/**']

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: "1.8"
      - name: Init
        run: terraform -chdir=infra init
      - name: Plan
        env:
          KAVACHOS_BASE_URL: ${{ secrets.KAVACHOS_BASE_URL }}
          KAVACHOS_TOKEN: ${{ secrets.KAVACHOS_TOKEN }}
        run: terraform -chdir=infra plan -out=tfplan
      - name: Apply (main branch only)
        if: github.ref == 'refs/heads/main'
        run: terraform -chdir=infra apply tfplan
```

PR-based review ensures every permission change has a diff, a reviewer, and an audit trail before it reaches production.

---

## Development

```bash
cd sdks/terraform
go build ./...
go vet ./...
```

To use a local copy of the Go SDK during development, uncomment the replace directive in `go.mod`:

```
replace github.com/kavachos/kavachos-go => ../go
```

Run `go mod tidy` after making changes.
