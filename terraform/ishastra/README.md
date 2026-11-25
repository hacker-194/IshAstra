# Terraform Provider for IshAstra

**Status: Alpha — Not published to Terraform Registry yet**

This provider enables infrastructure-as-code management of IshAstra resources:
- Tenants
- API Keys
- Scope Documents
- Assessment Jobs
- Organizations & Teams (PRO+)

## Installation

```hcl
terraform {
  required_providers {
    ishastra = {
      source  = "hacker-194/ishastra"
      version = "~> 0.1"
    }
  }
}
```

Run `terraform init` to download the provider.

## Authentication

Configure via provider block or environment variables:

```hcl
provider "ishastra" {
  api_url = "https://ishastra.example.com"
  api_key = "isk_live_..."
}
```

Or:
```bash
export ISHASTRA_API_URL="https://ishastra.example.com"
export ISHASTRA_API_KEY="isk_live_..."
```

## Resources

| Resource | Description |
|----------|-------------|
| `ishastra_tenant` | Create and manage tenants |
| `ishastra_api_key` | Create and manage API keys |
| `ishastra_scope` | Create and manage scope documents |
| `ishastra_assessment` | Create and run assessments |
| `ishastra_organization` | Create organizations (PRO+) |
| `ishastra_team` | Create teams within organizations (PRO+) |
| `ishastra_membership` | Manage team memberships (PRO+) |

## Data Sources

| Data Source | Description |
|-------------|-------------|
| `ishastra_tenant` | Look up tenant by ID or name |
| `ishastra_scope` | Look up scope document |
| `ishastra_assessment` | Look up assessment job |
| `ishastra_findings` | Query findings from an assessment |

## Example: Complete Assessment Workflow

```hcl
# 1. Create tenant
resource "ishastra_tenant" "prod" {
  name         = "production"
  display_name = "Production Environment"
  plan         = "pro"
}

# 2. Create API key for CI/CD
resource "ishastra_api_key" "ci" {
  tenant_id = ishastra_tenant.prod.id
  name      = "github-actions"
  role      = "analyst"
}

# 3. Define scope
resource "ishastra_scope" "prod" {
  name = "production-scope"
  json = jsonencode({
    version = 2
    program = "Production Security Assessment"
    authorized_by = "Security Team"
    authorization_ref = "CONTRACT-2024-001"
    include = ["api.example.com", "app.example.com"]
    exclude = ["admin.example.com"]
    authorized_networks = ["10.0.0.0/8", "172.16.0.0/12"]
    allowed_ports = [80, 443, 8080]
    allow_broad_networks = false
  })
}

# 4. Run assessment on every deploy
resource "ishastra_assessment" "deploy_scan" {
  tenant_id = ishastra_tenant.prod.id
  target    = "https://api.example.com"
  profile   = "web-deep"
  scope     = ishastra_scope.prod.json
  # Trigger on changes to target or scope
  triggers = {
    target_hash = sha256("https://api.example.com")
    scope_hash  = sha256(ishastra_scope.prod.json)
  }
}

# 5. Output findings for downstream use
data "ishastra_findings" "critical" {
  assessment_id = ishastra_assessment.deploy_scan.id
  severity      = "critical"
}

output "critical_findings_count" {
  value = length(data.ishastra_findings.critical.findings)
}
```

## Scope Document Schema

```json
{
  "version": 2,
  "program": "string",
  "authorized_by": "string",
  "authorization_ref": "string",
  "include": ["string"],
  "exclude": ["string"],
  "authorized_networks": ["string (CIDR)"],
  "allowed_ports": ["integer"],
  "allow_broad_networks": "boolean"
}
```

## Profiles

| Profile | Description |
|---------|-------------|
| `web` | HTTP probe + git exposure check |
| `web-deep` | Crawl, dynamic validation, Nuclei |
| `api` | HTTP probe + OpenAPI discovery |
| `api-deep` | Crawl, OpenAPI, authz, SSRF, dynamic validation, Nuclei |
| `network` | HTTP probe + native TCP + nmap |

## Development

```bash
# Build provider
go build -o terraform-provider-ishastra

# Test locally
export ISHASTRA_API_URL="http://localhost:8000"
export ISHASTRA_API_KEY="isk_test_..."
terraform init && terraform plan
```

## Publishing

Not yet published to the Terraform Registry. For now, use a local mirror or build from source.

## Roadmap

- [ ] Publish to Terraform Registry
- [ ] Add `ishastra_policy` resource (RoE, rate limits, techniques)
- [ ] Add `ishastra_webhook` resource (SIEM/ticketing integrations)
- [ ] Add import support for existing resources
- [ ] Provider acceptance tests