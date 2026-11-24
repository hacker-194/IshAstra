# Terraform Deployment

IshAstra provides a Terraform provider for infrastructure-as-code management.

## Provider Status

**Alpha** — Not yet published to the Terraform Registry. Use a local build or GitHub mirror.

Source: `terraform/ishastra/`

## Quick Start

```bash
# 1. Clone the provider
git clone https://github.com/hacker-194/IshAstra
cd IshAstra/terraform/ishastra

# 2. Build locally (requires Go 1.21+)
go build -o terraform-provider-ishastra_v0.1.0

# 3. Create a local mirror
mkdir -p ~/.terraform.d/plugins/hacker-194/ishastra/0.1.0/linux_amd64/
cp terraform-provider-ishastra_v0.1.0 ~/.terraform.d/plugins/hacker-194/ishastra/0.1.0/linux_amd64/

# 4. Use in your Terraform config
cat > main.tf <<'EOF'
terraform {
  required_providers {
    ishastra = {
      source  = "hacker-194/ishastra"
      version = "~> 0.1"
    }
  }
}

provider "ishastra" {
  api_url = "https://ishastra.example.com"
  api_key = "isk_live_..."
}
EOF

terraform init
terraform plan
```

## Resources

See [`terraform/ishastra/README.md`](../terraform/ishastra/README.md) for complete resource and data source reference.

## Example: Deploy IshAstra on Kubernetes with Terraform

```hcl
# 1. Provision Kubernetes cluster (example: EKS)
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"
  # ... cluster configuration
}

# 2. Deploy IshAstra Helm chart
resource "helm_release" "ishastra" {
  name       = "ishastra"
  repository = "oci://ghcr.io/hacker-194/charts"
  chart      = "ishastra"
  version    = "4.0.0-rc1"
  namespace  = "ishastra"
  create_namespace = true

  values = [
    templatefile("${path.module}/values.yaml.tpl", {
      api_replicas = 2
      worker_replicas = 2
      postgresql_enabled = true
      redis_enabled = true
    })
  ]
}

# 3. Configure IshAstra via provider
provider "ishastra" {
  api_url = "https://ishastra.${var.domain}"
  api_key = kubernetes_secret.ishastra_admin_key.data["api-key"]
}

resource "ishastra_tenant" "prod" {
  name         = "production"
  display_name = "Production Environment"
  plan         = "pro"
}

resource "ishastra_scope" "prod" {
  name = "production-scope"
  json = jsonencode({
    program = "Production Security Assessment"
    authorized_by = "Security Team"
    authorization_ref = "CONTRACT-2024-001"
    include = ["*.${var.domain}"]
    authorized_networks = ["10.0.0.0/8"]
    allowed_ports = [80, 443]
    allow_broad_networks = false
  })
}
```

## Authentication

The provider accepts credentials via:
1. Provider block arguments (`api_url`, `api_key`)
2. Environment variables (`ISHASTRA_API_URL`, `ISHASTRA_API_KEY`)
3. Terraform variables (recommended for CI/CD)

## CI/CD Integration

### GitHub Actions

```yaml
- name: Setup Terraform
  uses: hashicorp/setup-terraform@v3

- name: Terraform Init
  run: terraform init
  env:
    ISHASTRA_API_URL: ${{ secrets.ISHASTRA_API_URL }}
    ISHASTRA_API_KEY: ${{ secrets.ISHASTRA_API_KEY }}

- name: Terraform Plan
  run: terraform plan -out=tfplan
  env:
    ISHASTRA_API_URL: ${{ secrets.ISHASTRA_API_URL }}
    ISHASTRA_API_KEY: ${{ secrets.ISHASTRA_API_KEY }}

- name: Terraform Apply
  if: github.ref == 'refs/heads/main'
  run: terraform apply tfplan
```

## Publishing to Registry (Maintainers)

```bash
# 1. Tag release
git tag -a v0.1.0 -m "Terraform provider v0.1.0"
git push origin v0.1.0

# 2. Build for all platforms
GOOS=linux GOARCH=amd64 go build -o terraform-provider-ishastra_v0.1.0_linux_amd64
GOOS=darwin GOARCH=amd64 go build -o terraform-provider-ishastra_v0.1.0_darwin_amd64
GOOS=windows GOARCH=amd64 go build -o terraform-provider-ishastra_v0.1.0_windows_amd64.exe
# ... arm64 builds

# 3. Create SHA256SUMS
sha256sum terraform-provider-ishastra_v0.1.0_* > SHA256SUMS

# 4. Sign with cosign
cosign sign-blob --blob SHA256SUMS --output-signature SHA256SUMS.sig

# 5. Upload to GitHub Release
gh release upload v0.1.0 terraform-provider-ishastra_v0.1.0_* SHA256SUMS SHA256SUMS.sig

# 6. Submit to Terraform Registry via provider publishing workflow
```

## Roadmap

- [ ] Publish to Terraform Registry (v0.1.0)
- [ ] Add `ishastra_policy` resource (RoE, rate limits)
- [ ] Add `ishastra_webhook` resource (SIEM/ticketing)
- [ ] Import support for existing resources
- [ ] Provider acceptance tests (terraform-plugin-testing)