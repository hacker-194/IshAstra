terraform {
  required_version = ">= 1.5"
  required_providers {
    ishastra = {
      source  = "hacker-194/ishastra"
      version = "~> 0.1"
    }
  }
}

provider "ishastra" {
  # Configuration options
  # api_url   = var.ishastra_api_url
  # api_key   = var.ishastra_api_key
  # Or use environment variables: ISHASTRA_API_URL, ISHASTRA_API_KEY
}

# Example: Create a tenant
# resource "ishastra_tenant" "example" {
#   name        = "example-tenant"
#   display_name = "Example Tenant"
#   plan        = "pro"
# }

# Example: Create an API key for a tenant
# resource "ishastra_api_key" "example" {
#   tenant_id = ishastra_tenant.example.id
#   name      = "terraform-key"
#   role      = "analyst"
# }

# Example: Create an assessment job
# resource "ishastra_assessment" "example" {
#   tenant_id = ishastra_tenant.example.id
#   target    = "https://api.example.com"
#   profile   = "web-deep"
#   scope     = data.ishastra_scope.example.json
# }

# Example: Reference an existing scope
# data "ishastra_scope" "example" {
#   name = "production-scope"
# }

# Example: Create a scope document
# resource "ishastra_scope" "example" {
#   name = "production-scope"
#   json = jsonencode({
#     version = 2
#     program = "Production Assessment"
#     authorized_by = "Security Team"
#     authorization_ref = "CONTRACT-2024-001"
#     include = ["*.example.com"]
#     exclude = ["admin.example.com"]
#     authorized_networks = ["10.0.0.0/8"]
#     allowed_ports = [80, 443]
#     allow_broad_networks = false
#   })
# }