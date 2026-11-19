#!/usr/bin/env python3
"""
Generate production-ready secrets for Strix Helm deployment.

Usage:
    python3 scripts/generate-secrets.py [--output-dir OUTPUT_DIR] [--values-file VALUES_FILE]

Outputs:
    - secrets.yaml: Kubernetes Secret manifest (apply with kubectl apply -f)
    - values-secrets.yaml: Helm values snippet to include in your deployment
    - .env.secrets: Environment file for local development

All secrets are generated with cryptographically secure randomness.
"""

import argparse
import base64
import json
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path


def generate_ed25519_key() -> tuple[bytes, str]:
    """Generate Ed25519 keypair, return (private_key_pem, public_key_jwk)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        print("error: cryptography package required. Install with: pip install cryptography", file=sys.stderr)
        sys.exit(1)

    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # JWK format for Ed25519
    import base64

    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip("="),
        "kid": f"strix-{secrets.token_hex(8)}",
        "use": "sig",
        "alg": "EdDSA",
    }
    return private_pem, json.dumps(jwk)


def generate_aes256_key() -> str:
    """Generate a 32-byte AES-256 key, base64 encoded."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def generate_hmac_key() -> str:
    """Generate a 32-byte HMAC key, base64 encoded."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def generate_api_key() -> str:
    """Generate a secure API key (sk_live_ prefix for production)."""
    return f"sk_live_{secrets.token_urlsafe(32)}"


def generate_password(length: int = 32) -> str:
    """Generate a secure random password."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_database_url(host: str, port: int, username: str, password: str, database: str) -> str:
    """Generate PostgreSQL connection URL."""
    return f"postgresql://{username}:{password}@{host}:{port}/{database}"


def main():
    parser = argparse.ArgumentParser(description="Generate Strix production secrets")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory (default: current directory)",
    )
    parser.add_argument(
        "--values-file",
        default="values-secrets.yaml",
        help="Output Helm values file name (default: values-secrets.yaml)",
    )
    parser.add_argument(
        "--namespace",
        default="strix",
        help="Kubernetes namespace (default: strix)",
    )
    parser.add_argument(
        "--postgres-host",
        default="strix-postgresql",
        help="PostgreSQL host (default: strix-postgresql)",
    )
    parser.add_argument(
        "--postgres-port",
        type=int,
        default=5432,
        help="PostgreSQL port (default: 5432)",
    )
    parser.add_argument(
        "--postgres-user",
        default="strix",
        help="PostgreSQL username (default: strix)",
    )
    parser.add_argument(
        "--postgres-db",
        default="strix",
        help="PostgreSQL database name (default: strix)",
    )
    parser.add_argument(
        "--redis-host",
        default="strix-redis-master",
        help="Redis host (default: strix-redis-master)",
    )
    parser.add_argument(
        "--redis-port",
        type=int,
        default=6379,
        help="Redis port (default: 6379)",
    )
    parser.add_argument(
        "--k8s-manifest",
        action="store_true",
        help="Also generate Kubernetes Secret manifest (secrets.yaml)",
    )
    parser.add_argument(
        "--env-file",
        action="store_true",
        help="Also generate .env.secrets for local development",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Generating Strix production secrets...")
    print(f"Output directory: {output_dir}")

    # Generate all secrets
    ed25519_private_pem, ed25519_jwk = generate_ed25519_key()
    strix_api_key = generate_api_key()
    strix_audit_hmac_key = generate_hmac_key()
    strix_webhook_secret = generate_hmac_key()
    strix_encryption_key = generate_aes256_key()
    redis_password = generate_password(32)
    postgres_password = generate_password(32)
    grafana_admin_password = generate_password(24)

    # Database URL
    database_url = generate_database_url(
        args.postgres_host,
        args.postgres_port,
        args.postgres_user,
        postgres_password,
        args.postgres_db,
    )

    # Build Helm values snippet
    values_content = f"""# Strix Production Secrets - Generated {datetime.now(UTC).isoformat()}
# ⚠️  THIS FILE CONTAINS SENSITIVE SECRETS - DO NOT COMMIT TO GIT
# Store in a secret manager (Vault, SealedSecrets, External Secrets Operator)
# and reference via `helm upgrade --install -f values-secrets.yaml`

secrets:
  enabled: true
  createSecrets: false  # Let External Secrets / SealedSecrets manage the actual Secret
  strixSecrets:
    STRIX_API_KEY: "{strix_api_key}"
    STRIX_AUDIT_HMAC_KEY: "{strix_audit_hmac_key}"
    STRIX_WEBHOOK_SECRET: "{strix_webhook_secret}"
    STRIX_ENCRYPTION_KEY: "{strix_encryption_key}"
    STRIX_DATABASE_URL: "{database_url}"
  redisSecret:
    redis-password: "{redis_password}"
  postgresqlSecret:
    postgresql-password: "{postgres_password}"
  grafanaSecret:
    admin-user: "admin"
    admin-password: "{grafana_admin_password}"
  annotations:
    secrets-store.csi.k8s.io/secret-name: "strix-secrets"
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "strix"
    vault.hashicorp.com/secret-path: "secret/data/strix"
"""

    values_path = output_dir / args.values_file
    values_path.write_text(values_content)
    values_path.chmod(0o600)
    print(f"✓ Helm values: {values_path} (mode 600)")

    # Generate Kubernetes Secret manifest if requested
    if args.k8s_manifest:
        import yaml

        secret_manifest = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "strix-secrets",
                "namespace": args.namespace,
                "labels": {
                    "app.kubernetes.io/name": "strix",
                    "app.kubernetes.io/component": "secrets",
                    "app.kubernetes.io/managed-by": "Helm",
                },
            },
            "type": "Opaque",
            "stringData": {
                "STRIX_API_KEY": strix_api_key,
                "STRIX_AUDIT_HMAC_KEY": strix_audit_hmac_key,
                "STRIX_WEBHOOK_SECRET": strix_webhook_secret,
                "STRIX_ENCRYPTION_KEY": strix_encryption_key,
                "STRIX_DATABASE_URL": database_url,
            },
        }

        manifest_path = output_dir / "secrets.yaml"
        manifest_path.write_text(yaml.dump(secret_manifest, default_flow_style=False))
        manifest_path.chmod(0o600)
        print(f"✓ K8s Secret manifest: {manifest_path} (mode 600)")

    # Generate .env.secrets for local development
    if args.env_file:
        env_content = f"""# Strix Local Development Secrets - Generated {datetime.now(UTC).isoformat()}
# Source this file: source .env.secrets
# ⚠️  DO NOT COMMIT TO GIT

export STRIX_API_KEY="{strix_api_key}"
export STRIX_AUDIT_HMAC_KEY="{strix_audit_hmac_key}"
export STRIX_WEBHOOK_SECRET="{strix_webhook_secret}"
export STRIX_ENCRYPTION_KEY="{strix_encryption_key}"
export STRIX_DATABASE_URL="{database_url}"
export STRIX_REDIS_URL="redis://:{redis_password}@{args.redis_host}:{args.redis_port}/0"
export STRIX_LOG_LEVEL="DEBUG"
export STRIX_SCOPE_DIR="/etc/strix/scopes"
export STRIX_SCOPE_JWKS="/etc/strix/scope-jwks.json"
"""

        env_path = output_dir / ".env.secrets"
        env_path.write_text(env_content)
        env_path.chmod(0o600)
        print(f"✓ Local env file: {env_path} (mode 600)")

    # Save Ed25519 private key for scope signing
    key_path = output_dir / "scope-signing-key.pem"
    key_path.write_bytes(ed25519_private_pem)
    key_path.chmod(0o600)
    print(f"✓ Scope signing key: {key_path} (mode 600)")

    # Save JWKS
    jwks_path = output_dir / "scope-jwks.json"
    jwks_path.write_text(json.dumps({"keys": [json.loads(ed25519_jwk)]}, indent=2) + "\n")
    jwks_path.chmod(0o644)
    print(f"✓ JWKS: {jwks_path}")

    print("\n" + "=" * 60)
    print("SECRET SUMMARY (save these securely!)")
    print("=" * 60)
    print(f"STRIX_API_KEY:              {strix_api_key}")
    print(f"STRIX_AUDIT_HMAC_KEY:       {strix_audit_hmac_key}")
    print(f"STRIX_WEBHOOK_SECRET:       {strix_webhook_secret}")
    print(f"STRIX_ENCRYPTION_KEY:       {strix_encryption_key}")
    print(f"STRIX_DATABASE_URL:         {database_url}")
    print(f"Redis password:             {redis_password}")
    print(f"PostgreSQL password:        {postgres_password}")
    print(f"Grafana admin password:     {grafana_admin_password}")
    print(f"Scope signing key:          {key_path}")
    print(f"JWKS (public):              {jwks_path}")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Store these secrets in your secret manager (Vault, AWS Secrets Manager, etc.)")
    print("2. Use External Secrets Operator or SealedSecrets to sync to Kubernetes")
    print("3. Deploy with: helm upgrade --install strix ./deploy/helm/strix -f values-secrets.yaml")
    print("4. For local dev: source .env.secrets && docker-compose up -d")


if __name__ == "__main__":
    main()
