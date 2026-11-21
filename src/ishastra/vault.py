"""Vault integration for secrets management.

Provides a unified interface for retrieving secrets from HashiCorp Vault
with support for Kubernetes auth, token auth, and AppRole auth.
"""

from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)


_hvac: Any = None
_vault_client: Any = None
_vault_initialized = False


def _load_hvac() -> bool:
    """Lazy load hvac module. Returns True if successful."""
    global _hvac
    if _hvac is not None:
        return True
    try:
        import hvac

        _hvac = hvac
        return True
    except ImportError:
        log.debug("hvac not available - install with: pip install hvac")
        return False


class VaultError(Exception):
    """Vault operation error."""


class VaultClient:
    """Wrapper around hvac Client with simplified interface."""

    def __init__(
        self,
        address: str,
        token: str | None = None,
        role: str | None = None,
        k8s_auth_path: str = "kubernetes",
        namespace: str | None = None,
    ):
        if not _load_hvac():
            raise VaultError("hvac not installed. Install with: pip install hvac")

        self.address = address
        self.token = token
        self.role = role
        self.k8s_auth_path = k8s_auth_path
        self.namespace = namespace
        self._client: _hvac.Client | None = None
        self._authenticated = False

    def _create_client(self) -> _hvac.Client:
        """Create hvac client instance."""
        return _hvac.Client(url=self.address, namespace=self.namespace)

    def authenticate(self) -> bool:
        """Authenticate with Vault using available methods."""
        self._client = self._create_client()

        if self.token:
            self._client.token = self.token
            if self._client.is_authenticated():
                self._authenticated = True
                log.info("Vault authenticated via token")
                return True

        if self.role:
            try:
                sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
                if os.path.exists(sa_token_path):
                    with open(sa_token_path) as f:
                        jwt = f.read().strip()

                    response = self._client.auth.kubernetes.login(
                        role=self.role,
                        jwt=jwt,
                        mount_point=self.k8s_auth_path,
                    )
                    self._client.token = response["auth"]["client_token"]
                    if self._client.is_authenticated():
                        self._authenticated = True
                        log.info("Vault authenticated via Kubernetes auth (role=%s)", self.role)
                        return True
            except Exception as e:
                log.warning("Vault Kubernetes auth failed: %s", e)

        role_id = os.environ.get("VAULT_ROLE_ID")
        secret_id = os.environ.get("VAULT_SECRET_ID")
        if role_id and secret_id:
            try:
                response = self._client.auth.approle.login(role_id=role_id, secret_id=secret_id)
                self._client.token = response["auth"]["client_token"]
                if self._client.is_authenticated():
                    self._authenticated = True
                    log.info("Vault authenticated via AppRole")
                    return True
            except Exception as e:
                log.warning("Vault AppRole auth failed: %s", e)

        return False

    def ensure_authenticated(self) -> None:
        """Ensure client is authenticated, re-auth if needed."""
        if (
            not self._authenticated or not self._client or not self._client.is_authenticated()
        ) and not self.authenticate():
            raise VaultError("Failed to authenticate with Vault")

    def read_secret(
        self, path: str, mount_point: str = "secret", version: int | None = None
    ) -> dict[str, Any]:
        """Read a secret from Vault KV v2."""
        self.ensure_authenticated()
        if self._client is None:
            raise VaultError("Vault client not initialized")
        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount_point,
                version=version,
            )
            return response["data"]["data"]
        except _hvac.exceptions.InvalidPath:
            return {}
        except Exception as e:
            log.error("Failed to read secret %s: %s", path, e)
            raise VaultError(f"Failed to read secret {path}: {e}") from e

    def write_secret(self, path: str, secret: dict[str, Any], mount_point: str = "secret") -> bool:
        """Write a secret to Vault KV v2."""
        self.ensure_authenticated()
        if self._client is None:
            raise VaultError("Vault client not initialized")
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret,
                mount_point=mount_point,
            )
            return True
        except Exception as e:
            log.error("Failed to write secret %s: %s", path, e)
            raise VaultError(f"Failed to write secret {path}: {e}") from e

    def delete_secret(self, path: str, mount_point: str = "secret") -> bool:
        """Delete a secret from Vault KV v2."""
        self.ensure_authenticated()
        if self._client is None:
            raise VaultError("Vault client not initialized")
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=mount_point,
            )
            return True
        except Exception as e:
            log.error("Failed to delete secret %s: %s", path, e)
            raise VaultError(f"Failed to delete secret {path}: {e}") from e

    def list_secrets(self, path: str, mount_point: str = "secret") -> list[str]:
        """List secrets at a path."""
        self.ensure_authenticated()
        assert self._client is not None
        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=mount_point,
            )
            return response["data"]["keys"]
        except Exception as e:
            log.error("Failed to list secrets at %s: %s", path, e)
            raise VaultError(f"Failed to list secrets at {path}: {e}") from e


_vault_client_instance: VaultClient | None = None


def get_vault_client() -> VaultClient | None:
    """Get or create the global Vault client."""
    global _vault_client_instance, _vault_initialized

    if _vault_client_instance is not None:
        return _vault_client_instance

    if not _load_hvac():
        return None

    settings = None
    try:
        from ishastra.config import get_settings

        settings = get_settings()
    except Exception as e:
        log.error("Failed to load settings: %s", e)
        raise

    if settings and settings.vault_enabled:
        try:
            client = VaultClient(
                address=settings.vault_address,
                token=settings.vault_token or None,
                role=settings.vault_role or None,
                k8s_auth_path=settings.vault_k8s_auth_path,
            )
            if client.authenticate():
                _vault_client_instance = client
                _vault_initialized = True
                log.info("Vault client initialized successfully")
                return client
            log.warning("Vault client created but authentication failed")
        except Exception as e:
            log.error("Failed to initialize Vault client: %s", e)

    return None


def read_vault_secret(path: str, mount_point: str = "secret") -> dict[str, Any]:
    """Read a secret from Vault (convenience function)."""
    client = get_vault_client()
    if not client:
        return {}
    return client.read_secret(path, mount_point)


def write_vault_secret(path: str, secret: dict[str, Any], mount_point: str = "secret") -> bool:
    """Write a secret to Vault (convenience function)."""
    client = get_vault_client()
    if not client:
        return False
    return client.write_secret(path, secret, mount_point)


def delete_secret(path: str, mount_point: str = "secret") -> bool:
    """Delete a secret from Vault (convenience function)."""
    client = get_vault_client()
    if not client:
        return False
    return client.delete_secret(path, mount_point)


def list_secrets(path: str, mount_point: str = "secret") -> list[str]:
    """List secrets at a path in Vault (convenience function)."""
    client = get_vault_client()
    if not client:
        return []
    return client.list_secrets(path, mount_point)


def load_secrets_from_vault(prefix: str = "ishastra") -> dict[str, str]:
    """Load all secrets from a Vault path and return as flat dict.

    Expected structure in Vault:
    secret/data/ishastra/
      ISHASTRA_API_KEY: "sk_live_..."
      ISHASTRA_AUDIT_HMAC_KEY: "base64..."
      ISHASTRA_ENCRYPTION_KEY: "base64..."
      ISHASTRA_WEBHOOK_SECRET: "base64..."
      ISHASTRA_DATABASE_URL: "postgresql://..."
      ...
    """
    client = get_vault_client()
    if not client:
        return {}

    try:
        secrets = client.read_secret(prefix)

        flat = {}
        for key, value in secrets.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    flat[f"{key}_{sub_key}".upper()] = str(sub_value)
            else:
                flat[key.upper()] = str(value)
        log.info("Loaded %d secrets from Vault", len(flat))
        return flat
    except Exception as e:
        log.error("Failed to load secrets from Vault: %s", e)
        return {}


def inject_vault_secrets_into_env(prefix: str = "ishastra") -> int:
    """Load secrets from Vault and inject into environment variables.

    Returns number of secrets injected.
    Does not overwrite existing environment variables.
    """
    secrets = load_secrets_from_vault(prefix)
    count = 0
    for key, value in secrets.items():
        env_key = f"ISHASTRA_{key}" if not key.startswith("ISHASTRA_") else key
        if env_key not in os.environ:
            os.environ[env_key] = value
            count += 1
    return count
