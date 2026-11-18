"""SCIM 2.0 Provisioning for Strix.

Implements RFC 7644 (SCIM Protocol) for user and group management.
Supports Okta, Entra ID, Keycloak, Auth0 SCIM clients.

Endpoints:
- /scim/v2/Users - User management
- /scim/v2/Groups - Group management
- /scim/v2/ServiceProviderConfig - Provider capabilities
- /scim/v2/Schemas - Supported schemas
- /scim/v2/ResourceTypes - Resource type definitions

Attribute mapping:
- userName -> email (unique identifier)
- displayName -> name
- emails -> email address
- groups -> roles (admin, analyst, viewer)
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from strix.core import store

log = logging.getLogger(__name__)

# SCIM Constants
SCIM_VERSION = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

# Strix-specific schemas
STRIX_USER_SCHEMA = "urn:strix:params:scim:schemas:core:2.0:User"
STRIX_GROUP_SCHEMA = "urn:strix:params:scim:schemas:core:2.0:Group"


def _scim_timestamp(ts: float) -> str:
    """RFC 3339 UTC timestamp with microsecond precision."""
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class SCIMEmail(BaseModel):
    """SCIM email attribute."""

    value: str
    type: str = "work"
    primary: bool = True


class SCIMName(BaseModel):
    """SCIM name attribute."""

    formatted: str | None = None
    familyName: str | None = None
    givenName: str | None = None


class SCIMGroupRef(BaseModel):
    """SCIM group reference."""

    value: str
    display: str | None = None
    type: str = "direct"


class SCIMMeta(BaseModel):
    """SCIM resource metadata."""

    resourceType: str
    created: str
    lastModified: str
    location: str | None = None
    version: str | None = None


class SCIMUser(BaseModel):
    """SCIM User resource per RFC 7643."""

    schemas: list[str] = Field(default_factory=lambda: [SCIM_USER_SCHEMA, STRIX_USER_SCHEMA])
    id: str | None = None
    externalId: str | None = None
    userName: str  # Maps to email
    name: SCIMName | None = None
    displayName: str | None = None
    emails: list[SCIMEmail] = Field(default_factory=list)
    active: bool = True
    groups: list[SCIMGroupRef] = Field(default_factory=list)
    meta: SCIMMeta | None = None

    # Strix extensions
    role: str | None = None  # admin, analyst, viewer
    tenant_id: str | None = None

    @field_validator("userName")
    @classmethod
    def validate_userName(cls, v: str) -> str:
        if not v or "@" not in v:
            raise ValueError("userName must be a valid email address")
        return v.lower()

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is not None and v not in ("admin", "analyst", "viewer"):
            raise ValueError("role must be one of: admin, analyst, viewer")
        return v

    def to_strix_user(self) -> dict[str, Any]:
        """Convert SCIM user to Strix tenant user format."""
        email = self.userName
        display_name = self.displayName or (self.name.formatted if self.name else None) or email.split("@")[0]
        role = self.role or "analyst"

        # Determine scope from role
        scope = "read" if role == "viewer" else "write"

        return {
            "email": email,
            "display_name": display_name,
            "role": role,
            "scope": scope,
            "active": self.active,
            "external_id": self.externalId,
            "groups": [g.value for g in self.groups],
        }


class SCIMGroup(BaseModel):
    """SCIM Group resource per RFC 7643."""

    schemas: list[str] = Field(default_factory=lambda: [SCIM_GROUP_SCHEMA, STRIX_GROUP_SCHEMA])
    id: str | None = None
    externalId: str | None = None
    displayName: str
    members: list[SCIMGroupRef] = Field(default_factory=list)
    meta: SCIMMeta | None = None

    # Strix extensions
    tenant_id: str | None = None
    org_id: str | None = None

    def to_strix_group(self) -> dict[str, Any]:
        """Convert SCIM group to Strix format."""
        return {
            "display_name": self.displayName,
            "external_id": self.externalId,
            "tenant_id": self.tenant_id,
            "org_id": self.org_id,
            "member_ids": [m.value for m in self.members],
        }


class SCIMListResponse(BaseModel):
    """SCIM ListResponse per RFC 7644."""

    schemas: list[str] = Field(default_factory=lambda: [SCIM_LIST_RESPONSE_SCHEMA])
    totalResults: int
    itemsPerPage: int
    startIndex: int
    Resources: list[Any] = Field(default_factory=list)


class SCIMError(BaseModel):
    """SCIM Error response per RFC 7644."""

    schemas: list[str] = Field(default_factory=lambda: [SCIM_VERSION])
    status: int
    detail: str
    scimType: str | None = None


# SCIM Service Provider Configuration
class SCIMServiceProviderConfig(BaseModel):
    """SCIM Service Provider Configuration per RFC 7644 Section 4."""

    schemas: list[str] = Field(
        default_factory=lambda: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"]
    )
    patch: dict[str, bool] = Field(default_factory=lambda: {"supported": True})
    bulk: dict[str, Any] = Field(
        default_factory=lambda: {"supported": False, "maxOperations": 1000, "maxPayloadSize": 1048576}
    )
    filter: dict[str, Any] = Field(default_factory=lambda: {"supported": True, "maxResults": 200})
    changePassword: dict[str, bool] = Field(default_factory=lambda: {"supported": False})
    sort: dict[str, bool] = Field(default_factory=lambda: {"supported": True})
    etag: dict[str, bool] = Field(default_factory=lambda: {"supported": False})
    authenticationSchemes: list[dict[str, Any]] = Field(
        default_factory=lambda: [
            {
                "name": "OAuth Bearer Token",
                "description": "Bearer token authentication for SCIM endpoints",
                "specUri": "https://tools.ietf.org/html/rfc6750",
                "type": "oauthbearertoken",
                "primary": True,
            }
        ]
    )


class SCIMResourceType(BaseModel):
    """SCIM Resource Type per RFC 7644 Section 4."""

    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"])
    id: str
    name: str
    endpoint: str
    description: str
    schema_: str = Field(alias="schema")
    schemaExtensions: list[dict[str, Any]] = Field(default_factory=list)


class SCIMResourceTypesResponse(BaseModel):
    """SCIM Resource Types response."""

    schemas: list[str] = Field(default_factory=lambda: [SCIM_LIST_RESPONSE_SCHEMA])
    totalResults: int
    itemsPerPage: int
    startIndex: int
    Resources: list[SCIMResourceType] = Field(default_factory=list)


class SCIMSchema(BaseModel):
    """SCIM Schema definition per RFC 7644 Section 4."""

    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:schemas:core:2.0:Schema"])
    id: str
    name: str
    description: str
    attributes: list[dict[str, Any]]
    meta: dict[str, Any] = Field(default_factory=dict)


class SCIMSchemasResponse(BaseModel):
    """SCIM Schemas response."""

    schemas: list[str] = Field(default_factory=lambda: [SCIM_LIST_RESPONSE_SCHEMA])
    totalResults: int
    itemsPerPage: int
    startIndex: int
    Resources: list[SCIMSchema] = Field(default_factory=list)


@dataclass
class SCIMFilter:
    """Parsed SCIM filter expression."""

    attribute: str
    operator: str  # eq, ne, co, sw, ew, gt, lt, ge, le, pr
    value: str | None = None


class SCIMStore:
    """SCIM data persistence layer using Strix database."""

    @staticmethod
    def _generate_scim_id(prefix: str) -> str:
        """Generate a SCIM-compatible ID."""
        return f"{prefix}_{uuid.uuid4().hex[:24]}"

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def _generate_api_key() -> str:
        """Generate a new API key."""
        return f"strix_scim_{secrets.token_urlsafe(32)}"

    # User operations

    async def create_user(self, user: SCIMUser, tenant_id: str, scim_token: str) -> SCIMUser:
        """Create a new SCIM user (provisions in Strix)."""
        # Check if user already exists
        existing = await self.get_user_by_username(user.userName, tenant_id)
        if existing:
            raise ValueError(f"User with userName {user.userName} already exists")

        # Generate SCIM ID
        user.id = self._generate_scim_id("user")
        now = time.time()
        user.meta = SCIMMeta(
            resourceType="User",
            created=_scim_timestamp(now),
            lastModified=_scim_timestamp(now),
            location=f"/scim/v2/Users/{user.id}",
            version=hashlib.sha256(str(now).encode()).hexdigest()[:32],
        )
        user.tenant_id = tenant_id

        # Convert to Strix user and create
        strix_user = user.to_strix_user()
        user_id = f"user_{secrets.token_urlsafe(16)}"
        raw_key = self._generate_api_key()
        key_hash = self._hash_key(raw_key)

        expires_at = None  # SCIM users don't expire by default

        await store.save_tenant_user(
            user_id=user_id,
            tenant_id=tenant_id,
            email=strix_user["email"],
            display_name=strix_user["display_name"],
            role=strix_user["role"],
            key_hash=key_hash,
            scope=strix_user["scope"],
            active=strix_user["active"],
            created_at=now,
            expires_at=expires_at,
            last_used=None,
        )

        # Store SCIM ID mapping
        await self._save_user_mapping(user.id, user_id, tenant_id, scim_token)

        log.info("Created SCIM user %s for tenant %s", user.id, tenant_id)
        return user

    async def get_user(self, user_id: str, tenant_id: str, scim_token: str) -> SCIMUser | None:
        """Get a SCIM user by SCIM ID."""
        mapping = await self._get_user_mapping(user_id, tenant_id, scim_token)
        if not mapping:
            return None

        strix_user = await self._get_strix_user(mapping["strix_user_id"], tenant_id)
        if not strix_user:
            return None

        return self._strix_to_scim_user(strix_user, user_id)

    async def get_user_by_username(self, username: str, tenant_id: str) -> SCIMUser | None:
        """Get a SCIM user by userName (email)."""
        # Search in tenant_users
        users = await store.load_tenant_users()
        for user in users:
            if user["tenant_id"] == tenant_id and user.get("email", "").lower() == username.lower():
                # Get SCIM mapping
                mappings = await self._get_user_mappings_by_tenant(tenant_id)
                scim_id = None
                for m in mappings:
                    if m["strix_user_id"] == user["user_id"]:
                        scim_id = m["scim_id"]
                        break

                if scim_id:
                    return self._strix_to_scim_user(user, scim_id)

        return None

    async def update_user(self, user_id: str, user: SCIMUser, tenant_id: str, scim_token: str) -> SCIMUser:
        """Update a SCIM user (full replace - PUT)."""
        mapping = await self._get_user_mapping(user_id, tenant_id, scim_token)
        if not mapping:
            raise ValueError(f"User {user_id} not found")

        strix_user_id = mapping["strix_user_id"]

        # Get existing Strix user
        strix_user = await self._get_strix_user(strix_user_id, tenant_id)
        if not strix_user:
            raise ValueError(f"Strix user {strix_user_id} not found")

        # Update fields
        now = time.time()
        strix_user["display_name"] = (
            user.displayName or (user.name.formatted if user.name else None) or user.userName.split("@")[0]
        )
        strix_user["role"] = user.role or "analyst"
        strix_user["scope"] = "read" if user.role == "viewer" else "write"
        strix_user["active"] = user.active
        strix_user["email"] = user.userName

        # Update in database
        await store.save_tenant_user(
            user_id=strix_user_id,
            tenant_id=tenant_id,
            email=strix_user["email"],
            display_name=strix_user["display_name"],
            role=strix_user["role"],
            key_hash=strix_user["key_hash"],
            scope=strix_user["scope"],
            active=strix_user["active"],
            created_at=strix_user["created_at"],
            expires_at=strix_user.get("expires_at"),
            last_used=strix_user.get("last_used"),
        )

        # Return a new resource rather than mutating the caller's object
        updated = user.model_copy(deep=True)
        updated.meta = SCIMMeta(
            resourceType="User",
            created=_scim_timestamp(strix_user.get("created_at", now)),
            lastModified=_scim_timestamp(now),
            location=f"/scim/v2/Users/{user_id}",
            version=hashlib.sha256(str(now).encode()).hexdigest()[:32],
        )
        updated.id = user_id
        updated.tenant_id = tenant_id

        log.info("Updated SCIM user %s for tenant %s", user_id, tenant_id)
        return updated

    async def patch_user(
        self, user_id: str, operations: list[dict[str, Any]], tenant_id: str, scim_token: str
    ) -> SCIMUser:
        """Partially update a SCIM user (PATCH)."""
        mapping = await self._get_user_mapping(user_id, tenant_id, scim_token)
        if not mapping:
            raise ValueError(f"User {user_id} not found")

        strix_user_id = mapping["strix_user_id"]
        strix_user = await self._get_strix_user(strix_user_id, tenant_id)
        if not strix_user:
            raise ValueError(f"Strix user {strix_user_id} not found")

        # Apply PATCH operations per RFC 7644 Section 3.5.2
        for op in operations:
            op_type = op.get("op")
            path = op.get("path", "")
            value = op.get("value")

            if op_type == "replace":
                if path == "displayName":
                    strix_user["display_name"] = value
                elif path == "userName":
                    # Changing email requires validation
                    if not isinstance(value, str) or "@" not in value:
                        raise ValueError("userName must be a valid email")
                    strix_user["email"] = value.lower()
                elif path == "active":
                    strix_user["active"] = bool(value)
                elif path == "role":
                    if value not in ("admin", "analyst", "viewer"):
                        raise ValueError("role must be admin, analyst, or viewer")
                    strix_user["role"] = value
                    strix_user["scope"] = "read" if value == "viewer" else "write"
                elif path == "emails" and isinstance(value, list) and value:
                    # Use first primary email
                    for email in value:
                        if email.get("primary"):
                            strix_user["email"] = email["value"]
                            break
                elif path == "name" and isinstance(value, dict):
                    formatted = (
                        value.get("formatted")
                        or f"{value.get('givenName', '')} {value.get('familyName', '')}".strip()
                    )
                    if formatted:
                        strix_user["display_name"] = formatted

            elif op_type == "add" and path == "groups" and isinstance(value, list):
                # Group membership additions are not implemented yet
                pass

            elif op_type == "remove" and path == "groups":
                # Group membership removals are not implemented yet
                pass

        # Save updates
        await store.save_tenant_user(
            user_id=strix_user_id,
            tenant_id=tenant_id,
            email=strix_user.get("email", ""),
            display_name=strix_user["display_name"],
            role=strix_user["role"],
            key_hash=strix_user["key_hash"],
            scope=strix_user["scope"],
            active=strix_user["active"],
            created_at=strix_user["created_at"],
            expires_at=strix_user.get("expires_at"),
            last_used=strix_user.get("last_used"),
        )

        updated = await self.get_user(user_id, tenant_id, scim_token)
        if updated is None:
            raise ValueError(f"User {user_id} not found after update")
        return updated

    async def delete_user(self, user_id: str, tenant_id: str, scim_token: str) -> bool:
        """Delete a SCIM user (deprovisions from Strix)."""
        mapping = await self._get_user_mapping(user_id, tenant_id, scim_token)
        if not mapping:
            return False

        strix_user_id = mapping["strix_user_id"]
        result = await store.deactivate_tenant_user(tenant_id=tenant_id, user_id=strix_user_id)

        # Remove SCIM mapping
        await self._delete_user_mapping(user_id, tenant_id, scim_token)

        log.info("Deleted SCIM user %s for tenant %s", user_id, tenant_id)
        return result

    async def list_users(
        self,
        tenant_id: str,
        scim_token: str,
        start_index: int = 1,
        count: int = 100,
        filter_expr: str | None = None,
    ) -> SCIMListResponse:
        """List SCIM users with pagination and filtering."""
        users = await store.load_tenant_users()
        tenant_users = [u for u in users if u["tenant_id"] == tenant_id]

        # Apply filter if provided
        if filter_expr:
            parsed_filter = self._parse_filter(filter_expr)
            tenant_users = self._apply_filter(tenant_users, parsed_filter)

        total = len(tenant_users)

        # Pagination (SCIM uses 1-based indexing)
        start = max(0, start_index - 1)
        end = start + count
        page_users = tenant_users[start:end]

        # Convert to SCIM users
        resources = []
        mappings = await self._get_user_mappings_by_tenant(tenant_id)
        mapping_dict = {m["strix_user_id"]: m["scim_id"] for m in mappings}

        for user in page_users:
            scim_id = mapping_dict.get(user["user_id"])
            if scim_id:
                scim_user = self._strix_to_scim_user(user, scim_id)
                resources.append(scim_user.model_dump(exclude_none=True))

        return SCIMListResponse(
            totalResults=total,
            itemsPerPage=len(resources),
            startIndex=start_index,
            Resources=resources,
        )

    # Group operations

    async def create_group(
        self, group: SCIMGroup, tenant_id: str, org_id: str | None, scim_token: str
    ) -> SCIMGroup:
        """Create a new SCIM group."""
        group.id = self._generate_scim_id("group")
        now = time.time()
        group.meta = SCIMMeta(
            resourceType="Group",
            created=_scim_timestamp(now),
            lastModified=_scim_timestamp(now),
            location=f"/scim/v2/Groups/{group.id}",
            version=hashlib.sha256(str(now).encode()).hexdigest()[:32],
        )
        group.tenant_id = tenant_id
        group.org_id = org_id

        # Store group mapping
        await self._save_group_mapping(group.id, group.to_strix_group(), tenant_id, org_id, scim_token)

        log.info("Created SCIM group %s for tenant %s", group.id, tenant_id)
        return group

    async def get_group(self, group_id: str, tenant_id: str, scim_token: str) -> SCIMGroup | None:
        """Get a SCIM group by ID."""
        mapping = await self._get_group_mapping(group_id, tenant_id, scim_token)
        if not mapping:
            return None

        return self._mapping_to_scim_group(mapping, group_id)

    async def update_group(
        self, group_id: str, group: SCIMGroup, tenant_id: str, scim_token: str
    ) -> SCIMGroup:
        """Update a SCIM group (full replace)."""
        mapping = await self._get_group_mapping(group_id, tenant_id, scim_token)
        if not mapping:
            raise ValueError(f"Group {group_id} not found")

        now = time.time()
        updated = group.model_copy(deep=True)
        updated.meta = SCIMMeta(
            resourceType="Group",
            created=_scim_timestamp(mapping.get("created_at", now)),
            lastModified=_scim_timestamp(now),
            location=f"/scim/v2/Groups/{group_id}",
            version=hashlib.sha256(str(now).encode()).hexdigest()[:32],
        )
        updated.id = group_id
        updated.tenant_id = tenant_id

        await self._save_group_mapping(
            group_id, updated.to_strix_group(), tenant_id, mapping.get("org_id"), scim_token
        )

        log.info("Updated SCIM group %s for tenant %s", group_id, tenant_id)
        return updated

    async def patch_group(
        self, group_id: str, operations: list[dict[str, Any]], tenant_id: str, scim_token: str
    ) -> SCIMGroup:
        """Partially update a SCIM group."""
        mapping = await self._get_group_mapping(group_id, tenant_id, scim_token)
        if not mapping:
            raise ValueError(f"Group {group_id} not found")

        # Apply operations
        for op in operations:
            op_type = op.get("op")
            path = op.get("path", "")
            value = op.get("value")

            if op_type == "replace" and path == "displayName":
                mapping["display_name"] = value
            elif op_type == "add" and path == "members" and isinstance(value, list):
                for member in value:
                    if member.get("value") not in mapping.get("member_ids", []):
                        mapping.setdefault("member_ids", []).append(member["value"])
            elif op_type == "remove" and path == "members" and isinstance(value, list):
                for member in value:
                    if member.get("value") in mapping.get("member_ids", []):
                        mapping["member_ids"].remove(member["value"])

        await self._save_group_mapping(group_id, mapping, tenant_id, mapping.get("org_id"), scim_token)

        updated = await self.get_group(group_id, tenant_id, scim_token)
        if updated is None:
            raise ValueError(f"Group {group_id} not found after update")
        return updated

    async def delete_group(self, group_id: str, tenant_id: str, scim_token: str) -> bool:
        """Delete a SCIM group."""
        mapping = await self._get_group_mapping(group_id, tenant_id, scim_token)
        if not mapping:
            return False

        await self._delete_group_mapping(group_id, tenant_id, scim_token)

        log.info("Deleted SCIM group %s for tenant %s", group_id, tenant_id)
        return True

    async def list_groups(
        self,
        tenant_id: str,
        scim_token: str,
        start_index: int = 1,
        count: int = 100,
        filter_expr: str | None = None,
    ) -> SCIMListResponse:
        """List SCIM groups with pagination and filtering."""
        mappings = await self._get_group_mappings_by_tenant(tenant_id)

        # Apply filter if provided
        if filter_expr:
            parsed_filter = self._parse_filter(filter_expr)
            mappings = self._apply_filter_groups(mappings, parsed_filter)

        total = len(mappings)

        # Pagination
        start = max(0, start_index - 1)
        end = start + count
        page_groups = mappings[start:end]

        resources = [
            self._mapping_to_scim_group(m, m["scim_id"]).model_dump(exclude_none=True) for m in page_groups
        ]

        return SCIMListResponse(
            totalResults=total,
            itemsPerPage=len(resources),
            startIndex=start_index,
            Resources=resources,
        )

    # Helper methods

    def _strix_to_scim_user(self, strix_user: dict[str, Any], scim_id: str) -> SCIMUser:
        """Convert Strix user to SCIM user."""
        email = strix_user.get("email", strix_user.get("userName", ""))
        display_name = strix_user.get("display_name", email.split("@")[0] if "@" in email else email)
        role = strix_user.get("role", "analyst")

        user = SCIMUser(
            id=scim_id,
            userName=email,
            displayName=display_name,
            emails=[SCIMEmail(value=email, primary=True)],
            active=strix_user.get("active", True),
            role=role,
            tenant_id=strix_user.get("tenant_id"),
            externalId=strix_user.get("external_id"),
        )

        if strix_user.get("created_at"):
            user.meta = SCIMMeta(
                resourceType="User",
                created=_scim_timestamp(strix_user["created_at"]),
                lastModified=_scim_timestamp(strix_user.get("last_used") or strix_user["created_at"]),
                location=f"/scim/v2/Users/{scim_id}",
            )

        return user

    def _mapping_to_scim_group(self, mapping: dict[str, Any], scim_id: str) -> SCIMGroup:
        """Convert stored mapping to SCIM group."""
        members = [SCIMGroupRef(value=mid, display=mid) for mid in mapping.get("member_ids", [])]

        group = SCIMGroup(
            id=scim_id,
            displayName=mapping.get("display_name", ""),
            members=members,
            tenant_id=mapping.get("tenant_id"),
            org_id=mapping.get("org_id"),
            externalId=mapping.get("external_id"),
        )

        if mapping.get("created_at"):
            group.meta = SCIMMeta(
                resourceType="Group",
                created=_scim_timestamp(mapping["created_at"]),
                lastModified=_scim_timestamp(mapping.get("updated_at", mapping["created_at"])),
                location=f"/scim/v2/Groups/{scim_id}",
            )

        return group

    def _parse_filter(self, filter_expr: str) -> SCIMFilter | None:
        """Parse SCIM filter expression (simplified)."""
        # Supports: attribute eq "value", attribute co "value", etc.
        import re

        pattern = r'(\w+)\s+(eq|ne|co|sw|ew|gt|lt|ge|le|pr)\s+"([^"]*)"'
        match = re.match(pattern, filter_expr.strip())
        if match:
            return SCIMFilter(attribute=match.group(1), operator=match.group(2), value=match.group(3).lower())
        return None

    def _apply_filter(self, users: list[dict], filter_obj: SCIMFilter | None) -> list[dict]:
        """Apply filter to user list."""
        if not filter_obj:
            return users

        attr = filter_obj.attribute
        op = filter_obj.operator
        value = filter_obj.value.lower() if filter_obj.value else ""

        filtered = []
        for user in users:
            user_val = ""
            if attr == "userName":
                user_val = user.get("email", "").lower()
            elif attr == "displayName":
                user_val = user.get("display_name", "").lower()
            elif attr == "externalId":
                user_val = user.get("external_id", "").lower()
            elif attr == "active":
                user_val = str(user.get("active", True)).lower()

            match = False
            if op == "eq":
                match = user_val == value
            elif op == "ne":
                match = user_val != value
            elif op == "co":
                match = value in user_val
            elif op == "sw":
                match = user_val.startswith(value)
            elif op == "ew":
                match = user_val.endswith(value)
            elif op == "pr":
                match = bool(user_val)

            if match:
                filtered.append(user)

        return filtered

    def _apply_filter_groups(self, groups: list[dict], filter_obj: SCIMFilter | None) -> list[dict]:
        """Apply filter to group list."""
        if not filter_obj:
            return groups

        attr = filter_obj.attribute
        op = filter_obj.operator
        value = filter_obj.value.lower() if filter_obj.value else ""

        filtered = []
        for group in groups:
            group_val = ""
            if attr == "displayName":
                group_val = group.get("display_name", "").lower()
            elif attr == "externalId":
                group_val = group.get("external_id", "").lower()

            match = False
            if op == "eq":
                match = group_val == value
            elif op == "ne":
                match = group_val != value
            elif op == "co":
                match = value in group_val
            elif op == "sw":
                match = group_val.startswith(value)
            elif op == "ew":
                match = group_val.endswith(value)
            elif op == "pr":
                match = bool(group_val)

            if match:
                filtered.append(group)

        return filtered

    # Database mapping operations

    async def _save_user_mapping(
        self, scim_id: str, strix_user_id: str, tenant_id: str, scim_token: str
    ) -> None:
        """Save SCIM to Strix user mapping."""
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO scim_user_mappings
                   (scim_id, strix_user_id, tenant_id, scim_token, created_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(scim_id) DO UPDATE SET
                       strix_user_id = excluded.strix_user_id,
                       tenant_id = excluded.tenant_id,
                       scim_token = excluded.scim_token""",
                scim_id,
                strix_user_id,
                tenant_id,
                scim_token,
                time.time(),
            )

    async def _get_user_mapping(self, scim_id: str, tenant_id: str, scim_token: str) -> dict | None:
        """Get SCIM user mapping."""
        db = await store.get_database()
        async with db.transaction() as conn:
            result = await store._fetchone(
                conn,
                "SELECT * FROM scim_user_mappings WHERE scim_id = ? AND tenant_id = ? AND scim_token = ?",
                scim_id,
                tenant_id,
                scim_token,
            )
            return dict(result) if result else None

    async def _get_user_mappings_by_tenant(self, tenant_id: str) -> list[dict]:
        """Get all SCIM user mappings for a tenant."""
        db = await store.get_database()
        async with db.transaction() as conn:
            results = await store._fetchall(
                conn,
                "SELECT * FROM scim_user_mappings WHERE tenant_id = ?",
                tenant_id,
            )
            return [dict(r) for r in results]

    async def _delete_user_mapping(self, scim_id: str, tenant_id: str, scim_token: str) -> None:
        """Delete SCIM user mapping."""
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                "DELETE FROM scim_user_mappings WHERE scim_id = ? AND tenant_id = ? AND scim_token = ?",
                scim_id,
                tenant_id,
                scim_token,
            )

    async def _get_strix_user(self, user_id: str, tenant_id: str) -> dict | None:
        """Get Strix user by ID."""
        users = await store.load_tenant_users()
        for user in users:
            if user["user_id"] == user_id and user["tenant_id"] == tenant_id:
                return user
        return None

    async def _save_group_mapping(
        self, scim_id: str, group_data: dict[str, Any], tenant_id: str, org_id: str | None, scim_token: str
    ) -> None:
        """Save SCIM group mapping."""
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO scim_group_mappings
                   (scim_id, display_name, external_id, tenant_id, org_id,
                    member_ids, scim_token, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scim_id) DO UPDATE SET
                       display_name = excluded.display_name,
                       external_id = excluded.external_id,
                       tenant_id = excluded.tenant_id,
                       org_id = excluded.org_id,
                       member_ids = excluded.member_ids,
                       scim_token = excluded.scim_token,
                       updated_at = excluded.updated_at""",
                scim_id,
                group_data.get("display_name"),
                group_data.get("external_id"),
                tenant_id,
                org_id,
                json.dumps(group_data.get("member_ids", [])),
                scim_token,
                time.time(),
                time.time(),
            )

    async def _get_group_mapping(self, scim_id: str, tenant_id: str, scim_token: str) -> dict | None:
        """Get SCIM group mapping."""
        db = await store.get_database()
        async with db.transaction() as conn:
            result = await store._fetchone(
                conn,
                "SELECT * FROM scim_group_mappings WHERE scim_id = ? AND tenant_id = ? AND scim_token = ?",
                scim_id,
                tenant_id,
                scim_token,
            )
            if result:
                d = dict(result)
                d["member_ids"] = json.loads(d.get("member_ids", "[]"))
                return d
            return None

    async def _get_group_mappings_by_tenant(self, tenant_id: str) -> list[dict]:
        """Get all SCIM group mappings for a tenant."""
        db = await store.get_database()
        async with db.transaction() as conn:
            results = await store._fetchall(
                conn,
                "SELECT * FROM scim_group_mappings WHERE tenant_id = ?",
                tenant_id,
            )
            mappings = []
            for r in results:
                d = dict(r)
                d["member_ids"] = json.loads(d.get("member_ids", "[]"))
                mappings.append(d)
            return mappings

    async def _delete_group_mapping(self, scim_id: str, tenant_id: str, scim_token: str) -> None:
        """Delete SCIM group mapping."""
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                "DELETE FROM scim_group_mappings WHERE scim_id = ? AND tenant_id = ? AND scim_token = ?",
                scim_id,
                tenant_id,
                scim_token,
            )


# Global SCIM store instance
scim_store = SCIMStore()


async def init_scim_tables() -> None:
    """Initialize SCIM database tables."""
    db = await store.get_database()
    async with db.transaction() as conn:
        # SCIM user mappings
        await store._execute(
            conn,
            """
            CREATE TABLE IF NOT EXISTS scim_user_mappings (
                scim_id      TEXT PRIMARY KEY,
                strix_user_id TEXT NOT NULL,
                tenant_id    TEXT NOT NULL,
                scim_token   TEXT NOT NULL,
                created_at   REAL NOT NULL,
                UNIQUE(tenant_id, scim_token, scim_id)
            )
        """,
        )
        await store._execute(
            conn,
            """
            CREATE INDEX IF NOT EXISTS scim_user_mappings_by_tenant
            ON scim_user_mappings (tenant_id, scim_token)
        """,
        )

        # SCIM group mappings
        await store._execute(
            conn,
            """
            CREATE TABLE IF NOT EXISTS scim_group_mappings (
                scim_id      TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                external_id  TEXT,
                tenant_id    TEXT NOT NULL,
                org_id       TEXT,
                member_ids   TEXT NOT NULL DEFAULT '[]',
                scim_token   TEXT NOT NULL,
                created_at   REAL NOT NULL,
                updated_at   REAL NOT NULL,
                UNIQUE(tenant_id, scim_token, scim_id)
            )
        """,
        )
        await store._execute(
            conn,
            """
            CREATE INDEX IF NOT EXISTS scim_group_mappings_by_tenant
            ON scim_group_mappings (tenant_id, scim_token)
        """,
        )

        # SCIM tokens (for authentication)
        await store._execute(
            conn,
            """
            CREATE TABLE IF NOT EXISTS scim_tokens (
                token_hash   TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                org_id       TEXT,
                name         TEXT NOT NULL,
                active       INTEGER NOT NULL DEFAULT 1,
                created_at   REAL NOT NULL,
                expires_at   REAL,
                last_used    REAL
            )
        """,
        )
        await store._execute(
            conn,
            """
            CREATE INDEX IF NOT EXISTS scim_tokens_by_tenant
            ON scim_tokens (tenant_id, active)
        """,
        )


# SCIM Token Management


class SCIMTokenManager:
    """Manage SCIM bearer tokens."""

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _generate_token() -> str:
        return f"scim_{secrets.token_urlsafe(32)}"

    async def create_token(
        self, tenant_id: str, name: str, org_id: str | None = None, ttl_days: int | None = None
    ) -> tuple[str, str]:
        """Create a new SCIM token. Returns (raw_token, token_hash)."""
        raw_token = self._generate_token()
        token_hash = self._hash_token(raw_token)
        now = time.time()
        expires_at = now + ttl_days * 86400 if ttl_days else None

        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO scim_tokens
                   (token_hash, tenant_id, org_id, name, active, created_at, expires_at)
                   VALUES (?, ?, ?, ?, 1, ?, ?)""",
                token_hash,
                tenant_id,
                org_id,
                name,
                now,
                expires_at,
            )

        log.info("Created SCIM token %s for tenant %s", name, tenant_id)
        return raw_token, token_hash

    async def validate_token(self, token: str) -> dict | None:
        """Validate a SCIM token and return token info."""
        if not token:
            return None

        token_hash = self._hash_token(token)
        db = await store.get_database()
        async with db.transaction() as conn:
            result = await store._fetchone(
                conn,
                "SELECT * FROM scim_tokens WHERE token_hash = ? AND active = 1",
                token_hash,
            )

            if not result:
                return None

            token_data = dict(result)

            # Check expiration
            if token_data.get("expires_at") and time.time() >= token_data["expires_at"]:
                # Token expired, deactivate
                await store._execute(
                    conn,
                    "UPDATE scim_tokens SET active = 0 WHERE token_hash = ?",
                    token_hash,
                )
                return None

            # Update last_used
            await store._execute(
                conn,
                "UPDATE scim_tokens SET last_used = ? WHERE token_hash = ?",
                time.time(),
                token_hash,
            )

            return token_data

    async def revoke_token(self, token_hash: str) -> bool:
        """Revoke a SCIM token."""
        db = await store.get_database()
        async with db.transaction() as conn:
            result = await store._execute(
                conn,
                "UPDATE scim_tokens SET active = 0 WHERE token_hash = ? AND active = 1",
                token_hash,
            )
            return result.rowcount > 0

    async def list_tokens(self, tenant_id: str) -> list[dict]:
        """List all SCIM tokens for a tenant."""
        db = await store.get_database()
        async with db.transaction() as conn:
            rows = await store._fetchall(
                conn,
                "SELECT token_hash, tenant_id, org_id, name, active, created_at, "
                "expires_at, last_used FROM scim_tokens WHERE tenant_id = ?",
                tenant_id,
            )
            return [dict(r) for r in rows]


scim_token_manager = SCIMTokenManager()


# Service Provider Config
def get_service_provider_config() -> SCIMServiceProviderConfig:
    """Get SCIM Service Provider Configuration."""
    return SCIMServiceProviderConfig()


# Resource Types
def get_resource_types() -> SCIMResourceTypesResponse:
    """Get SCIM Resource Types."""
    return SCIMResourceTypesResponse(
        totalResults=2,
        itemsPerPage=2,
        startIndex=1,
        Resources=[
            SCIMResourceType(
                id="User",
                name="User",
                endpoint="/scim/v2/Users",
                description="SCIM User resource",
                schema=SCIM_USER_SCHEMA,
                schemaExtensions=[{"schema": STRIX_USER_SCHEMA, "required": False}],
            ),
            SCIMResourceType(
                id="Group",
                name="Group",
                endpoint="/scim/v2/Groups",
                description="SCIM Group resource",
                schema=SCIM_GROUP_SCHEMA,
                schemaExtensions=[{"schema": STRIX_GROUP_SCHEMA, "required": False}],
            ),
        ],
    )


# Schemas
def get_schemas() -> SCIMSchemasResponse:
    """Get SCIM Schemas."""
    user_schema = SCIMSchema(
        id=SCIM_USER_SCHEMA,
        name="User",
        description="SCIM Core User Schema",
        attributes=[
            {
                "name": "id",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readOnly",
                "returned": "always",
                "uniqueness": "global",
            },
            {
                "name": "externalId",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
            {
                "name": "userName",
                "type": "string",
                "multiValued": False,
                "required": True,
                "caseExact": False,
                "mutability": "readWrite",
                "returned": "always",
                "uniqueness": "global",
            },
            {
                "name": "name",
                "type": "complex",
                "multiValued": False,
                "required": False,
                "subAttributes": [
                    {"name": "formatted", "type": "string", "multiValued": False},
                    {"name": "familyName", "type": "string", "multiValued": False},
                    {"name": "givenName", "type": "string", "multiValued": False},
                ],
            },
            {
                "name": "displayName",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
            {
                "name": "emails",
                "type": "complex",
                "multiValued": True,
                "required": False,
                "subAttributes": [
                    {"name": "value", "type": "string", "multiValued": False},
                    {"name": "type", "type": "string", "multiValued": False},
                    {"name": "primary", "type": "boolean", "multiValued": False},
                ],
            },
            {
                "name": "active",
                "type": "boolean",
                "multiValued": False,
                "required": False,
                "mutability": "readWrite",
                "returned": "default",
            },
            {
                "name": "groups",
                "type": "complex",
                "multiValued": True,
                "required": False,
                "subAttributes": [
                    {"name": "value", "type": "string", "multiValued": False},
                    {"name": "display", "type": "string", "multiValued": False},
                    {"name": "type", "type": "string", "multiValued": False},
                ],
            },
            {
                "name": "meta",
                "type": "complex",
                "multiValued": False,
                "required": False,
                "mutability": "readOnly",
                "returned": "default",
                "subAttributes": [
                    {"name": "resourceType", "type": "string"},
                    {"name": "created", "type": "dateTime"},
                    {"name": "lastModified", "type": "dateTime"},
                    {"name": "location", "type": "string"},
                    {"name": "version", "type": "string"},
                ],
            },
        ],
    )

    group_schema = SCIMSchema(
        id=SCIM_GROUP_SCHEMA,
        name="Group",
        description="SCIM Core Group Schema",
        attributes=[
            {
                "name": "id",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readOnly",
                "returned": "always",
                "uniqueness": "global",
            },
            {
                "name": "externalId",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
            {
                "name": "displayName",
                "type": "string",
                "multiValued": False,
                "required": True,
                "caseExact": False,
                "mutability": "readWrite",
                "returned": "always",
                "uniqueness": "none",
            },
            {
                "name": "members",
                "type": "complex",
                "multiValued": True,
                "required": False,
                "subAttributes": [
                    {"name": "value", "type": "string", "multiValued": False},
                    {"name": "display", "type": "string", "multiValued": False},
                    {"name": "type", "type": "string", "multiValued": False},
                ],
            },
            {
                "name": "meta",
                "type": "complex",
                "multiValued": False,
                "required": False,
                "mutability": "readOnly",
                "returned": "default",
                "subAttributes": [
                    {"name": "resourceType", "type": "string"},
                    {"name": "created", "type": "dateTime"},
                    {"name": "lastModified", "type": "dateTime"},
                    {"name": "location", "type": "string"},
                    {"name": "version", "type": "string"},
                ],
            },
        ],
    )

    strix_user_schema = SCIMSchema(
        id=STRIX_USER_SCHEMA,
        name="StrixUser",
        description="Strix User Extension Schema",
        attributes=[
            {
                "name": "role",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
                "canonicalValues": ["admin", "analyst", "viewer"],
            },
            {
                "name": "tenant_id",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none",
            },
        ],
    )

    strix_group_schema = SCIMSchema(
        id=STRIX_GROUP_SCHEMA,
        name="StrixGroup",
        description="Strix Group Extension Schema",
        attributes=[
            {
                "name": "tenant_id",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none",
            },
            {
                "name": "org_id",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": False,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none",
            },
        ],
    )

    return SCIMSchemasResponse(
        totalResults=4,
        itemsPerPage=4,
        startIndex=1,
        Resources=[user_schema, group_schema, strix_user_schema, strix_group_schema],
    )
