"""Unit tests for Ishastra Project Key Scopes (multi-project tenant isolation)."""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
import time
from pathlib import Path

import pytest
import pytest_asyncio

from ishastra.core.key_scopes import (
    ProjectKey,
    authorize_request,
    check_key_scope,
    create_project_key,
    deactivate_project_key,
    get_project_key,
    get_project_rate_limit_key,
    list_project_keys,
    load_project_keys,
    rotate_project_key,
    save_project_key,
    validate_api_key_with_scopes,
    validate_project_key,
)
from ishastra.core.store import SQLiteDatabase, close_database, configure, get_database


@pytest_asyncio.fixture
async def temp_db():
    """Create a temporary SQLite database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    configure(path)
    db = await get_database()
    await db.migrate()
    yield path
    await close_database()
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)


@pytest_asyncio.fixture
async def db_with_tenant(temp_db):
    """Database with a test tenant."""

    yield "test-tenant-123"


class TestProjectKeyModel:
    """Test ProjectKey dataclass."""

    def test_project_key_creation(self):
        """Test ProjectKey can be created with all fields."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc123",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )
        assert key.tenant_id == "tenant-1"
        assert key.scope_type == "tenant"
        assert key.project_id is None
        assert key.allowed_projects == []
        assert key.resource_filters == {}

    def test_project_key_project_scoped(self):
        """Test ProjectKey with project scope type."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc123",
            tier="standard",
            admin=False,
            active=True,
            scope="read",
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b", "project-c"],
            resource_filters={"asset_type": ["web", "api"]},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=True,
            include_hosts="*.example.com",
        )
        assert key.scope_type == "project"
        assert key.project_id == "project-a"
        assert key.allowed_projects == ["project-b", "project-c"]
        assert key.resource_filters == {"asset_type": ["web", "api"]}
        assert key.ai_enabled is True
        assert key.include_hosts == "*.example.com"


class TestProjectScopesMigration:
    """Test project scopes database migration."""

    @pytest.mark.asyncio
    async def test_migrate_project_scopes_sqlite(self, temp_db):
        """Test migration 21 applies correctly to SQLite."""
        db = await get_database()
        assert isinstance(db, SQLiteDatabase)

        rows = await db.fetchall("PRAGMA table_info(api_keys)")
        columns = {row["name"] for row in rows}

        expected_columns = {
            "tenant_id",
            "key_hash",
            "tier",
            "admin",
            "active",
            "created_at",
            "expires_at",
            "last_used",
            "rotated_at",
            "ai_enabled",
            "scope",
            "scope_type",
            "project_id",
            "allowed_projects",
            "resource_filters",
            "include_hosts",
        }
        assert expected_columns.issubset(columns)

        indexes = await db.fetchall("PRAGMA index_list(api_keys)")
        index_names = {row["name"] for row in indexes}
        assert "api_keys_by_project" in index_names
        assert "api_keys_tenant_project" in index_names


class TestCoreStoreFunctions:
    """Test core store functions for project keys."""

    @pytest.mark.asyncio
    async def test_save_and_get_project_key(self, temp_db, db_with_tenant):
        """Test saving and retrieving a project-scoped key."""
        tenant_id = db_with_tenant
        key_hash = hashlib.sha256(b"test-key").hexdigest()
        now = time.time()

        await save_project_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier="standard",
            admin=False,
            active=True,
            created_at=now,
            expires_at=now + 86400,
            last_used=None,
            rotated_at=now,
            ai_enabled=False,
            scope="write",
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b"],
            resource_filters={"asset_type": ["web"]},
            include_hosts="*.example.com",
        )

        key = await get_project_key(tenant_id, "project-a")
        assert key is not None
        assert key.tenant_id == tenant_id
        assert key.key_hash == key_hash
        assert key.scope_type == "project"
        assert key.project_id == "project-a"
        assert key.allowed_projects == ["project-b"]
        assert key.resource_filters == {"asset_type": ["web"]}
        assert key.include_hosts == "*.example.com"

    @pytest.mark.asyncio
    async def test_get_tenant_scoped_key(self, temp_db, db_with_tenant):
        """Test retrieving a tenant-scoped key (project_id is None)."""
        tenant_id = db_with_tenant
        key_hash = hashlib.sha256(b"tenant-key").hexdigest()
        now = time.time()

        await save_project_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier="premium",
            admin=True,
            active=True,
            created_at=now,
            expires_at=None,
            last_used=None,
            rotated_at=now,
            ai_enabled=False,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            include_hosts=None,
        )

        key = await get_project_key(tenant_id, None)
        assert key is not None
        assert key.scope_type == "tenant"
        assert key.project_id is None
        assert key.admin is True

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, temp_db, db_with_tenant):
        """Test retrieving non-existent key returns None."""
        key = await get_project_key(db_with_tenant, "nonexistent")
        assert key is None

    @pytest.mark.asyncio
    async def test_list_project_keys(self, temp_db):
        """Test listing all project keys for a tenant."""

        now = time.time()
        tenants = ["tenant-1", "tenant-2", "tenant-3"]

        for i, tenant_id in enumerate(tenants):
            key_hash = hashlib.sha256(f"key-{i}".encode()).hexdigest()
            await save_project_key(
                tenant_id=tenant_id,
                key_hash=key_hash,
                tier="standard",
                admin=False,
                active=True,
                created_at=now + i,
                expires_at=None,
                last_used=None,
                rotated_at=now + i,
                ai_enabled=False,
                scope="write",
                scope_type="tenant",
                project_id=None,
                allowed_projects=[],
                resource_filters={},
                include_hosts=None,
            )

        for tenant_id in tenants:
            keys = await list_project_keys(tenant_id)
            assert len(keys) == 1
            assert keys[0].tenant_id == tenant_id
            assert keys[0].scope_type == "tenant"

    @pytest.mark.asyncio
    async def test_load_project_keys_filters_by_tenant(self, temp_db):
        """Test load_project_keys filters by tenant_id."""
        now = time.time()

        for tenant_id in ["tenant-1", "tenant-2"]:
            key_hash = hashlib.sha256(f"key-{tenant_id}".encode()).hexdigest()
            await save_project_key(
                tenant_id=tenant_id,
                key_hash=key_hash,
                tier="standard",
                admin=False,
                active=True,
                created_at=now,
                expires_at=None,
                last_used=None,
                rotated_at=now,
                ai_enabled=False,
                scope="write",
                scope_type="tenant",
                project_id=None,
                allowed_projects=[],
                resource_filters={},
                include_hosts=None,
            )

        keys_tenant_1 = await load_project_keys("tenant-1")
        keys_tenant_2 = await load_project_keys("tenant-2")
        all_keys = await load_project_keys(None)

        assert len(keys_tenant_1) == 1
        assert len(keys_tenant_2) == 1
        assert len(all_keys) == 2

    @pytest.mark.asyncio
    async def test_deactivate_project_key(self, temp_db, db_with_tenant):
        """Test deactivating a project key."""
        tenant_id = db_with_tenant
        key_hash = hashlib.sha256(b"deactivate-me").hexdigest()
        now = time.time()

        await save_project_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier="standard",
            admin=False,
            active=True,
            created_at=now,
            expires_at=None,
            last_used=None,
            rotated_at=now,
            ai_enabled=False,
            scope="write",
            scope_type="project",
            project_id="project-a",
            allowed_projects=[],
            resource_filters={},
            include_hosts=None,
        )

        key = await get_project_key(tenant_id, "project-a")
        assert key.active is True

        result = await deactivate_project_key(tenant_id, "project-a")
        assert result is True

        key = await get_project_key(tenant_id, "project-a")
        assert key.active is False

    @pytest.mark.asyncio
    async def test_deactivate_nonexistent_key(self, temp_db, db_with_tenant):
        """Test deactivating non-existent key returns False."""
        result = await deactivate_project_key(db_with_tenant, "nonexistent")
        assert result is False


class TestKeyLifecycle:
    """Test project key creation, validation, and rotation."""

    @pytest.mark.asyncio
    async def test_create_tenant_scoped_key(self, temp_db, db_with_tenant):
        """Test creating a tenant-scoped API key."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            tier="standard",
            admin=False,
            ttl_days=30,
            scope="write",
            scope_type="tenant",
        )

        assert raw_key.startswith("ishastra_")
        assert len(raw_key) > 10

        assert record.tenant_id == tenant_id
        assert record.key_hash == hashlib.sha256(raw_key.encode()).hexdigest()
        assert record.tier == "standard"
        assert record.admin is False
        assert record.active is True
        assert record.scope == "write"
        assert record.scope_type == "tenant"
        assert record.project_id is None
        assert record.allowed_projects == []
        assert record.resource_filters == {}
        assert record.expires_at is not None
        assert record.expires_at > time.time()

    @pytest.mark.asyncio
    async def test_create_project_scoped_key(self, temp_db, db_with_tenant):
        """Test creating a project-scoped API key."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            tier="premium",
            admin=False,
            ttl_days=90,
            scope="read",
            scope_type="project",
            project_id="project-x",
            allowed_projects=["project-y", "project-z"],
            resource_filters={"asset_type": ["api", "web"], "env": ["prod"]},
            include_hosts="*.example.com",
        )

        assert record.scope_type == "project"
        assert record.project_id == "project-x"
        assert record.allowed_projects == ["project-y", "project-z"]
        assert record.resource_filters == {"asset_type": ["api", "web"], "env": ["prod"]}
        assert record.include_hosts == "*.example.com"
        assert record.scope == "read"

    @pytest.mark.asyncio
    async def test_create_key_invalid_scope(self, temp_db, db_with_tenant):
        """Test creating key with invalid scope raises error."""
        with pytest.raises(ValueError, match="scope must be 'read' or 'write'"):
            await create_project_key(
                tenant_id=db_with_tenant,
                scope="invalid",
            )

    @pytest.mark.asyncio
    async def test_create_key_invalid_scope_type(self, temp_db, db_with_tenant):
        """Test creating key with invalid scope_type raises error."""
        with pytest.raises(ValueError, match="scope_type must be 'tenant' or 'project'"):
            await create_project_key(
                tenant_id=db_with_tenant,
                scope_type="invalid",
            )

    @pytest.mark.asyncio
    async def test_create_project_key_requires_project_id(self, temp_db, db_with_tenant):
        """Test creating project-scoped key without project_id raises error."""
        with pytest.raises(ValueError, match="project_id required when scope_type is 'project'"):
            await create_project_key(
                tenant_id=db_with_tenant,
                scope_type="project",
                project_id=None,
            )

    @pytest.mark.asyncio
    async def test_create_key_invalid_ttl(self, temp_db, db_with_tenant):
        """Test creating key with invalid TTL raises error."""
        with pytest.raises(ValueError, match="ttl_days must be between 1 and 3650"):
            await create_project_key(
                tenant_id=db_with_tenant,
                ttl_days=0,
            )
        with pytest.raises(ValueError, match="ttl_days must be between 1 and 3650"):
            await create_project_key(
                tenant_id=db_with_tenant,
                ttl_days=4000,
            )

    @pytest.mark.asyncio
    async def test_validate_project_key_valid(self, temp_db, db_with_tenant):
        """Test validating a valid project key."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            tier="standard",
            scope_type="tenant",
        )

        validated = await validate_project_key(raw_key)
        assert validated is not None
        assert validated.tenant_id == tenant_id
        assert validated.key_hash == record.key_hash
        assert validated.active is True

    @pytest.mark.asyncio
    async def test_validate_project_key_invalid(self, temp_db, db_with_tenant):
        """Test validating an invalid key returns None."""
        validated = await validate_project_key("ishastra_invalid_key_that_does_not_exist")
        assert validated is None

    @pytest.mark.asyncio
    async def test_validate_project_key_empty(self, temp_db):
        """Test validating empty key returns None."""
        validated = await validate_project_key(None)
        assert validated is None
        validated = await validate_project_key("")
        assert validated is None

    @pytest.mark.asyncio
    async def test_validate_project_key_expired(self, temp_db, db_with_tenant):
        """Test validating an expired key returns None and deactivates it."""
        tenant_id = db_with_tenant

        raw_key = "ishastra_" + "a" * 32
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        past = time.time() - 86400

        await save_project_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier="standard",
            admin=False,
            active=True,
            created_at=past,
            expires_at=past,
            last_used=None,
            rotated_at=past,
            ai_enabled=False,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            include_hosts=None,
        )

        validated = await validate_project_key(raw_key)
        assert validated is None

        key = await get_project_key(tenant_id, None)
        assert key is not None
        assert key.active is False

    @pytest.mark.asyncio
    async def test_validate_project_key_updates_last_used(self, temp_db, db_with_tenant):
        """Test validating a key updates last_used timestamp."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            scope_type="tenant",
        )

        assert record.last_used is None

        validated = await validate_project_key(raw_key)
        assert validated is not None
        assert validated.last_used is not None
        assert validated.last_used >= record.created_at


class TestKeyRotation:
    """Test project key rotation."""

    @pytest.mark.asyncio
    async def test_rotate_project_key(self, temp_db, db_with_tenant):
        """Test rotating a project key preserves scope configuration."""
        tenant_id = db_with_tenant

        raw_key, original = await create_project_key(
            tenant_id=tenant_id,
            tier="premium",
            admin=False,
            ttl_days=30,
            scope="read",
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b"],
            resource_filters={"env": ["staging"]},
            include_hosts="*.example.com",
        )

        result = await rotate_project_key(tenant_id, project_id="project-a", ttl_days=60)
        assert result is not None

        new_raw_key, new_record = result

        assert new_raw_key != raw_key
        assert new_record.key_hash != original.key_hash

        assert new_record.tenant_id == original.tenant_id
        assert new_record.tier == original.tier
        assert new_record.admin == original.admin
        assert new_record.scope == original.scope
        assert new_record.scope_type == original.scope_type
        assert new_record.project_id == original.project_id
        assert new_record.allowed_projects == original.allowed_projects
        assert new_record.resource_filters == original.resource_filters
        assert new_record.include_hosts == original.include_hosts
        assert new_record.ai_enabled == original.ai_enabled

        assert new_record.expires_at is not None
        assert new_record.expires_at > original.expires_at

        old_validated = await validate_project_key(raw_key)
        assert old_validated is None

        new_validated = await validate_project_key(new_raw_key)
        assert new_validated is not None
        assert new_validated.key_hash == new_record.key_hash

    @pytest.mark.asyncio
    async def test_rotate_tenant_scoped_key(self, temp_db, db_with_tenant):
        """Test rotating a tenant-scoped key (project_id=None)."""
        tenant_id = db_with_tenant

        raw_key, original = await create_project_key(
            tenant_id=tenant_id,
            scope_type="tenant",
        )

        result = await rotate_project_key(tenant_id, project_id=None, ttl_days=60)
        assert result is not None

        new_raw_key, new_record = result
        assert new_record.scope_type == "tenant"
        assert new_record.project_id is None

        assert await validate_project_key(raw_key) is None

        assert await validate_project_key(new_raw_key) is not None

    @pytest.mark.asyncio
    async def test_rotate_nonexistent_key(self, temp_db, db_with_tenant):
        """Test rotating non-existent key returns None."""
        result = await rotate_project_key(db_with_tenant, project_id="nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_rotate_inactive_key(self, temp_db, db_with_tenant):
        """Test rotating an inactive key returns None."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(tenant_id=tenant_id)

        await deactivate_project_key(tenant_id, None)

        result = await rotate_project_key(tenant_id, project_id=None)
        assert result is None

    @pytest.mark.asyncio
    async def test_rotate_expired_key(self, temp_db, db_with_tenant):
        """Test rotating an expired key returns None."""
        tenant_id = db_with_tenant

        raw_key = "ishastra_" + "b" * 32
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        past = time.time() - 86400

        await save_project_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier="standard",
            admin=False,
            active=True,
            created_at=past,
            expires_at=past,
            last_used=None,
            rotated_at=past,
            ai_enabled=False,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            include_hosts=None,
        )

        result = await rotate_project_key(tenant_id, project_id=None)
        assert result is None


class TestCheckKeyScope:
    """Test check_key_scope authorization logic."""

    def test_tenant_scoped_key_allows_all_projects(self):
        """Tenant-scoped keys have access to all projects in tenant."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert check_key_scope(key, required_project="project-a") is True
        assert check_key_scope(key, required_project="project-b") is True
        assert check_key_scope(key, required_project=None) is True

    def test_tenant_scoped_read_only_denies_write(self):
        """Tenant-scoped read-only key denies write access."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="read",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert check_key_scope(key, required_project="project-a", required_action="read") is True
        assert check_key_scope(key, required_project="project-a", required_action="write") is False

    def test_project_scoped_key_matches_project_id(self):
        """Project-scoped key allows access to its project_id."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="project",
            project_id="project-a",
            allowed_projects=[],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert check_key_scope(key, required_project="project-a") is True
        assert check_key_scope(key, required_project="project-b") is False
        assert check_key_scope(key, required_project=None) is False

    def test_project_scoped_key_allowed_projects(self):
        """Project-scoped key allows access to allowed_projects list."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b", "project-c"],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert check_key_scope(key, required_project="project-a") is True
        assert check_key_scope(key, required_project="project-b") is True
        assert check_key_scope(key, required_project="project-c") is True
        assert check_key_scope(key, required_project="project-d") is False
        assert check_key_scope(key, required_project=None) is False

    def test_project_scoped_read_only_denies_write(self):
        """Project-scoped read-only key denies write access."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="read",
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b"],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert check_key_scope(key, required_project="project-a", required_action="read") is True
        assert check_key_scope(key, required_project="project-a", required_action="write") is False
        assert check_key_scope(key, required_project="project-b", required_action="read") is True
        assert check_key_scope(key, required_project="project-b", required_action="write") is False

    def test_inactive_key_denied(self):
        """Inactive key is denied for all access."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=False,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert check_key_scope(key, required_project="project-a") is False
        assert check_key_scope(key, required_project=None) is False


class TestProjectRateLimiting:
    """Test project-scoped rate limiting key generation."""

    @pytest.mark.asyncio
    async def test_get_project_rate_limit_key_tenant_scoped(self):
        """Test rate limit key for tenant-scoped key."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        bucket_key = await get_project_rate_limit_key(key, "assessments")
        assert bucket_key == "assessments:tenant:tenant-1"

    @pytest.mark.asyncio
    async def test_get_project_rate_limit_key_project_scoped(self):
        """Test rate limit key for project-scoped key."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b"],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        bucket_key = await get_project_rate_limit_key(key, "assessments")
        assert bucket_key == "assessments:project:tenant-1:project-a"

    @pytest.mark.asyncio
    async def test_get_project_rate_limit_key_project_scoped_no_project_id(self):
        """Test rate limit key for project-scoped key without project_id falls back."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="project",
            project_id=None,
            allowed_projects=["project-a", "project-b"],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        bucket_key = await get_project_rate_limit_key(key, "assessments")

        assert bucket_key == "assessments:tenant:tenant-1"


class TestValidateApiKeyWithScopes:
    """Test the extended validate_api_key_with_scopes function."""

    @pytest.mark.asyncio
    async def test_validate_api_key_with_scopes_tenant(self, temp_db, db_with_tenant):
        """Test validate_api_key_with_scopes returns full scope info for tenant key."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            tier="premium",
            admin=True,
            scope="write",
            scope_type="tenant",
        )

        result = await validate_api_key_with_scopes(raw_key)
        assert result is not None
        assert result["tenant_id"] == tenant_id
        assert result["tier"] == "premium"
        assert result["admin"] is True
        assert result["global_admin"] is True
        assert result["role"] == "admin"
        assert result["scope"] == "write"
        assert result["scope_type"] == "tenant"
        assert result["project_id"] is None
        assert result["allowed_projects"] == []
        assert result["resource_filters"] == {}
        assert "record" in result
        assert result["record"]["key_hash"] == record.key_hash

    @pytest.mark.asyncio
    async def test_validate_api_key_with_scopes_project(self, temp_db, db_with_tenant):
        """Test validate_api_key_with_scopes returns full scope info for project key."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            tier="standard",
            admin=False,
            scope="read",
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b"],
            resource_filters={"asset_type": ["api"]},
            include_hosts="*.example.com",
        )

        result = await validate_api_key_with_scopes(raw_key)
        assert result is not None
        assert result["scope_type"] == "project"
        assert result["project_id"] == "project-a"
        assert result["allowed_projects"] == ["project-b"]
        assert result["resource_filters"] == {"asset_type": ["api"]}
        assert result["include_hosts"] == "*.example.com"
        assert result["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_validate_api_key_with_scopes_invalid(self, temp_db):
        """Test validate_api_key_with_scopes returns None for invalid key."""
        result = await validate_api_key_with_scopes("ishastra_invalid")
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_api_key_with_scopes_expired(self, temp_db, db_with_tenant):
        """Test validate_api_key_with_scopes returns None for expired key."""
        tenant_id = db_with_tenant

        raw_key = "ishastra_" + "c" * 32
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        past = time.time() - 86400

        await save_project_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier="standard",
            admin=False,
            active=True,
            created_at=past,
            expires_at=past,
            last_used=None,
            rotated_at=past,
            ai_enabled=False,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            include_hosts=None,
        )

        result = await validate_api_key_with_scopes(raw_key)
        assert result is None


class TestAuthorizeRequest:
    """Test the authorize_request convenience function."""

    @pytest.mark.asyncio
    async def test_authorize_request_tenant_write(self, temp_db, db_with_tenant):
        """Test authorize_request for tenant-scoped write key."""
        tenant_id = db_with_tenant

        raw_key, _ = await create_project_key(
            tenant_id=tenant_id,
            scope_type="tenant",
            scope="write",
        )

        key = await authorize_request(raw_key, required_project="project-a", required_action="write")
        assert key is not None
        assert key.scope_type == "tenant"

        key = await authorize_request(raw_key, required_project="project-b", required_action="read")
        assert key is not None

    @pytest.mark.asyncio
    async def test_authorize_request_project_scoped(self, temp_db, db_with_tenant):
        """Test authorize_request for project-scoped key."""
        tenant_id = db_with_tenant

        raw_key, _ = await create_project_key(
            tenant_id=tenant_id,
            scope_type="project",
            project_id="project-a",
            allowed_projects=["project-b"],
            scope="write",
        )

        key = await authorize_request(raw_key, required_project="project-a", required_action="write")
        assert key is not None

        key = await authorize_request(raw_key, required_project="project-b", required_action="write")
        assert key is not None

        key = await authorize_request(raw_key, required_project="project-c", required_action="write")
        assert key is None

    @pytest.mark.asyncio
    async def test_authorize_request_read_only(self, temp_db, db_with_tenant):
        """Test authorize_request denies write for read-only key."""
        tenant_id = db_with_tenant

        raw_key, _ = await create_project_key(
            tenant_id=tenant_id,
            scope_type="project",
            project_id="project-a",
            scope="read",
        )

        key = await authorize_request(raw_key, required_project="project-a", required_action="read")
        assert key is not None

        key = await authorize_request(raw_key, required_project="project-a", required_action="write")
        assert key is None

    @pytest.mark.asyncio
    async def test_authorize_request_invalid_key(self, temp_db):
        """Test authorize_request returns None for invalid key."""
        key = await authorize_request("ishastra_invalid", required_project="project-a")
        assert key is None

    @pytest.mark.asyncio
    async def test_authorize_request_none_key(self, temp_db):
        """Test authorize_request returns None for None key."""
        key = await authorize_request(None, required_project="project-a")
        assert key is None


class TestResourceFilters:
    """Test resource_filters for fine-grained access control."""

    def test_resource_filters_in_project_key(self):
        """Test resource_filters are stored and retrieved correctly."""
        filters = {
            "asset_type": ["web", "api", "mobile"],
            "env": ["production", "staging"],
            "tags": ["pci-dss", "hipaa"],
            "custom": {"max_depth": 5, "exclude_paths": ["/admin", "/internal"]},
        }

        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="project",
            project_id="project-a",
            allowed_projects=[],
            resource_filters=filters,
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert key.resource_filters == filters
        assert key.resource_filters["asset_type"] == ["web", "api", "mobile"]
        assert key.resource_filters["custom"]["max_depth"] == 5

    @pytest.mark.asyncio
    async def test_resource_filters_persisted(self, temp_db, db_with_tenant):
        """Test resource_filters are persisted to database."""
        tenant_id = db_with_tenant

        filters = {
            "asset_type": ["web"],
            "env": ["prod"],
        }

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            scope_type="project",
            project_id="project-a",
            resource_filters=filters,
        )

        reloaded = await get_project_key(tenant_id, "project-a")
        assert reloaded.resource_filters == filters

    @pytest.mark.asyncio
    async def test_resource_filters_empty_by_default(self, temp_db, db_with_tenant):
        """Test resource_filters defaults to empty dict."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            scope_type="tenant",
        )

        assert record.resource_filters == {}

        reloaded = await get_project_key(tenant_id, None)
        assert reloaded.resource_filters == {}


class TestMultiProjectKeys:
    """Test multi-project keys with allowed_projects list."""

    @pytest.mark.asyncio
    async def test_create_multi_project_key(self, temp_db, db_with_tenant):
        """Test creating a key with multiple allowed projects."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            scope_type="project",
            project_id="primary-project",
            allowed_projects=["secondary-1", "secondary-2", "secondary-3"],
        )

        assert record.project_id == "primary-project"
        assert record.allowed_projects == ["secondary-1", "secondary-2", "secondary-3"]

        reloaded = await get_project_key(tenant_id, "primary-project")
        assert reloaded.allowed_projects == ["secondary-1", "secondary-2", "secondary-3"]

    def test_multi_project_key_authorization(self):
        """Test authorization works for multi-project keys."""
        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="project",
            project_id="primary",
            allowed_projects=["secondary-1", "secondary-2"],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        assert check_key_scope(key, required_project="primary") is True

        assert check_key_scope(key, required_project="secondary-1") is True
        assert check_key_scope(key, required_project="secondary-2") is True

        assert check_key_scope(key, required_project="unauthorized") is False

    @pytest.mark.asyncio
    async def test_rotate_preserves_allowed_projects(self, temp_db, db_with_tenant):
        """Test rotation preserves allowed_projects list."""
        tenant_id = db_with_tenant

        raw_key, original = await create_project_key(
            tenant_id=tenant_id,
            scope_type="project",
            project_id="primary",
            allowed_projects=["secondary-1", "secondary-2"],
        )

        result = await rotate_project_key(tenant_id, project_id="primary", ttl_days=60)
        new_raw_key, new_record = result

        assert new_record.allowed_projects == ["secondary-1", "secondary-2"]

        for proj in ["primary", "secondary-1", "secondary-2"]:
            validated = await authorize_request(new_raw_key, required_project=proj)
            assert validated is not None, f"Failed for project {proj}"


class TestIncludeHosts:
    """Test include_hosts field for host allowlisting."""

    @pytest.mark.asyncio
    async def test_create_key_with_include_hosts(self, temp_db, db_with_tenant):
        """Test creating key with include_hosts."""
        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            scope_type="project",
            project_id="project-a",
            include_hosts="*.example.com, api.example.com",
        )

        assert record.include_hosts == "*.example.com, api.example.com"

        reloaded = await get_project_key(tenant_id, "project-a")
        assert reloaded.include_hosts == "*.example.com, api.example.com"

    @pytest.mark.asyncio
    async def test_include_hosts_in_validate_result(self, temp_db, db_with_tenant):
        """Test include_hosts appears in validate_api_key_with_scopes result."""
        tenant_id = db_with_tenant

        raw_key, _ = await create_project_key(
            tenant_id=tenant_id,
            scope_type="project",
            project_id="project-a",
            include_hosts="*.example.com",
        )

        result = await validate_api_key_with_scopes(raw_key)
        assert result["include_hosts"] == "*.example.com"


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_concurrent_key_creation(self, temp_db):
        """Test concurrent key creation for different tenants."""

        tenants = [f"tenant-{i}" for i in range(5)]

        async def create_key(tenant_id):
            return await create_project_key(
                tenant_id=tenant_id,
                scope_type="tenant",
            )

        results = await asyncio.gather(*[create_key(t) for t in tenants])

        assert len(results) == 5
        for raw_key, record in results:
            assert raw_key.startswith("ishastra_")
            assert record.tenant_id in tenants

    @pytest.mark.asyncio
    async def test_key_hash_uniqueness(self, temp_db):
        """Test that each created key has a unique hash."""

        hashes = set()
        for i in range(10):
            tenant_id = f"tenant-{i}"
            raw_key, record = await create_project_key(
                tenant_id=tenant_id,
                scope_type="tenant",
            )
            assert record.key_hash not in hashes, "Duplicate key hash generated"
            hashes.add(record.key_hash)

    @pytest.mark.asyncio
    async def test_validate_none_key(self, temp_db):
        """Test validate_project_key handles None gracefully."""
        result = await validate_project_key(None)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_key_scope_none_key(self):
        """Test check_key_scope handles None key (should not crash)."""

        key = ProjectKey(
            tenant_id="tenant-1",
            key_hash="abc",
            tier="standard",
            admin=False,
            active=True,
            scope="write",
            scope_type="tenant",
            project_id=None,
            allowed_projects=[],
            resource_filters={},
            created_at=time.time(),
            expires_at=None,
            last_used=None,
            rotated_at=time.time(),
            ai_enabled=False,
            include_hosts=None,
        )

        result = check_key_scope(key, required_project="project-a")
        assert result is True

    @pytest.mark.asyncio
    async def test_row_to_project_key_handles_missing_fields(self, temp_db, db_with_tenant):
        """Test _row_to_project_key handles missing optional fields."""

        tenant_id = db_with_tenant

        raw_key, record = await create_project_key(
            tenant_id=tenant_id,
            scope_type="tenant",
        )

        assert record.scope == "write"
        assert record.scope_type == "tenant"
        assert record.project_id is None
        assert record.allowed_projects == []
        assert record.resource_filters == {}
        assert record.include_hosts is None
        assert record.ai_enabled is False
        assert record.rotated_at is not None


class TestMigration24:
    """Test migration 24 (project-scoped API key extensions) from store."""

    @pytest.mark.asyncio
    async def test_migration_24_applied(self, temp_db):
        """Test that migration 24 columns and indexes exist."""
        db = await get_database()

        rows = await db.fetchall("PRAGMA table_info(api_keys)")
        columns = {row["name"] for row in rows}

        migration_24_columns = {
            "scope_type",
            "project_id",
            "allowed_projects",
            "resource_filters",
        }
        assert migration_24_columns.issubset(columns)

        indexes = await db.fetchall("PRAGMA index_list(api_keys)")
        index_names = {row["name"] for row in indexes}
        assert "api_keys_by_project" in index_names
        assert "api_keys_tenant_project" in index_names

    @pytest.mark.asyncio
    async def test_migration_24_default_values(self, temp_db, db_with_tenant):
        """Test migration 24 default values for new columns."""
        tenant_id = db_with_tenant
        key_hash = hashlib.sha256(b"test-migration").hexdigest()
        now = time.time()

        db = await get_database()
        async with db.transaction() as conn:
            await conn.execute(
                """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (tenant_id, key_hash, "standard", 0, 1, now),
            )

        key = await get_project_key(tenant_id, None)
        assert key is not None
        assert key.scope_type == "tenant"
        assert key.project_id is None
        assert key.allowed_projects == []
        assert key.resource_filters == {}
