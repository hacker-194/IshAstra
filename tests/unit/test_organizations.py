"""Unit tests for Strix Organization Hierarchy.

Tests cover:
- Org CRUD operations
- Team CRUD within org
- Membership add/remove/update
- Role-based access checks
- Org/team slug uniqueness
- Hierarchical queries (user's orgs, teams, effective permissions)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from strix.core import organizations, store
from strix.core.organizations import (
    Organization,
    Team,
    add_member,
    can_manage_role,
    create_org,
    create_team,
    delete_membership,
    delete_org,
    delete_team,
    get_membership,
    get_org,
    get_org_by_slug,
    get_org_memberships,
    get_team,
    get_team_by_slug,
    get_user_memberships,
    get_user_org_role,
    get_user_team_role,
    list_orgs,
    list_teams,
    remove_member,
    role_rank,
    update_member_role,
    update_member_status,
    update_org,
    update_team,
    user_has_org_access,
    user_has_team_access,
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store.configure(path)
    yield path
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)
    asyncio.run(store.close_database())


@pytest_asyncio.fixture
async def db(temp_db):
    """Initialize database with org hierarchy migrations."""
    await store.get_database()
    # Apply org hierarchy migrations (versions 21-23)
    await organizations.run_org_hierarchy_migrations(temp_db)
    yield
    await store.close_database()


# ---------------------------------------------------------------------------
# Role Hierarchy Tests
# ---------------------------------------------------------------------------


class TestRoleHierarchy:
    """Tests for role ordering and management permissions."""

    def test_role_rank_ordering(self):
        """Test role ranks are correctly ordered."""
        assert role_rank("viewer") == 0
        assert role_rank("team_member") == 10
        assert role_rank("org_member") == 20
        assert role_rank("team_lead") == 30
        assert role_rank("org_admin") == 40
        assert role_rank("invalid") == -1

    def test_can_manage_role(self):
        """Test role management permissions."""
        # org_admin can manage all lower roles
        assert can_manage_role("org_admin", "org_admin") is False  # cannot manage same
        assert can_manage_role("org_admin", "team_lead") is True
        assert can_manage_role("org_admin", "org_member") is True
        assert can_manage_role("org_admin", "team_member") is True
        assert can_manage_role("org_admin", "viewer") is True

        # team_lead can manage team_member and viewer
        assert can_manage_role("team_lead", "org_admin") is False
        assert can_manage_role("team_lead", "team_lead") is False
        assert can_manage_role("team_lead", "org_member") is True
        assert can_manage_role("team_lead", "team_member") is True
        assert can_manage_role("team_lead", "viewer") is True

        # org_member can manage team_member and viewer
        assert can_manage_role("org_member", "org_admin") is False
        assert can_manage_role("org_member", "team_lead") is False
        assert can_manage_role("org_member", "org_member") is False
        assert can_manage_role("org_member", "team_member") is True
        assert can_manage_role("org_member", "viewer") is True

        # team_member can only manage viewer
        assert can_manage_role("team_member", "org_member") is False
        assert can_manage_role("team_member", "team_member") is False
        assert can_manage_role("team_member", "viewer") is True

        # viewer cannot manage anyone
        assert can_manage_role("viewer", "viewer") is False


# ---------------------------------------------------------------------------
# Organization CRUD Tests
# ---------------------------------------------------------------------------


class TestOrgCRUD:
    """Tests for organization create, read, update, delete."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        pass

    async def test_create_org_minimal(self):
        """Create org with minimal params."""
        org = await create_org(name="Test Org")
        assert org.org_id.startswith("org_")
        assert org.name == "Test Org"
        assert org.slug == "test-org"
        assert org.tier == "standard"
        assert org.settings == {}
        assert org.created_at > 0

    async def test_create_org_with_all_params(self):
        """Create org with all params."""
        org = await create_org(
            name="Custom Org",
            slug="custom-org",
            tier="elevated",
            settings={"key": "value"},
        )
        assert org.name == "Custom Org"
        assert org.slug == "custom-org"
        assert org.tier == "elevated"
        assert org.settings == {"key": "value"}

    async def test_create_org_invalid_tier(self):
        """Invalid tier raises ValueError."""
        with pytest.raises(ValueError, match="Invalid tier"):
            await create_org(name="Test", tier="invalid")

    async def test_create_org_duplicate_slug(self):
        """Duplicate slug raises ValueError."""
        await create_org(name="Org One")
        with pytest.raises(ValueError, match="already exists"):
            await create_org(name="Org Two", slug="org-one")

    async def test_get_org_by_id(self):
        """Get org by ID."""
        created = await create_org(name="Test Org")
        org = await get_org(created.org_id)
        assert org is not None
        assert org.org_id == created.org_id
        assert org.name == "Test Org"

    async def test_get_org_by_slug(self):
        """Get org by slug."""
        created = await create_org(name="Test Org", slug="test-org")
        org = await get_org_by_slug("test-org")
        assert org is not None
        assert org.org_id == created.org_id

    async def test_get_org_not_found(self):
        """Get non-existent org returns None."""
        org = await get_org("org_nonexistent")
        assert org is None

    async def test_list_orgs(self):
        """List organizations."""
        await create_org(name="Org A")
        await create_org(name="Org B")
        orgs = await list_orgs()
        assert len(orgs) >= 2
        assert all(isinstance(o, Organization) for o in orgs)

    async def test_update_org_name(self):
        """Update org name."""
        org = await create_org(name="Original")
        updated = await update_org(org.org_id, name="Updated")
        assert updated.name == "Updated"
        assert updated.updated_at >= org.updated_at

    async def test_update_org_slug(self):
        """Update org slug with uniqueness check."""
        org = await create_org(name="Original", slug="original")
        updated = await update_org(org.org_id, slug="updated-slug")
        assert updated.slug == "updated-slug"

    async def test_update_org_duplicate_slug(self):
        """Update to duplicate slug raises ValueError."""
        await create_org(name="Org One", slug="org-one")
        org2 = await create_org(name="Org Two", slug="org-two")
        with pytest.raises(ValueError, match="already exists"):
            await update_org(org2.org_id, slug="org-one")

    async def test_update_org_tier(self):
        """Update org tier."""
        org = await create_org(name="Test", tier="standard")
        updated = await update_org(org.org_id, tier="unlimited")
        assert updated.tier == "unlimited"

    async def test_update_org_invalid_tier(self):
        """Update with invalid tier raises ValueError."""
        org = await create_org(name="Test")
        with pytest.raises(ValueError, match="Invalid tier"):
            await update_org(org.org_id, tier="invalid")

    async def test_update_org_settings(self):
        """Update org settings."""
        org = await create_org(name="Test", settings={"a": 1})
        updated = await update_org(org.org_id, settings={"b": 2})
        assert updated.settings == {"b": 2}

    async def test_update_org_no_changes(self):
        """Update with no changes returns same org."""
        org = await create_org(name="Test")
        updated = await update_org(org.org_id)
        assert updated.org_id == org.org_id
        assert updated.name == org.name

    async def test_delete_org(self):
        """Delete org cascades to teams and memberships."""
        org = await create_org(name="To Delete")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id)

        deleted = await delete_org(org.org_id)
        assert deleted is True

        # Verify cascaded deletion
        assert await get_org(org.org_id) is None
        assert await get_team(team.team_id) is None
        memberships = await get_org_memberships(org.org_id)
        assert len(memberships) == 0

    async def test_delete_org_not_found(self):
        """Delete non-existent org returns False."""
        deleted = await delete_org("org_nonexistent")
        assert deleted is False


# ---------------------------------------------------------------------------
# Team CRUD Tests
# ---------------------------------------------------------------------------


class TestTeamCRUD:
    """Tests for team create, read, update, delete within org."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        pass

    async def test_create_team_minimal(self):
        """Create team with minimal params."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Test Team")
        assert team.team_id.startswith("team_")
        assert team.org_id == org.org_id
        assert team.name == "Test Team"
        assert team.slug == "test-team"
        assert team.role_mappings == {}

    async def test_create_team_with_all_params(self):
        """Create team with all params."""
        org = await create_org(name="Test Org")
        team = await create_team(
            org_id=org.org_id,
            name="Custom Team",
            slug="custom-team",
            role_mappings={"lead": "admin", "member": "viewer"},
        )
        assert team.slug == "custom-team"
        assert team.role_mappings == {"lead": "admin", "member": "viewer"}

    async def test_create_team_org_not_found(self):
        """Create team in non-existent org raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            await create_team(org_id="org_nonexistent", name="Team")

    async def test_create_team_duplicate_slug(self):
        """Duplicate team slug in same org raises ValueError."""
        org = await create_org(name="Test Org")
        await create_team(org_id=org.org_id, name="Team One")
        with pytest.raises(ValueError, match="already exists"):
            await create_team(org_id=org.org_id, name="Team Two", slug="team-one")

    async def test_get_team_by_id(self):
        """Get team by ID."""
        org = await create_org(name="Test Org")
        created = await create_team(org_id=org.org_id, name="Test Team")
        team = await get_team(created.team_id)
        assert team is not None
        assert team.team_id == created.team_id

    async def test_get_team_by_slug(self):
        """Get team by org ID and slug."""
        org = await create_org(name="Test Org")
        created = await create_team(org_id=org.org_id, name="Test Team", slug="test-team")
        team = await get_team_by_slug(org.org_id, "test-team")
        assert team is not None
        assert team.team_id == created.team_id

    async def test_get_team_not_found(self):
        """Get non-existent team returns None."""
        team = await get_team("team_nonexistent")
        assert team is None

    async def test_list_teams(self):
        """List teams in organization."""
        org = await create_org(name="Test Org")
        await create_team(org_id=org.org_id, name="Team A")
        await create_team(org_id=org.org_id, name="Team B")
        teams = await list_teams(org.org_id)
        assert len(teams) == 2
        assert all(isinstance(t, Team) for t in teams)

    async def test_update_team_name(self):
        """Update team name."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Original")
        updated = await update_team(team.team_id, name="Updated")
        assert updated.name == "Updated"

    async def test_update_team_slug(self):
        """Update team slug with uniqueness check."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Original", slug="original")
        updated = await update_team(team.team_id, slug="updated-slug")
        assert updated.slug == "updated-slug"

    async def test_update_team_duplicate_slug(self):
        """Update to duplicate slug in same org raises ValueError."""
        org = await create_org(name="Test Org")
        await create_team(org_id=org.org_id, name="Team One", slug="team-one")
        team2 = await create_team(org_id=org.org_id, name="Team Two", slug="team-two")
        with pytest.raises(ValueError, match="already exists"):
            await update_team(team2.team_id, slug="team-one")

    async def test_update_team_role_mappings(self):
        """Update team role mappings."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Test")
        updated = await update_team(team.team_id, role_mappings={"lead": "admin"})
        assert updated.role_mappings == {"lead": "admin"}

    async def test_delete_team(self):
        """Delete team cascades to memberships."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="To Delete")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id)

        deleted = await delete_team(team.team_id)
        assert deleted is True

        assert await get_team(team.team_id) is None
        memberships = await get_org_memberships(org.org_id, team_id=team.team_id)
        assert len(memberships) == 0

    async def test_delete_team_not_found(self):
        """Delete non-existent team returns False."""
        deleted = await delete_team("team_nonexistent")
        assert deleted is False


# ---------------------------------------------------------------------------
# Membership Tests
# ---------------------------------------------------------------------------


class TestMembership:
    """Tests for adding, updating, removing members."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        pass

    async def test_add_member_org_level(self):
        """Add member at org level (no team)."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1", role="org_admin")
        assert membership.membership_id.startswith("mem_")
        assert membership.org_id == org.org_id
        assert membership.team_id is None
        assert membership.user_id == "user1"
        assert membership.role == "org_admin"
        assert membership.status == "active"

    async def test_add_member_team_level(self):
        """Add member to a team."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        membership = await add_member(
            org_id=org.org_id, user_id="user1", team_id=team.team_id, role="team_lead"
        )
        assert membership.team_id == team.team_id
        assert membership.role == "team_lead"

    async def test_add_member_invalid_role(self):
        """Invalid role raises ValueError."""
        org = await create_org(name="Test Org")
        with pytest.raises(ValueError, match="Invalid role"):
            await add_member(org_id=org.org_id, user_id="user1", role="invalid")

    async def test_add_member_invalid_status(self):
        """Invalid status raises ValueError."""
        org = await create_org(name="Test Org")
        with pytest.raises(ValueError, match="Invalid status"):
            await add_member(org_id=org.org_id, user_id="user1", status="invalid")

    async def test_add_member_org_not_found(self):
        """Add member to non-existent org raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            await add_member(org_id="org_nonexistent", user_id="user1")

    async def test_add_member_team_not_in_org(self):
        """Add member to team not in org raises ValueError."""
        org1 = await create_org(name="Org 1")
        org2 = await create_org(name="Org 2")
        team = await create_team(org_id=org2.org_id, name="Team")
        with pytest.raises(ValueError, match="not found in organization"):
            await add_member(org_id=org1.org_id, user_id="user1", team_id=team.team_id)

    async def test_add_member_duplicate(self):
        """Duplicate membership raises ValueError."""
        org = await create_org(name="Test Org")
        await add_member(org_id=org.org_id, user_id="user1")
        with pytest.raises(ValueError, match="already a member"):
            await add_member(org_id=org.org_id, user_id="user1")

    async def test_add_member_duplicate_team(self):
        """Duplicate team membership raises ValueError."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id)
        with pytest.raises(ValueError, match="already a member"):
            await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id)

    async def test_get_user_memberships(self):
        """Get all memberships for a user."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", role="org_member")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id, role="team_lead")

        memberships = await get_user_memberships("user1")
        assert len(memberships) == 2
        roles = {m.role for m in memberships}
        assert roles == {"org_member", "team_lead"}

    async def test_get_user_memberships_filtered_by_org(self):
        """Get user memberships filtered by org."""
        org1 = await create_org(name="Org 1")
        org2 = await create_org(name="Org 2")
        await add_member(org_id=org1.org_id, user_id="user1")
        await add_member(org_id=org2.org_id, user_id="user1")

        memberships = await get_user_memberships("user1", org_id=org1.org_id)
        assert len(memberships) == 1
        assert memberships[0].org_id == org1.org_id

    async def test_get_org_memberships(self):
        """Get all memberships in an org."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", role="org_admin")
        await add_member(org_id=org.org_id, user_id="user2", team_id=team.team_id, role="team_member")

        memberships = await get_org_memberships(org.org_id)
        assert len(memberships) == 2

    async def test_get_org_memberships_filtered_by_team(self):
        """Get org memberships filtered by team."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", role="org_member")
        await add_member(org_id=org.org_id, user_id="user2", team_id=team.team_id, role="team_member")

        memberships = await get_org_memberships(org.org_id, team_id=team.team_id)
        assert len(memberships) == 1
        assert memberships[0].user_id == "user2"

    async def test_update_member_role(self):
        """Update member role with actor validation."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1", role="org_member")

        # actor_role must be strictly greater than target role
        updated = await update_member_role(
            membership.membership_id, role="org_member", actor_role="org_admin"
        )
        assert updated.role == "org_member"

    async def test_update_member_role_insufficient_perms(self):
        """Update role with insufficient actor role raises ValueError."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1", role="org_member")

        with pytest.raises(ValueError, match="cannot assign role"):
            await update_member_role(membership.membership_id, role="org_admin", actor_role="org_member")

    async def test_update_member_role_no_actor(self):
        """Update role without actor validation."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1", role="org_member")

        updated = await update_member_role(membership.membership_id, role="org_admin")
        assert updated.role == "org_admin"

    async def test_update_member_status(self):
        """Update member status."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1")

        updated = await update_member_status(membership.membership_id, status="suspended")
        assert updated.status == "suspended"

    async def test_update_member_status_invalid(self):
        """Invalid status raises ValueError."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1")

        with pytest.raises(ValueError, match="Invalid status"):
            await update_member_status(membership.membership_id, status="invalid")

    async def test_remove_member(self):
        """Remove member (soft delete)."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1")

        removed = await remove_member(membership.membership_id)
        assert removed is True

        updated = await get_membership(membership.membership_id)
        assert updated.status == "removed"

    async def test_remove_member_not_found(self):
        """Remove non-existent member returns False."""
        removed = await remove_member("mem_nonexistent")
        assert removed is False

    async def test_delete_membership(self):
        """Permanently delete membership."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1")

        deleted = await delete_membership(membership.membership_id)
        assert deleted is True

        assert await get_membership(membership.membership_id) is None

    async def test_delete_membership_not_found(self):
        """Delete non-existent membership returns False."""
        deleted = await delete_membership("mem_nonexistent")
        assert deleted is False


# ---------------------------------------------------------------------------
# Role-Based Access Checks Tests
# ---------------------------------------------------------------------------


class TestRoleBasedAccess:
    """Tests for user_has_org_access and user_has_team_access."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        pass

    async def test_user_has_org_access_admin(self):
        """Org admin has access to all levels."""
        org = await create_org(name="Test Org")
        await add_member(org_id=org.org_id, user_id="user1", role="org_admin")

        assert await user_has_org_access("user1", org.org_id, "viewer") is True
        assert await user_has_org_access("user1", org.org_id, "team_member") is True
        assert await user_has_org_access("user1", org.org_id, "org_member") is True
        assert await user_has_org_access("user1", org.org_id, "team_lead") is True
        assert await user_has_org_access("user1", org.org_id, "org_admin") is True

    async def test_user_has_org_access_member(self):
        """Org member has access to member and below."""
        org = await create_org(name="Test Org")
        await add_member(org_id=org.org_id, user_id="user1", role="org_member")

        assert await user_has_org_access("user1", org.org_id, "viewer") is True
        assert await user_has_org_access("user1", org.org_id, "team_member") is True
        assert await user_has_org_access("user1", org.org_id, "org_member") is True
        assert await user_has_org_access("user1", org.org_id, "team_lead") is False
        assert await user_has_org_access("user1", org.org_id, "org_admin") is False

    async def test_user_has_org_access_no_membership(self):
        """User without membership has no access."""
        org = await create_org(name="Test Org")

        assert await user_has_org_access("user1", org.org_id, "viewer") is False

    async def test_user_has_org_access_inactive(self):
        """Inactive membership does not grant access."""
        org = await create_org(name="Test Org")
        membership = await add_member(org_id=org.org_id, user_id="user1", role="org_admin")
        await update_member_status(membership.membership_id, status="suspended")

        assert await user_has_org_access("user1", org.org_id, "viewer") is False

    async def test_user_has_team_access_lead(self):
        """Team lead has access to team member, viewer, and org_member (by rank)."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id, role="team_lead")

        assert await user_has_team_access("user1", team.team_id, "viewer") is True
        assert await user_has_team_access("user1", team.team_id, "team_member") is True
        assert await user_has_team_access("user1", team.team_id, "team_lead") is True
        # team_lead (rank 30) >= org_member (rank 20) by numeric comparison
        assert await user_has_team_access("user1", team.team_id, "org_member") is True

    async def test_user_has_team_access_member(self):
        """Team member has access to team member and viewer."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id, role="team_member")

        assert await user_has_team_access("user1", team.team_id, "viewer") is True
        assert await user_has_team_access("user1", team.team_id, "team_member") is True
        assert await user_has_team_access("user1", team.team_id, "team_lead") is False

    async def test_user_has_team_access_no_membership(self):
        """User without team membership has no access."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")

        assert await user_has_team_access("user1", team.team_id, "viewer") is False


# ---------------------------------------------------------------------------
# Slug Uniqueness Tests
# ---------------------------------------------------------------------------


class TestSlugUniqueness:
    """Tests for org and team slug uniqueness constraints."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        pass

    async def test_org_slug_unique_global(self):
        """Org slugs are globally unique."""
        await create_org(name="Org One", slug="my-org")
        with pytest.raises(ValueError, match="already exists"):
            await create_org(name="Org Two", slug="my-org")

    async def test_team_slug_unique_per_org(self):
        """Team slugs unique within org, but can repeat across orgs."""
        org1 = await create_org(name="Org 1")
        org2 = await create_org(name="Org 2")

        await create_team(org_id=org1.org_id, name="Team", slug="my-team")
        await create_team(org_id=org2.org_id, name="Team", slug="my-team")  # OK in different org

        # But not in same org
        with pytest.raises(ValueError, match="already exists"):
            await create_team(org_id=org1.org_id, name="Team 2", slug="my-team")

    async def test_org_slug_auto_generated(self):
        """Org slug auto-generated from name."""
        org = await create_org(name="My Cool Organization!")
        assert org.slug == "my-cool-organization"

    async def test_team_slug_auto_generated(self):
        """Team slug auto-generated from name."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="My Cool Team!")
        assert team.slug == "my-cool-team"

    async def test_slug_max_length(self):
        """Slug is auto-truncated to 64 characters."""
        org = await create_org(name="Test Org")
        # The _slugify function truncates to 64 chars
        long_name = "a" * 70  # 70 'a' chars -> slug of 64 'a' chars (truncated)
        team = await create_team(org_id=org.org_id, name=long_name)
        assert team.slug == "a" * 64


# ---------------------------------------------------------------------------
# Hierarchical Query Tests
# ---------------------------------------------------------------------------


class TestHierarchicalQueries:
    """Tests for hierarchical queries: user's orgs, teams, effective permissions."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        pass

    async def test_get_user_org_role_highest(self):
        """Get user's highest role in org across all teams."""
        org = await create_org(name="Test Org")
        team1 = await create_team(org_id=org.org_id, name="Team 1")
        team2 = await create_team(org_id=org.org_id, name="Team 2")

        # User has org_member at org level, team_lead in team1, team_member in team2
        await add_member(org_id=org.org_id, user_id="user1", role="org_member")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team1.team_id, role="team_lead")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team2.team_id, role="team_member")

        role = await get_user_org_role("user1", org.org_id)
        assert role == "team_lead"  # Highest role

    async def test_get_user_org_role_only_team(self):
        """Get user's highest role when only in teams."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id, role="team_lead")

        role = await get_user_org_role("user1", org.org_id)
        assert role == "team_lead"

    async def test_get_user_org_role_none(self):
        """User not in org returns None."""
        org = await create_org(name="Test Org")
        role = await get_user_org_role("user1", org.org_id)
        assert role is None

    async def test_get_user_team_role(self):
        """Get user's role in specific team."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", team_id=team.team_id, role="team_lead")

        role = await get_user_team_role("user1", team.team_id)
        assert role == "team_lead"

    async def test_get_user_team_role_not_in_team(self):
        """User not in team returns None."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        role = await get_user_team_role("user1", team.team_id)
        assert role is None

    async def test_user_memberships_across_orgs(self):
        """User can have memberships in multiple orgs."""
        org1 = await create_org(name="Org 1")
        org2 = await create_org(name="Org 2")

        await add_member(org_id=org1.org_id, user_id="user1", role="org_admin")
        await add_member(org_id=org2.org_id, user_id="user1", role="org_member")

        memberships = await get_user_memberships("user1")
        assert len(memberships) == 2

        org1_memberships = await get_user_memberships("user1", org_id=org1.org_id)
        assert len(org1_memberships) == 1
        assert org1_memberships[0].role == "org_admin"

    async def test_org_memberships_includes_team_info(self):
        """Org memberships include team_id when applicable."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")
        await add_member(org_id=org.org_id, user_id="user1", role="org_member")
        await add_member(org_id=org.org_id, user_id="user2", team_id=team.team_id, role="team_lead")

        memberships = await get_org_memberships(org.org_id)
        assert len(memberships) == 2

        org_level = [m for m in memberships if m.team_id is None]
        team_level = [m for m in memberships if m.team_id is not None]

        assert len(org_level) == 1
        assert org_level[0].user_id == "user1"
        assert len(team_level) == 1
        assert team_level[0].user_id == "user2"
        assert team_level[0].team_id == team.team_id

    async def test_effective_permissions_org_admin(self):
        """Org admin has org-level access but needs team membership for team access."""
        org = await create_org(name="Test Org")
        team1 = await create_team(org_id=org.org_id, name="Team 1")
        team2 = await create_team(org_id=org.org_id, name="Team 2")

        await add_member(org_id=org.org_id, user_id="user1", role="org_admin")

        # Org admin has org-level access
        assert await user_has_org_access("user1", org.org_id, "org_admin") is True

        # But needs explicit team membership for team-level access
        assert await user_has_team_access("user1", team1.team_id, "team_lead") is False
        assert await user_has_team_access("user1", team2.team_id, "team_lead") is False

        # Add org admin as team member
        await add_member(org_id=org.org_id, user_id="user1", team_id=team1.team_id, role="team_member")
        assert await user_has_team_access("user1", team1.team_id, "team_member") is True

    async def test_effective_permissions_team_lead_only_in_team(self):
        """Team lead permissions scoped to their team, but org role is derived from highest."""
        org = await create_org(name="Test Org")
        team1 = await create_team(org_id=org.org_id, name="Team 1")
        team2 = await create_team(org_id=org.org_id, name="Team 2")

        await add_member(org_id=org.org_id, user_id="user1", team_id=team1.team_id, role="team_lead")

        # Team lead in team1
        assert await user_has_team_access("user1", team1.team_id, "team_lead") is True
        assert await user_has_team_access("user1", team1.team_id, "team_member") is True

        # But not in team2
        assert await user_has_team_access("user1", team2.team_id, "viewer") is False

        # get_user_org_role returns highest role across all memberships in org
        # So team_lead (rank 30) gives org-level access >= org_member (rank 20)
        assert await user_has_org_access("user1", org.org_id, "org_member") is True
        assert await user_has_org_access("user1", org.org_id, "team_lead") is True
        assert await user_has_org_access("user1", org.org_id, "org_admin") is False

    async def test_inactive_membership_no_permissions(self):
        """Inactive/suspended/removed memberships grant no permissions."""
        org = await create_org(name="Test Org")
        team = await create_team(org_id=org.org_id, name="Team")

        membership = await add_member(org_id=org.org_id, user_id="user1", role="org_admin")
        await update_member_status(membership.membership_id, status="suspended")

        assert await user_has_org_access("user1", org.org_id, "viewer") is False

        membership2 = await add_member(
            org_id=org.org_id, user_id="user2", team_id=team.team_id, role="team_lead"
        )
        await update_member_status(membership2.membership_id, status="removed")

        assert await user_has_team_access("user2", team.team_id, "viewer") is False

    async def test_pending_membership_no_permissions(self):
        """Pending memberships grant no permissions."""
        org = await create_org(name="Test Org")
        await add_member(org_id=org.org_id, user_id="user1", role="org_admin", status="pending")

        assert await user_has_org_access("user1", org.org_id, "viewer") is False


# ---------------------------------------------------------------------------
# Integration Test: Full Hierarchy Flow
# ---------------------------------------------------------------------------


class TestFullHierarchyFlow:
    """Integration test for complete org->team->member flow."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup(self, db):
        pass

    async def test_complete_org_hierarchy(self):
        """Test creating org, teams, members and checking permissions."""
        # Create organization
        org = await create_org(name="Acme Corp", slug="acme", tier="elevated")
        assert org.tier == "elevated"

        # Create teams
        eng_team = await create_team(org_id=org.org_id, name="Engineering", slug="eng")
        sec_team = await create_team(org_id=org.org_id, name="Security", slug="sec")

        # Add members
        # Alice - org admin
        await add_member(org_id=org.org_id, user_id="alice", role="org_admin")

        # Bob - engineering team lead
        bob_eng = await add_member(
            org_id=org.org_id, user_id="bob", team_id=eng_team.team_id, role="team_lead"
        )

        # Carol - security team member
        carol_sec = await add_member(
            org_id=org.org_id, user_id="carol", team_id=sec_team.team_id, role="team_member"
        )

        # Dave - org member (no team)
        await add_member(org_id=org.org_id, user_id="dave", role="org_member")

        # Verify org memberships
        all_memberships = await get_org_memberships(org.org_id)
        assert len(all_memberships) == 4

        # Verify team memberships
        eng_memberships = await get_org_memberships(org.org_id, team_id=eng_team.team_id)
        assert len(eng_memberships) == 1
        assert eng_memberships[0].user_id == "bob"

        sec_memberships = await get_org_memberships(org.org_id, team_id=sec_team.team_id)
        assert len(sec_memberships) == 1
        assert sec_memberships[0].user_id == "carol"

        # Verify effective permissions
        # Alice (org_admin) has org access but needs team membership for team access
        assert await user_has_org_access("alice", org.org_id, "org_admin") is True
        assert await user_has_team_access("alice", eng_team.team_id, "team_lead") is False
        assert await user_has_team_access("alice", sec_team.team_id, "team_lead") is False

        # Bob (team_lead in eng) has access to eng team, and org access via highest role
        assert await user_has_org_access("bob", org.org_id, "org_member") is True  # team_lead >= org_member
        assert await user_has_org_access("bob", org.org_id, "team_lead") is True
        assert await user_has_org_access("bob", org.org_id, "org_admin") is False
        assert await user_has_team_access("bob", eng_team.team_id, "team_lead") is True
        assert await user_has_team_access("bob", eng_team.team_id, "team_member") is True
        assert await user_has_team_access("bob", sec_team.team_id, "viewer") is False

        # Carol (team_member in sec) has access to sec team, and org access via team_member
        assert await user_has_org_access("carol", org.org_id, "team_member") is True
        assert await user_has_org_access("carol", org.org_id, "org_member") is False
        # team_member < org_member
        assert await user_has_team_access("carol", sec_team.team_id, "team_member") is True
        assert await user_has_team_access("carol", sec_team.team_id, "viewer") is True
        assert await user_has_team_access("carol", eng_team.team_id, "viewer") is False

        # Dave (org_member) has org access but no team access
        assert await user_has_org_access("dave", org.org_id, "org_member") is True
        assert await user_has_org_access("dave", org.org_id, "team_member") is True
        assert await user_has_team_access("dave", eng_team.team_id, "viewer") is False

        # Verify highest role queries
        assert await get_user_org_role("alice", org.org_id) == "org_admin"
        assert await get_user_org_role("bob", org.org_id) == "team_lead"
        assert await get_user_org_role("carol", org.org_id) == "team_member"
        assert await get_user_org_role("dave", org.org_id) == "org_member"

        # Verify team-specific roles
        assert await get_user_team_role("bob", eng_team.team_id) == "team_lead"
        assert await get_user_team_role("carol", sec_team.team_id) == "team_member"
        assert await get_user_team_role("alice", eng_team.team_id) is None  # Not directly in team

        # Update role and verify
        await update_member_role(bob_eng.membership_id, role="org_member", actor_role="org_admin")
        assert await get_user_org_role("bob", org.org_id) == "org_member"
        assert await user_has_org_access("bob", org.org_id, "org_member") is True

        # Remove member and verify
        await remove_member(carol_sec.membership_id)
        assert await user_has_team_access("carol", sec_team.team_id, "viewer") is False
