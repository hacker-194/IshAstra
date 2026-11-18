"""SCIM group membership expressed from the user side (RFC 7644 user PATCH)."""

from __future__ import annotations

import pytest

from strix.core import scim, store

TENANT = "tenant_1"
TOKEN = "scim-token"


def _store() -> scim.SCIMStore:
    return scim.SCIMStore()


@pytest.fixture
def group_mapping(monkeypatch):
    """An in-memory group mapping instead of the database."""
    mappings = {"group_1": {"scim_id": "group_1", "display_name": "Analysts", "member_ids": []}}

    async def _get_group_mapping(scim_id, tenant_id, scim_token):
        found = mappings.get(scim_id)
        return dict(found) if found else None

    async def _get_group_mappings_by_tenant(tenant_id):
        return [dict(m) for m in mappings.values()]

    async def _save_group_mapping(scim_id, group_data, tenant_id, org_id, scim_token):
        mappings[scim_id] = {
            "scim_id": scim_id,
            "display_name": group_data.get("display_name"),
            "member_ids": list(group_data.get("member_ids", [])),
        }

    svc = _store()
    monkeypatch.setattr(svc, "_get_group_mapping", _get_group_mapping)
    monkeypatch.setattr(svc, "_get_group_mappings_by_tenant", _get_group_mappings_by_tenant)
    monkeypatch.setattr(svc, "_save_group_mapping", _save_group_mapping)
    return svc, mappings


async def test_add_then_remove_membership_by_group_id(group_mapping):
    svc, mappings = group_mapping
    await svc._apply_group_membership("user_1", [{"value": "group_1"}], TENANT, TOKEN, add=True)
    assert mappings["group_1"]["member_ids"] == ["user_1"]

    await svc._apply_group_membership("user_1", [{"value": "group_1"}], TENANT, TOKEN, add=False)
    assert mappings["group_1"]["member_ids"] == []


async def test_add_is_idempotent(group_mapping):
    svc, mappings = group_mapping
    await svc._apply_group_membership("user_1", ["group_1"], TENANT, TOKEN, add=True)
    await svc._apply_group_membership("user_1", ["group_1"], TENANT, TOKEN, add=True)
    assert mappings["group_1"]["member_ids"] == ["user_1"]


async def test_group_can_be_named_by_display_name(group_mapping):
    svc, mappings = group_mapping
    await svc._apply_group_membership("user_1", [{"display": "Analysts"}], TENANT, TOKEN, add=True)
    assert mappings["group_1"]["member_ids"] == ["user_1"]


async def test_unknown_group_is_ignored(group_mapping):
    svc, mappings = group_mapping
    await svc._apply_group_membership("user_1", [{"value": "nope"}], TENANT, TOKEN, add=True)
    assert mappings["group_1"]["member_ids"] == []


async def test_user_patch_routes_groups_to_membership(monkeypatch):
    svc = _store()
    calls: list[tuple] = []

    async def _get_user_mapping(user_id, tenant_id, scim_token):
        return {"strix_user_id": "su_1", "scim_id": user_id}

    async def _get_strix_user(user_id, tenant_id):
        return {
            "user_id": user_id,
            "email": "a@example.com",
            "display_name": "A",
            "role": "analyst",
            "scope": "write",
            "key_hash": "hash",
            "active": True,
            "created_at": 1.0,
        }

    async def _record(user_id, groups, tenant_id, scim_token, *, add):
        calls.append((user_id, [g.get("value") for g in groups], add))

    async def _save_tenant_user(**kwargs):
        return None

    async def _get_user(user_id, tenant_id, scim_token):
        return {"id": user_id}

    monkeypatch.setattr(svc, "_get_user_mapping", _get_user_mapping)
    monkeypatch.setattr(svc, "_get_strix_user", _get_strix_user)
    monkeypatch.setattr(svc, "_apply_group_membership", _record)
    monkeypatch.setattr(svc, "get_user", _get_user)
    monkeypatch.setattr(store, "save_tenant_user", _save_tenant_user)

    await svc.patch_user(
        "scim_user_1",
        [
            {"op": "add", "path": "groups", "value": [{"value": "group_1"}]},
            {"op": "remove", "path": "groups", "value": [{"value": "group_1"}]},
        ],
        TENANT,
        TOKEN,
    )

    assert calls == [
        ("scim_user_1", ["group_1"], True),
        ("scim_user_1", ["group_1"], False),
    ]
