"""Invitations: signed expiring tokens plus SMTP delivery."""

from __future__ import annotations

import types

import pytest

from strix.core import invitations


def test_token_roundtrip_normalises_email_and_carries_claims():
    token = invitations.create_invite_token(
        org_id="org_1", email="Analyst@Example.COM", role="org_member", secret="s3cret"
    )
    claims = invitations.verify_invite_token(token, "s3cret")
    assert claims["org_id"] == "org_1"
    assert claims["email"] == "analyst@example.com"
    assert claims["role"] == "org_member"
    assert claims["token_type"] == invitations.TOKEN_TYPE


def test_token_carries_team_when_given():
    token = invitations.create_invite_token(
        org_id="org_1", email="a@example.com", role="org_member", secret="s3cret", team_id="team_9"
    )
    assert invitations.verify_invite_token(token, "s3cret")["team_id"] == "team_9"


def test_expired_token_is_rejected():
    token = invitations.create_invite_token(
        org_id="org_1", email="a@example.com", role="org_member", secret="s3cret", ttl=-1
    )
    with pytest.raises(ValueError, match="invalid or expired"):
        invitations.verify_invite_token(token, "s3cret")


def test_forged_token_is_rejected():
    token = invitations.create_invite_token(
        org_id="org_1", email="a@example.com", role="org_member", secret="s3cret"
    )
    with pytest.raises(ValueError):
        invitations.verify_invite_token(token, "other-secret")


def test_missing_signing_key_is_refused():
    with pytest.raises(ValueError):
        invitations.create_invite_token(org_id="o", email="a@b.c", role="r", secret="")


def test_link_uses_public_base_url_when_set():
    assert invitations.build_invite_link("https://strix.example/", "tok") == (
        "https://strix.example/accept-invite?token=tok"
    )
    assert invitations.build_invite_link("", "tok") == "tok"


def test_message_contains_link_and_role():
    message = invitations.render_invite_message(
        to="a@example.com",
        sender="noreply@example.com",
        org_name="Acme",
        role="org_admin",
        link="https://strix.example/accept-invite?token=tok",
    )
    assert message["To"] == "a@example.com"
    assert "Acme" in message["Subject"]
    body = message.get_content()
    assert "org_admin" in body
    assert "accept-invite?token=tok" in body


def test_unconfigured_smtp_is_reported_clearly():
    settings = types.SimpleNamespace(smtp_host="", smtp_from="")
    with pytest.raises(invitations.SMTPNotConfigured, match="STRIX_SMTP_HOST"):
        invitations.send_invite_email(settings, to="a@example.com", org_name="Acme", role="r", token="t")


def test_send_uses_smtp_and_marks_message(monkeypatch):
    sent: list = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            sent.append("starttls")

        def login(self, username, password):
            sent.append((username, password))

        def send_message(self, message):
            sent.append(message)

    monkeypatch.setattr(invitations.smtplib, "SMTP", FakeSMTP)
    settings = types.SimpleNamespace(
        smtp_host="smtp.example.com",
        smtp_port=2525,
        smtp_username="mailer",
        smtp_password="pw",
        smtp_from="noreply@example.com",
        smtp_starttls=True,
        public_base_url="https://strix.example",
    )
    link = invitations.send_invite_email(
        settings, to="a@example.com", org_name="Acme", role="org_member", token="tok"
    )
    assert link == "https://strix.example/accept-invite?token=tok"
    assert ("smtp.example.com", 2525) in sent
    assert "starttls" in sent
    assert ("mailer", "pw") in sent
    delivered = [item for item in sent if hasattr(item, "get_content")]
    assert len(delivered) == 1
    assert "tok" in delivered[0].get_content()
