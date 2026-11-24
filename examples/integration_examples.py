"""
Ishastra Integration Connectors - Usage Examples

This script demonstrates how to use the various integration connectors
for sending findings to SIEMs, creating tickets, sending chat alerts,
triggering CI/CD pipelines, and managing secrets.
"""

import threading

from ishastra.integrations import (
    DatadogConfig,
    ElasticConfig,
    GitHubActionsConfig,
    GitHubIssuesConfig,
    GitLabCIConfig,
    GitLabIssuesConfig,
    JiraConfig,
    MattermostConfig,
    SentinelConfig,
    ServiceNowConfig,
    SlackConfig,
    SplunkHECConfig,
    TeamsConfig,
    get_connector,
)


SAMPLE_FINDING = {
    "finding": {
        "category": "sql_injection",
        "severity": "critical",
        "title": "SQL Injection in Login Endpoint",
        "location": "https://api.example.com/v1/login",
        "cwe": "CWE-89",
        "confidence": "high",
        "verification": "verified",
        "evidence": (
            "Parameter 'username' vulnerable to boolean-based blind SQL injection. Payload: ' OR '1'='1"
        ),
        "fingerprint": "a1b2c3d4e5f6",
        "remediation": (
            "Use parameterized queries / prepared statements. Validate and sanitize all user inputs."
        ),
    },
    "job": {
        "id": "job-2024-001",
        "profile": "owasp-top-10",
        "actor": "ishastra-scanner-01",
        "policy": {
            "policy_id": "pol-security-baseline",
            "tenant_id": "tenant-acme",
        },
    },
    "target": "https://api.example.com",
    "timestamp": 1700000000.0,
}


def create_siem_payloads():
    """Create sample payloads for SIEM connectors."""

    single = SAMPLE_FINDING.copy()

    batch = {
        "findings": [
            SAMPLE_FINDING["finding"],
            {
                **SAMPLE_FINDING["finding"],
                "category": "xss",
                "severity": "high",
                "title": "Reflected XSS in Search",
                "location": "https://api.example.com/v1/search",
                "cwe": "CWE-79",
                "evidence": "Parameter 'q' reflects unescaped user input",
                "fingerprint": "f6e5d4c3b2a1",
            },
        ],
        "job": SAMPLE_FINDING["job"],
        "target": SAMPLE_FINDING["target"],
        "timestamp": SAMPLE_FINDING["timestamp"],
    }
    return single, batch


async def example_siem_connectors():
    """Example: Send findings to SIEM systems."""
    print("=== SIEM Connectors ===\n")

    single, batch = create_siem_payloads()
    cancel = threading.Event()

    print("1. Splunk HEC:")
    splunk_config = SplunkHECConfig(
        enabled=True,
        host="splunk.example.com",
        port=8088,
        token="your-hec-token-here",
        index="main",
        sourcetype="_json",
        use_ssl=True,
        verify_ssl=True,
    )
    splunk = get_connector("splunk_hec")
    if splunk:
        splunk.config = splunk_config
        try:
            result = splunk.send(batch, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
            print(f"   External ID: {result.external_id}")
            print(f"   Details: {result.details}")
        except Exception as e:
            print(f"   Error (expected without real Splunk): {e}")

    print("\n2. Elasticsearch (ECS format):")
    elastic_config = ElasticConfig(
        enabled=True,
        hosts=["https://elasticsearch.example.com:9200"],
        api_key="your-base64-api-key",
        index="ishastra-findings",
        verify_ssl=True,
    )
    elastic = get_connector("elastic")
    if elastic:
        elastic.config = elastic_config
        try:
            result = elastic.send(batch, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real Elastic): {e}")

    print("\n3. Datadog Logs:")
    datadog_config = DatadogConfig(
        enabled=True,
        api_key="your-datadog-api-key",
        site="datadoghq.com",
        ddsource="ishastra",
        ddtags="env:prod,team:security",
        service="ishastra",
    )
    datadog = get_connector("datadog")
    if datadog:
        datadog.config = datadog_config
        try:
            result = datadog.send(single, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real Datadog): {e}")

    print("\n4. Azure Sentinel:")
    import base64

    sentinel_config = SentinelConfig(
        enabled=True,
        workspace_id="your-workspace-id",
        shared_key=base64.b64encode(b"your-32-byte-shared-key-here==").decode(),
        log_type="IshastraFindings",
    )
    sentinel = get_connector("sentinel")
    if sentinel:
        sentinel.config = sentinel_config
        try:
            result = sentinel.send(batch, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real Sentinel): {e}")


async def example_ticketing_connectors():
    """Example: Create tickets from findings."""
    print("\n=== Ticketing Connectors ===\n")

    single, batch = create_siem_payloads()
    cancel = threading.Event()

    print("1. Jira:")
    jira_config = JiraConfig(
        enabled=True,
        base_url="https://company.atlassian.net",
        email="security@company.com",
        api_token="your-jira-api-token",
        project_key="SEC",
        issue_type="Task",
        default_priority="High",
        labels=["ishastra", "critical", "sql-injection"],
    )
    jira = get_connector("jira")
    if jira:
        jira.config = jira_config
        try:
            result = jira.send(single, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
            print(f"   Issue: {result.details}")
        except Exception as e:
            print(f"   Error (expected without real Jira): {e}")

    print("\n2. GitHub Issues:")
    github_config = GitHubIssuesConfig(
        enabled=True,
        token="ghp_your-github-token",
        owner="myorg",
        repo="security-tracking",
        labels=["ishastra", "critical", "sql-injection"],
        assignees=["security-lead"],
    )
    github = get_connector("github_issues")
    if github:
        github.config = github_config
        try:
            result = github.send(single, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
            print(f"   Issue: {result.details}")
        except Exception as e:
            print(f"   Error (expected without real GitHub): {e}")

    print("\n3. GitLab Issues:")
    gitlab_config = GitLabIssuesConfig(
        enabled=True,
        base_url="https://gitlab.com",
        token="glpat_your-gitlab-token",
        project_id="mygroup/myproject",
        labels=["ishastra", "critical", "sql-injection"],
        assignee_ids=[12345],
    )
    gitlab = get_connector("gitlab_issues")
    if gitlab:
        gitlab.config = gitlab_config
        try:
            result = gitlab.send(single, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
            print(f"   Issue: {result.details}")
        except Exception as e:
            print(f"   Error (expected without real GitLab): {e}")

    print("\n4. ServiceNow (with CMDB linking):")
    servicenow_config = ServiceNowConfig(
        enabled=True,
        instance_url="https://company.service-now.com",
        username="ishastra.integration",
        password="your-servicenow-password",
        table="incident",
        caller_id="ishastra.integration",
        assignment_group="Security Operations",
        category="security",
        subcategory="vulnerability",
        impact="1",
        urgency="1",
    )
    servicenow = get_connector("servicenow")
    if servicenow:
        servicenow.config = servicenow_config
        try:
            result = servicenow.send(single, timeout=60.0, cancel=cancel)
            print(f"   Result: {result.message}")
            print(f"   Incident: {result.details}")
        except Exception as e:
            print(f"   Error (expected without real ServiceNow): {e}")


async def example_chatops_connectors():
    """Example: Send alerts to chat platforms."""
    print("\n=== ChatOps Connectors ===\n")

    single, _ = create_siem_payloads()
    cancel = threading.Event()

    print("1. Slack (Webhook):")
    slack_config = SlackConfig(
        enabled=True,
        webhook_url="https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>",
        default_channel="#security-alerts",
        username="ishastra",
        icon_emoji=":shield:",
    )
    slack = get_connector("slack")
    if slack:
        slack.config = slack_config
        try:
            result = slack.send(single, timeout=15.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real Slack): {e}")

    print("\n2. Microsoft Teams:")
    teams_config = TeamsConfig(
        enabled=True,
        webhook_url="https://outlook.office.com/webhook/xxx",
    )
    teams = get_connector("teams")
    if teams:
        teams.config = teams_config
        try:
            result = teams.send(single, timeout=15.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real Teams): {e}")

    print("\n3. Mattermost:")
    mattermost_config = MattermostConfig(
        enabled=True,
        webhook_url="https://mattermost.example.com/hooks/xxx",
        username="ishastra",
        channel="security-alerts",
    )
    mattermost = get_connector("mattermost")
    if mattermost:
        mattermost.config = mattermost_config
        try:
            result = mattermost.send(single, timeout=15.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real Mattermost): {e}")


async def example_cicd_connectors():
    """Example: Trigger CI/CD pipelines."""
    print("\n=== CI/CD Connectors ===\n")

    cancel = threading.Event()

    cicd_payload = {
        "findings": [
            {
                "category": "sql_injection",
                "severity": "critical",
                "title": "SQL Injection in Login",
                "location": "https://api.example.com/v1/login",
                "cwe": "CWE-89",
                "confidence": "high",
                "verification": "verified",
                "evidence": "Test finding for CI/CD trigger",
                "fingerprint": "test123",
            }
        ],
        "job": {
            "id": "job-2024-001",
            "profile": "owasp-top-10",
            "actor": "ishastra-scanner-01",
            "policy": {"policy_id": "pol-security", "tenant_id": "tenant-acme"},
        },
        "target": "https://api.example.com",
        "timestamp": 1700000000.0,
    }

    print("1. GitHub Actions:")
    gh_actions_config = GitHubActionsConfig(
        enabled=True,
        token="ghp_test12345678901234",
        owner="myorg",
        repo="security-pipeline",
        workflow_file="security-scan.yml",
        ref="main",
        inputs={
            "scan_type": "targeted",
            "target": "https://api.example.com",
        },
    )
    gh_actions = get_connector("github_actions")
    if gh_actions:
        gh_actions.config = gh_actions_config
        try:
            result = gh_actions.send(cicd_payload, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real GitHub): {e}")

    print("\n2. GitLab CI:")
    gitlab_ci_config = GitLabCIConfig(
        enabled=True,
        base_url="https://gitlab.com",
        token="glpat_test12345678901234",
        project_id="mygroup/myproject",
        ref="main",
        variables={
            "TARGET_URL": "https://api.example.com",
            "SCAN_PROFILE": "targeted",
        },
    )
    gitlab_ci = get_connector("gitlab_ci")
    if gitlab_ci:
        gitlab_ci.config = gitlab_ci_config
        try:
            result = gitlab_ci.send(cicd_payload, timeout=30.0, cancel=cancel)
            print(f"   Result: {result.message}")
        except Exception as e:
            print(f"   Error (expected without real GitLab): {e}")
