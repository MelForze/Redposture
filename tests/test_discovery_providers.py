"""Independent minimum-format examples survive the shared provider fast gate."""

from __future__ import annotations

import pytest

from redposture_core.discovery_rules import analyze_value


@pytest.mark.parametrize(
    "value,kind",
    [
        ("AIza" + "a" * 35, "google_api_key"),
        ("ghp_" + "a" * 20, "github_token"),
        ("github_pat_" + "a" * 22, "github_token"),
        ("glpat-" + "a" * 16, "gitlab_token"),
        ("xoxb-" + "a" * 10, "slack_token"),
        ("sk_test_" + "a" * 16, "stripe_key"),
        ("rk_live_" + "a" * 16, "stripe_key"),
        ("hvs." + "a" * 16, "vault_token"),
        ("npm_" + "a" * 20, "npm_token"),
        ("sk-" + "a" * 20, "api_token"),
        ("glsa_" + "a" * 20, "grafana_token"),
        ("dop_v1_" + "a" * 32, "digitalocean_token"),
        ("shpat_" + "a" * 24, "shopify_token"),
        ("dckr_pat_" + "a" * 20, "docker_token"),
        ("pypi-AgEI" + "a" * 16, "pypi_token"),
        ("SG." + "a" * 8 + "." + "b" * 16, "sendgrid_token"),
        ("SK" + "abcdef01" * 4, "twilio_token"),
        ("900000" + ":AA" + "a" * 20, "telegram_token"),
        ("https://hooks.slack.com/" + "services/QA/QA/QA", "slack_webhook"),
    ],
)
@pytest.mark.parametrize("prefix", ["", "service says: ", "λ summary "])
def test_shared_provider_formats_keep_full_token_in_logs(value, kind, prefix):
    actual = [
        (finding.secret_type, finding.value) for finding in analyze_value(prefix + value + " next") if finding.available
    ]
    assert (kind, value) in actual
