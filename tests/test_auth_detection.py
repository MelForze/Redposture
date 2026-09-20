from __future__ import annotations

from redposture_core.auth_detection import auth_required_text, detect_browser_sso


def test_detects_keycloak_from_redirect_url_and_page() -> None:
    result = detect_browser_sso(
        final_url=(
            "https://id.example/realms/company/protocol/openid-connect/auth"
            "?client_id=airflow&redirect_uri=https%3A%2F%2Fairflow.example%2Foauth-authorized"
            "&response_type=code&scope=openid"
        ),
        body='<form id="kc-form-login" action="/realms/company/login-actions/authenticate"></form>',
    )
    assert result is not None
    assert (result.provider, result.protocol) == ("keycloak", "oidc")
    assert result.evidence == ("identity_provider_url", "identity_provider_page")


def test_detects_common_identity_providers() -> None:
    cases = {
        "https://tenant.auth0.com/authorize?client_id=x&redirect_uri=x&response_type=code": "auth0",
        "https://tenant.okta.com/oauth2/v1/authorize?client_id=x&redirect_uri=x&response_type=code": "okta",
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=x&redirect_uri=x": "entra",
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&redirect_uri=x": "google",
        "https://proxy.example/oauth2/sign_in": "oauth2-proxy",
    }
    for url, provider in cases.items():
        result = detect_browser_sso(final_url=url)
        assert result is not None and result.provider == provider


def test_bearer_challenge_and_generic_login_are_not_sso() -> None:
    assert (
        detect_browser_sso(
            headers={"WWW-Authenticate": 'Bearer realm="https://registry.example/token"'},
            body="authentication required",
        )
        is None
    )
    assert detect_browser_sso(body='<form action="/login"><input name="username"></form>') is None
    assert detect_browser_sso(body="OAuth support is enabled") is None
    assert detect_browser_sso(final_url="https://api.example/realms/production/resources") is None


def test_generic_oidc_requires_full_authorize_evidence() -> None:
    assert detect_browser_sso(final_url="https://login.example/oauth/callback") is None
    result = detect_browser_sso(
        final_url=(
            "https://login.example/authorize?client_id=airflow&redirect_uri=https%3A%2F%2Fairflow.example%2Fcb"
            "&response_type=code"
        )
    )
    assert result is not None and result.provider == "oidc"


def test_auth_required_text_preserves_boolean_json_semantics() -> None:
    assert auth_required_text(True, "sso") == "sso"
    assert auth_required_text(True, "native") == "True"
    assert auth_required_text(False, "anonymous") == "False"
    assert auth_required_text(None, None) == "unknown"
