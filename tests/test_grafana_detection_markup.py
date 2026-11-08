"""Title/cookie evidence must belong to an actual application DOM."""

from types import SimpleNamespace

import pytest

from redposture_core.modules.grafana import actions
from tests.application_markup import application_page


@pytest.mark.parametrize(
    "body,headers",
    [
        ("<title>Other</title><!-- <title>Grafana</title> -->", {}),
        ('<title>Other</title><script>var x="<title>Grafana</title>";</script>', {}),
        ('<style>x:after{content:"<title>Grafana</title>"}</style>', {}),
        ("<template><title>Grafana</title></template>", {}),
        ("<textarea><title>Grafana</title></textarea>", {}),
        ("<svg><title>Grafana</title></svg>", {}),
        ("<title>Other</title><title>Grafana</title>", {}),
        ("<title>Documentation <b>Grafana</b></title>", {}),
        ("<title>Grafana", {}),
        ("<![invalid markup]><!-- <title>Grafana</title> -->", {}),
        ("", {"Set-Cookie": "other=grafana_session; Path=/"}),
        ("", {"Set-Cookie": "old_grafana_session=x; Path=/"}),
        ("", {"Set-Cookie": "grafana_session_other=x; Path=/"}),
        ("", {"Set-Cookie": "other=x; Path=/grafana_session"}),
        ("", {"Set-Cookie": "other=x; grafana_session=extension"}),
        ("", {"Set-Cookie": "GRAFANA_SESSION=x; Path=/"}),
    ],
)
def test_inert_markup_and_unrelated_cookies_do_not_identify_grafana(body, headers):
    body += application_page("grafana", include_title=False)
    assert actions._looks_like_grafana_login(200, body, headers) is False


@pytest.mark.parametrize(
    "body,headers",
    [
        ("<title>Grafana</title>", {}),
        ("<HTML><HEAD><TITLE> Grafana login </TITLE></HEAD></HTML>", {}),
        ("<title>Grafana &lt;Main&gt; &#x41;&#66;</title>", {}),
        ("<title>Grafana</title><svg><title>Other</title></svg>", {}),
        ("<title>Grafana</title><!-- documentation --><title>Other</title>", {}),
        ("", {"Set-Cookie": "grafana_session=proof; Path=/; HttpOnly"}),
        ("", {"set-cookie": 'grafana_session="proof"; Path=/'}),
        ("", {"Set-Cookie": "other=x; Path=/\ngrafana_session=proof; Path=/"}),
        ("", {"Set-Cookie": "grafana_session=x; Expires=Wed, 01 Jan 2030 00:00:00 GMT; Path=/"}),
    ],
)
def test_real_login_proofs_are_kept_without_health_api(body, headers):
    body += application_page("grafana", include_title=False)
    assert actions._looks_like_grafana_login(200, body, headers) is True


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_error_page_does_not_identify_grafana(status):
    assert actions._looks_like_grafana_login(status, "<title>Grafana</title>", {}) is False


@pytest.mark.parametrize(
    "body,headers,expected",
    [
        ("<title>Other</title><!-- <title>Grafana</title> -->", {}, False),
        ('<script>var x="<title>Grafana</title>";</script>', {}, False),
        ("<title>Other</title>", {"Set-Cookie": "other=grafana_session"}, False),
        ("<title>Grafana</title>", {}, True),
        ("<title>Other</title>", {"Set-Cookie": "grafana_session=proof"}, True),
    ],
)
def test_complete_detect_decision_does_not_promote_fake_login(body, headers, expected):
    body += application_page("grafana", include_title=False)
    context = SimpleNamespace(host="qa", port=3000, lifecycle_state=None, args=SimpleNamespace(timeout=1, retries=0))
    steps = actions._detect_grafana_steps(context, {"show_datasources": False, "check_urls": []})
    try:
        request = next(steps)
        assert request.args[2] == "/api/health"
        request = steps.send((404, "not found", {}))
        assert request.args[2] == "/login"
        try:
            steps.send((200, body, headers))
            steps.send(None)  # Unavailable auth APIs cannot supply product proof.
        except StopIteration as result:
            record = result.value
        else:
            pytest.fail("detection must finish without extra network calls")
        assert record["is_grafana"] is expected
        assert record["auth_required"] is None
        assert record["status"] == ("unknown_auth" if expected else "not_grafana")
    finally:
        steps.close()
