from __future__ import annotations

from redposture_core import stage_kubeapi as kube


def test_tls_verify_error_detection() -> None:
    assert kube._is_tls_verify_error("tls verification failed") is True
    assert kube._is_tls_verify_error("self signed certificate") is True
    assert kube._is_tls_verify_error("connection timeout") is False


def test_basic_auth_and_header_precedence() -> None:
    basic = kube._basic_auth_value("admin", "admin")
    assert basic.startswith("Basic ")

    token_headers = kube._kube_api_headers("tok", "u", "p")
    assert token_headers == {"Authorization": "Bearer tok"}

    basic_headers = kube._kube_api_headers(None, "u", "p")
    assert basic_headers["Authorization"].startswith("Basic ")


def test_kube_exec_status_from_error_channel() -> None:
    code, msg, success = kube._kube_exec_status_from_error_channel("")
    assert code is None and msg is None and success is None

    code, msg, success = kube._kube_exec_status_from_error_channel('{"status":"Success"}')
    assert code == 0 and msg is None and success is True

    code, msg, success = kube._kube_exec_status_from_error_channel(
        '{"status":"Failure","message":"boom","details":{"causes":[{"reason":"ExitCode","message":"2"}]}}'
    )
    assert code == 2 and msg == "boom" and success is False


def test_kube_status_message_resolution() -> None:
    assert kube._kube_status_message(403, {}) == "authentication required"
    assert kube._kube_status_message(404, {}) == "endpoint not found"
    assert kube._kube_status_message(500, {"message": "oops"}) == "oops"
    assert kube._kube_status_message(500, {"kind": "Status", "code": 500}) == "kubernetes status code=500"


def test_kube_payload_and_version_helpers() -> None:
    assert kube._looks_like_kube_api_payload({"gitVersion": "v1.31.0"}) is True
    assert kube._looks_like_kube_api_payload({"kind": "NamespaceList"}) is True
    assert kube._looks_like_kube_api_payload({"hello": "world"}) is False

    assert kube._kube_version_text({"gitVersion": "v1.30.2"}) == "v1.30.2"
    assert kube._kube_version_text({"major": "1", "minor": "31"}) == "v1.31"
    assert kube._kube_version_text({"x": 1}) is None


def test_namespace_filters_and_pod_selector() -> None:
    assert kube._normalize_namespace_filters(["default,prod", "default"]) == ["default", "prod"]
    assert kube._parse_pod_selector("ns/pod") == ("ns", "pod")
    assert kube._parse_pod_selector("pod") == (None, "pod")
    assert kube._parse_pod_selector("  ") == (None, None)


def test_resolve_exec_pod_target_variants() -> None:
    ns, pod, err = kube._resolve_exec_pod_target(None, [], None)
    assert ns is None and pod is None and "missing --pod" in str(err)

    ns, pod, err = kube._resolve_exec_pod_target("kube-system/coredns", [], None)
    assert (ns, pod, err) == ("kube-system", "coredns", None)

    ns, pod, err = kube._resolve_exec_pod_target("api", ["default"], None)
    assert (ns, pod, err) == ("default", "api", None)

    ns, pod, err = kube._resolve_exec_pod_target(
        "api",
        [],
        [{"namespace": "a", "name": "api"}, {"namespace": "b", "name": "api"}],
    )
    assert ns is None and pod is None and "multiple pods named 'api'" in str(err)


def test_format_detect_record_and_status_summary() -> None:
    detect = kube._format_detect_record(
        {
            "host": "127.0.0.1",
            "port": 6443,
            "status": "detected",
            "auth_required": False,
            "version": "v1.30.2",
        },
        "txt",
    )
    assert "[*] Kubernetes API" in detect

    summary_anon = kube._status_summary_line(
        {
            "status": "detected",
            "auth_mode": "none",
            "auth_required": False,
            "show_namespaces": True,
            "namespaces": ["default"],
            "show_pods": False,
            "show_secrets": False,
        }
    )
    assert summary_anon == "[+] anonymous access (namespaces:1)"

    summary_token_fail = kube._status_summary_line(
        {
            "status": "auth_failed",
            "auth_mode": "token",
            "auth_valid": False,
            "auth_error": "denied",
            "show_namespaces": False,
            "show_pods": False,
            "show_secrets": False,
        }
    )
    assert summary_token_fail is not None
    assert summary_token_fail.startswith("[-] token auth failed")
    assert "err=denied" in summary_token_fail
