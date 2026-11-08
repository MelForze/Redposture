"""Stable evidence IDs and grammar policies for the shared discovery engine.

These are evidence rules, not assertions that a credential is valid remotely.
Regex grammars are exposed by the classifier itself, so metadata cannot grow a
second independently maintained provider-token matcher.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class RulePolicy:
    id: str
    minimum_syntax: str
    value_policy: str
    dialect: str = "product-neutral"
    evidence: str = "explicit"


_POLICIES = (
    RulePolicy(
        "vault_private_export",
        "200 from an exportable Transit private export; positive version, complete validated base64 (>=16 decoded bytes) or closed private-key PEM",
        "full returned private material, including weak keys; no public-key or certificate export",
        "Vault Transit API",
    ),
    RulePolicy(
        "entropy_candidate",
        "20..256 ASCII token characters; >=3 character classes, lower-case and entropy >=4.2; metadata/routes/decoded plaintext excluded",
        "full candidate; never remote validation",
        evidence="heuristic",
    ),
    RulePolicy(
        "aws_credential_pair",
        "valid-format access-key identifier paired with a non-placeholder secret key in one object",
        "secret key only",
    ),
    RulePolicy(
        "credential_uri",
        "URI authority has hostname and user:password@",
        "percent-decoded password; invalid UTF-8 retains encoded component",
    ),
    RulePolicy("basic_auth", "Basic + strict base64 of a syntactically valid user:password", "decoded password"),
    RulePolicy(
        "cloud_init_password",
        "#cloud-config and explicit chpasswd/list literal user:password block",
        "password after the first user colon",
        "legacy cloud-init list literal; not a general YAML parser",
    ),
    RulePolicy(
        "credential_pair",
        "completed sensitive-name assignment or structurally decoded credential",
        "full extracted value",
    ),
    RulePolicy(
        "sensitive_field", "sensitive literal field name and non-placeholder value", "full original field value"
    ),
    RulePolicy(
        "sql_password",
        "CREATE/ALTER USER account IDENTIFIED BY quoted literal, or PASSWORD quoted literal",
        "collapse doubled delimiter; retain backslashes by default",
        "unknown; standard/mysql only when explicitly supplied",
    ),
    RulePolicy(
        "csv_secret_column",
        "first physical record has identifiable sensitive header; valid CSV cell",
        "RFC-style unquoting and doubled quotes",
        "CSV",
    ),
    RulePolicy("private_key_pem", "matched private-key BEGIN/END pair with body", "full PEM"),
    RulePolicy("jwt_structure", "three segments; JSON object header with string alg; object payload", "full token"),
    RulePolicy(
        "jwe_structure", "five segments; object header with string alg/enc and required nonempty segments", "full token"
    ),
    RulePolicy(
        "provider_token_format",
        "one of the shared classifier's exact provider regex grammars",
        "full token; no network validation",
    ),
    RulePolicy("bearer_auth", "Bearer with plausible opaque value", "full token"),
    RulePolicy("password_hash", "supported password-hash prefix and minimum encoded body", "full stored hash"),
    RulePolicy("webhook_url", "recognized secret-bearing webhook URL", "full URL"),
    RulePolicy("session_assignment", "recognized session name and at least eight value characters", "full value"),
    RulePolicy("xml_secret_element", "matched sensitive XML element", "XML entity decoded value", "XML/HTML"),
    RulePolicy("xml_secret_attribute", "completed sensitive XML/HTML attribute", "entity decoded value", "XML/HTML"),
    RulePolicy("html_secret_input", "input with sensitive name and completed value", "entity decoded value", "HTML"),
    RulePolicy("azure_sas", "SAS context fields plus sufficiently long sig", "decoded signature"),
    RulePolicy("azure_storage_connection_string", "AccountKey in storage connection context", "full key"),
    RulePolicy(
        "base64_credential", "strict encoded credential structure under sensitive field context", "decoded secret"
    ),
    RulePolicy(
        "placeholder", "recognized missing/masked/template sentinel", "unavailable; not a secret", evidence="indicator"
    ),
    RulePolicy(
        "aws_access_key_format",
        "AWS access-key identifier only",
        "identifier unavailable as standalone secret",
        evidence="indicator",
    ),
    RulePolicy(
        "plausible_value", "entropy evidence under an already sensitive field", "full value", evidence="supporting"
    ),
)

RULE_CATALOG = MappingProxyType({policy.id: policy for policy in _POLICIES})


def provider_grammars() -> dict[str, str]:
    """Exact active syntax for each provider; no additional regex evaluation."""
    from . import discovery_rules as rules

    named = (
        ("google_api_key_format", rules._GOOGLE_API_RE),
        ("github_token_format", rules._GITHUB_RE),
        ("gitlab_token_format", rules._GITLAB_RE),
        ("slack_token_format", rules._SLACK_RE),
        ("stripe_key_format", rules._STRIPE_RE),
        ("vault_token_format", rules._VAULT_RE),
        ("npm_token_format", rules._NPM_RE),
    )
    return {
        **{name: regex.pattern for name, regex in named},
        **{f"provider.{kind}": regex.pattern for regex, kind in rules._PROVIDER_TOKENS},
    }


def rule_catalog() -> MappingProxyType[str, RulePolicy]:
    """Return immutable current policies, including every actual provider grammar."""
    policies = dict(RULE_CATALOG)
    policies.update(
        {
            name: RulePolicy(name, syntax, "full token; format evidence only")
            for name, syntax in provider_grammars().items()
        }
    )
    return MappingProxyType(policies)
