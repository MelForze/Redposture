"""Provider prefix selection must preserve the complete rule results."""

import random

from redposture_core import discovery_rules as rules
from tests.test_secret_detection_prefilter import SAMPLES


def test_provider_selection_has_exact_full_scan_parity(monkeypatch):
    original = rules._candidate_provider_rules
    rng = random.Random(20261109)
    corpus = list(SAMPLES)
    corpus += [s.swapcase() for s in SAMPLES]
    corpus += [s.replace("s", "ſ").replace("K", "K") for s in SAMPLES]
    corpus += [a + b for a in SAMPLES for b in SAMPLES]
    corpus += ["\n".join(rng.choices(SAMPLES, k=5)) for _ in range(100)]
    corpus += ["ordinary " * count + SAMPLES[8] for count in (0, 450, 455, 456, 600, 9000)]
    corpus += ["glpat-" + "q" * size for size in (4090, 4091, 4092, 65530, 65531, 65532)]
    for path in ("", "password", "version"):
        monkeypatch.setattr(rules, "_candidate_provider_rules", lambda _text: rules._PROVIDER_RULES)
        full = [rules.analyze_value(value, path=path) for value in corpus]
        monkeypatch.setattr(rules, "_candidate_provider_rules", original)
        assert [rules.analyze_value(value, path=path) for value in corpus] == full


def test_selector_covers_every_provider_and_preserves_rule_order():
    samples = (*SAMPLES, "AIza" + "a" * 35, "hvs." + "a" * 20, "npm_" + "a" * 20)
    assert len(rules._PROVIDER_RULES) == len(rules._PROVIDER_STARTS)
    seen = set()
    for text in samples:
        expected = tuple(rule for rule in rules._PROVIDER_RULES if rule[0].search(text))
        selected = rules._candidate_provider_rules(text)
        assert all(rule in selected for rule in expected)
        seen.update(rule[1] for rule in expected)
    assert seen == {rule[1] for rule in rules._PROVIDER_RULES}
    text = " ".join(reversed(samples))
    assert rules._candidate_provider_rules(text) == rules._PROVIDER_RULES
    assert [rule[1] for rule in rules._candidate_provider_rules(samples[8])] == ["gitlab_token"]
    assert rules._candidate_provider_rules("ordinary neutral text") == ()
    assert rules._candidate_provider_rules("padding " * 9000 + samples[8]) == rules._PROVIDER_RULES
