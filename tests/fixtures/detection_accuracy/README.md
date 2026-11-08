# Detection accuracy corpus

`holdout.json` is a frozen, independently labelled **negative** evaluation split.
All six endpoints are synthetic unrelated applications, not captured products.
Their `expected:false` is a manual identity label; no classifier supplies expected
answers. The literal SHA in `scripts/detection_accuracy.py` locks the bytes. Do not
update it automatically on failure or tune fixtures to accommodate false positives.
A deliberate new corpus version requires review and a preserved previous version.

The reference split replays the hand-written wire fixtures for all 32 products in
`tests/test_network_fingerprint_matrix.py` and nine UI controls: seven fixtures from
`tests/test_web_panels.py`, plus explicit PostgREST and Kubernetes Dashboard
responses in the gate. These positive controls are **emulated**, not independent
captures from 32 real servers. They are not unseen holdout data. Genuine local
product checks and their exact versions must be recorded separately in QA reports.

Run from the repository root, with development dependencies installed:

```sh
.ci-venvs/py3.12/bin/python -m scripts.detection_accuracy --output /tmp/redposture-detection-accuracy-new
```

The output directory must be new. Each module and the UI group run sequentially
in a separate process, with a 120-second watchdog. A crash/timeout is FAIL, never
a true negative. Every observation keeps expected and actual identity, sync/async
mode, explicit fallback, adapter status/error, elapsed/CPU time and wire exchanges.
The resource metric is process peak RSS, including the fixture. HTTP exchanges
count received requests; native exchanges count accepted protocol connections,
not every message on a persistent session. They must not be compared as the same
unit or advertised as production throughput. UI/auth schemas and protocol service
families are not evidence of a particular vendor/version without its own marker.

The same positive must survive nginx headers, gzip and an explicit mount prefix
where HTTP is applicable. Foreign-product, malformed JSON, generic inventory/
capabilities/version, generic login and rate-limit controls must not be confirmed.
Adapter-reported inconclusive states and fallback remain visible. Decision parity
does not imply that all routes use a native async transport.

No external target scanning, execute, credential spray or data/discover actions
are enabled by this gate. Tests for cleanup, corrupted/truncated responses and
credential/CVE gating remain in the protocol/UI/network test suites and must also
be run for release acceptance. This finite corpus cannot certify all versions,
all proxies, production precision/recall, or availability when every proof is hidden.
