"""Deterministic credentials fixture; not configuration for production Airflow."""

# Worker-local counters make a variable subset of the same catalogue return
# HTTP 429. Test real-target rate-limit handling separately, without hiding it
# in the golden normalizer or misclassifying it as an invalid password.
AUTH_RATE_LIMITED = False
