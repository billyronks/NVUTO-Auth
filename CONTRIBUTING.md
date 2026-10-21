# Contributing

Use synthetic data and a new private test database. Never point the integration runner at a deployed database. Changes to credentials, authorization or migrations require real-route denial, replay, concurrency and rollback coverage.

Run python scripts/check.py and python scripts/integration.py before proposing a change. Keep the OpenAPI contract, migration version, configuration reference and operational runbook current. Do not re-enable HR, SSO or SMS routes through compatibility aliases. Do not introduce debug logging of requests or credentials.

Contributions are provided under the MIT license. Describe the problem, resulting behavior, validation and any compatibility change. Security reports belong in the private reporting process described in SECURITY.md.
