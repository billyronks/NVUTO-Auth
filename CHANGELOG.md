# Changelog

## 0.1.0 — 21 October 2026

Added a self-hosting quickstart, configuration reference, upgrade/rollback guide, existing-product integration guide, private configuration initializer and a runnable product app demonstrating login, MFA, workspace-bound resources, refresh and logout. Integration acceptance now exercises the product against the real auth binary.

New standalone authentication API and auth-owned schema. Replaces the extracted HR runtime with verified accounts, transactional single-use grants, opaque revocable sessions, refresh-family reuse detection, isolated MFA enrollment, encrypted mail delivery, current-state authorization and a local owner bootstrap.

This is a new installation, not an in-place upgrade. Legacy routes, JWT transport, HR profile fields, demo provisioning and unimplemented SSO/SMS are excluded. See docs/RELEASE.md for validation and remaining deployment gates.

Future backward-incompatible API changes require a minor version while pre-1.0. Security patches use patch releases. Schema changes must be forward-only and include an upgrade test; database restoration is the rollback strategy.
