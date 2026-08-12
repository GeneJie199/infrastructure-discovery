# Changelog

## 0.3.0 - 2026-08-12

- Add audited drift review, expiring decisions, and selective approved-resource promotion into an atomic baseline.
- Discover Nginx routes and service coverage, then generate FleetScope-native application collection configuration without external collector dependencies.
- Add read-only PostgreSQL/MySQL metadata capture and structural diffing without collecting business rows.
- Rebuild the viewer around risk, assets, exposure, collection plans, database structure, and drift workflows, including IME-safe Chinese search.
- Add the shared suite header, configurable module switcher, and direct FleetScope data-ingest handoff.
- Make remote viewing explicitly read-only: review and baseline-promotion APIs remain disabled on non-loopback listeners.
- Gate tag releases on Windows, macOS, and Linux tests plus race, static, vulnerability, formatting, vet, and changelog checks.

## 0.2.0 - 2026-08-12

- Add the embedded local Web viewer and automatic file refresh.
- Add approved baselines, release checks, severity thresholds, and continuous watch mode.
- Discover Docker and Compose containers as service resources.
- Redact common secrets from process, systemd, and container command lines.
- Filter scanner process trees and volatile kernel workers from drift.
- Add atomic state writes, CI, multi-platform releases, checksums, installation assets, and operations documentation.
- Upgrade PostgreSQL and Unicode dependencies to patched versions and enforce `govulncheck` in CI.

## 0.1.0

- Discover Linux hosts, processes, listening endpoints, and systemd services.
- Generate inventories and snapshots with stable resource IDs.
- Compare snapshots and classify deterministic drift risk.
