# Changelog

## 0.4.0 - 2026-08-23

- Add `infrascout up` for one-command discovery, state initialization, drift refresh, local serving, and browser launch.
- Standardize deployments, containers, databases, networks, volumes, observations, evidence, relationships, and change events while retaining v0.x service compatibility.
- Diff relationship topology and allow relationship changes through the existing review and selective baseline-promotion workflow.
- Link Nginx routes to discovered upstream endpoints and capture systemd auto-start/restart/unit facts plus Docker restart policy.
- Upgrade PostgreSQL/MySQL read-only metadata to v2 with PK, unique and foreign-key constraints, roles, broader privileges, managed database drift state, unified five-state review, release blocking, and selective promotion.
- Rebuild the embedded viewer around applications, resource dossiers, exposure and dependency evidence, unified state semantics, complete database catalogs, and responsive offline Lucide icons.
- Raise the minimum Go version to 1.26.6.

## 0.3.2 - 2026-08-13

- Add consistent visual product marks to the suite switcher while retaining InfraScout's dense risk-focused navigation.
- Reconcile the overview risk count with explicit exposure/drift destinations and disclose risks hidden by the compact six-row priority queue.

## 0.3.1 - 2026-08-12

- Align the suite patch release with the FleetScope transient CPU health-classification fix validated by the cross-module published-artifact gate.

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
