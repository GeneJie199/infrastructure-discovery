# infrastructure-discovery v2.0.0-rc.2 Community

InfraScout presents the existing discovery, inventory, drift, database and monitoring views in the shared Suite design. The change preserves the independent CLI and the underlying scan/review contracts.

## Changes in this candidate

- Shared Light / Dark / System appearance, responsive sidebar and mobile navigation, consistent cards and form/dialog surfaces. Module links preserve the current Suite hosts, ports and theme.
- Asset composition bars show counts from the loaded inventory using SVG and external theme classes, compatible with the existing strict Content Security Policy. Empty data remains explicit.
- The standalone HTML report embeds the same theme resources and requires no external CSS, JavaScript or CDN. It is generated from the selected local state; an empty state is not a successful scan.
- Read-only `GET /api/diagnostics/runtime` exposes seven aggregate process counters: goroutines, heap allocation, heap system/in-use bytes, total runtime system bytes, GC count and uptime. It exposes no profiles, configuration, environment, process arguments or credentials.
- The local Host/Origin boundary continues to reject foreign browser requests and accepts the actual supported loopback listener. The new presentation and diagnostics grant no additional scan, approval or production-operation authority.

## Installation and independent use

Use this component's [standalone CLI quick start](https://github.com/GeneJie199/infrastructure-discovery/blob/main/README.md#quick-start) and [operations guide](https://github.com/GeneJie199/infrastructure-discovery/blob/main/docs/operations.md). The component archive contains its binary, README, installation scripts, operations documents and license material.

For the combined Suite, follow the [online quick start](https://github.com/GeneJie199/ai-devops-open-suite/blob/main/docs/quickstart.md) or the [full offline installation guide](https://github.com/GeneJie199/ai-devops-open-suite/blob/main/docs/offline-install.md). Those Suite documents are linked online rather than assumed to exist inside a standalone component archive. Pin the requested candidate version, verify published checksums and use an isolated evaluation prefix. Back up configuration and state before an upgrade or rollback.

The delivery interface is the CLI binary/archive and vendored Corresponding Source. Historical Go module paths do not include `/v2`; this candidate makes no `go install ...@v2` compatibility promise. Native macOS CLI checks are separate from complete Suite offline installation, whose supported package scope is Windows/Linux amd64.

## Candidate and safety scope

This is an RC, not GA. These changes do not assert completed final 136/168 functional acceptance, uninterrupted 24-hour stability, or live GPT/Kimi/DeepSeek three-model collaboration. Those require their own version-bound evidence. Demo/example reports remain explicitly identified; appearance screenshots do not prove a release or scan result.

The Suite generic CLI runtime remains for trusted single-user local environments. Worktrees and role path checks do not provide an OS sandbox for untrusted users. Enforcing isolation policies fail closed, R4 remains blocked, and a ReleaseGuard GO grants no production deployment permission. No model credentials, subscription/API entitlement, automatic purchase, HA or untrusted multi-tenancy are added here.

New v2 source is AGPL-3.0-only; historical v1.x keeps its original Apache-2.0 terms. Archives retain full license texts, third-party notices, inventory and SBOM. Corresponding Source is distributed separately with vendored Go dependencies and checksums. Commercial alternatives remain subject to verified rights and a separate agreement; no signed CLA, copyright transfer or third-party relicensing right is asserted. Published target binaries must pass the configured reachable-vulnerability scans. See SECURITY.md for reporting.
