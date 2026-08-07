# infrastructure-discovery

**Professional:** Linux infrastructure discovery CLI and library for inventory snapshots and drift comparison.  
**通俗说明：** 在 Linux 主机上采集“有什么东西在跑”，写出可对比的清单和快照，方便发现配置漂移。

Aligned conceptually with [lifecycle-spec](https://github.com/GeneJie199/lifecycle-spec) v0.1 (`inventory.json` / `snapshot.json`, stable resource IDs, RFC3339 times, no plaintext secrets).

## Scope (INF-001 … INF-004)

| ID | Capability |
|----|------------|
| INF-001 | Inventory + Snapshot models, JSON output, noise policy |
| INF-002 | Host basics: hostname, OS, kernel, CPU, memory, disks, NICs |
| INF-003 | Processes, listening ports, process↔port association (exe/cwd/cmdline/user) |
| INF-004 | systemd service units |

**Out of scope for this milestone:** Docker/K8s, Windows collectors, Kafka, vuln scanning, remote execution, AI.

## Resource IDs

| Type | Pattern |
|------|---------|
| `host` | `host:{hostname}` |
| `svc.systemd` | `svc.systemd:{host}/{unit}` |
| `process.bin` | `process.bin:{host}/{exe}` (never includes PID) |
| `net.listener` | `net.listener:{host}/{proto}/{addr}/{port}` |

PID and `startedAt` are stored as attributes but listed in `noisePolicy.filteredFields` so snapshot diffs ignore them.

## Install / Build

Requires Go 1.22+.

```bash
git clone https://github.com/GeneJie199/infrastructure-discovery.git
cd infrastructure-discovery
go build -o infra-discovery ./cmd/infra-discovery
```

## Usage

### Scan (Linux live)

```bash
./infra-discovery scan --out ./out
# writes ./out/inventory.json and ./out/snapshot.json
```

### Scan with fixtures (any OS, including Windows/macOS)

```bash
./infra-discovery scan --fixture ./testdata/host-sample --out ./out
```

### Diff two snapshots

```bash
./infra-discovery diff --baseline ./out/snapshot.json --candidate ./out2/snapshot.json --out ./drift.json
```

## Tests

Parsers are covered by **real sample fixtures** under `testdata/host-sample` (procfs-style tree + systemd JSON). Live `/proc` and `systemctl` collectors are Linux-only (`//go:build linux`).

```bash
go test ./...
```

## Layout

```text
cmd/infra-discovery/     CLI entrypoint
internal/model/          Inventory, Snapshot, DriftReport
internal/id/             Stable resource ID helpers
internal/collect/        Scan orchestration
internal/collect/host/   Host parsers (+ linux collector)
internal/collect/process/
internal/collect/net/
internal/collect/systemd/
internal/diff/           Snapshot diff with noise filtering
testdata/host-sample/    Fixture /proc + systemd samples
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
