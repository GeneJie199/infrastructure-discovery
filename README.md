# InfraScout

Linux 基础设施发现与漂移检测工具。它把主机上实际运行的资源采成稳定清单，建立人工认可的基线，并在发布前后给出确定性变化和风险。

[![CI](https://github.com/GeneJie199/infrastructure-discovery/actions/workflows/ci.yml/badge.svg)](https://github.com/GeneJie199/infrastructure-discovery/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Screenshot

![InfraScout infrastructure risk dashboard](https://raw.githubusercontent.com/GeneJie199/ai-devops-open-suite/main/assets/infrascout-risk.png)

## Why

Deployment documents say what should exist; incidents happen against what actually exists. InfraScout creates a read-only, evidence-backed inventory, lets a human approve the baseline, and turns later infrastructure or database changes into reviewable drift.

## Core Features

- 主机、CPU、内存、磁盘、网络接口、进程、监听端口和 systemd 服务发现。
- `infrascout up` 一条命令完成首次扫描、批准基线、当前态、漂移报告、本地 Viewer 和自动打开浏览器。
- Docker 容器、镜像、端口、网络、卷和 Compose 标签发现；权限不足转为 warning。
- 静态解析 Nginx `server` / `listen` / `location` / `proxy_pass` 路由并写入资源关系。
- PostgreSQL/MySQL 只读结构元数据 v2：schema、表、字段、PK/唯一/FK、索引、视图、触发器、函数、角色和多层权限。
- 数据库结构 Diff，区分新增、删除、修改并给出风险级别。
- 标准化 Host、Process、Service、Deployment、Container、Database、Endpoint、Volume、Network、Relationship、Observation、Evidence 和 ChangeEvent；PID 和容器临时 ID 不参与稳定身份。
- `scan`、`snapshot`、`baseline`、`check`、`watch`、`diff`、`report` 和 `serve` 完整流程。
- 密钥、Token、常见密码变量和带凭据 URL 脱敏。
- 响应式中文 Web 查看器包含应用聚合、资源详情抽屉、关系证据、数据库漂移和 Observed/Approved/Desired 状态模型；无 Node/CDN 运行依赖。

## Quick Start

需要 Go 1.26.6+。Linux 可实机采集，Windows/macOS 可用仓库夹具验证全部确定性逻辑。

```bash
go build -trimpath -o infrascout ./cmd/infrascout
sudo ./infrascout up --state-dir /var/lib/infrascout
```

命令会自动打开 `http://127.0.0.1:8765/`。第一次运行创建批准基线，以后运行刷新当前事实和漂移。试用内置完整样例可执行 `./infrascout serve --demo`。
无图形界面的服务器增加 `--no-open`，再通过 SSH 隧道访问本地 Viewer。

发布包同时提供安装器与 systemd unit。只安装二进制执行 `sudo sh scripts/install.sh install ./infrascout`；需要安装并启用 systemd unit 时增加 `INSTALL_SERVICE=1`，首次 `up` 建立基线后再启动持续服务。

## Online Install

Install and start the complete Open Suite, including InfraScout, with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/GeneJie199/ai-devops-open-suite/main/scripts/bootstrap.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/GeneJie199/ai-devops-open-suite/main/scripts/bootstrap.ps1 | iex
```

For InfraScout alone, download the archive for your platform from [Releases](https://github.com/GeneJie199/infrastructure-discovery/releases/latest), extract it, and run the included installer. Linux is the verified native discovery platform; Windows and macOS builds support deterministic file review and demo viewing but do not claim native host discovery parity.

## Offline Install

On an online machine, download the matching `infrascout-<version>-<os>-<arch>` archive and `checksums.txt`. Transfer both, extract, then run:

```bash
sudo sh scripts/install.sh install ./infrascout ./checksums.txt
```

```powershell
.\scripts\install.ps1 -Action Install -Source .\infrascout.exe -Checksums .\checksums.txt
```

The full Open Suite offline bundle contains the binary, installer, protocol schemas, manifest, and checksums for a network-free install.

## First Five Minutes

1. Run `sudo infrascout up --state-dir /var/lib/infrascout` on the Linux host.
2. Review warnings and discovered public listeners before accepting the initial baseline.
3. Open `http://127.0.0.1:8765/` locally or through an SSH tunnel.
4. Make a controlled service, port, image, or configuration change.
5. Run `sudo infrascout check --state-dir /var/lib/infrascout --fail-on warning` and classify the drift.

## AI Optional

InfraScout discovery, stable identities, database metadata, drift, risk, review, and reports are deterministic and require no AI account. Other suite modules may explain its evidence, but AI cannot alter a baseline or change classification without an explicit user action.

## Comparison

| Tool category | Primary job | InfraScout's role |
|---|---|---|
| Configuration management | Apply desired configuration | Observes actual state without applying changes |
| CMDB / inventory | Curated asset records | Produces a local, evidence-backed snapshot directly from the host |
| Vulnerability scanners | Find known security weaknesses | Detects structural exposure and drift; it is not a CVE scanner |
| Monitoring agents | Track runtime health | Discovers deployment structure and baseline change for FleetScope |

## Architecture

```mermaid
flowchart LR
  H[Linux host and config] --> C[Read-only collectors]
  C --> I[Typed inventory]
  I --> S[Stable snapshot]
  B[Approved / desired baseline] --> D[Deterministic diff]
  S --> D
  D --> V[Viewer and lifecycle artifacts]
```

Collectors never import another product's internals. Inventory, snapshots, drift, evidence, and monitoring recommendations are versioned files that FleetScope and ReleaseGuard can consume.

## Security

- Collection is local and read-only; database collectors use read-only transactions and never query business rows.
- The Viewer is loopback-only by default, and remote mode disables mutation APIs.
- Credentials come from environment variables and common secret forms are redacted.
- Releases include SHA-256 checksums, a CycloneDX SBOM, and GitHub build provenance.

See [SECURITY.md](SECURITY.md) and [docs/operations.md](docs/operations.md).

## Roadmap

The v1.0 scope prioritizes high-quality Linux, systemd, Docker, Nginx, PostgreSQL, and MySQL discovery. Additional platforms and collectors are tracked in the [Open Suite roadmap](https://github.com/GeneJie199/ai-devops-open-suite/blob/main/ROADMAP.md) only after they can meet the same evidence standard.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). New collectors need typed fixtures, deterministic IDs, malformed-input tests, and documented privilege boundaries. Security reports follow [SECURITY.md](SECURITY.md).

## Product Reference

## 生产工作流

```bash
# 1. 首次扫描、初始化基线并打开本地工作台
sudo infrascout up --state-dir /var/lib/infrascout

# 2. 发布前后检查；WARNING 及以上返回非零
sudo infrascout check --state-dir /var/lib/infrascout --fail-on warning

# 3. 持续检查并提供只读本地查看器
sudo infrascout watch \
  --state-dir /var/lib/infrascout \
  --addr 127.0.0.1:8765 \
  --interval 1m
```

状态写入使用临时文件 + rename，避免 Viewer 读到半份 JSON。不要在每次发布后自动替换 baseline；只有审核通过的实际状态才能成为新基线。

## 数据库结构

凭据必须放在环境变量中，建议使用只读元数据账户：

```bash
export INFRASCOUT_DATABASE_DSN='postgres://monitor:...@127.0.0.1/app?sslmode=require'
infrascout database --engine postgres --state-dir /var/lib/infrascout
```

PostgreSQL 的表、字段、约束和触发器通过只读系统目录采集；视图、函数和权限仍遵循当前账号的可见范围。MySQL 由服务端按权限裁剪 `information_schema`，完整触发器需要目标库的 `TRIGGER` 权限，完整用户/角色需要 `mysql.user` 的 `SELECT` 权限；缺少的范围会写入 `warnings`，不会伪装成已采集。采集事务始终为只读，且从不查询业务表行。

也可以直接并入首次启动或持续采集：`infrascout up --database-engine postgres ...`，或为 `watch` 增加 `--database-engine postgres`；DSN 仍只从环境变量读取。

第一次采集自动建立数据库元数据基线，以后同一条命令写入 `database-current.json` 和 `database-diff.json`，`up` / `serve --state-dir` 自动加载。明确批准新结构时执行：

```bash
infrascout database --engine postgres --state-dir /var/lib/infrascout --approve-baseline
```

数据库变化会合并到统一 `drift.json`：可在 Web/CLI 使用同一套预期、批准、临时允许、待审核、禁止决策，`check --fail-on` 同时阻断主机、关系和数据库风险，已批准的单个字段/约束/角色/权限变化可以选择性提升。

## 输出

| 文件 | 内容 |
|---|---|
| `inventory.json` | 类型化资源、应用聚合、关系、证据、观测、Nginx 路由、监控建议和 warnings |
| `snapshot.json` | 标准化、可比较的资源状态 |
| `drift.json` | 资源与关系的 added/removed/changed、ChangeEvent、风险、摘要和审核状态 |
| `monitoring-plan.yaml` | 推荐采集器、目标、优先级和覆盖缺口 |
| `database-baseline.json` / `database-current.json` / `database-diff.json` | 数据库结构、约束、角色、权限和结构 Diff |
| `infrascout-report.html` | 可离线打开的自包含报告 |

## 风险规则

| 场景 | 默认风险 |
|---|---|
| 新增普通进程/资源 | INFO |
| systemd 服务消失或 ExecStart 变化 | WARNING |
| 监听端口消失 | WARNING |
| 新增公网监听端口 | CRITICAL |
| root 进程新增公网暴露 | CRITICAL |
| 数据库删除表/字段或高影响结构变化 | WARNING / CRITICAL |

这些规则是确定性的，不调用 AI，也不自动把变化判为“正常”。

## 稳定 ID

```text
host:{hostname}
process:{host}/{name}@{cwdHash}
endpoint:{host}/{proto}/{addr}/{port}
service:systemd:{host}/{unit}
service:docker:{host}/{name}
nginx.route:{host}/{routeHash}
deployment:{method}:{host}/{name}
database:{engine}:{host}/{sourceHash}
relationship:{source+type+targetHash}
```

## Known Limitations and Runtime Boundaries

- Viewer 默认拒绝非 loopback 地址；远程访问优先用 SSH 隧道。
- `--allow-remote` 仅适用于已配置身份认证的反向代理和严格网络策略；远程监听时审核和基线提升 API 会被服务端强制禁用，启动日志会明确显示这一安全边界。
- 非 root 扫描仍可用，但部分进程、Docker 和端口关联可能缺失并写入 warnings。
- 清单仍可能包含路径、用户名、镜像和服务名，分享前需要复核。
- InfraScout 不执行远程命令、不修复漂移，也不替代 FleetScope 的运行期采集、存储、告警和处置能力。

安装、systemd、备份和退出码见 [docs/operations.md](docs/operations.md)。

Apache-2.0。贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题见 [SECURITY.md](SECURITY.md)。
