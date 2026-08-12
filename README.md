# InfraScout

Linux 基础设施发现与漂移检测工具。它把主机上实际运行的资源采成稳定清单，建立人工认可的基线，并在发布前后给出确定性变化和风险。

[![CI](https://github.com/GeneJie199/infrastructure-discovery/actions/workflows/ci.yml/badge.svg)](https://github.com/GeneJie199/infrastructure-discovery/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## 可交付能力

- 主机、CPU、内存、磁盘、网络接口、进程、监听端口和 systemd 服务发现。
- Docker 容器、镜像、端口、网络、卷和 Compose 标签发现；权限不足转为 warning。
- 静态解析 Nginx `server` / `listen` / `location` / `proxy_pass` 路由并写入资源关系。
- PostgreSQL/MySQL 只读结构元数据：schema、表、字段、索引、视图、触发器、函数和权限。
- 数据库结构 Diff，区分新增、删除、修改并给出风险级别。
- 稳定 Resource ID，不把 PID 和容器临时 ID 当身份。
- `scan`、`snapshot`、`baseline`、`check`、`watch`、`diff`、`report` 和 `serve` 完整流程。
- 密钥、Token、常见密码变量和带凭据 URL 脱敏。
- 响应式中文 Web 查看器与自包含离线 HTML 报告，无 Node/CDN 运行依赖。

## 快速开始

需要 Go 1.26+。Linux 可实机采集，Windows/macOS 可用仓库夹具验证全部确定性逻辑。

```bash
go test ./...
go build -trimpath -o infrascout ./cmd/infrascout

./infrascout scan --fixture ./testdata/host-sample -o inventory.json
./infrascout snapshot --fixture ./testdata/host-sample -o snapshot-old.json
./infrascout snapshot --fixture ./testdata/host-sample-v2 -o snapshot-new.json
./infrascout diff snapshot-old.json snapshot-new.json -j drift.json
./infrascout serve --demo
```

打开 `http://127.0.0.1:8765/`。内置 demo 同时展示资产、风险、服务识别、监控建议、Nginx 路由、数据库结构和漂移。

## 生产工作流

```bash
# 1. 首次扫描并人工审核基线
sudo infrascout baseline --state-dir /var/lib/infrascout

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
infrascout database --engine postgres -o database-before.json

# 发布后再次采集
infrascout database --engine postgres -o database-after.json
infrascout database-diff database-before.json database-after.json -o database-diff.json
```

Viewer 可和主机数据一起加载数据库元数据：

```bash
infrascout serve \
  --inventory inventory.json \
  --drift drift.json \
  --database database-after.json
```

## 输出

| 文件 | 内容 |
|---|---|
| `inventory.json` | 资源、关系、服务识别、Nginx 路由、监控建议和 warnings |
| `snapshot.json` | 标准化、可比较的资源状态 |
| `drift.json` | added/removed/changed、风险、摘要和时间 |
| `monitoring-plan.yaml` | 推荐采集器、目标、优先级和覆盖缺口 |
| `database-*.json` | 数据库结构/权限元数据或结构 Diff |
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
```

## 安全与运行边界

- Viewer 默认拒绝非 loopback 地址；远程访问优先用 SSH 隧道。
- `--allow-remote` 仅适用于已配置身份认证的反向代理和严格网络策略；远程监听时审核和基线提升 API 会被服务端强制禁用，启动日志会明确显示这一安全边界。
- 非 root 扫描仍可用，但部分进程、Docker 和端口关联可能缺失并写入 warnings。
- 清单仍可能包含路径、用户名、镜像和服务名，分享前需要复核。
- InfraScout 不执行远程命令、不修复漂移，也不替代 FleetScope 的运行期采集、存储、告警和处置能力。

安装、systemd、备份和退出码见 [docs/operations.md](docs/operations.md)。

Apache-2.0。贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题见 [SECURITY.md](SECURITY.md)。
