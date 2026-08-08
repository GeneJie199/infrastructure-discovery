# infrastructure-discovery (InfraScout)

**内部代号：** InfraScout  
**一句话定位：** 在 Linux 上发现主机、进程、端口与 systemd 服务，生成清单与快照，并对比变化。

**专业名称：** Infrastructure Discovery & Drift CLI  
**通俗解释：** 先看清机器上实际在跑什么，再对比两次结果，标出新增、删除、修改和风险级别。

## v0.1 范围

| 做 | 不做 |
|----|------|
| Host / Process / Endpoint / Service / Relationship | Docker / Kubernetes |
| `infrascout scan` → inventory.json | AI |
| `infrascout snapshot` → snapshot.json | Web UI / FleetScope |
| `infrascout diff old new`（JSON + 人类可读） | 远程控制 / 云平台 |
| 风险分级 INFO / WARNING / CRITICAL | 数据库元数据 |

可复用库：`pkg/infrascout`（供未来 FleetScope Agent 引用）。

## 安装

```bash
git clone https://github.com/GeneJie199/infrastructure-discovery.git
cd infrastructure-discovery
go test ./...
go build -o infrascout ./cmd/infrascout
```

## 快速开始

```bash
# 任意 OS：用夹具
./infrascout scan --fixture ./testdata/host-sample -o inventory.json
./infrascout snapshot --fixture ./testdata/host-sample -o snapshot-old.json
./infrascout snapshot --fixture ./testdata/host-sample-v2 -o snapshot-new.json
./infrascout diff snapshot-old.json snapshot-new.json
./infrascout diff snapshot-old.json snapshot-new.json -j drift.json

# Linux 实机
./infrascout scan -o inventory.json
./infrascout snapshot -o snapshot.json
```

## 稳定 ID

| 类型 | 格式 | 说明 |
|------|------|------|
| host | `host:{hostname}` | |
| process | `process:{host}/{name}@{cwdHash}` | **不含 PID**；二进制路径可变 |
| endpoint | `endpoint:{host}/{proto}/{addr}/{port}` | |
| service | `service:systemd:{host}/{unit}` | |

## 风险规则（确定性，非 AI）

| 场景 | 级别 |
|------|------|
| 新增普通进程 | INFO |
| 新增公网监听端口 | CRITICAL |
| root 进程暴露公网端口 | CRITICAL（文案强调） |
| systemd 服务消失 / ExecStart 变化 | WARNING |
| 端口消失 | WARNING |

## 布局

```text
cmd/infrascout/          CLI
pkg/infrascout/          可复用模型、Discover、Diff、人类可读输出
internal/collect/        Linux/夹具采集（host/process/net/systemd）
testdata/host-sample/    基线夹具
testdata/host-sample-v2/ 变更夹具（集成 Diff 测试）
```

## 许可

Apache-2.0 — [LICENSE](LICENSE)  
套件总览：https://github.com/GeneJie199/project-docs
