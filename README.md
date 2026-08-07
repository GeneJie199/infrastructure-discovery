# infrastructure-discovery

**内部代号：** InfraScout  
**一句话定位：** 发现 Linux 机器上实际在跑什么，并对比两次状态找出漂移。

**专业名称：** Infrastructure Discovery & Drift CLI  
**通俗解释：** 扫主机 → 写出「现在有什么」的清单和快照 → 和上次比，哪些是新增、删除或改动。

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

属于 [AI DevOps Open Suite](https://github.com/GeneJie199/project-docs) 中的基础设施发现组件。数据形状对齐 [lifecycle-spec](https://github.com/GeneJie199/lifecycle-spec)。

---

## 为什么需要它

- 机器多了以后，文档和现实很容易脱节；  
- 上线或热修后，常说不清生产到底变了什么；  
- 传统监控擅长看 CPU/内存，不擅长回答「多了哪个端口、换了哪个二进制」。

本工具用确定性方式读取系统信息（如 `/proc`、systemd），**不依赖 AI 也能跑**。

---

## 当前能做什么

| 能力 | 说明 |
|------|------|
| 主机信息 | 主机名、系统、内核、CPU、内存、磁盘、网卡 |
| 进程与端口 | 运行进程、监听端口、进程↔端口关联；可执行文件、工作目录、命令行、用户 |
| systemd | 识别服务单元 |
| 输出 | `inventory.json`（资产清单）、`snapshot.json`（标准化快照） |
| 对比 | 两次快照 Diff：新增 / 删除 / 变更；默认忽略 PID、启动时间等噪声 |

**本阶段不做：** Docker/K8s、Windows 采集、漏洞扫描、远程执行、自动修复、AI 分析。

---

## 快速开始

需要 Go 1.22+。

```bash
git clone https://github.com/GeneJie199/infrastructure-discovery.git
cd infrastructure-discovery
go test ./...
go build -o infra-discovery ./cmd/infra-discovery
```

**任意系统（夹具演示）：**

```bash
./infra-discovery scan --fixture ./testdata/host-sample --out ./out
./infra-discovery diff --baseline ./out/snapshot.json --candidate ./out/snapshot.json --out ./drift.json
```

**Linux 实机扫描：**

```bash
./infra-discovery scan --out ./out
# 生成 ./out/inventory.json 与 ./out/snapshot.json
```

---

## 关键术语

| 专业名称 | 通俗解释 |
|----------|----------|
| Inventory（资产清单） | 「这台机器上有什么」的汇总视图 |
| Snapshot（快照） | 去掉噪声后、可用来对比的一版标准状态 |
| Infrastructure Drift（基础设施漂移） | 实际状态相对基线/预期发生了偏离 |
| Resource ID（资源稳定标识） | 资源的「身份证」，重启后仍应尽量稳定（不用 PID） |

---

## 设计要点

- **本地优先：** 扫描结果是本地 JSON 文件  
- **稳定 ID：** 例如 `host:{hostname}`、`net.listener:{host}/{proto}/{addr}/{port}`  
- **噪声过滤：** PID、`startedAt` 可记录，但 Diff 默认忽略  
- **无密钥进清单：** 不采集密码/私钥明文  

---

## 项目结构（给开发者）

```text
cmd/infra-discovery/     CLI
internal/model/          Inventory / Snapshot / DriftReport
internal/collect/        采集编排与 host/process/net/systemd
internal/diff/           快照对比
testdata/host-sample/    解析器用的真实样例夹具
```

实机采集代码带 `//go:build linux`；非 Linux 请用 `--fixture`。

---

## 贡献与许可

- Issue / PR：请附 OS、命令、脱敏后的输出片段  
- 许可：Apache-2.0，见 [LICENSE](LICENSE)  
- 套件总览：[project-docs](https://github.com/GeneJie199/project-docs)
