/* InfraScout 本地查看器 — 无依赖 vanilla JS，直接渲染 CLI 真实 JSON 字段 */
(function () {
  "use strict";

  var STATUS = document.getElementById("status");
  var currentCtx = null;
  var selectedResourceId = "";
  var currentTab = "overview";
  var lastSuccess = 0;
  var lastETag = "";
  var loading = false;
  var dirtyTabs = { overview: true, applications: true, resources: true, ports: true, monitoring: true, database: true, drift: true };
  var monitoringConfigText = "";
  var driftFilter = "blocking";
  var toastTimer = 0;
	var overviewRiskExpanded = false;

  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtBytes(n) {
    if (!n && n !== 0) return "-";
    var units = ["B", "KiB", "MiB", "GiB", "TiB"];
    var v = Number(n), i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
  }

  function fmtTime(s) {
    if (!s) return "-";
    var d = new Date(s);
    if (isNaN(d.getTime())) return esc(s);
    return d.toLocaleString("zh-CN", { hour12: false });
  }

  function driftSummary(value) {
    var summary = String(value || "");
    var match;
    if ((match = summary.match(/^A new root process exposes port (\d+)$/))) return "新的 root 进程暴露端口 " + match[1];
    if ((match = summary.match(/^added process (.+)$/))) return "新增进程 " + match[1];
    if ((match = summary.match(/^systemd service disappeared: (.+)$/))) return "systemd 服务已消失：" + match[1];
    if ((match = summary.match(/^removed nginx\.route (.+)$/))) return "删除 Nginx 路由 " + match[1];
    if ((match = summary.match(/^(.+): exec_start changed$/))) return match[1] + "：启动命令已变化";
    if ((match = summary.match(/^(.+): executable changed$/))) return match[1] + "：可执行文件已变化";
	if ((match = summary.match(/^database (\S+) (added|removed|changed): (.+)$/))) return "数据库" + databaseKindText(match[1]) + ({ added: "新增：", removed: "删除：", changed: "变化：" })[match[2]] + match[3];
	if ((match = summary.match(/^relationship (added|removed|changed): (\S+) (\S+) (\S+)$/))) return "关系" + ({ added: "新增：", removed: "删除：", changed: "变化：" })[match[1]] + match[2] + " " + relationLabel(match[3]) + " " + match[4];
    if ((match = summary.match(/^(added|removed) (\S+) (.+)$/))) return ({ added: "新增", removed: "删除" })[match[1]] + (TYPE_TEXT[match[2]] || match[2]) + " " + match[3];
    return summary;
  }

  function databaseKindText(kind) {
	return ({ table: "表", column: "字段", constraint: "约束", index: "索引", view: "视图", trigger: "触发器", routine: "函数/过程", role: "角色", privilege: "权限" })[kind] || kind;
  }

  var SEV_CLASS = { CRITICAL: "crit", WARNING: "warn", INFO: "info" };
  var SEV_TEXT = { CRITICAL: "严重", WARNING: "警告", INFO: "提示" };
  function sevBadge(sev) {
    var c = SEV_CLASS[sev] || "muted";
    return '<span class="badge ' + c + '">' + esc(SEV_TEXT[sev] || sev) + "</span>";
  }

  var TYPE_TEXT = { host: "主机", process: "进程", endpoint: "端口", service: "服务", deployment: "部署", database: "数据库", "docker.network": "容器网络", "docker.volume": "数据卷", "nginx.route": "代理路由", relationship: "关系" };
  function typeBadge(t) {
	var label = TYPE_TEXT[t] || (String(t).indexOf("database.") === 0 ? "数据库" + databaseKindText(String(t).slice(9)) : t);
	return '<span class="badge muted">' + esc(label) + "</span>";
  }

  var EXPOSE_TEXT = { public: "公网暴露", localhost: "仅本机", private: "内网", unknown: "未知" };
  function exposeBadge(level) {
    var c = level === "public" ? "crit" : level === "localhost" ? "ok" : level === "private" ? "info" : "muted";
    return '<span class="badge ' + c + '">' + esc(EXPOSE_TEXT[level] || level || "未知") + "</span>";
  }

  /* ---------- 数据归一化：inventory 优先，snapshot 兜底 ---------- */
  function normalize(data) {
    var inv = data.inventory || null;
    var snap = data.snapshot || null;
    var resources = (inv && inv.resources) || (snap && snap.resources) || [];
    var hostname = (inv && inv.hostname) || (snap && snap.hostname) || "-";
    var capturedAt = (inv && inv.collected_at) || (snap && snap.timestamp) || "";
    var byType = { host: [], process: [], endpoint: [], service: [], deployment: [], database: [], "docker.network": [], "docker.volume": [], "nginx.route": [] };
    resources.forEach(function (r) {
      if (byType[r.type]) byType[r.type].push(r);
    });
    return {
      inventory: inv, snapshot: snap, drift: data.drift || null, database: data.database || null, databaseDiff: data.database_diff || null,
      resources: resources, byType: byType,
      hostname: hostname, capturedAt: capturedAt,
      summary: inv && inv.summary ? inv.summary : null,
      generatedAt: data.generated_at, sources: data.sources || {}, reviewEnabled: Boolean(data.review_enabled),
      sourceMode: inv ? "inventory" : "snapshot"
    };
  }

  function refreshIcons() {
    if (window.lucide) window.lucide.createIcons({ attrs: { "stroke-width": 1.8, "aria-hidden": "true" } });
  }

  function riskItems(ctx) {
    var items = [];
    ctx.byType.endpoint.forEach(function (resource) {
      var endpoint = resource.endpoint || {};
      var risk = portRisk(endpoint);
      if (risk.cls === "crit" || risk.cls === "warn") items.push({ id: resource.id, type: "endpoint", cls: risk.cls, title: (endpoint.process_name || "未知进程") + " 暴露 " + endpoint.address + ":" + endpoint.port, detail: risk.text });
    });
    if (ctx.drift) ["added", "removed", "changed"].forEach(function (kind) {
      (ctx.drift[kind] || []).forEach(function (item) {
        if ((item.classification === "unexpected" || item.classification === "denied" || !item.classification) && (item.severity === "CRITICAL" || item.severity === "WARNING")) items.push({ id: item.id, type: item.type, cls: SEV_CLASS[item.severity], title: driftSummary(item.summary), detail: kind === "added" ? "新增资产" : kind === "removed" ? "资产消失" : "资产发生变化" });
      });
    });
    return items.sort(function (a, b) { return (a.cls === "crit" ? 0 : 1) - (b.cls === "crit" ? 0 : 1); });
  }

  function renderExposureFlow(ctx) {
    var endpoints = ctx.byType.endpoint.filter(function (item) { return item.endpoint && item.endpoint.exposed_level === "public"; });
    var services = ctx.byType.service;
    if (!endpoints.length) return '<div class="notice">没有公网监听端口，当前未形成外部暴露链路。</div>';
    return '<div class="flow-list">' + endpoints.map(function (resource) {
      var endpoint = resource.endpoint;
      var service = services.find(function (item) { return item.service && Number(item.service.main_pid) === Number(endpoint.process_id); });
      return '<button class="flow-row" type="button" data-open-resource="' + esc(resource.id) + '"><span class="flow-node external">外部网络</span><i>→</i><span class="flow-node"><b>' + esc(endpoint.address + ':' + endpoint.port) + '</b><small>' + esc(endpoint.protocol) + '</small></span><i>→</i><span class="flow-node"><b>' + esc(endpoint.process_name || '未知进程') + '</b><small>PID ' + esc(endpoint.process_id || '-') + ' · ' + esc(endpoint.process_user || '-') + '</small></span><i>→</i><span class="flow-node"><b>' + esc(service && service.service ? service.service.name : '未关联服务') + '</b><small>' + (service && service.service ? esc(service.service.active_state + ' / ' + service.service.sub_state) : '需要补充关系证据') + '</small></span></button>';
    }).join('') + '</div>';
  }

  function applicationList(ctx) {
    var applications = (ctx.inventory && ctx.inventory.applications) || [];
    if (applications.length) return applications;
    return (((ctx.inventory || {}).detected_services) || []).map(function (item) {
      var endpointIDs = ctx.byType.endpoint.filter(function (resource) { return (item.endpoints || []).some(function (endpoint) { var match = String(endpoint).match(/:(\d+)$/); return match && Number(match[1]) === Number(resource.endpoint.port); }); }).map(function (resource) { return resource.id; });
	  return { id: "application:" + item.resource_id, name: item.name, kind: item.kind, source: item.source, confidence: item.confidence, resource_ids: [item.resource_id], endpoint_ids: endpointIDs, deployment_ids: [], needs_review: Number(item.confidence) < .9 };
    });
  }

  function resourceByID(ctx, id) {
    return ctx.resources.find(function (item) { return item.id === id; }) || null;
  }

  function applicationCard(ctx, app) {
    var endpoints = (app.endpoint_ids || []).map(function (id) { return resourceByID(ctx, id); }).filter(Boolean);
    var deployments = (app.deployment_ids || []).map(function (id) { return resourceByID(ctx, id); }).filter(Boolean);
    var publicCount = endpoints.filter(function (item) { return item.endpoint && item.endpoint.exposed_level === "public"; }).length;
    var primaryResource = (app.resource_ids || [])[0] || "";
    var deployment = deployments[0] && deployments[0].deployment;
    var portText = endpoints.map(function (item) { return item.endpoint ? item.endpoint.address + ":" + item.endpoint.port : item.id; }).join(", ") || "未发现监听";
    var icon = ({ nginx: "server-cog", postgresql: "database", mysql: "database", redis: "database-zap", java: "coffee", nodejs: "hexagon", python: "code-2", "php-fpm": "file-code-2" })[app.kind] || "box";
    return '<article class="application-card"><div class="application-top"><span class="application-icon"><i data-lucide="' + icon + '"></i></span><div><h3>' + esc(app.name || app.kind) + '</h3><p>' + esc(app.kind) + ' · ' + esc(app.source || 'unknown') + '</p></div><span class="confidence ' + (app.needs_review ? 'review' : '') + '">' + (app.needs_review ? '待确认' : '已识别') + '</span></div>' +
      '<div class="application-facts"><span><i data-lucide="activity"></i><b>' + esc(app.status || '已发现') + '</b></span><span><i data-lucide="network"></i><b>' + esc(portText) + '</b></span><span><i data-lucide="package-open"></i><b>' + esc(deployment ? (deployment.method + ' · ' + deployment.name) : (app.source || '进程发现')) + '</b></span></div>' +
      '<div class="application-foot"><span class="' + (publicCount ? 'warn-text' : 'ok-text') + '">' + (publicCount ? publicCount + ' 个公网入口' : '无公网入口') + '</span><button class="link-btn" type="button" data-open-resource="' + esc(primaryResource) + '">查看运行档案 <i data-lucide="arrow-up-right"></i></button></div></article>';
  }

  function renderApplications(ctx) {
    var el = document.getElementById("tab-applications");
    var applications = applicationList(ctx);
    var html = '<div class="page-head compact"><div><span class="eyebrow">工作负载视角</span><h1>机器里运行着什么</h1><p>按应用聚合进程、部署、端口、依赖和可复核证据，低置信识别会明确标记为待确认。</p></div><div class="capture"><span>识别结果</span><strong>' + applications.length + ' 个应用</strong></div></div>';
    if (!applications.length) {
      html += '<div class="empty-state"><span class="empty-icon"><i data-lucide="scan-search"></i></span><h2>尚未识别到应用</h2><p>当前扫描仍保留全部原始资产。可从资产页核对进程，也可以刷新采集结果。</p><button type="button" class="chip" data-jump="resources">查看全部资产</button></div>';
    } else {
      html += '<div class="application-grid">' + applications.map(function (app) { return applicationCard(ctx, app); }).join('') + '</div>';
    }
    el.innerHTML = html;
  }

  /* ---------- 概览 ---------- */
  function renderOverview(ctx) {
    var el = document.getElementById("tab-overview");
    var host = ctx.byType.host.length ? ctx.byType.host[0].host : null;
    var counts = ctx.summary || {
      hosts: ctx.byType.host.length,
      processes: ctx.byType.process.length,
      endpoints: ctx.byType.endpoint.length,
      services: ctx.byType.service.length
    };
    var publicPorts = ctx.byType.endpoint.filter(function (r) {
      return r.endpoint && r.endpoint.exposed_level === "public";
    });
    var rootPublic = publicPorts.filter(function (r) {
      return r.endpoint.process_user === "root";
    });

    var risks = riskItems(ctx);
    var exposureRisks = risks.filter(function (item) { return item.type === "endpoint"; });
    var driftRisks = risks.filter(function (item) { return item.type !== "endpoint"; });
	var visibleRisks = overviewRiskExpanded ? risks : risks.slice(0, 6);
    var hiddenRiskCount = Math.max(0, risks.length - visibleRisks.length);
    var html = '<div class="page-head"><div><span class="eyebrow">主机事实</span><h1>' + esc(ctx.hostname) + '</h1><p>从实际进程、监听、服务、路由和快照变化中定位需要处理的基础设施事实。</p></div><div class="capture"><span class="source-badge">' + (ctx.sourceMode === 'inventory' ? '实时清单' : '快照回放') + '</span><span>最近采集</span><strong>' + fmtTime(ctx.capturedAt) + '</strong></div></div>';
	if (ctx.inventory && ctx.inventory.warnings && ctx.inventory.warnings.length) {
		html += '<div class="notice warning-notice"><strong>采集提示</strong><br>' +
		  ctx.inventory.warnings.map(esc).join('<br>') + '</div>';
	}
    html += '<div class="kpi-grid"><button class="kpi" data-scroll-target="risk-queue"><span>需处理风险</span><b class="' + (risks.length ? 'crit-text' : 'ok-text') + '">' + risks.length + '</b><small>' + exposureRisks.length + ' 暴露 · ' + driftRisks.length + ' 漂移</small></button>' +
      '<button class="kpi" data-jump="ports"><span>公网监听</span><b>' + publicPorts.length + '</b><small>' + rootPublic.length + ' 个由 root 运行</small></button>' +
      '<button class="kpi" data-jump="resources"><span>运行资产</span><b>' + (counts.processes + counts.services) + '</b><small>' + counts.processes + ' 进程 · ' + counts.services + ' 服务</small></button>' +
      '<button class="kpi" data-jump="drift"><span>最近变更</span><b>' + (ctx.drift ? (ctx.drift.added || []).length + (ctx.drift.removed || []).length + (ctx.drift.changed || []).length : 0) + '</b><small>' + (ctx.drift ? (SEV_TEXT[ctx.drift.highest_risk] || ctx.drift.highest_risk) : '未加载对比') + '</small></button></div>';

    html += '<div class="state-model" aria-label="事实状态模型"><div class="active"><i data-lucide="scan-eye"></i><span>Observed 观测态</span><b>当前扫描事实</b></div><i data-lucide="arrow-right"></i><div><i data-lucide="shield-check"></i><span>Approved 批准态</span><b>审核后的可信基线</b></div><i data-lucide="arrow-right"></i><div><i data-lucide="target"></i><span>Desired 期望态</span><b>交给发布门禁校验</b></div></div>';

    var applications = applicationList(ctx);
    html += '<section class="home-applications"><div class="panel-head"><div><span class="eyebrow">应用视角</span><h2>机器里运行着什么</h2></div><button class="link-btn" data-jump="applications">全部应用 <i data-lucide="arrow-right"></i></button></div>';
    html += applications.length ? '<div class="application-grid compact-grid">' + applications.slice(0, 3).map(function (app) { return applicationCard(ctx, app); }).join('') + '</div>' : '<div class="notice">当前未识别到应用，原始资产仍可在资产页完整查看。</div>';
    html += '</section>';

    html += '<div class="dashboard-grid"><section class="dashboard-panel" id="risk-queue"><div class="panel-head"><div><span class="eyebrow">待处理</span><h2>风险优先队列</h2></div><div class="panel-actions"><button class="link-btn" data-jump="ports">暴露 ' + exposureRisks.length + '</button><button class="link-btn" data-jump="drift">漂移 ' + driftRisks.length + '</button></div></div>';
    html += risks.length ? '<div class="risk-list">' + visibleRisks.map(function (item) { return '<button type="button" class="risk-row ' + item.cls + '" data-open-resource="' + esc(item.id) + '"><span class="risk-mark"></span><span><b>' + esc(item.title) + '</b><small>' + esc(item.detail) + ' · ' + esc(item.id) + '</small></span><em>查看</em></button>'; }).join('') + (hiddenRiskCount ? '<button type="button" class="risk-more" data-expand-risks>展开其余 ' + hiddenRiskCount + ' 条风险</button>' : '') + '</div>' : '<div class="notice ok-notice">当前快照未发现需要立即处置的暴露或漂移风险。</div>';
    html += '</section><section class="dashboard-panel"><div class="panel-head"><div><span class="eyebrow">系统轮廓</span><h2>主机轮廓</h2></div></div>';
    html += '<div class="host-profile">';
    if (host) {
      html += "<dl>" +
        "<dt>操作系统</dt><dd>" + esc(host.os) + "</dd>" +
        "<dt>内核</dt><dd>" + esc(host.kernel) + "</dd>" +
        "<dt>架构</dt><dd>" + esc(host.architecture) + "</dd>" +
        "<dt>CPU</dt><dd>" + esc(host.cpu && host.cpu.model) + " × " + esc(host.cpu && host.cpu.cores) + "</dd>" +
        "<dt>内存</dt><dd>" + fmtBytes(host.memory && host.memory.total_bytes) + "</dd>" +
        "</dl>";
    }
    html += '</div></section></div>';

    html += '<section class="dashboard-panel flow-panel"><div class="panel-head"><div><span class="eyebrow">暴露链路</span><h2>外部暴露链路</h2></div><button class="link-btn" data-jump="monitoring">查看 Nginx 与监控</button></div>' + renderExposureFlow(ctx) + '</section>';

    if (host && host.disks && host.disks.length) {
      html += '<details class="facts-details"><summary>磁盘与挂载（' + host.disks.length + '）</summary><div class="tablewrap"><table>' +
        "<thead><tr><th>设备</th><th>挂载点</th><th>文件系统</th><th>容量</th></tr></thead><tbody>";
      host.disks.forEach(function (dk) {
        html += "<tr><td class='mono'>" + esc(dk.name) + "</td><td class='mono'>" + esc(dk.mount_point || "-") +
          "</td><td>" + esc(dk.fs_type || "-") + "</td><td>" + fmtBytes(dk.size_bytes) + "</td></tr>";
      });
      html += "</tbody></table></div></details>";
    }
    if (host && host.network_interfaces && host.network_interfaces.length) {
      html += '<details class="facts-details"><summary>网络接口（' + host.network_interfaces.length + '）</summary><div class="tablewrap"><table>' +
        "<thead><tr><th>名称</th><th>MAC</th><th>地址</th><th>状态</th></tr></thead><tbody>";
      host.network_interfaces.forEach(function (ni) {
        var st = ni.state === "up" ? '<span class="badge ok">up</span>' : '<span class="badge muted">' + esc(ni.state || "未知") + "</span>";
        html += "<tr><td class='mono'>" + esc(ni.name) + "</td><td class='mono'>" + esc(ni.mac || "-") +
          "</td><td class='mono'>" + esc((ni.addresses || []).join(", ") || "-") + "</td><td>" + st + "</td></tr>";
      });
      html += "</tbody></table></div></details>";
    }

    if (!ctx.drift) {
      html += '<h2 class="section-title">变更报告</h2><div class="notice">未加载变更报告。启动时加 <code class="inline">--drift drift.json</code> 即可查看新增 / 删除 / 修改。</div>';
    }
    el.innerHTML = html;
  }

  /* ---------- 资源 ---------- */
  var resFilter = { type: "all", q: "" };
  function resourceDesc(r) {
    if (r.type === "host" && r.host) return r.host.os + " / " + (r.host.kernel || "");
    if (r.type === "process" && r.process) {
      var p = r.process;
      return (p.executable || p.name || "") + "（用户 " + (p.user || "?") + "）";
    }
    if (r.type === "endpoint" && r.endpoint) {
      var e = r.endpoint;
      return e.protocol + " " + e.address + ":" + e.port + " · " + (e.process_name || "未知进程");
    }
    if (r.type === "service" && r.service) {
      var s = r.service;
      return (s.active_state || "?") + " / " + (s.sub_state || "?") + " · " + (s.description || "");
    }
	if (r.type === "deployment" && r.deployment) return r.deployment.method + " · " + r.deployment.name + " · " + (r.deployment.location || r.deployment.command || "");
	if (r.type === "database" && r.database) return r.database.engine + " · " + r.database.name;
	if (r.type === "docker.network" && r.network) return r.network.name;
	if (r.type === "docker.volume" && r.volume) return r.volume.source + " → " + (r.volume.destination || "-");
	if (r.type === "nginx.route" && r.metadata) return (r.metadata.server_name || "_") + (r.metadata.location || "/") + " → " + r.metadata.upstream;
    return "";
  }

  function resourcePayload(resource) {
    return resource && (resource[resource.type] || resource.container || resource.deployment || resource.database || resource.network || resource.volume || resource.metadata) || {};
  }

  function relationLabel(type) {
    return ({ runs_on: "运行于", listens_on: "监听", deployed_as: "部署方式", connected_to: "连接到", mounts: "挂载", configured_on: "配置于", proxies_to: "代理到", provides_database: "提供数据库" })[type] || type;
  }

  function openResourceDrawer(id) {
    if (!currentCtx || !id) return;
    var resource = resourceByID(currentCtx, id);
    var removed = flattenDrift(currentCtx.drift).find(function (item) { return item.id === id; });
    var dialog = document.getElementById("resource-dialog");
    var body = document.getElementById("resource-body");
    document.getElementById("resource-kind").textContent = resource ? (TYPE_TEXT[resource.type] || resource.type) + "档案" : "历史资产";
    document.getElementById("resource-title").textContent = resource ? (resourceDesc(resource).split(" · ")[0] || resource.id) : "资产已从当前快照消失";
    document.getElementById("resource-subtitle").textContent = id;
    if (!resource) {
      var changeNotice = removed && removed.type === 'relationship' ? '这是一条关系变化，关系本身也可以独立审核并提升到基线。' : removed && String(removed.type).indexOf('database.') === 0 ? '这是一条只读数据库元数据变化，可使用同一套审核和单条基线提升流程处置。' : '该资产只存在于批准基线，当前扫描已无法找到。';
	  body.innerHTML = '<div class="notice warning-notice">' + changeNotice + '</div>' + (removed ? '<section class="drawer-section"><h3>变化前</h3>' + kvTable(removed.before) + '</section><section class="drawer-section"><h3>变化后</h3>' + kvTable(removed.after) + '</section>' : '');
	  if (!dialog.open) dialog.showModal(); refreshIcons(); return;
    }
    var relationships = ((currentCtx.inventory && currentCtx.inventory.relationships) || (currentCtx.snapshot && currentCtx.snapshot.relationships) || []).filter(function (item) { return item.source === id || item.target === id; });
    var changes = flattenDrift(currentCtx.drift).filter(function (item) { return item.id === id; });
    var payload = resourcePayload(resource);
    var html = '<div class="drawer-status"><span>' + typeBadge(resource.type) + '</span><span><i data-lucide="fingerprint"></i> 稳定 ID</span><span><i data-lucide="database-zap"></i> ' + esc((resource.evidence || []).length) + ' 条直接证据</span></div>';
    html += '<section class="drawer-section"><div class="section-heading"><div><h3>运行事实</h3><p>采集器直接观测到的字段，敏感命令参数已脱敏。</p></div></div>' + kvTable(payload) + '</section>';
    if (resource.service) {
      var s = resource.service;
      html += '<section class="drawer-section action-facts"><h3>如何运行</h3><div class="fact-grid"><div><span>部署来源</span><b>' + esc(s.source || '-') + '</b></div><div><span>开机自启</span><b>' + esc(s.auto_start || '未知') + '</b></div><div><span>重启策略</span><b>' + esc(s.restart_policy || '未知') + '</b></div><div><span>运行用户</span><b>' + esc(s.user || '-') + '</b></div></div><div class="command-fact"><span>重启命令</span><code>' + esc(s.source === 'docker' ? 'docker restart ' + s.name : 'systemctl restart ' + s.name) + '</code></div></section>';
    }
    html += '<section class="drawer-section"><h3>关系与依赖</h3>' + (relationships.length ? '<div class="relationship-list">' + relationships.map(function (item) { var outbound = item.source === id; var peer = outbound ? item.target : item.source; return '<button type="button" data-open-resource="' + esc(peer) + '"><span class="relation-direction">' + (outbound ? '出' : '入') + '</span><span><b>' + esc(relationLabel(item.type)) + '</b><small>' + esc(peer) + '</small></span><em>' + Math.round(Number(item.confidence || 0) * 100) + '%</em></button>'; }).join('') + '</div>' : '<div class="notice">尚未采集到与该资产相关的关系。</div>') + '</section>';
    html += '<section class="drawer-section"><h3>最近变化</h3>' + (changes.length ? changes.map(function (item) { return '<div class="mini-change">' + sevBadge(item.severity) + '<span>' + esc(driftSummary(item.summary)) + '</span><b>' + esc(dispositionText(item.classification)) + '</b></div>'; }).join('') : '<div class="notice ok-notice">相对批准基线没有变化。</div>') + '</section>';
    body.innerHTML = html;
    if (!dialog.open) dialog.showModal();
    refreshIcons();
  }
  function renderResources(ctx) {
    var el = document.getElementById("tab-resources");
    var types = [["all", "全部"], ["host", "主机"], ["process", "进程"], ["endpoint", "端口"], ["service", "服务"], ["deployment", "部署"], ["database", "数据库"], ["docker.network", "网络"], ["docker.volume", "卷"]];
    var html = '<div class="page-head compact"><div><span class="eyebrow">统一资源模型</span><h1>全部资产事实</h1><p>浏览 Host、Process、Service、Deployment、Container、Database、Endpoint、Volume 和 Network；打开任意条目可核对完整字段与关系证据。</p></div><div class="capture"><span>当前快照</span><strong>' + ctx.resources.length + ' 项资源</strong><span>' + (((ctx.inventory || {}).relationships) || []).length + ' 条关系</span></div></div><div class="toolbar">';
    types.forEach(function (t) {
      html += '<button class="chip' + (resFilter.type === t[0] ? " active" : "") + '" data-rtype="' + t[0] + '">' + t[1] + "</button>";
    });
    html += '<input type="search" id="res-q" placeholder="搜索 ID / 名称 / 命令行…" value="' + esc(resFilter.q) + '">';
    html += "</div>";

    var rows = ctx.resources.filter(function (r) {
      if (resFilter.type !== "all" && r.type !== resFilter.type) return false;
      if (!resFilter.q) return true;
      var hay = (r.id + " " + resourceDesc(r) + " " + JSON.stringify(r[r.type] || {})).toLowerCase();
      return hay.indexOf(resFilter.q.toLowerCase()) !== -1;
    });

    var missing = selectedResourceId && !ctx.resources.some(function (resource) { return resource.id === selectedResourceId; });
    if (missing) {
      var removed = flattenDrift(ctx.drift).find(function (item) { return item.id === selectedResourceId && item._kind === "removed"; });
      html += '<div class="removed-resource"><strong>该资产已从当前快照消失</strong><span>' + esc(removed ? driftSummary(removed.summary) : selectedResourceId) + '</span>' + (removed && removed.before ? '<details><summary>查看基线证据</summary>' + kvTable(removed.before) + '</details>' : '') + '</div>';
    }

    html += '<div class="tablewrap"><table><thead><tr><th>类型</th><th>资源 ID</th><th>关键信息</th></tr></thead><tbody>';
    if (!rows.length) html += '<tr><td colspan="3" class="muted-cell">无匹配资源</td></tr>';
    rows.forEach(function (r) {
      html += '<tr class="selectable' + (selectedResourceId === r.id ? ' selected' : '') + '"><td>' + typeBadge(r.type) + "</td><td class='mono'><button class='row-open' type='button' data-open-resource='" + esc(r.id) + "'>" + esc(r.id) + "</button></td><td>" + esc(resourceDesc(r)) + "</td></tr>";
    });
    html += "</tbody></table></div>";
    el.innerHTML = html;

    el.querySelectorAll(".chip").forEach(function (btn) {
      btn.addEventListener("click", function () {
        resFilter.type = btn.getAttribute("data-rtype");
        renderResources(ctx);
      });
    });
    var q = document.getElementById("res-q");
    var composing = false;
    function applyResourceQuery() {
      resFilter.q = q.value;
      renderResources(ctx);
      var next = document.getElementById("res-q");
      next.focus();
      next.setSelectionRange(next.value.length, next.value.length);
    }
    q.addEventListener("compositionstart", function () { composing = true; });
    q.addEventListener("compositionend", function () {
      composing = false;
      applyResourceQuery();
    });
    q.addEventListener("input", function () {
      resFilter.q = q.value;
      if (!composing) applyResourceQuery();
    });
  }

  /* ---------- 端口风险 ---------- */
  function portRisk(e) {
    if (e.exposed_level === "public" && e.process_user === "root") {
      return { cls: "crit", text: "严重：root 进程暴露公网端口" };
    }
    if (e.exposed_level === "public") {
      return { cls: "warn", text: "警告：公网可访问，请确认必要性" };
    }
    if (e.exposed_level === "private") return { cls: "info", text: "内网监听" };
    if (e.exposed_level === "localhost") return { cls: "ok", text: "仅本机，风险低" };
    return { cls: "muted", text: "暴露级别未知" };
  }
  function renderPorts(ctx) {
    var el = document.getElementById("tab-ports");
    var eps = ctx.byType.endpoint.slice().sort(function (a, b) {
      var rank = function (r) {
        var e = r.endpoint;
        if (e.exposed_level === "public" && e.process_user === "root") return 0;
        if (e.exposed_level === "public") return 1;
        if (e.exposed_level === "private") return 2;
        if (e.exposed_level === "localhost") return 3;
        return 4;
      };
      var d = rank(a) - rank(b);
      return d !== 0 ? d : (a.endpoint.port - b.endpoint.port);
    });
    var html = "";
    var routes = (ctx.inventory && ctx.inventory.nginx_routes) || [];
    var proxyRelationships = ((ctx.inventory && ctx.inventory.relationships) || []).filter(function (item) { return item.type === "proxies_to"; });
    html += '<div class="page-head compact"><div><span class="eyebrow">网络拓扑</span><h1>暴露与依赖</h1><p>从监听入口追到责任进程、反向代理上游与部署关系，所有连线均附带采集证据。</p></div><div class="capture"><span>关系证据</span><strong>' + (((ctx.inventory || {}).relationships) || []).length + ' 条</strong></div></div><div class="exposure-list">';
    if (!eps.length) html += '<div class="notice">没有监听端口数据。</div>';
    eps.forEach(function (r) {
      var e = r.endpoint;
      var risk = portRisk(e);
      html += '<article class="exposure-item ' + risk.cls + '"><div class="port-number"><span>' + esc(e.protocol) + '</span><b>' + esc(e.port) + '</b></div><div class="exposure-main"><div><strong>' + esc(e.address) + ':' + esc(e.port) + '</strong>' + exposeBadge(e.exposed_level) + '</div><p>' + esc(risk.text) + '</p><dl><dt>进程</dt><dd>' + esc(e.process_name || '未知') + (e.process_id ? ' · PID ' + esc(e.process_id) : '') + '</dd><dt>用户</dt><dd>' + esc(e.process_user || '-') + '</dd></dl></div><button class="link-btn" type="button" data-open-resource="' + esc(r.id) + '">定位资产</button></article>';
    });
    html += "</div>";
    html += '<section class="topology-section"><div class="section-heading"><div><h2>Nginx 代理链路</h2><p>配置文件中的 proxy_pass 已与实际监听端点进行匹配。</p></div><span class="badge ' + (routes.length && !proxyRelationships.length ? 'warn' : 'ok') + '">' + proxyRelationships.length + ' 条已连线</span></div>';
    if (routes.length) html += '<div class="route-grid">' + routes.map(function (route) { var routeResource = ctx.byType["nginx.route"].find(function (item) { return item.metadata && item.metadata.source_file === route.source_file && item.metadata.location === route.location; }); var rel = routeResource && proxyRelationships.find(function (item) { return item.source === routeResource.id; }); return '<article class="route-card"><div class="route-source"><i data-lucide="globe-2"></i><span><b>' + esc((route.server_name || '_') + (route.location || '/')) + '</b><small>' + esc(route.listen || 'default listen') + '</small></span></div><i data-lucide="arrow-right"></i><div class="route-target"><i data-lucide="server"></i><span><b>' + esc(route.upstream) + '</b><small>' + (rel ? '已匹配 ' + esc(rel.target) : '未匹配到本机监听') + '</small></span></div><button type="button" class="icon-command" data-open-resource="' + esc(routeResource ? routeResource.id : '') + '" title="查看路由证据" aria-label="查看路由证据"><i data-lucide="file-search"></i></button></article>'; }).join('') + '</div>';
    else html += '<div class="notice">未发现静态 Nginx proxy_pass 路由。</div>';
    html += '</section>';
    el.innerHTML = html;
  }

  /* ---------- FleetScope 原生采集计划与 Nginx 路由 ---------- */
  function targetName(value) {
    var name = String(value || "target").split(/[/:]/).pop().replace(/\.service$/i, "");
    return name.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "target";
  }

  function recommendationPort(item, fallback) {
    var endpoints = item.parameters && item.parameters.endpoints ? item.parameters.endpoints.split(",") : [];
    var match = endpoints.length ? endpoints[0].match(/:(\d+)$/) : null;
    return match ? Number(match[1]) : fallback;
  }

  function fleetApplicationsConfig(recommendations, detected) {
    var config = { max_concurrency: 4 };
    var names = {};
    var serviceByTarget = {};
    detected.forEach(function (service) { serviceByTarget[service.resource_id] = service; });
    function unique(value) {
      var base = targetName(value), name = base, n = 2;
      while (names[name]) name = base + "-" + n++;
      names[name] = true;
      return name;
    }
    recommendations.forEach(function (item) {
      var collector = String(item.collector || "").split("/").pop();
      if (collector === "system") return;
      var detectedService = serviceByTarget[item.target_id] || {};
      var name = unique(detectedService.name || item.target_id);
      if (collector === "nginx") {
        (config.nginx || (config.nginx = [])).push({ name: name, url: "http://127.0.0.1:" + recommendationPort(item, 8080) + "/nginx_status", timeout_seconds: 5, required: item.priority === "required" });
      } else if (collector === "redis") {
        (config.redis || (config.redis = [])).push({ name: name, address: "127.0.0.1:" + recommendationPort(item, 6379), password_env: "FLEET_REDIS_PASSWORD", timeout_seconds: 5, required: item.priority === "required" });
      } else if (collector === "postgresql" || collector === "mysql") {
        var envName = "FLEET_" + name.toUpperCase().replace(/[^A-Z0-9]+/g, "_") + "_DSN";
        (config.databases || (config.databases = [])).push({ name: name, engine: collector === "postgresql" ? "postgres" : "mysql", dsn_env: envName, timeout_seconds: 5, required: item.priority === "required" });
      } else if (collector === "docker") {
        if (!config.docker) config.docker = [{ name: "local-engine", socket: "/var/run/docker.sock", max_containers: 100, timeout_seconds: 10, required: item.priority === "required" }];
      } else {
        (config.processes || (config.processes = [])).push({ name: name, match: detectedService.name || targetName(item.target_id), required: item.priority === "required" });
      }
    });
    return config;
  }

  function gapResource(value) {
    var match = String(value || "").match(/(endpoint:[^\s]+)/);
    return match ? match[1] : "";
  }

  function renderMonitoring(ctx) {
    var el = document.getElementById("tab-monitoring");
    var inventory = ctx.inventory || {};
    var detected = inventory.detected_services || [];
    var plan = inventory.monitoring_plan || {};
    var recommendations = plan.recommendations || [];
    var routes = inventory.nginx_routes || [];
    var nativeConfig = fleetApplicationsConfig(recommendations, detected);
    var hasApplicationTargets = Object.keys(nativeConfig).some(function (key) { return key !== "max_concurrency" && nativeConfig[key].length; });
    monitoringConfigText = hasApplicationTargets ? JSON.stringify(nativeConfig, null, 2) : "";
    var html = '<div class="page-head compact"><div><span class="eyebrow">原生采集</span><h1>FleetScope 采集计划</h1><p>InfraScout 根据当前资产事实生成可直接交给 FleetScope Agent 的原生采集目标。</p></div><div class="capture"><span>计划版本</span><strong>' + esc(plan.version || '-') + '</strong><a class="suite-handoff" data-suite="fleetscope">打开 FleetScope 数据接入 →</a></div></div>';
    html += '<div class="summary-strip"><span><b>' + detected.length + '</b> 识别服务</span><span><b>' + recommendations.length + '</b> 采集目标</span><span class="' + ((plan.coverage_gaps || []).length ? 'warn-text' : 'ok-text') + '"><b>' + (plan.coverage_gaps || []).length + '</b> 覆盖缺口</span><span><b>' + routes.length + '</b> Nginx 路由</span></div>';
    html += '<h2 class="section-title">识别到的服务</h2>';
    if (detected.length) {
      html += '<div class="tablewrap"><table><thead><tr><th>类型</th><th>名称</th><th>来源</th><th>端点</th><th>置信度</th></tr></thead><tbody>' + detected.map(function (item) {
        return '<tr><td>' + esc(item.kind) + '</td><td class="mono">' + esc(item.name) + '</td><td>' + esc(item.source) + '</td><td class="mono">' + esc((item.endpoints || []).join(', ') || '-') + '</td><td>' + Math.round(Number(item.confidence || 0) * 100) + '%</td></tr>';
      }).join('') + '</tbody></table></div>';
    } else html += '<div class="notice">尚未识别到可分类的服务。</div>';
    html += '<div class="section-heading"><div><h2>原生采集目标</h2><p>系统指标由 Agent 内置采集，其余目标写入 applications.json。</p></div></div>';
    if (recommendations.length) {
      html += '<div class="collector-list">' + recommendations.map(function (item) {
        return '<article class="collector-row"><div><span class="badge ' + (item.priority === 'required' ? 'warn' : 'muted') + '">' + (item.priority === 'required' ? '必须' : '建议') + '</span><code>' + esc(item.collector) + '</code></div><div><strong>' + esc(item.target_id) + '</strong><p>' + esc(item.reason) + '</p></div></article>';
      }).join('') + '</div>';
    } else html += '<div class="notice">当前清单没有生成监控建议。</div>';
    html += '<div class="section-heading config-heading"><div><h2>Agent 应用采集配置</h2><p>凭据只引用环境变量名，不会写入配置文件。</p></div>' + (hasApplicationTargets ? '<div class="action-group"><button class="chip" type="button" data-copy-config>复制 JSON</button><button class="chip" type="button" data-export-config>导出配置</button></div>' : '') + '</div>';
    if (hasApplicationTargets) html += '<pre class="config-preview"><code>' + esc(monitoringConfigText) + '</code></pre><div class="agent-argument"><span>Agent 参数</span><code>--applications /etc/fleetscope/applications.json</code></div>';
    else html += '<div class="notice ok-notice">当前只需要 FleetScope Agent 内置系统采集，无需额外应用配置。</div>';
    if ((plan.coverage_gaps || []).length) html += '<div class="coverage-list"><div class="section-heading"><div><h2>覆盖缺口</h2><p>这些公网端点尚未匹配到服务级采集器。</p></div></div>' + plan.coverage_gaps.map(function (gap) { var id = gapResource(gap); return '<div class="coverage-row"><span>' + esc(gap) + '</span>' + (id ? '<button class="link-btn" type="button" data-open-resource="' + esc(id) + '">定位资产</button>' : '') + '</div>'; }).join('') + '</div>';
    html += '<h2 class="section-title">Nginx 反向代理路由</h2>';
    if (routes.length) {
      html += '<div class="tablewrap"><table><thead><tr><th>Server</th><th>Listen</th><th>Location</th><th>Upstream</th><th>配置文件</th></tr></thead><tbody>' + routes.map(function (route) {
        return '<tr><td>' + esc(route.server_name || '-') + '</td><td class="mono">' + esc(route.listen || '-') + '</td><td class="mono">' + esc(route.location || '/') + '</td><td class="mono">' + esc(route.upstream) + '</td><td class="mono">' + esc(route.source_file) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
    } else html += '<div class="notice">未发现静态 Nginx proxy_pass 路由。</div>';
    el.innerHTML = html;
  }

  /* ---------- 数据库结构 ---------- */
  function databaseObjectTable(title, values, icon) {
    if (!values || !values.length) return "";
    return '<details class="db-object-group"><summary><span><i data-lucide="' + icon + '"></i><b>' + esc(title) + '</b></span><em>' + values.length + ' 项</em></summary><div class="tablewrap"><table><thead><tr><th>架构 / 主体</th><th>名称</th><th>类型</th><th>详情</th></tr></thead><tbody>' + values.map(function (item) { return '<tr><td class="mono">' + esc(item.schema || '-') + '</td><td class="mono">' + esc(item.name || '-') + '</td><td>' + esc(item.type || '-') + '</td><td class="mono wrap-code">' + esc(item.detail || '-') + '</td></tr>'; }).join('') + '</tbody></table></div></details>';
  }

  function databaseDriftPanel(diff) {
    if (!diff) return '<div class="notice">尚未建立数据库结构对比。运行 <code class="inline">infrascout database --engine postgres --state-dir .infrascout</code> 后会自动保存基线并持续对比。</div>';
    var items = [];
    [["added", diff.added || []], ["removed", diff.removed || []], ["changed", diff.changed || []]].forEach(function (group) { group[1].forEach(function (item) { items.push(Object.assign({ action: group[0] }, item)); }); });
    if (!items.length) return '<div class="notice ok-notice"><strong>数据库结构与批准基线一致</strong><br>已核对表、字段、约束、索引、视图、触发器、例程、角色和权限。</div>';
    return '<div class="database-drift"><div class="section-heading"><div><h2>数据库结构变化</h2><p>独立于业务数据，只比较结构与授权元数据；变化同时进入统一审核与发布阻断。</p></div>' + sevBadge(diff.highest_risk) + '</div>' + items.map(function (item) { return '<div class="db-drift-row ' + (SEV_CLASS[item.severity] || 'info') + '">' + sevBadge(item.severity) + '<span class="badge muted">' + esc(driftKindText(item.action)) + '</span><div><b>' + esc(item.id) + '</b><small>' + esc(databaseKindText(item.kind)) + '</small></div></div>'; }).join('') + '</div>';
  }

  function renderDatabase(ctx) {
    var el = document.getElementById("tab-database");
    var database = ctx.database;
    if (!database) {
      el.innerHTML = '<div class="notice">未加载数据库结构。先运行 <code class="inline">infrascout database</code>，再用 <code class="inline">serve --database database-metadata.json</code> 查看。</div>';
      return;
    }
    var schemas = database.schemas || [];
    var tables = [];
    schemas.forEach(function (schema) { (schema.tables || []).forEach(function (table) { tables.push(table); }); });
    var constraints = database.constraints || [], roles = database.roles || [];
    var html = '<div class="page-head compact"><div><span class="eyebrow">数据库元数据 v2</span><h1>数据库结构与授权</h1><p>通过只读事务查看结构、依赖和授权，不执行任何业务表数据查询。</p></div><div class="capture"><span>数据库</span><strong>' + esc(database.database_name || database.engine) + '</strong><span>' + fmtTime(database.collected_at) + '</span></div></div><div class="db-safety"><i data-lucide="shield-check"></i><div><b>只读元数据边界</b><span>仅访问 information_schema、系统目录和授权视图，不读取业务记录。</span></div></div><div class="cards"><div class="card"><h3>数据库</h3><div class="big">' + esc(database.engine) + '</div><dl><dt>名称</dt><dd>' + esc(database.database_name || '-') + '</dd><dt>服务版本</dt><dd>' + esc(database.server_version || '-') + '</dd></dl></div>' +
      '<div class="card"><h3>结构对象</h3><div class="big">' + tables.length + ' 张表</div><dl><dt>架构</dt><dd>' + schemas.length + '</dd><dt>约束</dt><dd>' + constraints.length + '</dd><dt>索引</dt><dd>' + (database.indexes || []).length + '</dd><dt>视图</dt><dd>' + (database.views || []).length + '</dd></dl></div>' +
      '<div class="card"><h3>授权与逻辑</h3><div class="big">' + (database.privileges || []).length + ' 项权限</div><dl><dt>角色 / 用户</dt><dd>' + roles.length + '</dd><dt>函数 / 过程</dt><dd>' + (database.routines || []).length + '</dd><dt>采集警告</dt><dd>' + (database.warnings || []).length + '</dd></dl></div></div>';
    html += databaseDriftPanel(ctx.databaseDiff);
    html += '<div class="database-browser"><aside><span class="eyebrow">模式列表</span>' + schemas.map(function (schema) { return '<button type="button" class="schema-link" data-scroll-schema="db-' + esc(schema.name) + '"><b>' + esc(schema.name) + '</b><span>' + (schema.tables || []).length + ' 张表</span></button>'; }).join('') + '</aside><div class="schema-list">';
    if (!tables.length) html += '<div class="notice">没有用户表。</div>';
    schemas.forEach(function (schema, schemaIndex) {
      html += '<section id="db-' + esc(schema.name) + '"><div class="schema-head"><div><span class="eyebrow">模式</span><h2>' + esc(schema.name) + '</h2></div><span>' + (schema.tables || []).length + ' 张表</span></div>';
      (schema.tables || []).forEach(function (table, tableIndex) {
        var tableConstraints = constraints.filter(function (item) { return item.schema === schema.name && item.table === table.name; });
        html += '<details class="db-table" ' + (schemaIndex === 0 && tableIndex === 0 ? 'open' : '') + '><summary><span><b>' + esc(table.name) + '</b><small>' + (table.columns || []).length + ' 个字段 · ' + tableConstraints.length + ' 个约束</small></span><em>查看结构</em></summary><div class="tablewrap"><table><thead><tr><th>字段</th><th>类型</th><th>可空</th><th>默认值</th></tr></thead><tbody>' + (table.columns || []).map(function (column) { return '<tr><td class="mono">' + esc(column.name) + '</td><td class="mono">' + esc(column.data_type) + '</td><td>' + (column.nullable ? '是' : '<span class="badge warn">NOT NULL</span>') + '</td><td class="mono">' + esc(column.default || '-') + '</td></tr>'; }).join('') + '</tbody></table></div>' + (tableConstraints.length ? '<div class="constraint-list">' + tableConstraints.map(function (item) { return '<div><span class="badge info">' + esc(item.type) + '</span><b>' + esc(item.name) + '</b><code>' + esc((item.columns || []).join(', ')) + (item.reference_table ? ' → ' + item.reference_schema + '.' + item.reference_table + '(' + (item.reference_columns || []).join(', ') + ')' : '') + '</code></div>'; }).join('') + '</div>' : '') + '</details>';
      });
      html += '</section>';
    });
    html += '</div></div>';
    html += '<section class="db-catalog"><div class="section-heading"><div><h2>完整对象目录</h2><p>以下对象同样进入数据库漂移比较。</p></div></div>' + databaseObjectTable('索引', database.indexes || [], 'list-tree') + databaseObjectTable('视图', database.views || [], 'panels-top-left') + databaseObjectTable('触发器', database.triggers || [], 'zap') + databaseObjectTable('函数与过程', database.routines || [], 'braces') + databaseObjectTable('角色与用户', roles, 'users') + databaseObjectTable('权限', database.privileges || [], 'key-round') + '</section>';
    if ((database.warnings || []).length) html += '<div class="notice warning-notice monitor-gap">' + database.warnings.map(esc).join('<br>') + '</div>';
    el.innerHTML = html;
  }

  /* ---------- 变更报告 ---------- */
  function kvTable(obj) {
    var keys = Object.keys(obj || {});
    if (!keys.length) return '<div class="kv muted-kv">（无字段）</div>';
    return keys.map(function (k) {
      return '<div class="kv"><span class="k">' + esc(k) + ":</span> <span class='mono'>" + esc(JSON.stringify(obj[k])) + "</span></div>";
    }).join("");
  }
  function flattenDrift(report) {
    if (!report) return [];
    var items = [];
    [["added", report.added || []], ["removed", report.removed || []], ["changed", report.changed || []]].forEach(function (group) {
      group[1].forEach(function (item) { items.push(Object.assign({ _kind: group[0] }, item)); });
    });
    return items;
  }

  function driftKindText(kind) {
    return ({ added: "新增", removed: "删除", changed: "修改" })[kind] || kind;
  }

  function decisionDetails(item) {
    if (!item.decision) return item.decision_expired ? '<div class="decision-meta expired">原临时审核已到期，需要重新处置。</div>' : '';
    var decision = item.decision;
    return '<dl class="decision-meta"><dt>审核人</dt><dd>' + esc(decision.actor || '-') + '</dd><dt>审核时间</dt><dd>' + fmtTime(decision.decided_at) + '</dd><dt>处置依据</dt><dd>' + esc(decision.note || '-') + '</dd>' + (decision.expires_at ? '<dt>有效期至</dt><dd class="' + (item.decision_expired ? 'expired' : '') + '">' + fmtTime(decision.expires_at) + (item.decision_expired ? ' · 已到期' : '') + '</dd>' : '') + '</dl>';
  }

  function driftGroup(title, items) {
    var html = '<h2 class="section-title">' + esc(title) + "（" + items.length + "）</h2>";
    if (!items.length) return html + '<div class="notice">无</div>';
    items.forEach(function (it) {
      var cls = SEV_CLASS[it.severity] || "info";
      html += '<div class="drift-item ' + cls + '"><div class="head">' +
        sevBadge(it.severity) + '<span class="badge muted">' + esc(driftKindText(it._kind)) + '</span>' + typeBadge(it.type) +
        "<span>" + esc(driftSummary(it.summary)) + "</span></div>" +
        '<div class="id mono">' + esc(it.id) + "</div>" +
        '<span class="disposition ' + esc(it.classification || 'unexpected') + '">' + esc(dispositionText(it.classification)) + (it.decision_expired ? ' · 已到期' : '') + '</span>' +
        decisionDetails(it) + ((it.before || it.after) ? '<details class="diff-evidence" ' + (it._kind === 'changed' ? 'open' : '') + '><summary>查看变化证据</summary><div class="diffkv"><div class="col"><h4>变更前</h4>' + kvTable(it.before) + '</div><div class="col"><h4>变更后</h4>' + kvTable(it.after) + '</div></div></details>' : '') + '<div class="drift-actions"><button type="button" class="link-btn" data-open-resource="' + esc(it.id) + '">定位资产</button>' + reviewActions(it) + '</div>' +
        "</div>";
    });
    return html;
  }
  function dispositionText(value) {
    return ({ expected: "预期", approved: "已批准", temporary: "临时允许", unexpected: "待审核", denied: "禁止" })[value] || "待审核";
  }
  function reviewActions(item) {
    if (!currentCtx || !currentCtx.reviewEnabled || !item.fingerprint) return "";
    var html = '<button type="button" data-review="' + esc(item.fingerprint) + '" data-review-resource="' + esc(item.id) + '" data-review-classification="' + esc(item.classification || 'unexpected') + '">审核</button>';
    if (item.classification === "approved" || item.classification === "expected") html += '<button type="button" class="promote" data-promote="' + esc(item.fingerprint) + '">提升到基线</button>';
    return html;
  }
  function renderDrift(ctx) {
    var el = document.getElementById("tab-drift");
    var d = ctx.drift;
    if (!d) {
      el.innerHTML = '<div class="notice">未加载变更报告。先用 <code class="inline">infrascout diff old.json new.json -j drift.json</code> 生成，再以 <code class="inline">--drift drift.json</code> 启动。</div>';
      return;
    }
    var items = flattenDrift(d);
    var count = function (classification) { return items.filter(function (item) { return (item.classification || "unexpected") === classification; }).length; };
    var blocking = items.filter(function (item) { var value = item.classification || "unexpected"; return value === "unexpected" || value === "denied"; });
    var blockingRisk = d.blocking_risk || (blocking.some(function (item) { return item.severity === "CRITICAL"; }) ? "CRITICAL" : blocking.some(function (item) { return item.severity === "WARNING"; }) ? "WARNING" : blocking.length ? "INFO" : "");
    var html = '<div class="page-head compact"><div><span class="eyebrow">变更队列</span><h1>变更处置</h1><p>按处置状态审核基础设施变化，只有逐条批准或标记预期的变化可以提升到基线。</p></div></div>';
    if (blockingRisk) html += '<div class="blocking-banner"><div><strong>' + esc(SEV_TEXT[blockingRisk] || blockingRisk) + '风险正在阻断</strong><span>' + blocking.length + ' 条变化需要处置</span></div><button type="button" class="chip" data-drift-filter="blocking">查看阻断项</button></div>';
    html += '<div class="cards">' +
      '<div class="card"><h3>观测风险</h3><div class="big">' + sevBadge(d.highest_risk) + "</div></div>" +
      '<div class="card"><h3>阻断风险</h3><div class="big">' + (blockingRisk ? sevBadge(blockingRisk) : '<span class="badge ok">无</span>') + "</div></div>" +
      '<div class="card"><h3>对比时间</h3><dl>' +
      "<dt>基线快照</dt><dd>" + fmtTime(d.baseline_timestamp) + "</dd>" +
      "<dt>对比快照</dt><dd>" + fmtTime(d.candidate_timestamp) + "</dd>" +
      "<dt>生成时间</dt><dd>" + fmtTime(d.compared_at) + "</dd>" +
      "</dl></div>" +
      '<div class="card"><h3>统计</h3><dl>' +
      "<dt>新增</dt><dd>" + (d.added || []).length + "</dd>" +
      "<dt>删除</dt><dd>" + (d.removed || []).length + "</dd>" +
      "<dt>修改</dt><dd>" + (d.changed || []).length + "</dd>" +
      "<dt>未变化</dt><dd>" + (d.unchanged_count || 0) + "</dd>" +
      "</dl></div></div>";
    html += '<div class="toolbar drift-filters" aria-label="变更筛选"><button class="chip' + (driftFilter === 'blocking' ? ' active' : '') + '" data-drift-filter="blocking">待处置 ' + blocking.length + '</button><button class="chip' + (driftFilter === 'all' ? ' active' : '') + '" data-drift-filter="all">全部 ' + items.length + '</button><button class="chip' + (driftFilter === 'unexpected' ? ' active' : '') + '" data-drift-filter="unexpected">待审核 ' + count('unexpected') + '</button><button class="chip' + (driftFilter === 'denied' ? ' active' : '') + '" data-drift-filter="denied">禁止 ' + count('denied') + '</button><button class="chip' + (driftFilter === 'temporary' ? ' active' : '') + '" data-drift-filter="temporary">临时 ' + count('temporary') + '</button><button class="chip' + (driftFilter === 'resolved' ? ' active' : '') + '" data-drift-filter="resolved">已处置 ' + (count('approved') + count('expected')) + '</button></div>';
    var visible = items.filter(function (item) {
      var value = item.classification || "unexpected";
      if (driftFilter === "all") return true;
      if (driftFilter === "blocking") return value === "unexpected" || value === "denied";
      if (driftFilter === "resolved") return value === "approved" || value === "expected";
      return value === driftFilter;
    });
    if (!visible.length) html += '<div class="notice ok-notice">当前筛选下没有变更。</div>';
    else if (driftFilter === "all") {
      ["unexpected", "denied", "temporary", "approved", "expected"].forEach(function (classification) {
        var group = visible.filter(function (item) { return (item.classification || "unexpected") === classification; });
        if (group.length) html += driftGroup(dispositionText(classification), group);
      });
    } else html += driftGroup(driftFilter === "blocking" ? "待处置队列" : driftFilter === "resolved" ? "已处置" : dispositionText(driftFilter), visible);
    el.innerHTML = html;
  }

  function findDrift(fingerprint) {
    if (!currentCtx || !currentCtx.drift) return null;
    return flattenDrift(currentCtx.drift).find(function (item) { return item.fingerprint === fingerprint; }) || null;
  }

  function openReview(button) {
    var fingerprint = button.getAttribute("data-review");
    var item = findDrift(fingerprint);
    document.getElementById("review-fingerprint").value = fingerprint;
    document.getElementById("review-resource").textContent = item ? driftSummary(item.summary) + " · " + item.id : button.getAttribute("data-review-resource");
    document.getElementById("review-classification").value = button.getAttribute("data-review-classification") || "unexpected";
    document.getElementById("review-actor").value = item && item.decision ? item.decision.actor || "" : "";
    document.getElementById("review-note").value = item && item.decision ? item.decision.note || "" : "";
    document.getElementById("review-expiry").value = item && item.decision && item.decision.expires_at ? new Date(item.decision.expires_at).toISOString().slice(0, 16) : "";
    toggleReviewExpiry();
    setFormError("review-error", "");
    document.getElementById("review-dialog").showModal();
  }

  function setFormError(id, message) {
    var element = document.getElementById(id);
    element.textContent = message || "";
    element.classList.toggle("hidden", !message);
  }

  function showToast(message, failed) {
    var toast = document.getElementById("toast");
    window.clearTimeout(toastTimer);
    toast.textContent = message;
    toast.className = "toast" + (failed ? " error" : "");
    toastTimer = window.setTimeout(function () { toast.classList.add("hidden"); toast.textContent = ""; }, 3500);
  }

  function openPromote(button) {
    var fingerprint = button.getAttribute("data-promote");
    var item = findDrift(fingerprint);
    if (!item) return;
    document.getElementById("promote-fingerprint").value = fingerprint;
    document.getElementById("promote-resource").textContent = driftSummary(item.summary) + " · " + item.id;
    document.getElementById("promote-before").innerHTML = kvTable(item.before);
    document.getElementById("promote-after").innerHTML = kvTable(item.after);
    document.getElementById("promote-decision").innerHTML = decisionDetails(item) || '<div class="notice">没有可核验的审核记录。</div>';
    document.getElementById("promote-ack").checked = false;
    document.getElementById("promote-submit").disabled = true;
    setFormError("promote-error", "");
    document.getElementById("promote-dialog").showModal();
  }

  function toggleReviewExpiry() {
    var temporary = document.getElementById("review-classification").value === "temporary";
    document.getElementById("review-expiry-field").classList.toggle("hidden", !temporary);
    document.getElementById("review-expiry").required = temporary;
  }

  function apiMutation(path, options) {
    return fetch(path, Object.assign({ cache: "no-store" }, options || {})).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        if (!response.ok) throw new Error(body.error || "请求失败 (" + response.status + ")");
        return body;
      });
    });
  }

  function renderTab(tab) {
    if (!currentCtx) return;
	({ overview: renderOverview, applications: renderApplications, resources: renderResources, ports: renderPorts, monitoring: renderMonitoring, database: renderDatabase, drift: renderDrift })[tab](currentCtx);
    dirtyTabs[tab] = false;
	refreshIcons();
  }

  function updateDriftBadge(ctx) {
    var pending = flattenDrift(ctx && ctx.drift).filter(function (item) {
      var value = item.classification || "unexpected";
      return value === "unexpected" || value === "denied";
    }).length;
    var badge = document.getElementById("drift-tab-badge");
    badge.textContent = pending;
    badge.classList.toggle("hidden", pending === 0);
    badge.setAttribute("aria-label", pending + " 条待处置变化");
  }

  function captureViewState(tab) {
    var page = document.getElementById("tab-" + tab);
    return { scrollY: window.scrollY, details: Array.from(page.querySelectorAll("details")).map(function (detail) { return detail.open; }) };
  }

  function restoreViewState(tab, state) {
    if (!state) return;
    document.getElementById("tab-" + tab).querySelectorAll("details").forEach(function (detail, index) { detail.open = Boolean(state.details[index]); });
    window.scrollTo(0, state.scrollY);
  }

  /* ---------- 标签页 ---------- */
  function activateTab(tab, updateHash) {
    if (!["overview", "applications", "resources", "ports", "monitoring", "database", "drift"].includes(tab)) tab = "overview";
    currentTab = tab;
    if (currentCtx && dirtyTabs[tab]) renderTab(tab);
    document.querySelectorAll("#tabs button").forEach(function (button) {
      var active = button.getAttribute("data-tab") === tab;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
      button.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll(".tabpage").forEach(function (page) { page.classList.toggle("hidden", page.id !== "tab-" + tab); });
    if (updateHash) history.pushState(null, "", "#/" + tab);
    if (updateHash) document.getElementById("tab-" + tab).focus({ preventScroll: true });
  }

  function initTabs() {
    document.getElementById("tabs").addEventListener("click", function (ev) {
      var btn = ev.target.closest("button[data-tab]");
      if (!btn) return;
      activateTab(btn.getAttribute("data-tab"), true);
    });
    document.getElementById("tabs").addEventListener("keydown", function (event) {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight" && event.key !== "Home" && event.key !== "End") return;
      var buttons = Array.from(document.querySelectorAll("#tabs button[data-tab]"));
      var index = buttons.indexOf(document.activeElement);
      if (event.key === "Home") index = 0;
      else if (event.key === "End") index = buttons.length - 1;
      else index = (index + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
      event.preventDefault();
      buttons[index].focus();
      activateTab(buttons[index].getAttribute("data-tab"), true);
    });
    document.addEventListener("click", function (event) {
      var jump = event.target.closest("[data-jump]");
      if (jump) activateTab(jump.getAttribute("data-jump"), true);
      var scroll = event.target.closest("[data-scroll-target]");
      if (scroll) document.getElementById(scroll.getAttribute("data-scroll-target"))?.scrollIntoView({ behavior: "smooth", block: "start" });
      var open = event.target.closest("[data-open-resource]");
      if (open) {
        selectedResourceId = open.getAttribute("data-open-resource");
		openResourceDrawer(selectedResourceId);
      }
      var schema = event.target.closest("[data-scroll-schema]");
      if (schema) document.getElementById(schema.getAttribute("data-scroll-schema"))?.scrollIntoView({ behavior: "smooth", block: "start" });
      var review = event.target.closest("[data-review]");
      if (review) openReview(review);
      var promote = event.target.closest("[data-promote]");
      if (promote) openPromote(promote);
      var driftChoice = event.target.closest("[data-drift-filter]");
      if (driftChoice) { driftFilter = driftChoice.getAttribute("data-drift-filter"); renderDrift(currentCtx); }
	  if (event.target.closest("[data-expand-risks]")) { overviewRiskExpanded = true; renderOverview(currentCtx); refreshIcons(); }
      if (event.target.closest("[data-copy-config]") && monitoringConfigText) {
        navigator.clipboard.writeText(monitoringConfigText).then(function () { showToast("FleetScope 配置已复制"); }).catch(function () { showToast("浏览器不允许访问剪贴板", true); });
      }
      if (event.target.closest("[data-export-config]") && monitoringConfigText) {
        var url = URL.createObjectURL(new Blob([monitoringConfigText + "\n"], { type: "application/json" }));
		var link = document.createElement("a"); link.href = url; link.download = "applications.json"; link.click(); window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000); showToast("applications.json 已导出");
      }
    });
    window.addEventListener("popstate", function () { activateTab((location.hash.split("/")[1] || "overview"), false); });
    activateTab((location.hash.split("/")[1] || "overview"), false);
  }

  /* ---------- 启动 ---------- */
  function loadData(options) {
    options = options || {};
    if (loading) return Promise.resolve();
    if (options.background && (document.hidden || document.querySelector("dialog[open]"))) return Promise.resolve();
    loading = true;
    var refresh = document.getElementById("refresh");
    refresh.disabled = true;
    document.getElementById("sync-state").className = "sync-state";
    document.querySelector("#sync-state span").textContent = "正在刷新";
    if (!currentCtx) {
      STATUS.classList.remove("hidden", "error");
      STATUS.querySelector("span").textContent = "正在加载基础设施事实…";
    }
    var headers = {};
    if (lastETag) headers["If-None-Match"] = lastETag;
    return fetch("/api/data", { cache: "no-store", headers: headers })
    .then(function (resp) {
      if (resp.status === 304) return null;
      return resp.json().catch(function () { return {}; }).then(function (body) {
        if (!resp.ok) throw new Error(body.error || "HTTP " + resp.status);
        lastETag = resp.headers.get("ETag") || "";
        return body;
      });
    })
    .then(function (data) {
      if (data) {
        var viewState = currentCtx ? captureViewState(currentTab) : null;
        var ctx = normalize(data);
        currentCtx = ctx;
        Object.keys(dirtyTabs).forEach(function (tab) { dirtyTabs[tab] = true; });
        renderTab(currentTab);
        restoreViewState(currentTab, viewState);
        updateDriftBadge(ctx);
        var src = Object.keys(ctx.sources).map(function (k) { return k + ": " + ctx.sources[k]; }).join(" · ");
        document.getElementById("footer-sources").textContent = "数据来源 — " + (src || "无") + " · 更新于 " + fmtTime(ctx.generatedAt) + " · 每 10 秒检查更新";
      }
      STATUS.classList.add("hidden");
      document.getElementById("retry").classList.add("hidden");
      document.getElementById("stale-banner").classList.add("hidden");
      document.getElementById("sync-state").className = "sync-state ok";
      document.querySelector("#sync-state span").textContent = data ? "事实已同步" : "没有新变化";
      lastSuccess = Date.now();
    })
    .catch(function (err) {
      if (currentCtx) {
        var banner = document.getElementById("stale-banner");
        banner.textContent = "本次刷新失败，当前页面保留上一次成功数据。请在继续判断风险前重试：" + err.message;
        banner.classList.remove("hidden");
        document.getElementById("sync-state").className = "sync-state error";
        document.querySelector("#sync-state span").textContent = "数据可能陈旧";
      } else {
        STATUS.querySelector("span").textContent = "基础设施数据加载失败：" + err.message;
        STATUS.classList.add("error");
        document.getElementById("retry").classList.remove("hidden");
      }
    }).finally(function () {
      refresh.disabled = false;
      loading = false;
    });
  }

  initTabs();
	refreshIcons();
  document.getElementById("refresh").addEventListener("click", loadData);
  document.getElementById("retry").addEventListener("click", loadData);
	document.getElementById("resource-close").addEventListener("click", function () { document.getElementById("resource-dialog").close(); });
  document.getElementById("review-close").addEventListener("click", function () { document.getElementById("review-dialog").close(); });
  document.getElementById("review-cancel").addEventListener("click", function () { document.getElementById("review-dialog").close(); });
  document.getElementById("review-classification").addEventListener("change", toggleReviewExpiry);
  document.getElementById("review-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var fingerprint = document.getElementById("review-fingerprint").value;
    var classification = document.getElementById("review-classification").value;
    var expiry = document.getElementById("review-expiry").value;
    var body = { classification: classification, actor: document.getElementById("review-actor").value.trim(), note: document.getElementById("review-note").value.trim() };
    if (classification === "temporary" && expiry) body.expires_at = new Date(expiry).toISOString();
    var submit = document.getElementById("review-submit");
    submit.disabled = true;
    setFormError("review-error", "");
    apiMutation("/api/reviews/" + encodeURIComponent(fingerprint), { method: "PATCH", headers: { "Content-Type": "application/json", "X-InfraScout-Action": "1" }, body: JSON.stringify(body) }).then(function () {
      document.getElementById("review-dialog").close();
      lastETag = "";
      showToast("审核记录已保存");
      return loadData();
    }).catch(function (error) { setFormError("review-error", error.message); }).finally(function () { submit.disabled = false; });
  });
  document.getElementById("promote-close").addEventListener("click", function () { document.getElementById("promote-dialog").close(); });
  document.getElementById("promote-cancel").addEventListener("click", function () { document.getElementById("promote-dialog").close(); });
  document.getElementById("promote-ack").addEventListener("change", function (event) { document.getElementById("promote-submit").disabled = !event.target.checked; });
  document.getElementById("promote-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var fingerprint = document.getElementById("promote-fingerprint").value;
    var submit = document.getElementById("promote-submit");
    submit.disabled = true;
    setFormError("promote-error", "");
    apiMutation("/api/reviews/" + encodeURIComponent(fingerprint) + "/promote", { method: "POST", headers: { "X-InfraScout-Action": "1" } }).then(function () {
      document.getElementById("promote-dialog").close();
      lastETag = "";
      showToast("已将这一条变化提升到基线");
      return loadData();
    }).catch(function (error) { setFormError("promote-error", error.message); submit.disabled = false; });
  });
  loadData();
  window.setInterval(function () { loadData({ background: true }); }, 10000);
})();
