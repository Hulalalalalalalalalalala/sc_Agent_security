# LCT 三机物理互联部署与运维指南（Multi-Host Federation）

本文档说明如何在 3 台独立物理主机（或同一主机的多角色演练环境）上部署、配置、验证与排障 **Lineage Capability Tree (LCT)** 跨组织联邦系统。各角色（`alpha`、`beta`、`pay`、`audit`）支持按主机任意组合（例如 `Machine 1: alpha,audit`、`Machine 2: beta`、`Machine 3: pay`，或单机 `all`）。

---

## 1. 物理拓扑、网络地址段与端口分配

每台物理机仅运行本机所承担角色对应的独立 Kind 集群（集群名前缀统一为 `lctmh-`），通过 Kind `extraPortMappings`（`listenAddress: 0.0.0.0`，`containerPort == hostPort == NodePort`）在宿主网卡暴露跨组织通信端口：

| 物理节点 | 部署角色（Kind 集群） | 信任域 | Pod CIDR / Service CIDR | 宿主机暴露 TCP 端口 | 端口用途与传输层安全要求 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Machine 1** | `alpha` (`lctmh-alpha`)<br>`audit` (`lctmh-audit`) | `org-alpha.io`<br>`org-audit.io` | `10.241.0.0/16` / `10.97.0.0/16`<br>`10.244.0.0/16` / `10.100.0.0/16` | `30094`<br>`30491`, `30492`<br>`30441`<br>`30990`<br>`30893` | `alpha-ca` 只读公钥束（HTTP + SHA-256 信任锚校验）<br>`alpha-directory` / `alpha-revocation` 跨机联邦同步（双向 mTLS 1.3）<br>`orchestrator-alpha` A2A v1.0 入口（双向 mTLS 1.3 + DPoP + LCT）<br>`e2e-user-gateway` 场景 3B 临时同步钩子（平时无 Service/监听，仅在 `e2e` 场景 3B 期间临时创建 `NodePort` 并校验随机 `X-LCT-Sync-Token`，场景结束后自动删除）<br>`audit-collector` 无签名密钥审计收集器（TLS 1.3 服务端认证） |
| **Machine 2** | `beta` (`lctmh-beta`) | `org-beta.io` | `10.242.0.0/16` / `10.98.0.0/16` | `31094`<br>`31491`, `31492`<br>`31441`, `31442`, `31443` | `beta-ca` 只读公钥束（HTTP + SHA-256 信任锚校验）<br>`beta-directory` / `beta-revocation` 跨机联邦同步（双向 mTLS 1.3）<br>`flight-specialist` / `hotel-specialist-primary` / `hotel-specialist-backup`（双向 mTLS 1.3） |
| **Machine 3** | `pay` (`lctmh-pay`) | `org-payment.io` | `10.243.0.0/16` / `10.99.0.0/16` | `32094`<br>`32491`, `32492`<br>`32441`, `32442`, `32443` | `payment-ca` 只读公钥束（HTTP + SHA-256 信任锚校验）<br>`payment-directory` / `payment-revocation` 跨机联邦同步（双向 mTLS 1.3）<br>`settlement-converger` / `travel-ops-mcp` / `payment-vault-mcp`（双向 mTLS 1.3） |

边界隔离约束：
1. 集群内部身份签发端口（`:8090`）、本地目录注册与隔离端口（`:8091`）、本地撤销写入端口（`:8092`）、Sidecar 本地回环代理端口（`127.0.0.1:8081`）以及业务容器回环端口（`127.0.0.1:9001`）始终保持 `ClusterIP` 或 Pod 本地回环，绝不通过 `extraPortMappings` 暴露至宿主机网卡。
2. 所有 X.509 证书与 `AgentCard` 均绑定公共组织 FQDN（如 `https://flight-specialist.org-beta.io:31441`），由各集群 CoreDNS 将组织域名解析为对应物理机 IPv4 地址，客户端全程启用 `check_hostname=True` 与信任域 `NameConstraints` 校验。

---

## 2. 各操作系统前置环境准备

### 2.1 通用软件依赖
在每台参与部署的机器上克隆本仓库并执行依赖自举脚本：

```bash
bash lineage/scripts/setup_deps.sh --lang python --install-k8s-tools
```

硬件与运行时要求：
- Docker 运行时正常启动，单机建议分配至少 `4 CPU`、`6 GB RAM`；
- Python `>= 3.11`（含 `cryptography`、`httpx`、`PyYAML`）；
- `kind`、`kubectl` 在 `PATH` 中可执行。

### 2.2 macOS（Docker Desktop）
- 启动 Docker Desktop，确认 `docker info` 正常返回；
- 获取当前活动网卡局域网 IPv4 地址（例如 Wi-Fi `en0`）：
  ```bash
  ipconfig getifaddr en0
  ```
- 在 macOS 系统设置「网络 -> 防火墙」中，允许 Docker 入站连接（或关闭系统应用层阻断规则）。

### 2.3 Linux（Docker Engine）
- 确保当前用户在 `docker` 组中且 `systemctl is-active docker` 为 `active`；
- 获取主网卡 IPv4 地址：
  ```bash
  ip -4 route get 1.1.1.1 | awk '{print $7; exit}'
  ```
- 若启用了 `ufw` 或 `firewalld`，按本机角色放行对应 TCP 端口：
  ```bash
  # 示例：Machine 2 (beta) 使用 ufw 放行来自局域网网段 192.168.1.0/24 的端口
  sudo ufw allow from 192.168.1.0/24 to any port 31094,31491,31492,31441,31442,31443 proto tcp
  ```

### 2.4 Windows 10 / 11（Docker Desktop + WSL2 后端）
- 安装 Docker Desktop 并启用 **Use the WSL 2 based engine**，在 WSL2 Ubuntu 发行版终端内执行本仓库脚本；
- 获取 Windows 宿主机局域网网卡 IPv4（在 PowerShell 中执行 `Get-NetIPAddress -AddressFamily IPv4` 查看物理无线/有线网卡地址，切勿使用 `172.x.x.x` WSL 内部虚拟网卡地址）；
- 在管理员权限 PowerShell 中按机器角色放行 Windows Defender 防火墙入站 TCP 规则：
  ```powershell
  # Machine 1 (alpha,audit)
  New-NetFirewallRule -DisplayName "LCT-Alpha-Audit" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 30094,30491,30492,30441,30990,30893 -Profile Private,Domain

  # Machine 2 (beta)
  New-NetFirewallRule -DisplayName "LCT-Beta" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 31094,31491,31492,31441-31443 -Profile Private,Domain

  # Machine 3 (pay)
  New-NetFirewallRule -DisplayName "LCT-Pay" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 32094,32491,32492,32441-32443 -Profile Private,Domain
  ```
- 说明：Docker Desktop 默认将 `0.0.0.0` 发布的容器端口绑定至 Windows 宿主网卡；若旧版 WSL2 未自动转发宿主机物理网卡流量，可在管理员 PowerShell 中对上述端口配置 `netsh interface portproxy add v4tov4` 指向 `127.0.0.1`（或启用 WSL2 `networkingMode=mirrored`）。

### 2.5 本地与跨机共享 LLM（Ollama `qwen2.5:3b`）说明
- **默认推荐模式（每机独立本地回环 Ollama）**：在运行 `alpha`、`beta`、`pay` 的机器上启动默认监听 `127.0.0.1:11434` 的 `ollama serve`，并执行 `ollama pull qwen2.5:3b`。容器内默认通过 `http://host.docker.internal:11434/v1` 访问本机 Ollama（Linux 下 Kind 节点同样自动注入网关映射；仅运行 `audit` 角色的机器无需启动 Ollama）。
- **跨机共享 Ollama 模式（可选 `--llm-url`）**：若算力受限需多机共用一台主机（例如 `192.168.1.6`）上的 Ollama，可在部署时传入 `--llm-url http://192.168.1.6:11434/v1`。
- **安全注意事项**：Ollama 原生 HTTP 接口不包含客户端身份认证。若在共享主机上设置 `OLLAMA_HOST=0.0.0.0:11434`，必须通过宿主机防火墙将 `11434/tcp` 的源地址严格限制为其余两台实验主机的单播 IP，严禁在公共或不可信网段无限制暴露 `0.0.0.0:11434`；推荐默认保持回环监听。

---

## 3. 网络互联要求与系统时钟同步（NTP）

### 3.1 支持的网络环境
1. **无客户端隔离的同一局域网（有线交换机或家用/实验路由器）**：确认路由器已关闭「AP 隔离 / 客户端隔离（Client Isolation）」，三台主机互相可连通对应角色 TCP 端口；
2. **手机热点局域网**：三台主机连接同一手机热点（注意部分系统热点默认开启客户端隔离，部署前用 `preflight.sh` 验证端口连通性）；
3. **Tailscale / WireGuard 组建的虚拟局域网**：校园网或企业 Wi-Fi 开启客户端隔离时，可在三台机器安装 Tailscale 登录同一账号，直接使用分配的 `100.x.y.z` IPv4 地址作为 `--alpha-ip`、`--beta-ip`、`--pay-ip` 参数。

### 3.2 系统时钟同步门禁
LCT 的 RFC 9449 DPoP 证明、CA Proof-of-Possession（PoP）与跨组织撤销指令均强制执行约 `30s` 的时间戳新鲜度窗口。`preflight.sh` 会自动读取对端节点 HTTP `Date` 响应头计算时钟偏差：
- 偏差 `<= 10s`：正常通过（`OK`）；
- `10s < 偏差 <= 25s`：输出告警（`WARN`），提示尽快校时；
- `偏差 > 25s`：直接阻断退出（`FAIL`）。

各系统校时命令：
- **macOS**：`sudo sntp -sS time.apple.com`
- **Linux**：`sudo chronyc makestep` 或 `sudo timedatectl set-ntp true`
- **Windows（管理员 PowerShell）**：`Start-Service w32time; w32tm /resync /force`

---

## 4. 密钥托管模型与跨机信任锚（Trust Anchor）安全机制

1. **部署期内持久化的单域根 CA 密钥**：
   `deploy-role.sh` 在宿主机内存中为本机所属信任域生成独立的 ES256 JWK 根密钥与带 `NameConstraints` 的 X.509 v3 根证书，通过标准输入管道直接写入对应集群的 Kubernetes `Secret`（`<domain>-ca-keys`），宿主机文件系统与日志文件零私钥写入。该 `Secret` 仅以 `defaultMode: 0440` 配合 `fsGroup: 2000`（`readOnly: true`）挂载至本域唯一所属的 CA Pod，集群内配置零 RBAC `secrets` 读取权限，任何业务 Pod、目录服务、撤销服务或网关 Pod 均无权访问。CA Pod 重启后保持相同根公钥与信任锚，不会中断已建立的跨机联邦关系。
2. **工作负载短期身份与 50% 生命周期自动续期**：
   每个业务 Sidecar 与控制面工作负载仍在各自容器内存（RAM）中独立生成私钥，并通过 Kubernetes 投射 ServiceAccount 令牌与 PoP 向本域 CA 申请 `JWT-SVID` 与 `X.509-SVID`（默认有效期 `1800s`）。后台 `WorkloadIdentityRenewer` 在剩余有效期降至 `50%` 时自动重读 Kubelet 轮换后的投射令牌、完成重新签发、原子热替换客户端与服务端 TLS 1.3 `SSLContext`，并在到期前以单调递增版本号重新注册签名 `AgentCard`。
3. **无签名密钥（Keyless）TLS 1.3 审计收集器**：
   `lctmh-audit` 集群内的最小化 `audit-ca`（仅持有 `org-audit.io` X.509 根证书，不含任何 ES256 JWK 签名密钥）为 `audit-collector` 签发服务端 TLS 证书。`audit-collector` 自身容器内存生成 TLS 私钥，持有零域 CA 私钥且挂载零 Kubernetes ServiceAccount 令牌；所有 Sidecar 与域 CA 通过经信任锚校验的 TLS 1.3 连接推送逐条带 ES256 签名的审计记录。
4. **SSH 风格信任锚固定与热加载**：
   每台主机部署完成后输出单行信任锚：
   `<trust_domain> sha256:<64位X509根SPKI哈希>:<64位JWKS公钥集哈希|keyless>`。
   运维人员通过带外渠道（如即时通讯软件或终端核对）确认指纹一致后，执行 `trust add` 写入本机命名空间的 `ConfigMap` (`lct-trust-anchors`)。`FederationBundleSyncer` 在导入任何远端公钥前强制比对固定指纹；若未配置指纹或指纹不匹配则立即拒绝导入（Fail-Closed），更新 `ConfigMap` 后所有工作负载在无需重启容器的情况下自动完成客户端与服务端双向 TLS 信任库热加载。

---

## 5. 三机标准部署与交互操作流程

假设三台机器在局域网内的 IPv4 地址分别为：
- Machine 1 (`alpha,audit`)：`192.168.1.11`
- Machine 2 (`beta`)：`192.168.1.12`
- Machine 3 (`pay`)：`192.168.1.13`

三台机器**无启动先后顺序限制**（任意机器先启动时，工作负载保持存活 `Running` 且零重启，待对端上线并完成信任锚固定后自动转为 `Ready`）。

### 步骤 1：在三台机器分别执行前置检查（Preflight）

```bash
# Machine 1
bash lineage/scripts/multihost.sh preflight \
  --roles alpha,audit \
  --alpha-ip 192.168.1.11 --beta-ip 192.168.1.12 --pay-ip 192.168.1.13

# Machine 2
bash lineage/scripts/multihost.sh preflight \
  --roles beta \
  --alpha-ip 192.168.1.11 --beta-ip 192.168.1.12 --pay-ip 192.168.1.13

# Machine 3
bash lineage/scripts/multihost.sh preflight \
  --roles pay \
  --alpha-ip 192.168.1.11 --beta-ip 192.168.1.12 --pay-ip 192.168.1.13
```

### 步骤 2：在三台机器分别部署本机角色并记录输出的信任锚

```bash
# Machine 1（输出 org-alpha.io 与 org-audit.io 两行信任锚）
bash lineage/scripts/multihost.sh deploy \
  --roles alpha,audit \
  --alpha-ip 192.168.1.11 --beta-ip 192.168.1.12 --pay-ip 192.168.1.13

# Machine 2（输出 org-beta.io 信任锚）
bash lineage/scripts/multihost.sh deploy \
  --roles beta \
  --alpha-ip 192.168.1.11 --beta-ip 192.168.1.12 --pay-ip 192.168.1.13

# Machine 3（输出 org-payment.io 信任锚）
bash lineage/scripts/multihost.sh deploy \
  --roles pay \
  --alpha-ip 192.168.1.11 --beta-ip 192.168.1.12 --pay-ip 192.168.1.13
```

> 若所在网络访问 Docker Hub 受限，可在执行 `deploy` 前通过环境变量指定本地缓存或国内镜像源：
> `KIND_NODE_IMAGE=docker.m.daocloud.io/kindest/node:v1.32.2 BASE_IMAGE=python:3.12-slim bash lineage/scripts/multihost.sh deploy ...`

### 步骤 3：跨机交换并固定信任锚（Trust Pinning）

推荐方式 A（严格带外复制粘贴 `trust add`）：将各机器步骤 2 终端打印的 `sha256:...` 字符串在对端机器执行固定：

```bash
# 在 Machine 1 上固定 Machine 2 与 Machine 3 的信任锚（本机 alpha 与 audit 已自动互信）
bash lineage/scripts/multihost.sh trust add org-beta.io    sha256:<BETA_SPKI_HEX>:<BETA_JWKS_HEX>
bash lineage/scripts/multihost.sh trust add org-payment.io sha256:<PAY_SPKI_HEX>:<PAY_JWKS_HEX>

# 在 Machine 2 上固定 alpha、pay、audit 的信任锚
bash lineage/scripts/multihost.sh trust add org-alpha.io   sha256:<ALPHA_SPKI_HEX>:<ALPHA_JWKS_HEX>
bash lineage/scripts/multihost.sh trust add org-payment.io sha256:<PAY_SPKI_HEX>:<PAY_JWKS_HEX>
bash lineage/scripts/multihost.sh trust add org-audit.io   sha256:<AUDIT_SPKI_HEX>:keyless

# 在 Machine 3 上固定 alpha、beta、audit 的信任锚
bash lineage/scripts/multihost.sh trust add org-alpha.io   sha256:<ALPHA_SPKI_HEX>:<ALPHA_JWKS_HEX>
bash lineage/scripts/multihost.sh trust add org-beta.io    sha256:<BETA_SPKI_HEX>:<BETA_JWKS_HEX>
bash lineage/scripts/multihost.sh trust add org-audit.io   sha256:<AUDIT_SPKI_HEX>:keyless
```

可选方式 B（使用对端运维人员提供的预期摘要执行带校验拉取 `trust fetch --expect`）：

```bash
bash lineage/scripts/multihost.sh trust fetch \
  --domain org-beta.io \
  --ip 192.168.1.12 \
  --expect sha256:<BETA_SPKI_HEX>:<BETA_JWKS_HEX>
```

> 安全说明：`trust fetch --expect sha256:...` 会通过常量时间摘要比对（`hmac.compare_digest`）核验远端返回的候选公钥束，摘要不一致时立即非零退出且绝不写入 `ConfigMap`。请勿在不可信局域网中使用不带 `--expect` 的 `--yes`（会触发 `[SECURITY WARNING: UNVERIFIED TOFU]` 告警）。

固定完成后数秒内，三台机器上的全部 Deployment 自动热加载并通过就绪探针（`1/1` 或 `2/2 Running`）。可通过 `trust show` 查看当前已固定的锚点表。

### 步骤 4：在 Machine 1 上使用跨机交互 CLI 验证业务链路

```bash
# 1. 查看全域健康状态、CoreDNS 解析出的物理机 IP 及已同步的跨机签名 AgentCard
bash lineage/scripts/multihost.sh status

# 2. 发起真实跨三机 A2A v1.0 流式调用（Alpha -> Beta -> Pay），打印逐跳 SPIFFE ID、证书签发域、解析 IP、TLS 1.3 密码套件与授权决策
bash lineage/scripts/multihost.sh send \
  --text "Book business travel to Tokyo for Alice with flight budget up to 650 USD and hotel budget up to 420 USD." \
  --stream

# 3. 验证 A2A v1.0 CancelTask 跨三机级联前缀撤销与对端同步状态
bash lineage/scripts/multihost.sh cancel task-demo-cancel-01 --stage-first

# 4. 从 TLS 1.3 审计中心拉取签名日志并执行 CausalChainAuditor 完整因果树重建
bash lineage/scripts/multihost.sh audit <task_id>

# 5. 运行全套跨机端到端验收套件（场景 1, 2A, 2B, 3A, 3B, 4, 5, 6）
#    当 beta 位于远端 Machine 2 时，脚本会在场景 2B / 3B / 6 自动暂停并打印需在 Machine 2 执行的精确 fault 命令，检测到网络状态变化后自动继续
bash lineage/scripts/multihost.sh e2e
```

---

## 6. 故障注入演示、DHCP IP 变更更新与安全清理

### 6.1 跨机故障注入与恢复（在目标角色所在物理机执行）

```bash
# 在 Machine 2 (beta) 终止主酒店 Agent Pod（触发向下原子剪枝与替补重派 / 向上越级安全汇报）
bash lineage/scripts/multihost fault --kill hotel-primary

# 在 Machine 2 (beta) 恢复主酒店 Agent Pod
bash lineage/scripts/multihost fault --restore hotel-primary

# 在 Machine 2 (beta) 阻断整机跨集群流量（演示场景 6 高风险操作 503 Fail-Closed 与其余主机自治存活）
bash lineage/scripts/multihost fault --partition --role beta

# 在 Machine 2 (beta) 恢复跨集群网络通信
bash lineage/scripts/multihost fault --heal --role beta
```

### 6.2 局域网 DHCP 地址变化后的免重装热更新（`update-peer-ips`）
若某台机器因路由器租约刷新改变了局域网 IP（例如 Machine 2 变为 `192.168.1.88`），无需重建集群或重新签发证书，只需在每台机器上执行：

```bash
bash lineage/scripts/multihost.sh update-peer-ips \
  --alpha-ip 192.168.1.11 --beta-ip 192.168.1.88 --pay-ip 192.168.1.13
```

该命令仅原地更新各集群 CoreDNS `hosts` 映射并滚动重启 CoreDNS，所有 LCT CA 与业务工作负载保持零重启继续运行。

### 6.3 安全清理（`teardown.sh`）
在每台参与实验的机器上执行以下命令，仅删除本机 `lctmh-*` 集群，不会触碰任何其他 Docker 容器或既有实验集群：

```bash
bash lineage/scripts/multihost.sh teardown
```

---

## 7. 常见故障排查对照表

| 故障现象 | 根因定位方法 | 标准解决措施 |
| :--- | :--- | :--- |
| 对端端口连接超时（`ConnectTimeout` / `preflight` 提示对端不可达） | 在源机器执行 `nc -vz <对端IP> 31094`，同时在目标机器确认 `docker ps` 显示 `0.0.0.0:31094->31094/tcp` | 检查目标机器操作系统防火墙（Windows Defender `New-NetFirewallRule`、Linux `ufw`/`firewalld`、macOS 防火墙）是否放行对应角色 TCP 端口段 |
| 同一 Wi-Fi 下宿主机之间 `ping` 与 TCP 端口全部超时，但各自本机 `curl` 正常 | 无线路由器或校园网/热点启用了 **AP 客户端隔离（Client Isolation）** | 关闭路由器「AP 隔离」选项，或在三台机器安装 Tailscale 改用 `100.x.y.z` 虚拟网段 IP 执行 `update-peer-ips` |
| `preflight` 报错 `Clock skew EXCEEDS 25s` 或运行中报 `DPoP proof expired / stale_pop_jws` | 两台物理机系统 UTC 时钟偏差超过 `25s`–`30s` | 在偏差主机执行 NTP 强制同步（macOS: `sudo sntp -sS time.apple.com`；Linux: `sudo chronyc makestep`；Windows: `w32tm /resync /force`） |
| Pod 保持 `Running` 但未进入 `Ready`（`0/1` 或 `1/2`），`/readyz` 返回 `503` 且含 `TRUST ANCHOR PIN MISMATCH` 或 `Missing required trust anchor` | 本机 `lct-trust-anchors` 未录入对端锚点，或远端集群曾使用 `--regenerate-ca` 重新生成了根密钥 | 带外核对远端 `deploy` 输出的真实指纹后，在本机重新执行 `bash lineage/scripts/multihost.sh trust add <domain> sha256:...`（约 2 秒内自动热加载恢复 `Ready`） |
| `deploy` 阶段拉取 `kindest/node` 或 `python:3.12-slim` 超时 | 当前网络环境访问 Docker Hub / GHCR 受限 | 通过环境变量覆盖为可用镜像源或离线导入镜像：`KIND_NODE_IMAGE=<镜像源>/kindest/node:v1.32.2 BASE_IMAGE=<镜像源>/python:3.12-slim bash lineage/scripts/multihost.sh deploy ...` |
