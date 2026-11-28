# LCT 四机物理互联部署与运维指南（Identity-Addressed Multi-Host Federation）

本文档说明如何在 **4 台独立物理主机 `1:1` 架构**（或任意角色组合 / 单机多集群演练环境）上部署、配置、验证、迁移与排障 **Lineage Capability Tree (LCT)** 跨组织联邦系统。

自 Milestone 7 起，系统全面采用**身份与位置密码学分离（Identifier / Locator Separation）**：
- **身份（SPIFFE ID + 固定的域根公钥 SHA-256 锚点）** 是唯一寻址目标；
- **`IP:port` 位置指示器（Locator）** 由每台机器上的宿主守护进程 `locator-agent.py` 自动侦测本机物理局域网网卡 IPv4（RFC1918），并由各域 CA 与工作负载实时自签名发布，通过不可信引导种子（`--seed`）与传递式 Gossip 自动收敛；
- **零静态对端配置**：部署命令、容器环境变量、Kubernetes 清单与 CoreDNS 中均**不再填写任何对端机器 IP、固定全局端口表或跨集群 `hosts` 映射**。DHCP 地址变化与角色跨机迁移均零重启自动收敛。

---

## 1. 四机 `1:1` 物理拓扑、子网隔离与按机动态端口分配

每台物理机运行自身承担角色对应的独立 Kind 集群（集群名前缀统一为 `lctmh-`），通过 Kind `extraPortMappings`（`listenAddress: 0.0.0.0`，`containerPort == hostPort == NodePort`）暴露本机跨组织通信端口：

| 物理节点 | 部署角色（Kind 集群） | 自治信任域 | 集群内隔离 Pod / Service CIDR | 本机动态分配的服务槽位（Slots） | 传输层安全要求 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Machine 1** | `alpha` (`lctmh-alpha`) | `org-alpha.io` | `10.241.0.0/16` / `10.97.0.0/16` | `ca_federation`、`directory_federation`、`revocation_federation`、`orchestrator-alpha`、`e2e_sync_hook` | `ca_federation`：只读 HTTP 公钥束与签名描述符广播（客户端强制校验 SHA-256 信任锚与域根 JWS）<br>其余联邦与 A2A 入口：双向 mTLS 1.3 + `expected_spiffe_id` 精确钉扎<br>`e2e_sync_hook`：平时无 Service/监听，仅在 `e2e` 场景 3B 期间临时创建 `Service/e2e-user-gateway-sync` 并校验随机 `X-LCT-Sync-Token`，结束后立即删除 |
| **Machine 2** | `beta` (`lctmh-beta`) | `org-beta.io` | `10.242.0.0/16` / `10.98.0.0/16` | `ca_federation`、`directory_federation`、`revocation_federation`、`flight-specialist`、`hotel-specialist-primary`、`hotel-specialist-backup` | `ca_federation` 只读 HTTP + 双向 mTLS 1.3 控制面与 A2A 业务端口 |
| **Machine 3** | `pay` (`lctmh-pay`) | `org-payment.io` | `10.243.0.0/16` / `10.99.0.0/16` | `ca_federation`、`directory_federation`、`revocation_federation`、`settlement-converger`、`travel-ops-mcp`、`payment-vault-mcp` | `ca_federation` 只读 HTTP + 双向 mTLS 1.3 控制面、A2A 汇聚器与签名 MCP 工具服务（通过 `skill://mcp.travel-ops`、`skill://mcp.payment-vault` 按身份发现） |
| **Machine 4** | `audit` (`lctmh-audit`) | `org-audit.io` | `10.244.0.0/16` / `10.100.0.0/16` | `ca_federation`、`audit_collector` | `ca_federation`：只读 HTTP 发布 `audit-ca` X.509 根签名描述符<br>`audit_collector`：无签名密钥（Keyless）TLS 1.3 服务端认证（固定 `spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector`） |

**端口与平台边界说明**：
1. **无全局固定端口约定**：端口号完全是每台机器的本地部署决策（`preflight.sh` 与 `deploy-role.sh` 会自动检测本机已被占用的 TCP 端口并在 `30000–32767` 范围内选择空闲端口，也可通过 `--base-port <N>` 或 `--port-override <slot=port>` 显式指定），最终端口通过签名描述符与签名 `AgentCard` 动态通告给对端。
2. **Kind `extraPortMappings` 平台约束**：Docker / Kind 容器的宿主机端口映射在 `kind create cluster` 创建集群容器时一次性固定；若后续希望更改某角色的宿主机端口号，需对该角色执行 `teardown` 后以新端口重新 `deploy`（对端将通过新签名位置指示器自动收敛）。
3. **内部管理接口零暴露**：集群内部身份签发（`:8090`）、本地目录注册（`:8091`）、本地撤销写入（`:8092`）、Sidecar 回环代理（`127.0.0.1:8081`）与业务容器回环（`127.0.0.1:9001`）始终保持 `ClusterIP` 或 Pod 本地回环，绝不映射至宿主机网卡。

---

## 2. 各操作系统前置准备与实战注意事项

### 2.1 通用软件依赖
在每台参与部署的机器上克隆仓库并执行依赖初始化脚本：

```bash
bash lineage/scripts/setup_deps.sh --lang python --install-k8s-tools
```

运行时要求：Docker 正常启动（建议单角色至少 `4 CPU`、`6 GB RAM`）、Python `>= 3.11`（含 `cryptography`、`httpx`、`PyYAML`）、`kind` 与 `kubectl` 在 `PATH` 中可执行。运行 `alpha`、`beta`、`pay` 的机器需启动本地 `ollama serve` 并完成 `ollama pull qwen2.5:3b`（仅运行 `audit` 的 Machine 4 无需安装或启动 Ollama）。

### 2.2 Windows 10 / 11（Docker Desktop + WSL2）实战要点
1. **防火墙规则必须指定 `-Profile Any`**：
   校园网或公共无线网在 Windows 中通常被归类为 **`Public`（公用网络）**，若仅放行 `Private,Domain` 会导致入站包被静默丢弃。请在**管理员权限 PowerShell** 中放行 LCT NodePort 范围（或 `preflight` 输出的具体端口）：
   ```powershell
   New-NetFirewallRule -DisplayName "LCT-Federation-NodePorts" `
     -Direction Inbound -Action Allow -Protocol TCP `
     -LocalPort 30000-32767 -Profile Any
   ```
2. **多网卡环境（VMware / Hyper-V / VPN 虚拟网卡）**：
   `locator-agent.py` 在 WSL2 内会自动调用 Windows 宿主侧 `powershell.exe` / `ipconfig.exe` 提取物理无线/有线网卡的局域网 IPv4（自动过滤 WSL2 内部 `172.x` NAT 网卡及 `VMware Network Adapter VMnet1/VMnet8` `192.168.x.1` 虚拟网卡）。若宿主机同时连接了多个物理网段，可通过 `--advertise-ip <校园网/局域网IPv4>` 显式指定通告地址：
   ```bash
   # 部署前可随时预览本机自动识别出的局域网 IP：
   bash lineage/scripts/multihost.sh locator-agent --detect-only
   ```
3. **部署前关闭临时测口监听进程**：
   若此前使用 `nc -l`、`python -m http.server` 或 PowerShell 测试过端口连通性，务必在执行 `deploy` 前关闭该临时监听进程，避免占用目标端口。
4. **关闭代理 / 游戏加速器软件（如 QuickQ、全局 TUN 代理）**：
   系统代理或虚拟网卡加速器可能劫持局域网直连路由（如 `10.29.0.0/16`、`192.168.0.0/16`）。请退出此类加速器，或确认局域网子网走物理网卡直连路由。
5. **WSL2 后台 `locator-agent` 生命周期维护**：
   `deploy` 会自动在 WSL2 后台启动 `locator-agent.py` 守护进程（支持英文与简体中文 Windows `powershell.exe` UTF-8 / `ipconfig.exe /all` GBK 双编码自动解析）。实验期间请保持至少一个 WSL2 终端或 Docker Desktop WSL 集成处于活跃状态（避免 Windows 因空闲自动休眠关闭整个 WSL2 虚拟机）；若曾手动执行 `wsl --shutdown` 或重启了 WSL2，只需重新拉起守护进程即可恢复实时网卡监听：
   ```bash
   # 检查守护进程是否存活，或在 WSL2 重启后一键恢复：
   pgrep -fl locator_agent || bash lineage/scripts/multihost.sh locator-agent --daemon
   ```

### 2.3 macOS 与 Linux
- **macOS（Docker Desktop）**：确认系统设置「网络 -> 防火墙」未阻断 Docker 入站连接；`locator-agent.py` 自动从默认路由物理接口（如 `en0`）读取局域网 IPv4。
- **Linux（Docker Engine）**：若启用 `ufw` 或 `firewalld`，放行来自实验局域网子网的 NodePort 范围：
  ```bash
  sudo ufw allow from 10.29.0.0/16 to any port 30000:32767 proto tcp
  ```

### 2.4 局域网互通与 NTP 时钟同步要求
1. **局域网二层/三层互通（校园网 AP 隔离处理）**：
   4 台机器需处于可互相直连 TCP 端口的 RFC1918 私网（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）。若校园无线网开启了无线客户端隔离（AP Isolation，表现为同网段主机互相无法建立 TCP 连接），请将 4 台机器接入**同一台未开启客户端隔离的路由器 / 有线交换机**，或连接**同一部手机共享热点**。
   > 注：无线局域网首次跨机通信触发 ARP 解析时，偶发首包短暂返回 `No route to host` 或 `ConnectTimeout` 属正常二层现象，等待 1–2 秒重试即可，LCT 后台同步器亦会自动重试。
2. **系统时钟同步门禁（`<= 25s`）**：
   RFC 9449 DPoP 证明与 CA PoP 强制执行约 `30s` 新鲜度窗口。`preflight` 会通过种子节点的 HTTP `Date` 响应头检测时钟偏差（`> 10s` 告警，`> 25s` 阻断）：
   - **macOS**：`sudo sntp -sS time.apple.com`
   - **Linux**：`sudo chronyc makestep`
   - **Windows（管理员 PowerShell）**：`Start-Service w32time; w32tm /resync /force`

---

## 3. 密钥托管边界与描述符信任链

1. **部署期内持久化的单域根 CA 密钥**：
   `deploy` 在内存中生成本域 ES256 JWK 根密钥与带 `NameConstraints(critical=True)` 的 X.509 v3 根证书，通过标准输入流直接写入本集群 Kubernetes `Secret`（宿主机磁盘与日志零私钥落盘）。该 `Secret` 仅以 `defaultMode: 0440` 配合 `fsGroup: 2000`（`readOnly: true`）挂载至本域唯一所属的 CA Pod，命名空间内零 `secrets` 读取 RBAC。
2. **SSH 风格信任锚校验 → 域根签名描述符 → SPIFFE 钉扎 TLS 1.3**：
   种子地址 `--seed <ip:port>` 仅被视为**不可信传输提示**。节点从种子或对端拉取 `SignedDomainDescriptor` 后，必须先通过本地 `ConfigMap/lct-trust-anchors` 中固定的 `sha256:<x509-spki-hex>:<jwks-set-hex|keyless>` 常量时间比对，再用该已钉扎公钥束中的域根公钥验证描述符 JWS 签名与单调版本号，随后才接纳其中的动态 `ip:port` 位置；发起实际 TLS 1.3 连接时，全程强制校验证书链与精确 `expected_spiffe_id` URI SAN（绝不发送 IP 字面量 SNI）。

---

## 4. 四机 `1:1` 标准部署与交互流程（零静态对端 IP）

4 台机器**无启动先后顺序限制**。以下以四机 `1:1` 角色布局为例（例如处于 `10.29.0.0/16` DHCP 校园网段）：
- **Machine 1**：`alpha`（`org-alpha.io`）
- **Machine 2**：`beta`（`org-beta.io`）
- **Machine 3**：`pay`（`org-payment.io`）
- **Machine 4**：`audit`（`org-audit.io`）

### 步骤 1：在四台机器分别执行前置检查（Preflight）

```bash
# Machine 1 (alpha)
bash lineage/scripts/multihost.sh preflight --roles alpha

# Machine 2 (beta) — 多网卡 Windows 主机可加 --advertise-ip <本机局域网IP>
bash lineage/scripts/multihost.sh preflight --roles beta

# Machine 3 (pay)
bash lineage/scripts/multihost.sh preflight --roles pay

# Machine 4 (audit) — 无需本地 Ollama
bash lineage/scripts/multihost.sh preflight --roles audit
```

### 步骤 2：部署各机角色（仅需传入任意一个对端 `--seed`）

先启动任意一台机器（例如 Machine 1），终端末尾会打印本机自动识别出的**可共享种子地址**（如 `--seed 10.29.77.23:30100`）以及本域**信任锚指纹行**。其余三台机器部署时仅需附带该 `--seed`（甚至链式指向任意已启动对端，Gossip 会自动传递全网描述符）：

```bash
# 1. Machine 1 (alpha)：首个节点无需 --seed（自动启动后台 locator-agent）
bash lineage/scripts/multihost.sh deploy --roles alpha

# 假设 Machine 1 输出了种子：--seed 10.29.77.23:30100
# 2. Machine 2 (beta)：仅需提供 1 个种子（多网卡机器可加 --advertise-ip 10.29.101.203）
bash lineage/scripts/multihost.sh deploy --roles beta --seed 10.29.77.23:30100

# 3. Machine 3 (pay)：仅需提供 1 个种子（指向 Machine 1 或 Machine 2 均可）
bash lineage/scripts/multihost.sh deploy --roles pay --seed 10.29.77.23:30100

# 4. Machine 4 (audit)：仅需提供 1 个种子
bash lineage/scripts/multihost.sh deploy --roles audit --seed 10.29.77.23:30100
```

> - `beta`、`pay`、`audit` 在完成信任锚钉扎后，会自动通过有界 `POST /v1/federation/descriptors` 向 Machine 1 (`alpha`) 宣告自身签名描述符，并由 Machine 1 的 Gossip 视图自动向全网分发，因此 Machine 1 无需添加反向 `--seed` 即可完成四机全互通收敛。
> - 若四台机器均以无种子方式独立启动，也可随时在任意节点执行 `bash lineage/scripts/multihost.sh seeds add <任一对端IP:ca_port>`；在未开启组播隔离的同一二层交换机局域网内，还可在 `deploy` 时附加可选参数 `--discover mdns`（启用 `_lct._tcp.local.` 自动发现不可信候选种子）。

### 步骤 3：汇总四行信任锚并通过 `trust import` 批量确认钉扎

将四台机器 `deploy` 输出的 4 行信任锚汇总保存为文本文件 `anchors.txt`（每行格式 `<domain> sha256:...`）：

```text
org-alpha.io sha256:<ALPHA_SPKI_HEX>:<ALPHA_JWKS_HEX>
org-beta.io sha256:<BETA_SPKI_HEX>:<BETA_JWKS_HEX>
org-payment.io sha256:<PAY_SPKI_HEX>:<PAY_JWKS_HEX>
org-audit.io sha256:<AUDIT_SPKI_HEX>:keyless
```

在**全部 4 台机器**上执行同一条导入命令（CLI 会逐行展示全部指纹、自动核对本机所属域指纹一致性、并在交互确认后将其他 3 个域的锚点热写入本集群 `ConfigMap/lct-trust-anchors`）：

```bash
bash lineage/scripts/multihost.sh trust import anchors.txt
```

（也可使用单条命令逐个钉扎：`bash lineage/scripts/multihost.sh trust add <domain> sha256:...`。）

钉扎完成后约 2–5 秒内，4 台机器通过种子与 Gossip 自动验证全网描述符与签名 `AgentCard`（含 MCP 工具卡片），所有 Pod 自动变为 `Ready`（`1/1` 或 `2/2 Running`），并将已验证描述符持久化至 `ConfigMap/lct-learned-descriptors`（后续即使重启也无需再次输入种子）。

### 步骤 4：查看动态寻址状态并发起跨四机业务调用

```bash
# 1. 在任意机器查看本机通告 IP/端口、已学习的签名域描述符版本/剩余 TTL 与工作负载卡片位置
bash lineage/scripts/multihost.sh locator show

# 2. 在 Machine 1 查看逐跳「SPIFFE 身份 -> 动态 IP:port」解析表与实时 TLS 1.3 握手遥测
bash lineage/scripts/multihost.sh status

# 3. 发起跨机 A2A v1.0 实时 SSE 流式委托调用（Alpha -> Beta -> Pay -> Audit），输出逐跳身份->位置解析轨迹
bash lineage/scripts/multihost.sh send \
  --text "Book business travel to Tokyo for Alice with flight budget up to 650 USD and hotel budget up to 420 USD." \
  --stream

# 4. 验证 A2A v1.0 CancelTask 跨机级联撤销同步
bash lineage/scripts/multihost.sh cancel task-demo-cancel-01 --stage-first

# 5. 从 Machine 4 (audit) 拉取签名审计链并执行 CausalChainAuditor 100% 因果树重建
bash lineage/scripts/multihost.sh audit

# 6. 运行完整 8 场景跨机验收套件（1, 2A, 2B, 3A, 3B, 4, 5, 6）
bash lineage/scripts/multihost.sh e2e
```

---

## 5. DHCP 地址自动切换、角色在线迁移与安全清理

### 5.1 局域网 DHCP 地址变化（全自动、零人工干预、零 Pod 重启）
当某台物理机（例如 Machine 2 `beta`）因 DHCP 租约更新变更了局域网 IP 时：
1. 该机器后台运行的 `locator-agent.py` 在 2 秒内自动侦测到新物理网卡 IPv4 并更新 `ConfigMap/lct-node-locator`；
2. 该集群内的 `beta-ca` 与全部 Sidecar 监听到文件更新后，在内存中以单调递增 `version + 1` 重新签发 `SignedDomainDescriptor` 与 `AgentCard`（**容器零重启**）；
3. 其余三台机器通过后台联邦同步自动验证新版本签名并切换路由至新 `IP:port`，**对端机器无需执行任何命令**（旧版 `update-peer-ips` 已废弃）。
4. 若在多网卡机器上使用了 `--advertise-ip` 手动覆盖地址，也可随时在线热切换：
   ```bash
   bash lineage/scripts/multihost.sh locator-agent --set-role-ip --role beta --advertise-ip <新局域网IPv4>
   ```

### 5.2 角色跨物理机在线迁移（Role Migration）
若需将某个角色（例如将 `audit` 从旧主机迁移至一台全新的第 4 台主机，或迁移 `beta` 至新主机）：
1. **在新主机部署该角色**：
   ```bash
   bash lineage/scripts/multihost.sh deploy --roles audit --seed <任一存活节点IP:ca_port>
   ```
   在新主机导入其余三个域的锚点（`bash lineage/scripts/multihost.sh trust import anchors.txt`）。
2. **在其余存活主机更新该角色的信任锚（零 `seeds add` 自动收敛）**：
   将新主机 `deploy` 打印的新 `org-audit.io sha256:...` 指纹在其余主机执行覆盖固定（或更新 `anchors.txt` 后重新执行 `trust import`）：
   ```bash
   bash lineage/scripts/multihost.sh trust add org-audit.io sha256:<NEW_AUDIT_SPKI_HEX>:keyless
   ```
   其余主机检测到信任锚更新后立即自动驱逐旧主机公钥；新主机通过其启动时的 `--seed` 主动宣告新签名描述符并通过 Gossip 传播至全网，所有存活节点无需手动修改种子即可自动收敛至新主机签发的位置指示器（零容器重启）。
3. **下线旧主机上的该角色**：
   ```bash
   bash lineage/scripts/multihost.sh teardown --roles audit
   ```

### 5.3 OAuth 2.0 Token Exchange（Keycloak 26.5.2）与 LCT 同机/跨机实证对比（`compare`）
默认部署（`--sts-engine auto --delegation-mode dual`）会在 Machine 1 (`alpha`) 自动拉起真实 **`quay.io/keycloak/keycloak:26.5.2`** Pod（若低内存机器需跳过 JVM，可在 `deploy` 时传 `--sts-engine lightweight`），并在 `beta`、`pay` 启动轻量级联邦 RFC 8693 STS（自动通过 `SignedDomainDescriptor.locators["oauth_sts"]` 签名广播）：

1. **四机独立物理部署时同步 `oauth_centralized` 客户端凭据（仅 `oauth_centralized` 需要；`oauth_federated` 与 `lct` 基于已固定 SPIFFE SVID 零密钥拷贝即可运行）**：
   ```bash
   # 在 Machine 1 (alpha) 导出 0600 凭据文件：
   bash lineage/scripts/multihost.sh oauth export-creds --output oauth-creds.json
   # 将 oauth-creds.json 传至 Machine 2 (beta) 与 Machine 3 (pay) 导入：
   bash lineage/scripts/multihost.sh oauth import-creds oauth-creds.json
   ```
2. **在 Machine 1 一键执行六维实证对比（`oauth_centralized` vs. `oauth_federated` vs. `lct` + Hop-0 Keycloak 桥接）**：
   ```bash
   bash lineage/scripts/multihost.sh compare --output-dir ./compare-results
   ```
   命令会自动输出 Markdown 对比表与脱敏 JSON 指标文件（`m8_protocol_comparison.md` / `.json`）；若 `alpha` 部署在远端机器且无需在对比中途缩放 `alpha-sts` 副本数，可附加 `--skip-sts-partition`。

### 5.4 对称工作助手平台（Platform v2 / v2.1：`--topology workspace` + 12 场景套件 + 去中心化按需审计）
除传统四机订票拓扑外，`deploy` 支持一键切换至 **Platform v2.1 对称个人/组织工作助手拓扑**（仅需 `alpha`、`beta`、`pay` 三个业务信任域，内置 `beta-user-gateway` 对称入口与多组织 OIDC `lct_sub` 映射，**无需部署中心化 `audit` 集群**；所有签名审计链存储在各节点本地 `LocalAuditStore`，由 `DistributedAuditor` 按 `task_id` 经 mTLS 1.3 定向拉取重构）：

```bash
# 1. 部署对称工作助手网络（--registry-mode centralized 使用 alpha 上的不可信公共黄页；也可传 federated）
#    单机三集群预演：
bash lineage/scripts/multihost.sh deploy --roles alpha,beta,pay --topology workspace --registry-mode centralized --wait-all-ready
#    三台独立物理机部署：
#    Machine 1: bash lineage/scripts/multihost.sh deploy --roles alpha --topology workspace --registry-mode centralized
#    Machine 2: bash lineage/scripts/multihost.sh deploy --roles beta  --topology workspace --registry-mode centralized --seed <M1_IP:PORT>
#    Machine 3: bash lineage/scripts/multihost.sh deploy --roles pay   --topology workspace --registry-mode centralized --seed <M1_IP:PORT>

# 2. 执行完整 11 阶段端到端套件（覆盖金融风控、企业法务采购与医疗隐私聚合全部 12 个目录场景；支持 --scenarios 6,7,8,9,10,11 按需筛选）
bash lineage/scripts/multihost.sh workspace-demo --output-dir ./workspace-results

# 3. 无中心收集器按需拉取任意 task_id 的全网签名因果图
bash lineage/scripts/multihost.sh audit <task_id> --distributed

# 4. 运行 4 / 12 / 24 节点规模化延迟、级联撤销与去中心化审计基准测试
bash lineage/scripts/multihost.sh scale-bench --tiers 4,12,24 --output-dir lineage/scale/results

# 5. （可选，Milestone 11）启用真实开源 Node.js Pi 智能体（@mariozechner/pi-agent-core + 本地 qwen2.5:3b / 云端 LLM_BASE_URL）并运行两大异构实证案例
bash lineage/scripts/multihost.sh deploy --roles alpha,beta,pay --topology workspace --registry-mode centralized --with-pi-agent --wait-all-ready
bash lineage/scripts/multihost.sh pi-demo --output-dir ./pi-results
```

### 5.5 安全清理（`teardown.sh`）
在每台参与实验的机器上执行以下命令，仅删除本机 `lctmh-*` 集群并干净停止后台 `locator-agent.py` 守护进程，绝不触碰任何其他 Docker 容器或既有实验环境：

```bash
bash lineage/scripts/multihost.sh teardown
```

---

## 6. 常见故障排查对照表

| 故障现象 | 根因定位方法 | 标准解决措施 |
| :--- | :--- | :--- |
| 对端种子端口连接超时（`ConnectTimeout`） | 在源机器执行 `nc -vz <对端IP> <对端ca_port>`，在目标机器执行 `bash lineage/scripts/multihost.sh locator show` 核对 `shareable_seed_endpoints` | 1. Windows 主机确认防火墙规则使用了 `-Profile Any`；<br>2. 关闭目标机加速软件/全局 TUN 代理（如 QuickQ）；<br>3. 若首次通信报 `No route to host`，等待 1–2 秒待 ARP 解析完成重试 |
| 同一校园 Wi-Fi 下宿主机之间所有 TCP 端口均超时，但本机访问正常 | 校园无线网启用了 **AP 客户端隔离（Client Isolation）** | 将 4 台机器连接至**同一台未开启客户端隔离的路由器 / 有线交换机**，或连接**同一部手机共享热点** |
| Windows 主机 `locator show` 显示通告了 `192.168.x.1`（VMware）而非校园网 `10.29.x.x` | 宿主机存在多张活动网卡且虚拟网卡排在了前面 | 执行 `bash lineage/scripts/multihost.sh locator-agent --set-role-ip --role <role> --advertise-ip <真实局域网IP>` 在线热修正（无需重建集群） |
| `locator show` 中对端域缺失，或 Pod `/readyz` 返回 `503` | 尚未导入对端信任锚，或本机缺少至少一个可达的 `--seed` | 1. 执行 `bash lineage/scripts/multihost.sh trust show` 核对 `pinned_peer_anchors` 是否已包含其余 3 个域；<br>2. 执行 `bash lineage/scripts/multihost.sh seeds list`，若为空则执行 `seeds add <任一对端IP:ca_port>` |
| `preflight` 报错 `Clock skew EXCEEDS 25s` 或运行期报 `DPoP proof expired` | 物理机之间系统 UTC 时钟偏差超过 `25s`–`30s` | 在偏差机器执行 NTP 同步（macOS: `sudo sntp -sS time.apple.com`；Linux: `sudo chronyc makestep`；Windows: `w32tm /resync /force`） |
| 希望修改已创建 `lctmh-*` 集群的宿主机 `NodePort` 端口号 | Kind 容器的 `extraPortMappings` 在创建容器时静态绑定 | 对该角色执行 `teardown --roles <role>` 后使用 `--base-port` 或 `--port-override` 重新 `deploy`（对端将自动学习新端口） |
