# 验收结果

集群 context：`kind-agent-identity-lab`。本轮时间：2026-11-15。令牌、口令和密钥原文没有写入本文件。11 月 13 日的记录保留在文末，不作为本轮结论。

## 2026-11-16 03:43Z 授权链审计基线

记录在 `lab/experiments/03-authorization-chain-audit-baseline/REPORT.md`。规则在同目录 `AUTHZ-RULES.md`。常驻策略和 `two-agent-v1` 没有改，DPoP 入口不在这条基线里。

六次业务调用的 LAB_CORR 标识都能对齐，短路径没有被补出 A。授权链完整重建是 0/6：认证日志没有任务 ID，委托历史没有 `act`。11 条交换记录都不能唯一连到任务。四份证据副本的删除、改父调用、混入和改关联都被发现；改父调用后，下游仍会像一条独立短路径。full-ny 和 short-lon 的工具上游暂时不可用。并发四次的回答跟着所请求的城市，但工具 JSON 行没有任务 ID，不能确定归属。

## 2026-11-15 16:20Z DPoP 发送方绑定

记录在 `lab/experiments/02-sender-binding/REPORT.md`，能力核查在同目录 `CAPABILITY.md`。`two-agent-v1` 和实验一的文件没有改。

当前 AuthBridge v0.7.0-rc.1 不校验 DPoP 或证书指纹。Keycloak 26.5.2 的令牌端点是 HTTP，RFC 8705 无法在签发时看到客户端证书。RFC 9449 可以和现有 JWT-SVID 交换一起用。独立入口 `dpop-guard` 在 `2026-11-15T16:20:18Z` 至 `16:20:36Z` 对 `ny-1`、`lon-1` 两枚新令牌做了对照：持有匹配证明的天气 Agent Pod 完成 `tools/list`；复制令牌的 `rossoctl-backend` 分别因缺少 proof 和 `jkt` 不匹配被拒绝。未绑定但 audience 正确的令牌在 JWT 校验通过后因缺少 `cnf.jkt` 被拒绝。现有工具入口仍接受没有 proof 的绑定令牌。入口和临时凭据已删除。

## 2026-11-15 23:49 连续令牌交换与同一枚 T2

记录在 `lab/experiments/01-token-holder-binding/REPORT.md`，原始脱敏输出在同目录 `run.log`。`two-agent-v1` 快照和访问策略没有改。

`2026-11-15T15:49:13Z` 至 `15:49:21Z` 完成 ny-1、lon-1、ny-2。每次都是 T0，再由 A 换成面向 B 的 T1，再由 B 以该 T1 换成面向工具的 T2。第二次输入指纹等于 T1，三次交换都是 200。ny-2 是 lab-ny 的新令牌，指纹与 ny-1 不同。

同一枚 T2 从 `rossoctl-backend` 和天气 Agent Pod 分别完成 MCP `initialize` 与 `tools/list`，两边都是 HTTP 200。天气 Agent 出站对工具 Pod IP 记录为 passthrough，没有重新交换。缺令牌和原始 T0 仍是 401。

## 2026-11-15 22:08 用户主体与凭据补充

说明在 `lab/baseline/two-agent-v1/ADDENDUM-subject-and-credentials.md`。`SNAPSHOT.md` 没有改写。

受控复现确认：`weather-lab-user` 的 access token 没有 `sub` 这个键。realm 没有 `basic` scope，也没有把用户 ID 写入 `sub` 的 protocol mapper。UserInfo 仍能把这枚令牌对应到 lab-ny 或 lab-lon。用它做 token exchange 后，T1 和 T2 的 `sub` 与 UserInfo 一致，两个用户不会混成同一个主体。AuthBridge 入口的 `subject` 只取已验证 JWT 的 `sub`，所以原始令牌的入站日志主体为空，客户端仍记为 `weather-lab-user`。

凭据准备脚本是 `lab/scripts/prepare-lab-credentials.sh`。它从 Secret `rossoctl-system/lab-user-credentials` 写入容器内文件。`KC_PASSWORD_FILE` 由容器内进程打开，不是 Mac 上的同名路径。删除旧的容器内口令文件后，只用该脚本完成了任务 `51ae6126-62e1-401f-91da-1b02fccc0873`，工具 JSON 为 42.6°F、17.1 km/h、风向 319、代码 0、GMT。

## 2026-11-15 21:55 协调 Agent 重建与直连 B

冻结目录是 `lab/baseline/two-agent-v1/`。`12:11Z` 历史基线没有改写。

协调 Agent 的 Deployment 清单里已经有 `diag-guard`。重建前 UID `d247cb04-0f96-4efe-bc13-a3ff6151b3ff`，删除 Pod 后新 UID `252e4c84-c47b-4144-8784-c4a4a8c505f0`。没有执行补救脚本。init 顺序是 `diag-guard`、`proxy-init`。`/shared/client-id.txt` 仍是协调 Agent 自己的 SPIFFE ID，认证器仍是 `federated-jwt`。`authproxy-routes` 里 A→B 和 B→工具两条路由都在。`weather-lab-user` 仍有协调 Agent 与天气 Agent 的 audience scope，没有工具 audience。

同命名空间 `lab-plain` 和其他命名空间的 backend 连接新 Pod 的 `9091/9093/9094` 都被拒绝。本机 `9091/healthz`、`9093/stats`、`9094/v1/sessions` 为 200。业务代理监听 `8001`，进程监听 `8002`，Service `8080` 指向 `8001`。无令牌访问 Service 得到 jwt-validation 401。直接打到 Pod `8002` 的无令牌请求被 token-exchange 以缺少 Authorization 拒绝，没有完成任务。

重建后的 A→B→工具任务 `5e692fa4-283b-4acc-be24-3845d4072f10` 完成。A 的出站 audience 是天气 Agent，B 的入站客户端是协调 Agent、`subject` 是 lab-ny，B 的出站 audience 是工具。工具 JSON 与回答都是 42.2°F、16.5 km/h、风向 321、代码 0、`timezone=GMT`、时间 `2026-11-15T13:45`。本轮没有改身份、路由或用户上下文，双用户并发仍用上一轮的 `a8cd2ad5-3609-4c4f-8141-6e9fa77b2117` 和 `82b33c6d-3fd2-47fa-8590-6881e1cbaca2`。

新签发的 `lab-ny` 令牌 `azp=weather-lab-user`，audience 含协调 Agent、天气 Agent 和 realm，不含工具，原始令牌没有 `sub`。该令牌直接 `SendMessage` 到 B，任务 `99b1c2be-887c-4362-8012-3de6b2259a15` 完成，B 入站客户端是 `weather-lab-user`，工具收到这个任务 ID，工具入站 `subject` 是 lab-ny、`clientID` 是天气 Agent。同一令牌访问工具是 401。无令牌的 Agent Card 为 200，不作为任务授权。因此 A 是可选协调入口。若要让 A 成为必经入口，需要去掉用户令牌里的天气 Agent audience，并复测直连 B 失败、经 A 仍成功。本轮没有改这条策略。

令牌都是策略变更后新签发的。旧令牌撤销没有测试。交换令牌跨 Pod 重放仍只引用上一阶段 `12:55:15Z` 的结果。

## 2026-11-15 21:32 Pod 重建与双 Agent

`12:11Z` 基线仍在 `lab/baseline/BASELINE.md`。本阶段不改写它。

### 重建后自动恢复

诊断端口配置的生成者是 Rossoctl mutating webhook。它在 Pod 创建时写出 `authbridge-config-<workload>`，内容来自命名空间里的 `authbridge-runtime-config`，再加上 Operator 二进制里固定的 `forward_proxy_addr` 和 `reverse_proxy_addr`。Operator 二进制没有 `health_addr`、`session_api_addr` 或 `id_headers`，所以只改每 Pod 的 ConfigMap 会在下次创建时被盖掉。`9093` 没有单独的监听地址字段；`bind_loopback_only: true` 会把 `8000` 也绑到 localhost。

因此限制放进 Deployment 的 init 容器 `diag-guard`（镜像 `proxy-init:v0.7.0-rc.1`，具备 `NET_ADMIN`）。它在 `proxy-init` 和其他容器之前运行，对 `9091`、`9093`、`9094` 插入 `INPUT` 拒绝规则，接口只对 `lo` 开放。`proxy-init` 改的是 nat 表，不会清掉这条 filter 规则。`8001` 仍由 Deployment 环境变量 `HOST=127.0.0.1` 控制，重建后还在。

| Pod | 重建前 UID | 重建后 UID |
| --- | --- | --- |
| weather-service-advanced | `dcc2264f-261a-4806-91c9-ceb1ed179d44` | `ca44abf9-6649-45b3-a975-ab017f127532` |
| weather-tool-advanced | `38991dba-b834-4bb4-8b06-84a7758be786` | `9f40f85f-407d-48cb-ad63-680290e2a99f` |

重建后没有执行 `isolate-diag-ports.sh`。同命名空间 `lab-plain` 和其他命名空间的 backend 连接工具与 Agent 的 `9091/9093/9094` 都被拒绝。`127.0.0.1:9093/stats` 仍返回 200。`8000` 可连接，无令牌是 401。`8001` 对其他 Pod 拒绝。

Keycloak realm 默认 scope 在重建后仍没有工具 audience。下面的令牌都是策略变更之后新签发的。变更前已经发出的旧令牌没有做撤销测试。

重建后的 `lab-ny` 任务 `638a917f-0417-434c-9c29-3451ebc2a754` 完成。工具 JSON 与回答都是 41.7°F、16.0 km/h、风向 320、代码 0、GMT、`2026-11-15T13:30`。同一轮新令牌直接访问工具仍是 401。缺令牌、坏签名、`exp-iat=5` 的过期令牌、错误 audience 的拒绝文案彼此不同。

回滚 init 容器：从两个 Deployment 删除名为 `diag-guard` 的 initContainer。

### AuthBridge 日志排查结论

运行镜像是 `ghcr.io/rossoctl/cortex/authbridge:v0.7.0-rc.1`，digest `sha256:8ada36b1e8bb24ab178fdc747ee828f9675a67fc829dbdf79bd4f6e04f03b916`。镜像没有 OCI 源码标签。对应标签的上游树在 `github.com/rossoctl/cortex` 的 `v0.7.0-rc.1`。

源码证据：`authbridge/authlib/plugins/tokenexchange/plugin.go` 的 `recordDelegationHop` 把 audience、scope、subject 和 `FromCache` 写入会话里的委托扩展，不写进 `slog` 的交换行。`session/idheader.go` 说明 `id_headers` 是客户端自报的会话分桶键，注释写明它未认证，不能当授权依据。Operator 二进制不含 `id_headers`，因此写在每 Pod ConfigMap 里的这项会在重建时消失。

实测：配置还在时，session API 的 default 桶里没有 A2A 任务 ID。四次并发调用都记下 `outbound token exchanged`，没有出现 `outbound cache hit`。二进制里存在这句文案，说明缓存命中可以记日志，但本轮没有观察到命中。

结论：无法把每一条交换日志逐任务关联。这登记为单跳基线限制。没有为此升级平台，也没有再试没有依据的配置键。

### 双 Agent

协调者是新的 Deployment `weather-coordinator`，ServiceAccount 同名，由 AgentRuntime 登记为 `type: agent`。SPIFFE 客户端是 `spiffe://localtest.me/ns/team1/sa/weather-coordinator`，认证器 `federated-jwt`。Weather Agent 保持为第二跳。`authproxy-routes` 增加了 host `weather-service-advanced`，audience 是天气 Agent 的 SPIFFE ID。`weather-lab-user` 增加了 `agent-team1-weather-coordinator-aud`，没有加回工具 audience。新令牌同时含协调者和天气 Agent 的 audience，不含工具 audience。

单次任务 `945e9912-ac43-4a0b-b293-e0f6a0c389a8`，消息 `coord-ny-msg`：

- 协调者入站 `clientID=weather-lab-user`。
- 协调者出站交换，audience 是天气 Agent SPIFFE ID。
- 天气 Agent 入站 `subject=87d55f09-1648-49af-ab6c-103acd884ae4`，`clientID` 是协调者 SPIFFE ID。
- 天气 Agent 出站交换，audience 是工具 SPIFFE ID。
- 工具入站 `subject` 仍是 lab-ny，`clientID` 是天气 Agent SPIFFE ID，并执行了 `CallToolRequest`。
- 回答与工具 JSON 都是 41.7°F、16.0 km/h、风向 320、代码 0、GMT。

并发：

| 用户 | 消息 | 任务 | 回答 |
| --- | --- | --- | --- |
| lab-ny | `c2-ny-msg` | `a8cd2ad5-3609-4c4f-8141-6e9fa77b2117` | 41.7°F，16.0 km/h，320，代码 0 |
| lab-lon | `c2-lon-msg` | `82b33c6d-3fd2-47fa-8590-6881e1cbaca2` | 49.0°F，6.5 km/h，193，代码 51 |

两个 subject 都出现在天气 Agent 入站，`clientID` 都是协调者；工具侧 `clientID` 都是天气 Agent。工具 JSON 同时有这两组数。交换行本身仍没有任务 ID，所以不能把某一条交换单独指到其中一个用户。没有 `act`。不把这称为完整委托链。

回滚双 Agent：删除 AgentRuntime、Deployment、Service、ServiceAccount 和 `weather-coordinator-script`，并从 `authproxy-routes` 去掉 `weather-service-advanced` 那一条，再从 `weather-lab-user` 去掉协调者 audience scope。

## 2026-11-15 20:48 诊断隔离与用户令牌收紧

`12:11Z` 基线仍在 `lab/baseline/BASELINE.md`，没有改写。本阶段开始时的运行配置是：Ollama 0.40.16、`qwen2.5:3b`、AuthBridge `v0.7.0-rc.1` 镜像 `sha256:8ada36b1e8bb24ab178fdc747ee828f9675a67fc829dbdf79bd4f6e04f03b916`，MCP `HOST=127.0.0.1`，工具结果补丁 `lab/k8s/patch_tool.py`，Agent 补丁 `lab/k8s/patch_agent.py`。运行中的镜像 digest 没有换；补丁在容器启动时写入镜像里的源文件。

### 诊断端口

`bind_loopback_only: true` 会把反向代理 `8000`、转发代理和透明代理一并绑到 `127.0.0.1`，Agent 会变为 NotReady。因此没有使用这个总开关。本版本可以把 `health_addr` 和 `session_api_addr` 单独写成 `127.0.0.1:9091` 和 `127.0.0.1:9094`。统计端口 `9093` 没有独立地址字段，仍监听 `[::]:9093`。

实际隔离：

- `9091`、`9094` 只监听 localhost。同命名空间无 sidecar 的 `lab-plain` 和其他命名空间的 backend 连接都被拒绝。
- `9093` 用 Pod 网络命名空间里的 iptables 拒绝非 `lo` 流量。`lab-plain` 和其他命名空间连接返回拒绝。Pod 内 `127.0.0.1:9093/stats` 仍是 200。
- `8000` 仍对集群开放。无令牌访问是 401 `missing Authorization header`。
- `8001` 仍只在 `127.0.0.1`，其他 Pod 连接被拒绝。

把当前 `/config` 原样 POST 回去得到 200，随后读到的文档长度仍是 1158 字节，并且仍包含 `jwt-validation`。没有提交另一份认证配置。

Kind 的 NetworkPolicy 之前已证明不会生效。Pod 重建会让 webhook 覆盖 ConfigMap，并清掉网络命名空间里的 iptables。重新执行 `lab/scripts/isolate-diag-ports.sh`。回滚是恢复 ConfigMap 里原来的 listener，并删除对应 iptables 规则。

### 用户令牌不再直接访问工具

从 realm 默认 scope，以及 `weather-advanced-e2e`、`weather-lab-user`、`rossoctl` 的默认 scope 中去掉 `agent-team1-weather-tool-advanced-aud`。这三个客户端的 optional scope 里也去掉 `weather-tool-exchange-aud`。Agent SPIFFE 客户端保留该交换 scope。用户访问 Agent 所需的 Agent audience scope 仍在。回滚脚本是 `lab/scripts/rollback-tool-audience.sh`。

`lab-ny` 原始令牌：`azp=weather-lab-user`，`aud` 只有 Agent SPIFFE ID 和 realm issuer，`tool_aud=false`，`exp-iat=1800`。自行请求工具 scope 时 Keycloak 返回 `invalid_scope`。`initialize`、`tools/list`、`tools/call` 都是 401，日志是期望 audience 为工具 SPIFFE ID。没有按 MCP 方法分开的规则。

Agent 用自己的 JWT-SVID 做 token exchange 返回 200。交换结果 `azp` 是 Agent SPIFFE ID，`sub=87d55f09-1648-49af-ab6c-103acd884ae4`，`aud` 含工具 SPIFFE ID，没有 `act`。`weather-lab-user` 自己发起交换返回 403 `Client not allowed to exchange`。

同一枚已交换令牌从 `lab-plain` 重放，`initialize` 200。工具只认令牌，不认网络发送方。这不是 audience 修复能挡住的。版本里没有发送方绑定字段。

### 负向令牌

| 构造 | 结果 |
| --- | --- |
| 不带 Authorization | 401 `missing Authorization header` |
| 签名段中部改一个字符，其余保持为刚交换出的有效令牌 | 401 `could not verify message using any of the signatures or keys` |
| 临时把 `weather-lab-user` 的 access token 寿命设为 5 秒并加上工具 audience，取令牌后立刻去掉该 scope 和寿命，等待 8 秒再提交。令牌 `exp-iat=5` 且当时含工具 audience | 401 `"exp" not satisfied` |
| 有效签名但 audience 只有 Agent SPIFFE ID 和 realm issuer | 401 期望 audience 是工具 SPIFFE ID |

这四条日志文案彼此不同。

### 真实任务与并发

普通用户 `lab-ny` 经 Agent 的任务 `ca1e2a45-3f28-403a-bfae-294d8c754977` 于 `12:54:30Z` 完成。Agent 与工具日志都有这个任务 ID。Agent AuthBridge 在 `12:54:31.126Z` 记录 `outbound token exchanged`，audience 为工具 SPIFFE ID。工具侧 `subject` 是 lab-ny 的用户 ID，`clientID` 是 Agent SPIFFE ID，并有地理编码和预报出站。

随后两轮并发，城市对调。四条任务的 ID 都同时出现在 Agent 和工具的 `LAB_CORR` 里：

| 轮次 | 用户 | 城市 | 任务 | 回答中的数值 |
| --- | --- | --- | --- | --- |
| 1 | lab-ny | 纽约 | `104e6c18-3b87-4c44-af08-72672dd3407d` | 39.3°F，14.2 km/h，312，代码 0，GMT |
| 1 | lab-lon | 伦敦 | `51cfe69b-0308-49a8-80ec-6ca4846c8298` | 47.6°F，4.3 km/h，156，代码 61，GMT |
| 2 | lab-ny | 伦敦 | `b07c8161-940f-4a69-9ba8-0c29f371836e` | 47.6°F，4.3 km/h，156，代码 61，GMT |
| 2 | lab-lon | 纽约 | `a3ec630d-1976-45a7-b697-8ef3a7cbcfd1` | 39.3°F，14.2 km/h，312，代码 0，GMT |

工具 JSON 里对应的两组值就是这两对，时间都是 `2026-11-15T12:45`，`timezone=GMT`，`utc_offset_seconds=0`。纽约回答写了“经度：不提供、纬度：不提供”，没有写出坐标数字。

这四次 Agent 侧都各有一条 `outbound token exchanged`。没有出现缓存命中日志，因此没有观察到可关联的缓存命中。AuthBridge 的交换行和工具侧 `subject` 行都没有任务 ID。`session.id_headers: [X-Lab-Task-Id]` 已写入配置，localhost session API 里这四个任务 ID 的命中数是 0。仓库里没有 AuthBridge 源码，不能在不更换镜像的情况下给这个二进制加日志。任务 ID 的贯通停在 Agent 进程和工具进程。

## 2026-11-15 20:11 之后的基线、单位、访问边界和并发关联

基线快照在 `lab/baseline/BASELINE.md`。`12:11:27Z` 的复测任务 `e8493d43-1ed0-4521-84ae-2e949b742c1c` 在改单位字段之前完成，状态 `TASK_STATE_COMPLETED`，工具 JSON 仍是当时的 37.3°F 观测。模型接入前的 502 和 18:47、20:09 的成功任务都保留在下面。

### 单位和时区

工具原来只返回 `current_weather`。Open-Meteo 预报响应本身带有 `timezone=GMT`、`utc_offset_seconds=0`，以及 `current_weather_units`（温度 `°F`，风速 `km/h`）。请求没有传 `timezone` 参数，所以上游给出的时区是 GMT，不是纽约当地时间。

`lab/k8s/patch_tool.py` 把这些字段写进工具结果，并标明 `weather data retrieved from Open-Meteo`。`lab/k8s/patch_agent.py` 要求模型引用这些字段，时区缺失时说明未提供，不把时间说成纽约当地时间。应用命令是 `lab/scripts/apply-lab-patches.sh`。回到上一版提示的命令是 `lab/scripts/rollback-lab-patches.sh`。`MCP` 容器的 `HOST=127.0.0.1` 也写进了 `lab/k8s/weather-tool-lab.patch.yaml`。

复测任务 `365e598c-cec0-4377-aad5-50faef3df87a`，会话 `512600f0-db35-43db-9ef6-da78e836f6da`，`12:20:16Z` 到 `12:20:25Z`，`TASK_STATE_COMPLETED`。工具 JSON：`time=2026-11-15T12:15`，`temperature=37.7`，`temperature_unit=°F`，`windspeed=12.6`，`windspeed_unit=km/h`，`winddirection=305`，`timezone=GMT`，`utc_offset_seconds=0`，`is_day=1`，`weathercode=0`。回答使用了这些数值和 GMT，并写明数据来自 Open-Meteo。回答另把天气代码 0 说成晴朗，JSON 里没有这个文字。

### 当前授权规则

这些是配置和本轮请求实际表现，不是额外假设。

- 工具入站只有 `jwt-validation`。它检查 Keycloak 签名，并要求 `aud` 含工具 SPIFFE ID `spiffe://localtest.me/ns/team1/sa/weather-tool-advanced`。没有令牌是 401 `missing Authorization header`。有效签名但没有该 audience 是 401，日志写明期望 audience 和令牌里的 audience。
- 配置没有按工具名、MCP 方法或参数区分的规则。`tools/list` 和 `tools/call` 使用同一令牌，本轮都是 200。MCP 操作级 scope：**当前未配置／未覆盖**。
- `mtls.mode=permissive`。工具不要求调用方出示工作负载证书。
- 出站只对 host `weather-tool-advanced-mcp` 做令牌交换，其他 host 透传。交换使用 Agent 的 JWT-SVID，认证器是 `federated-jwt`。
- Realm 默认 scope 含 `agent-team1-weather-tool-advanced-aud`。仍挂着这个 scope 的客户端发出的用户令牌，`aud` 里已经有工具 SPIFFE ID。`weather-lab-noaud` 从客户端默认 scope 里去掉它之后，新令牌不再包含工具 audience。
- `alice` 有 realm 角色 `admin` 和 `rossoctl-operator`。本轮普通用户是 `lab-ny`（`87d55f09-1648-49af-ab6c-103acd884ae4`）和 `lab-lon`（`816acfdc-0eb3-4828-8ef0-6a7bc72a9d1e`），只有 `default-roles-rossoctl`。口令没有写入仓库。这两个用户的原始访问令牌没有 `sub` 声明；经过 Agent 交换后，工具日志里的 `subject` 是上面的用户 ID。

### 访问边界

| 测试 | 执行 | 观察 | 相对“必须由指定 Agent 代表用户调用” |
| --- | --- | --- | --- |
| 1. `lab-ny` 经 Weather Agent 查波士顿 | PASS | 任务 `97858bce-2be0-4420-93c8-6594411ff283`，`TASK_STATE_COMPLETED`。工具侧 `subject=87d55f09-1648-49af-ab6c-103acd884ae4`，`clientID` 为 Agent SPIFFE ID | 符合当前交换路径 |
| 2. 同一用户的原始令牌从 `rossoctl-backend` 直接访问工具 | PASS | `azp=weather-lab-user`，`aud` 含工具 SPIFFE ID，`scope` 含 `agent-team1-weather-tool-advanced-aud`。`initialize` 200。工具日志 `clientID=weather-lab-user`，`subject` 为空 | 当前规则允许。令牌 audience 满足 `jwt-validation`，不要求请求来自 Agent |
| 3. 有效签名、无工具 audience | PASS | 客户端 `weather-lab-noaud`。`aud` 只有 Agent SPIFFE ID 和 realm issuer。401，插件 `jwt-validation`，日志列出期望的工具 SPIFFE ID | 符合 audience 规则 |
| 4. `default/lab-caller` 重放同一用户令牌 | PASS | HTTP 200。工具日志仍是 `clientID=weather-lab-user`，没有调用方 Pod 身份 | 当前规则不区分实际调用方。同一 Bearer 可从另一个工作负载使用 |
| 5. MCP 方法级 scope | 当前未配置／未覆盖 | 同一令牌的 `tools/list` 和 `tools/call` 都是 200。AuthBridge 配置没有方法级 scope | 没有这项控制 |

### 辅助端口

| 端口 | 进程 | 无认证时能读到什么 | 是否能改配置 |
| --- | --- | --- | --- |
| 8000 | AuthBridge 反向代理 | 无令牌 401 | 业务入口，本轮保持集群内可达 |
| 8001 | 天气 MCP 进程 | 修改前，其他命名空间的 `initialize` 返回 200，绕过 `jwt-validation` | 已把 `HOST` 改为 `127.0.0.1`。其他 Pod 再连接是 `ConnectionRefused`。回滚：`kubectl set env deployment/weather-tool-advanced -c mcp HOST=0.0.0.0` |
| 9091 | 健康检查 | `/healthz` 200，正文为空 | 未发现写接口 |
| 9093 | 状态和配置页 | `/`、`/stats`、`/config` 200。`/config` 含监听地址和插件名，抽查片段没有令牌 | `POST /config` 返回 200。随后读到的配置仍含 `jwt-validation`，无令牌访问 8000 仍是 401。空 JSON 没有关掉认证；该接口接受 POST，存在改配置的入口 |
| 9094 | session API | `GET /v1/sessions` 列出 session。事件字段含 `requestId`、`subject`、`clientId`、`scopes`、路径。抽查事件没有 `eyJ` | `POST /v1/sessions` 405 |

Service 只发布 8000。没有默认拒绝的网络策略生效。本轮添加了 `lab/k8s/weather-tool-diag-netpol.yaml`，它允许任意来源访问 8000，只允许 `team1` 访问 9091/9093/9094。应用到集群后，其他命名空间仍能连上 9093 和 9094。这个 Kind 节点的 kindnet 没有执行该策略。回滚：`kubectl delete -f lab/k8s/weather-tool-diag-netpol.yaml`。

把 `bind_loopback_only` 写进 `authbridge-config-weather-tool-advanced` 后，Pod 重建时 webhook 会按 Deployment 重新生成这份 ConfigMap，循环地址被覆盖。因此 9091/9093/9094 仍在 `:::909x` 监听。诊断端口的网络限制：**FAIL**（策略已提交，但没有生效）。8001 的本机绑定：**PASS**。

### 并发关联

Agent 把 A2A `task_id` 放进 `X-Lab-Task-Id`。工具进程记下 `LAB_CORR task_id=...`。AuthBridge 日志没有这个 ID，也没有 A2A 任务 ID。关联 ID 只用于追踪。

| 用户 | 任务 | 会话 | 工具参数 | 工具 JSON 中的温度、风速、风向、代码 | 回答 |
| --- | --- | --- | --- | --- | --- |
| lab-ny | `ee8d59f2-3cb6-482f-a5d3-1b5b992d9638` | `e77a719a-2ea6-46f0-bc85-e9b38b16f250` | `New York` | 38.6°F，14.0 km/h，311，0，GMT | 这些数值一致。回答另写了经纬度，工具 JSON 没有经纬度 |
| lab-lon | `4527702a-dfa9-4c7a-8cef-3146a5a76379` | `6d814b7c-4121-445e-9b45-23820b96db9b` | `London` | 47.3°F，4.7 km/h，146，61，GMT | 数值和 GMT 与该城市的工具 JSON 一致 |

两条 `LAB_CORR` 都出现在 Agent 和工具进程。工具侧 `subject` 分别是 lab-ny 和 lab-lon 的用户 ID，`clientID` 都是 Agent SPIFFE ID。两次交换日志没有任务 ID，不能把某一次 `outbound token exchanged` 单独指派给其中一条任务。这是证据缺口，没有按时间靠近去拼接。

可重复的基线命令仍是：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
RUN_ID=wx-manual /Users/hulalala/Desktop/A/lab/scripts/run-weather-agent-task.sh
```

## 2026-11-15 20:09 再次执行的真实 Agent 任务

这一轮在上一轮成功之后重新提交，没有改认证、模型或出站配置。用户 `alice`，客户端 `weather-advanced-e2e`，模型 `qwen2.5:3b`，地址 `http://host.docker.internal:11434/v1`。提示词仍是「请调用天气工具查询纽约当前天气，并根据工具返回的数据回答。」AuthBridge 日志没有 A2A 任务 ID，用该时间窗内唯一请求、`messageId` 和工具调用 ID 对齐。

| 层 | 状态 | 证据 |
| --- | --- | --- |
| 模型调用 | PASS | `12:08:59.302Z` 与 `12:09:05.684Z` 两次 `outbound passthrough` 到 `host.docker.internal:11434`。`model_name=qwen2.5:3b`，`chatcmpl-140`，`finish_reason=tool_calls` |
| Agent 执行工具 | PASS | 业务进程发出 `tools/call`，`get_weather`，`city=New York`，调用 ID `call_ulaznmsp`。工具进程记 `CallToolRequest` |
| 身份认证与令牌交换 | PASS | `12:08:59.151Z` 入站 `clientID=weather-advanced-e2e`。`12:08:59.227Z` `outbound token exchanged`，audience 为工具 SPIFFE ID。工具侧从 `12:08:59.228Z` 起 `inbound authorized`，`clientID` 为 Agent SPIFFE ID，`subject=67c216e9-347f-4d01-80d4-ce440598158b` |
| 外部天气数据 | PASS | `12:09:00.704Z` 出站 `geocoding-api.open-meteo.com:443`，`12:09:03.097Z` 出站 `api.open-meteo.com:443`。`isError=false`。观测与 18:47 的 37.5°F 不同，说明是一次新的预报响应 |
| 最终回答 | PASS | 时间、温度、风速、风向、白天与天气代码都与该次 JSON 一致。回答另写了「地方时间」和「天气代码0表示晴朗」，这两句不在 JSON 字段里 |

首次完整成功：

- 提交 `2026-11-15T12:08:58Z`，完成 `2026-11-15T12:09:06.372486Z`
- 任务 `d112d7c3-0890-418c-80a2-70dcb0bf7c9b`，会话 `7d9d22ea-1cdb-45cb-a51c-bdeb670bd6ed`，消息 `wx-20261115-2009-msg`
- 工具结果：`{"time":"2026-11-15T12:00","interval":900,"temperature":37.3,"windspeed":12.2,"winddirection":304,"is_day":1,"weathercode":0}`
- 最终状态 `TASK_STATE_COMPLETED`
- 回答：「纽约当前的时间是2026-11-15T12:00（地方时间），温度为37.3华氏度，风速为12.2公里/小时，风向为304度，当前为白天，天气代码为0。天气代码0表示晴朗。」

独立重复：

- 提交 `2026-11-15T12:09:20Z`，完成 `2026-11-15T12:09:23.253343Z`
- 任务 `ea493452-a13a-4d94-94ea-b641d7322fe5`，会话 `1dbb8852-33fa-4101-ae8f-d798b04f3aec`，消息 `wx-20261115-2010-msg`
- 模型调用 `chatcmpl-194`，工具调用 `call_mtmbvl6o`，工具进程再次记 `CallToolRequest`
- 工具 JSON 与上一条相同，回答数值一致，最终状态 `TASK_STATE_COMPLETED`
- 这次没有新的预报连接日志。工具进程复用了 12:09:03 建立的 HTTP 连接；`CallToolRequest` 和返回 JSON 仍然存在

本轮没有新的配置修改。仍使用 `lab/k8s/weather-tool-city-hint.patch.yaml`、`lab/k8s/weather-agent-answer-hint.patch.yaml` 和 `LLM_MODEL=qwen2.5:3b`。可重复命令：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
RUN_ID=wx-manual /Users/hulalala/Desktop/A/lab/scripts/run-weather-agent-task.sh
```

## 2026-11-15 18:47 模型接入后的第一次完整成功

用户 `alice`，客户端 `weather-advanced-e2e`，认证模式 `federated-jwt`。模型 `qwen2.5:3b`，地址 `http://host.docker.internal:11434/v1`，Ollama 0.40.16。提示词是「请调用天气工具查询纽约当前天气，并根据工具返回的数据回答。」提交入口是集群内 A2A `SendMessage`，请求头 `A2A-Version: 1.0`。命令是 `lab/scripts/run-weather-agent-task.sh`。

AuthBridge 日志没有 A2A 任务 ID。下面用该时间窗里唯一的在途请求、`messageId` 和工具调用 ID 对齐。令牌原文没有写入本文件。

| 层 | 状态 | 证据 |
| --- | --- | --- |
| 模型调用 | PASS | Agent 访问 `host.docker.internal:11434`，AuthBridge 记 `outbound passthrough`。`model_name=qwen2.5:3b`，`finish_reason=tool_calls` |
| Agent 执行工具 | PASS | 业务进程发出 MCP `tools/call`，参数 `get_weather` / `city=New York`。工具进程记 `CallToolRequest` |
| 身份认证与令牌交换 | PASS | Agent AuthBridge：`inbound authorized`，`clientID=weather-advanced-e2e`；随后 `outbound token exchanged`，audience 为工具 SPIFFE ID。工具 AuthBridge 对同一次调用记 `inbound authorized`，`clientID` 为 Agent SPIFFE ID，`subject=67c216e9-347f-4d01-80d4-ce440598158b` |
| 外部天气数据 | PASS | 工具出站先到 `geocoding-api.open-meteo.com:443`，再到 `api.open-meteo.com:443`。`tools/call` 的 `isError=false`，正文是观测 JSON |
| 最终回答 | PASS | 回答中的时间、温度、风速、风向、是否白天和天气代码与该次工具 JSON 一致，温度按工具请求的华氏度表述。回答里多写了「地方时间」，JSON 本身没有这个字段 |

首次完整成功：

- 提交 `2026-11-15T10:47:42Z`，完成 `2026-11-15T10:47:48.401304Z`
- 任务 `9ce5e597-09b7-4aed-817f-a5d8c68cddae`，会话 `b77c2627-d592-4e43-9a60-65420df53dfc`，消息 `wx-20261115-1052-msg`
- 模型调用 `chatcmpl-419`，工具调用 `call_fkdtm5uf`
- 工具结果：`{"time":"2026-11-15T10:45","interval":900,"temperature":37.5,"windspeed":11.7,"winddirection":294,"is_day":0,"weathercode":0}`
- 最终状态 `TASK_STATE_COMPLETED`
- 回答：「纽约当前的时间是2026-11-15T10:45（地方时间），温度为37.5华氏度。当前的风速为11.7公里/小时，风向为294度。当前不是白天，天气代码为0。」

独立重复：

- 提交 `2026-11-15T10:48:09Z`，完成 `2026-11-15T10:48:11.640074Z`
- 任务 `a41ab96a-61c9-4148-9652-b29bb696142c`，会话 `d6ffce47-4a94-4702-8828-97569aac9f83`，消息 `wx-20261115-repeat-msg`
- 模型调用 `chatcmpl-16`，工具调用 `call_slz979ej`，工具进程再次记 `CallToolRequest`
- 工具结果与上一次相同，回答数值一致，最终状态 `TASK_STATE_COMPLETED`
- 这次没有新的 `api.open-meteo.com` 连接日志。工具进程复用了上一轮的 HTTP 连接池；sidecar 只在新建连接时记 `outbound passthrough`。`CallToolRequest` 和返回 JSON 仍然存在

同一次任务之前还有两次未达验收的真实 Agent 运行，都由 Weather Agent 业务进程执行：

| 时间 (UTC) | 任务 | 结果 |
| --- | --- | --- |
| 10:43:00–10:43:06 | `3d98e2ff-9e37-4cc2-9e65-76bfb4f67870` | 模型调用和认证通过。模型把城市参数设为「纽约」。地理编码 HTTP 200，响应没有 `results`，工具返回 `City 纽约 not found`。预报接口没有被调用。任务 `TASK_STATE_COMPLETED`，回答是未找到天气，不能算天气查询成功 |
| 10:46:16–10:46:23 | `84aeb5a1-66c5-4b53-aaea-0d1c8ff8c1d4` | 模型调用、`call_bpmtd2id`、令牌交换、`CallToolRequest` 和预报接口都通过。工具 JSON 已是 37.5 / 11.7 / 294。模型把温度写成 37.5°C，并称数据是模拟的。数值来自工具，单位和「模拟」表述与工具结果不符 |

外部接口复查：宿主机和工具 Pod 里，`name=纽约` 的地理编码约 2.5–3.2 秒返回 HTTP 200 且没有结果；`name=New York` 约 2.2 秒返回纬度 40.71427、经度 -74.00597；预报接口约 2.2–2.7 秒返回 HTTP 200。此前的 TLS 超时这次没有复现，DNS、证书校验和认证配置都没有改。

为让同一句中文提示得到可核对的天气回答，只改了两处运行时文案，认证、JWT 校验和预报地址都保持原样：

- `lab/k8s/weather-tool-city-hint.patch.yaml`：工具说明要求 `city` 使用地理编码索引中的英文地名。官方镜像文件仍由启动命令改写，Deployment 未改成透传。
- `lab/k8s/weather-agent-answer-hint.patch.yaml`：系统提示要求按工具 JSON 原样引用，并说明温度是华氏度、风速是公里/小时。
- `lab/scripts/run_agent_task.py` 的等待时间改为 420 秒，避免慢预报把客户端提前断开。
- Deployment `weather-service-advanced` 的 `LLM_MODEL` 是 `qwen2.5:3b`。

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
kubectl --context kind-agent-identity-lab -n team1 patch deployment weather-tool-advanced --patch-file lab/k8s/weather-tool-city-hint.patch.yaml
kubectl --context kind-agent-identity-lab -n team1 patch deployment weather-service-advanced --patch-file lab/k8s/weather-agent-answer-hint.patch.yaml
RUN_ID=wx-manual /Users/hulalala/Desktop/A/lab/scripts/run-weather-agent-task.sh
```

## 2026-11-15 模型接入前

以下记录发生在 Ollama 可用之前，保留当时的 502 和失败任务。

平台在 Docker Desktop 重新启动后恢复。节点容器 `agent-identity-lab-control-plane` 为 Up，context 仍是 `kind-agent-identity-lab`。控制台、Keycloak discovery、SPIRE `/keys` 本轮都返回 200。`team1` 的 Agent 和工具都是 2/2，`CLIENT_AUTH_TYPE=federated-jwt`，`client-secret.txt` 为 0 字节，JWT-SVID 文件约 710 字节。

| 问题 | 状态 | 本轮证据 |
| --- | --- | --- |
| Agent 是否在线 | PASS | `weather-service-advanced` 2/2。A2A `SendMessage` 到达业务进程，任务 ID `bd86adff-b206-4b51-aa0e-94eed220decf`。Agent AuthBridge 记录 `inbound authorized`，`clientID=weather-advanced-e2e` |
| 模型是否接入并支持工具调用 | BLOCKED | 配置仍是 `LLM_API_BASE=http://host.docker.internal:11434/v1`、`LLM_MODEL=llama3.2:3b-instruct-fp16`、`LLM_API_KEY` 已设置但只是本地占位。宿主机 11434 没有监听，环境变量里没有远程模型密钥。Agent 对 `/v1/chat/completions` 得到 502。Ollama v0.40.16 的 macOS 包约 177MB，GitHub 下载大约 30KB/s，本轮没有装完，因此没有验证工具调用 |
| MCP initialize | PASS | 直接测试，不是 Agent。协议 `2025-03-26`，服务名 `Weather`，返回了会话 ID |
| MCP tools/list | PASS | 直接测试。唯一工具 `get_weather`，必填参数 `city` |
| MCP 真实工具执行 | FAIL | 直接测试。`tools/call` HTTP 200，`isError=false`，返回文本是 `Weather service temporarily unavailable for New York`。认证和协议已通过。地理编码 `geocoding-api.open-meteo.com` 返回纽约坐标；`api.open-meteo.com` 的预报接口在宿主机和 Pod 里都超时。失败在外部天气接口，不在 AuthBridge |
| JWT-SVID 客户端认证 | PASS | 从 Agent 的 AuthBridge 容器读取 JWT-SVID 文件，断言类型 `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`。`client_credentials` 返回 200。`azp` 是 Agent 的 SPIFFE ID |
| 工具令牌交换 | PASS | 同一 JWT-SVID 换出的访问令牌 `aud` 是工具 SPIFFE ID，`scope` 含 `weather-tool-exchange-aud`，没有 `act`。缺令牌和改坏签名的 initialize 都是 401，工具日志分别是 `missing Authorization header` 和签名校验失败 |
| 真实 Agent 到工具的完整任务 | FAIL | 任务由 Weather Agent 进程执行，不是测试程序代为调用工具。Agent 先用入站用户令牌连上 MCP 并完成 `tools/list`，Agent AuthBridge 记录 `outbound token exchanged`，工具 AuthBridge 记录 `inbound authorized` 且处理了 `ListToolsRequest`。随后模型请求失败，任务状态 `TASK_STATE_FAILED`，没有 `CallToolRequest`，也没有根据天气数据作答 |

直接 MCP 测试和真实 Agent 测试是分开的。真实 Agent 这次只完成了工具列表，没有完成模型驱动的 `get_weather`。

可重复命令：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
/Users/hulalala/Desktop/A/lab/scripts/verify-federated-mcp.sh
```

真实 Agent 任务脚本是 `lab/scripts/run_agent_task.py`。它向 `http://weather-service-advanced.team1.svc:8080/` 发送 `SendMessage`，并带 `A2A-Version: 1.0`。模型未就绪时它会失败在 `chat/completions`。

访问入口仍是 http://rossoctl-ui.localtest.me:8080 、http://keycloak.localtest.me:8080 。模型配置在 Deployment `team1/weather-service-advanced` 的 `LLM_API_BASE`、`LLM_MODEL`、`LLM_API_KEY`。远程密钥应放 Secret，不要写进 Git。

当时的剩余阻塞：

- 本机没有可用模型。需要等 Ollama 包下完并拉取一个支持 OpenAI tools 的模型，或提供远程兼容接口和 Secret。
- `api.open-meteo.com` 从当前网络超时，所以即使模型调用了 `get_weather`，工具也会返回暂时不可用，除非这条出站恢复。

这两项已由上面「模型接入后的真实 Agent 任务」一节关闭。

上一轮把示例客户端 `weather-advanced-e2e` 的 access token 寿命临时改成 5 秒。本轮已改回 `1800`。

## 2026-11-13 历史记录

集群 context：`kind-agent-identity-lab`。时间：2026-11-13。令牌、口令和密钥原文没有写入本文件。

## 一条已验证的调用链

1. SPIRE 给 `weather-service-advanced` 签发 JWT-SVID。观察到的声明：`iss=https://oidc-discovery.localtest.me`，`sub=spiffe://localtest.me/ns/team1/sa/weather-service-advanced`，`aud=http://keycloak.localtest.me:8080/realms/rossoctl`。`exp-iat=300` 秒，和 SPIRE entry 的 JWT-SVID TTL 一致。
2. 用户 `alice` 通过客户端 `weather-advanced-e2e` 的密码模式拿到 Keycloak 访问令牌。`azp` 是这个客户端，`iss` 是 realm issuer。
3. Agent Pod 内的进程带着用户令牌访问 `http://weather-tool-advanced-mcp:8000/mcp`。Agent 的 AuthBridge 记录 `outbound token exchanged`，`audience=spiffe://localtest.me/ns/team1/sa/weather-tool-advanced`。Keycloak 客户端认证使用的是 `jwt-spiffe` 断言，不是 client secret。
4. 交换后的令牌到达工具 AuthBridge。日志是 `inbound authorized`，`clientID` 为 Agent 的 SPIFFE ID。MCP `initialize` 返回 200。
5. 交换结果里没有 `act`。`azp` 是 Agent 的 SPIFFE ID，`aud` 是工具的 SPIFFE ID，`scope` 含 `weather-tool-exchange-aud`，`sub` 是用户在 Keycloak 里的 ID。

这证明的是 Agent Pod 出站流量上的 AuthBridge 交换，以及工具入口的 JWT 校验。发起这次 HTTP 调用的是 Pod 里的验收进程，不是天气 Agent 里的模型循环。

## 矩阵

| 检查 | 状态 | 操作和证据 |
| --- | --- | --- |
| 平台界面、Keycloak、SPIRE | PASS | `rossoctl-ui`、Keycloak discovery、Tornjak 返回 200。SPIRE server、agent、OIDC、Tornjak、CSI 为 Running。Keycloak realm issuer 为 `http://keycloak.localtest.me:8080/realms/rossoctl`，并列出 token-exchange grant。SPIRE JWKS 有一把 `use=sig` 的 RS256 密钥 |
| Agent 与工具 SPIFFE ID 不同，签发和更新可观察 | PASS | 工具 `.../sa/weather-tool-advanced`，Agent `.../sa/weather-service-advanced`。SPIRE entry 显示 JWT TTL 300 秒、X509 TTL 86400 秒。同一 Agent 文件先后读到 `iat=1794571189` 和 `iat=1794571398`，说明 JWT-SVID 已更新 |
| 工作负载用 JWT-SVID 做 Keycloak 客户端认证 | PASS | Operator 日志：`SPIFFE ID authentication enabled: using JWT-SVID`。Operator、Agent、工具客户端的 `clientAuthenticatorType=federated-jwt`，`jwt.credential.issuer=spire-spiffe`，`jwt.credential.sub` 等于各自 SPIFFE ID。`client-secret.txt` 为 0 字节。`client_credentials` 在断言类型 `jwt-spiffe` 下返回 200。通用 `jwt-bearer` 和 client secret 都是 401，Keycloak 记录 federated-jwt 流程未完成 |
| 用户身份进入调用，交换前后声明符合配置 | PASS | 见上节。`act` 不存在，没有把它写成已实现。安装脚本把 access token 寿命设为 1800 秒；短寿命负向测试临时把示例客户端改成 5 秒后已删掉该属性 |
| 合法令牌访问受保护 MCP | PASS | 交换后的令牌对 `weather-tool-advanced-mcp:8000/mcp` 的 `initialize` 返回 200，工具日志 `inbound authorized` |
| 缺少令牌 | PASS | 401。工具日志：`jwt-validation`，`missing Authorization header`。拒绝发生在工具 AuthBridge，不是 MCP 进程 |
| 签名无效 | PASS | 只改签名段中部一个字符、其余不变。从 `rossoctl-backend` 发出，避开 Agent sidecar 重写。401。日志：`could not verify message using any of the signatures or keys`。只改签名最后一个字符时曾得到 200，不能把那种改法当成签名测试 |
| 过期 | PASS | 同一 Keycloak 签名的令牌，`exp-iat=5`，等待 8 秒后从 backend 重放。401。日志：`"exp" not satisfied`，插件 `jwt-validation` |
| 错误 issuer | 部分 | 把 SPIRE JWT-SVID 当作访问令牌送给工具，401。日志是 Keycloak JWKS 中找不到该 `kid`，属于签名密钥查找失败，不是单独的 issuer 字符串比较。没有构造“签名仍由 Keycloak 签发、只改 iss”的令牌 |
| 错误 audience | PASS | 暂时去掉示例客户端和 realm 默认范围里的工具 audience scope，拿到仍由 Keycloak 签名、`aud` 只有 Agent SPIFFE 和 realm issuer 的令牌。401。日志明确写出期望 audience 是工具 SPIFFE ID，令牌里没有它。测试后已把 scope 加回 |
| Agent 出站时 AuthBridge 确实交换，而不是测试脚本自己交换 | PASS，范围见说明 | Agent 容器访问 Service 名 `weather-tool-advanced-mcp:8000` 时，sidecar 日志为 `outbound token exchanged`。官方脚本自己用 client secret 调 Keycloak 的那次失败，没有算进这条 |
| 真实 LLM 到工具的一次调用 | BLOCKED | 没有 Ollama、LM Studio，也没有 OpenAI/Azure/Anthropic/Gemini 环境变量。不能把无 LLM 结果写成模型已调用工具 |
| 绕过 sidecar 的路径 | PASS，有旁路 | Service `weather-tool-advanced-mcp:8000` 和 Pod IP `:8000` 无令牌均为 401。工具容器访问自身 `127.0.0.1:8000` 也是 401。Agent 的 `/.well-known/agent.json` 无令牌 200，`/health`、`/ready`、`/mcp` 为 401。从其他命名空间访问工具 Pod IP 时：`:9091` 返回 404，`:9093` 和 `:9094` 返回 200。启动日志写明 `:9094` 的 session API 不认证。这些端口没有进 Service，但集群内 Pod 网络可以打到 |
| scope 允许与拒绝 | 未覆盖 | 示例只有 audience scope。`weather-tool-exchange-aud` 是 realm 的 optional scope，用来把工具 SPIFFE ID 放进 `aud`。没有按 MCP 方法区分允许和拒绝的策略。上面的 audience 测试不能代替这项 |

官方 `deploy_and_verify_advanced.sh` 在部署和 Keycloak scope 设置上走到了校验阶段，然后 client secret 交换失败并退出。这是 FAIL，原因是脚本与 `federated-jwt` 不一致，不是平台退回了 client secret。

另外，Operator 会把 `agent-team1-weather-tool-advanced-aud` 设成 realm 默认 scope。不删掉它时，普通用户令牌的 `aud` 已经包含工具 SPIFFE ID，工具会直接放行，交换不是唯一入口。删掉该 scope 后，同样签名的令牌会被 audience 检查拒绝。

## 公开且按设计可无令牌访问的地址

- `http://rossoctl-ui.localtest.me:8080/`
- `http://keycloak.localtest.me:8080/realms/rossoctl/.well-known/openid-configuration`
- `http://spire-oidc.localtest.me:8080/keys`。同一主机的 discovery 文档会因域名不在允许列表而返回 400
- `http://spire-tornjak-ui.localtest.me:8080/`
- Agent Service 上的 `/.well-known/agent.json`

这些不是受保护的 MCP 业务接口。

## 能力边界

已实现且这次验证过：

- 每个工作负载有独立 SPIFFE ID，SPIRE 签发并更新 JWT-SVID
- Operator 与 Agent/工具用 JWT-SVID 向 Keycloak 做客户端认证，不依赖写在 Pod 里的 client secret
- 用户 OAuth 访问令牌可以按路由交换成另一个 audience
- 工具 AuthBridge 校验签名、过期时间和 audience

存在实现但这次没有验证：

- AuthBridge 日志里的 `mTLS enabled mode=permissive`。Istio ambient 没有安装。Operator 在注入前记录过 X.509 mTLS 所需的 SPIRE socket 还不可见。不能把 JWT-SVID 认证写成已经启用了强制链路 mTLS
- X.509 SVID 文件 `/opt/svid.pem` 已生成

需要额外配置：

- 真实模型。`weather-service-advanced` 现在指向 `http://host.docker.internal:11434/v1`，本机 11434 没有监听。要改 `LLM_API_BASE`、`LLM_MODEL`，并把密钥放进 Secret
- 若要让“没有工具 audience scope 的用户令牌”默认被拒绝，需要处理 Operator 自动加入的 realm 默认 audience scope。这次只在负向测试中临时移开，随后已恢复

未确认支持，本次没有当成已实现：

- 多个 Agent 协作。现在是一个 Agent 和一个工具
- 多跳委托链、权限逐跳衰减、级联撤销。令牌过期只让这一张令牌失效
- 不可篡改审计。现有的是 Pod 日志里的 AuthBridge 文本
- 以 scope 而不是 audience 区分工具操作的授权

## 日志

安装和官方示例脚本的输出在 `lab/logs/`。Keycloak 管理员口令已从 `setup-rossoctl-4.log` 替换掉。
