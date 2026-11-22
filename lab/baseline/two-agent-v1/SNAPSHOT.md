# 双 Agent 基线 two-agent-v1

记录时间：2026-11-15。`12:11Z` 的单跳快照仍在 `lab/baseline/BASELINE.md`，本目录不替换它。口令、完整令牌和 JWT-SVID 没有写入这里。

## 架构

用户把 A2A `SendMessage` 发给协调 Agent A（`weather-coordinator`）。A 只转发请求。AuthBridge 把用户令牌换成天气 Agent B 的 audience。B 调用 Ollama `qwen2.5:3b`，再把令牌换成天气工具的 audience 并调用 `get_weather`。普通用户的原始令牌也可以直接调用 B，所以 A 是可选协调入口，不是必经入口。原始令牌不能直接调用工具。

## 版本

| 组件 | 版本或 digest |
| --- | --- |
| Rossoctl | v0.8.0，提交 `b380fffd77bddb861f774f9e7a6aef0257216a2b` |
| AuthBridge / proxy-init | `v0.7.0-rc.1`，`sha256:8ada36b1e8bb24ab178fdc747ee828f9675a67fc829dbdf79bd4f6e04f03b916` / `sha256:2313eae23d6dce09980fbed78f407d113fbbed19da1ba92dd11bca803a1763bb` |
| 协调 Agent 业务镜像 | `ghcr.io/rossoctl/rossoctl/backend:v0.8.0`，`sha256:9408dcb18356deb4d70325371f9c5fe992ed2f7a290eaff54a16a9e8c2f92c29` |
| 天气 Agent | `ghcr.io/rossoctl/examples/weather_service@sha256:69816d73cdfd12e657f928373e20cb668d3fa3b4bc9916d2544a9869a2a6cffa` |
| 天气工具 | `ghcr.io/rossoctl/examples/weather_tool@sha256:9ebbc02f679622fa7ddb612beaf0735add81f3ba85506eeed9dbf3b0d3a90700` |
| Keycloak | 26.5.2 |
| Ollama | 0.40.16，模型 `qwen2.5:3b`，ID `357c53fb659c` |
| 认证 | `federated-jwt` |

## 身份

| 工作负载 | ServiceAccount | SPIFFE ID | Keycloak 认证器 |
| --- | --- | --- | --- |
| weather-coordinator | weather-coordinator | `spiffe://localtest.me/ns/team1/sa/weather-coordinator` | federated-jwt |
| weather-service-advanced | weather-service-advanced | `spiffe://localtest.me/ns/team1/sa/weather-service-advanced` | federated-jwt |
| weather-tool-advanced | weather-tool-advanced | `spiffe://localtest.me/ns/team1/sa/weather-tool-advanced` | federated-jwt |

`weather-lab-user` 是 public client，直接授权已开启。它的默认 scope 含协调 Agent audience 和天气 Agent audience，不含工具 audience。自行附加工具 scope 会得到 `invalid_scope`。`lab-ny` 的用户 ID 是 `87d55f09-1648-49af-ab6c-103acd884ae4`，`lab-lon` 是 `816acfdc-0eb3-4828-8ef0-6a7bc72a9d1e`。原始访问令牌没有 `sub`；交换后的令牌在工具侧能看到这个用户 ID。

## 端口

协调 Agent 的反向代理在 `8001`，业务进程在 `8002`，Service `8080` 指向 `8001`。天气 Agent 的代理在 `8000`，进程在 `8001`。工具进程只监听 `127.0.0.1:8001`。三个工作负载的 `diag-guard` 在容器启动前拒绝非本机访问 `9091`、`9093`、`9094`。

## 重建验收

协调 Agent 重建前 UID `d247cb04-0f96-4efe-bc13-a3ff6151b3ff`，重建后 `252e4c84-c47b-4144-8784-c4a4a8c505f0`。没有执行补救脚本。同命名空间和其他命名空间连接诊断端口被拒绝，本机 `/stats`、`/healthz` 和 session 列表为 200。任务 `5e692fa4-283b-4acc-be24-3845d4072f10` 的工具 JSON 与回答都是 42.2°F、16.5 km/h、风向 321、代码 0、`timezone=GMT`、时间 `2026-11-15T13:45`。

本轮没有改身份、交换路由或用户上下文处理。双用户并发仍引用上一轮任务 `a8cd2ad5-3609-4c4f-8141-6e9fa77b2117`（纽约 41.7°F）和 `82b33c6d-3fd2-47fa-8590-6881e1cbaca2`（伦敦 49.0°F、代码 51）。

## 用户直接调用 B

新签发的 `lab-ny` 令牌 audience 含协调 Agent、天气 Agent 和 realm，不含工具。直接 `SendMessage` 到 B 得到任务 `99b1c2be-887c-4362-8012-3de6b2259a15`，`TASK_STATE_COMPLETED`。B 的入站客户端是 `weather-lab-user`。工具收到该任务 ID，入站 `subject` 是 lab-ny，`clientID` 是天气 Agent。无令牌的 Agent Card 返回 200，那不是任务接口授权。因此 A 是可选协调入口。

若以后要求 A 成为必经入口，需要从 `weather-lab-user` 去掉 `agent-team1-weather-service-advanced-aud`，并确认交换出的令牌仍带 B 的 audience、用户不能自己申请该 scope、直连 B 变为 401、经 A 的路径仍成功。本轮没有做这项修改。

## 基线限制

- AuthBridge 交换日志不能逐任务关联。上游 `v0.7.0-rc.1` 把委托信息放进会话扩展，不放进交换日志行。这项排查已结束。
- 没有 `act` 委托历史。
- 上一阶段 `12:55:15Z` 已观察到交换令牌从另一个 Pod 重放成功。本轮没有复测。
- 没有 MCP 方法级授权。
- 策略变更前旧令牌的撤销行为尚未测试。本轮使用的都是变更后新签发的令牌。

## 回滚

删除 `agentruntime/weather-coordinator`、Deployment、Service、ServiceAccount 和 ConfigMap `weather-coordinator-script`。从 `authproxy-routes` 去掉 `weather-service-advanced` 路由。从 `weather-lab-user` 去掉 `agent-team1-weather-coordinator-aud`。三个工作负载的 `diag-guard` 可从 Deployment 删除。

## 命令

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
/Users/hulalala/Desktop/A/lab/scripts/check-workloads.sh
KC_CLIENT=weather-lab-user KC_USERNAME=lab-ny KC_PASSWORD_FILE=/tmp/lab-ny.pass \
  AGENT_URL=http://weather-coordinator.team1.svc:8080/ \
  RUN_ID=manual /Users/hulalala/Desktop/A/lab/scripts/run-weather-agent-task.sh
/Users/hulalala/Desktop/A/lab/scripts/check-two-agent-boundary.sh
```

第二条命令要求 `rossoctl-backend` 里已有 `/tmp/lab-ny.pass`。该文件不在 git 中。
