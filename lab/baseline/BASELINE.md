# 2026-11-15 成功基线

这是 `2026-11-15T12:11Z` 复测时的快照。其后的单位与时区字段、任务关联头，以及把 MCP 后端绑到 `127.0.0.1`，记在 `lab/RESULTS.md` 的下一阶段，不改写这一节。

记录时间：2026-11-15T12:11Z 复测之后、单位/时区补丁之前。架构 linux/arm64。导出里没有密码、私钥、完整 token 或 JWT-SVID。`LLM_API_KEY` 只是本地占位，不作为远程密钥。

## 复测

基线复测任务 `e8493d43-1ed0-4521-84ae-2e949b742c1c`，会话 `7c4e2ca7-d593-4d14-8f98-594e0b818eb8`，消息 `wx-baseline-20261115-msg`。用户 `alice`，客户端 `weather-advanced-e2e`。提交 `2026-11-15T12:11:27Z`，完成 `2026-11-15T12:11:33.669569Z`，状态 `TASK_STATE_COMPLETED`。

工具 JSON：`{"time":"2026-11-15T12:00","interval":900,"temperature":37.3,"windspeed":12.2,"winddirection":304,"is_day":1,"weathercode":0}`。回答中的数值与此一致。这一结果当时还没有时区和单位字段。

此前两次成功任务：

- `9ce5e597-09b7-4aed-817f-a5d8c68cddae`，会话 `b77c2627-d592-4e43-9a60-65420df53dfc`，`2026-11-15T10:47:42Z`
- `a41ab96a-61c9-4148-9652-b29bb696142c`，会话 `d6ffce47-4a94-4702-8828-97569aac9f83`，`2026-11-15T10:48:09Z`

20:09 的另一次成功是 `d112d7c3-0890-418c-80a2-70dcb0bf7c9b` 和 `ea493452-a13a-4d94-94ea-b641d7322fe5`。

复现命令：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
RUN_ID=wx-manual /Users/hulalala/Desktop/A/lab/scripts/run-weather-agent-task.sh
```

## 版本

| 组件 | 版本 | digest |
| --- | --- | --- |
| rossoctl 源码 | v0.8.0 | 提交 `b380fffd77bddb861f774f9e7a6aef0257216a2b` |
| cortex 示例源码 | v0.7.0-rc.1 | 提交 `520dc8a30534303f6279f79c4af15837d1683c94` |
| operator chart | 0.4.0 | `sha256:b43322b0d837d0aeb7a7f71401d545a30f74a6525ce50a08b4a93e24f7fcb090` |
| Operator | 0.4.0 | `ghcr.io/rossoctl/operator/rossoctl-operator@sha256:80c4d3f7c24522b15e7b1d3fc21c718e6c537e732bf1621e37ac03888b4f078a` |
| AuthBridge / proxy-init | v0.7.0-rc.1 | `sha256:8ada36b1e8bb24ab178fdc747ee828f9675a67fc829dbdf79bd4f6e04f03b916` / `sha256:2313eae23d6dce09980fbed78f407d113fbbed19da1ba92dd11bca803a1763bb` |
| backend / ui | v0.8.0 | `sha256:9408dcb18356deb4d70325371f9c5fe992ed2f7a290eaff54a16a9e8c2f92c29` / `sha256:c480e1c0f20db67cbf598d599c3a0e442387530acc09022371611b39e88e1151` |
| weather agent | 镜像 digest | `ghcr.io/rossoctl/examples/weather_service@sha256:69816d73cdfd12e657f928373e20cb668d3fa3b4bc9916d2544a9869a2a6cffa` |
| weather tool | 镜像 digest | `ghcr.io/rossoctl/examples/weather_tool@sha256:9ebbc02f679622fa7ddb612beaf0735add81f3ba85506eeed9dbf3b0d3a90700` |
| Keycloak | 26.5.2 | `quay.io/keycloak/keycloak@sha256:fb31a59deb46f746f2aaa25adc5da39ceccac4fd22d36a519562b0bf02e8df20` |
| Ollama | 0.40.16 | 模型 `qwen2.5:3b`，ID `357c53fb659c`，1.9GB |
| SPIRE | 1.13.0 | server `sha256:d715435ba011eca7a3c098ca66a781d2ab2cecf5de9afcfb0a0e071957ef1d32` |

模型地址 `http://host.docker.internal:11434/v1`。Ollama 监听 `0.0.0.0:11434`。

## 与上游的差别

上游 `k8s/weather-service-advanced.yaml` 和 `k8s/weather-tool-advanced.yaml` 没有容器 `command`，`LLM_MODEL` 默认是 `llama3.2:3b-instruct-fp16`。上游 `configmaps-advanced.yaml` 原来写 `client-secret`；本集群 ConfigMap `team1/authbridge-config` 的 `CLIENT_AUTH_TYPE` 是 `federated-jwt`。

本机相对上游的运行时改动：

- Deployment `weather-service-advanced`：`LLM_MODEL=qwen2.5:3b`。启动命令来自 `lab/k8s/weather-agent-answer-hint.patch.yaml`，只改系统提示。
- Deployment `weather-tool-advanced`：启动命令来自 `lab/k8s/weather-tool-city-hint.patch.yaml`，只改工具说明，要求英文地名。
- `lab/scripts/run_agent_task.py` 的 HTTP 等待时间是 420 秒。
- 没有 NetworkPolicy。Service `weather-tool-advanced-mcp` 只发布 8000。

重新应用到这一基线：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
kubectl --context kind-agent-identity-lab -n team1 set env deployment/weather-service-advanced LLM_MODEL=qwen2.5:3b
kubectl --context kind-agent-identity-lab -n team1 patch deployment weather-tool-advanced --patch-file lab/k8s/weather-tool-city-hint.patch.yaml
kubectl --context kind-agent-identity-lab -n team1 patch deployment weather-service-advanced --patch-file lab/k8s/weather-agent-answer-hint.patch.yaml
```

回到上游镜像入口：删除两个 Deployment 容器的 `command`，并把 `LLM_MODEL` 改回清单里的 `llama3.2:3b-instruct-fp16`。那会失去已验证的英文地名提示和回答约束。

## Keycloak realm `rossoctl`

- `accessTokenLifespan=1800` 秒。`weather-advanced-e2e` 的 client attributes 当前为空，因此使用 realm 寿命，不是单独的 5 秒。
- Realm 默认 client scope 包含 `agent-team1-weather-tool-advanced-aud` 和 `agent-team1-weather-service-advanced-aud`。两者都是 `oidc-audience-mapper`，分别把工具 SPIFFE ID 和 Agent SPIFFE ID 写入 access token 的 `aud`。
- `weather-tool-exchange-aud` 是 realm 的 optional scope，mapper 同样写入工具 SPIFFE ID。AuthBridge 路由在交换时请求 `openid weather-tool-exchange-aud`。
- `weather-advanced-e2e` 是 public client，开启 direct access grant，默认 scope 里也有上述两个 audience scope。认证器是 `client-secret`，但 public client 的密码模式不使用 client secret。
- Agent 与工具的 Keycloak 客户端 ID 等于各自 SPIFFE ID，`clientAuthenticatorType=federated-jwt`。
- 用户 `alice`（`67c216e9-347f-4d01-80d4-ce440598158b`）拥有 realm 角色 `admin` 和 `rossoctl-operator`。`bob` 是 `rossoctl-viewer`。基线天气任务使用的是 alice，不能把她的成功当成普通用户授权。

## 运行中的 AuthBridge

工具与 Agent 的 `/etc/authbridge/config.yaml` 都是 `mode: proxy-sidecar`，`mtls.mode: permissive`。入站插件只有 `jwt-validation`（issuer 为 realm issuer）。出站插件是 `token-exchange`，`default_policy: passthrough`。唯一路由是 host `weather-tool-advanced-mcp`，audience 为工具 SPIFFE ID。配置里没有按 MCP 方法或工具参数区分的规则。
