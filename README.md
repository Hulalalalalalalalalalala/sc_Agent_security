# Agent 身份认证实验：Rossoctl v0.8.0

本目录是在当前 Mac 上部署并验收官方 Rossoctl（原 Kagenti）平台的记录。本阶段只使用发行版里的 SPIFFE 身份、OAuth、令牌交换和 Weather Agent advanced 示例，没有自研 STS、委托协议或新的 Agent 框架。

## 当前状态

成功基线在 `lab/baseline/BASELINE.md`。`2026-11-15T12:11Z` 复测任务 `e8493d43-1ed0-4521-84ae-2e949b742c1c` 仍能完成纽约天气查询。其后工具结果保留了 Open-Meteo 返回的 `°F`、`km/h` 和 `timezone=GMT`；请求没有传时区参数，所以上游给出的是 GMT。复测任务 `365e598c-cec0-4377-aad5-50faef3df87a` 的回答与这些字段一致。

当前架构是用户 → 协调 Agent A → 天气 Agent B → 天气 MCP 工具。A 只转发请求，B 调用 `qwen2.5:3b` 和天气工具。两级 JWT-SVID 交换会保留用户主体。普通用户的新令牌也可以直接调用 B，所以 A 是可选协调入口；该令牌不能直接调用工具。诊断端口由各工作负载的 `diag-guard` 在监听前限制。冻结记录在 `lab/baseline/two-agent-v1/`。用户主体和凭据准备的补充说明在 `lab/baseline/two-agent-v1/ADDENDUM-subject-and-credentials.md`。AuthBridge 交换日志仍不能按任务关联。`2026-11-15T15:49:13Z` 的连续交换和同一枚 T2 跨工作负载调用记录在 `lab/experiments/01-token-holder-binding/`。`2026-11-15T16:20:18Z` 的 DPoP 发送方绑定对照记录在 `lab/experiments/02-sender-binding/`。`2026-11-16T03:43:03Z` 的授权链审计基线在 `lab/experiments/03-authorization-chain-audit-baseline/`。

20:09 的成功任务、18:47 的第一次成功，以及模型接入前的 502，都保留在 `lab/RESULTS.md`。

模型接入前的 502 和 `TASK_STATE_FAILED` 仍保留在 `lab/RESULTS.md`。当时 `host.docker.internal:11434` 没有服务。

可重复验收：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
RUN_ID=wx-manual /Users/hulalala/Desktop/A/lab/scripts/run-weather-agent-task.sh
```

这条命令用用户 `alice`、客户端 `weather-advanced-e2e`，向 Weather Agent 的 A2A `SendMessage` 提交「请调用天气工具查询纽约当前天气，并根据工具返回的数据回答。」脚本只打印状态和脱敏后的响应。

## 访问

| 项 | 值 |
| --- | --- |
| context | `kind-agent-identity-lab` |
| 节点 | `agent-identity-lab-control-plane` |
| 平台命名空间 | `rossoctl-system` |
| 身份 | `keycloak`、`spire-mgmt`、`spire-system`、`zero-trust-workload-identity-manager` |
| 示例 | `team1`（`team2` 只有平台创建的命名空间，没有示例工作负载） |
| 控制台 | http://rossoctl-ui.localtest.me:8080 |
| API | http://rossoctl-api.localtest.me:8080 |
| Keycloak | http://keycloak.localtest.me:8080 |
| SPIRE OIDC 密钥 | http://spire-oidc.localtest.me:8080/keys |
| Tornjak | http://spire-tornjak-ui.localtest.me:8080 |

`localtest.me` 解析到本机。Kind 把节点的 30080 映射到宿主机 8080，9443 映射到宿主机 9443。部署前这两个端口没有监听。

登录信息不要写进仓库或聊天记录。在仓库检出目录执行：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
kubectl --context kind-agent-identity-lab -n keycloak \
  get secret keycloak-initial-admin \
  -o go-template='{{.data.username|base64decode}}{{"\n"}}'
kubectl --context kind-agent-identity-lab -n keycloak \
  get secret keycloak-initial-admin \
  -o go-template='{{.data.password|base64decode}}{{"\n"}}'
```

控制台用户优先读 `keycloak` 命名空间里的 `rossoctl-test-user`。没有这个 Secret 时，官方 `show-services.sh` 会退回上面的 Keycloak 管理员。脚本会把口令打到终端：

```bash
cd /Users/hulalala/Desktop/A/src/rossoctl
./.github/scripts/local-setup/show-services.sh
```

示例用户 `alice` 由 advanced 脚本创建，只用于无 LLM 的密码模式。不要把它当成平台登录账号。

## 环境

- macOS 27.0.1，Apple M5 Pro，arm64，不是 WSL2
- 18 核 CPU，24 GiB 内存，数据卷约 1.0 TiB 可用
- Docker Desktop 4.91.0 / Engine 29.8.0，分配 18 CPU、约 15.6 GiB 内存。官方完整安装建议 18 GiB，这次没有装 Istio ambient、MLflow、Tekton，实际装完并完成了验收
- 开始时没有 Kind、Helm、Podman、Minikube，也没有其他 kube context。Kind v0.33.0 和 Helm v3.22.1 放在 `.tools/bin`
- 宿主机访问 `registry-1.docker.io` 会失败。Kind 节点网络可以连 Docker Hub，但很慢。节点的 containerd 把 `docker.io` 指到 `https://docker.m.daocloud.io`，见 `lab/containerd/certs.d/docker.io/hosts.toml`
- Keycloak 的 Postgres 不用 `mirror.gcr.io`（这里连不上），改为 `public.ecr.aws/docker/library/postgres:17`，见 `lab/helm/rossoctl-deps-values.yaml`
- GitHub Release 资源下载不稳定。cert-manager v1.17.2 和 Gateway API v1.4.0 用 `gh api` 下到 `lab/manifests` 后预先装上，安装脚本发现已存在就跳过。SPIRE chart 由 `lab/bin/helm` 改用同一发行版的本地 tarball：`spire-crds-0.5.0.tgz`、`spire-0.27.0.tgz`
- 已核对的平台镜像都有 linux/arm64

## 固定版本

详见 `lab/VERSIONS.md`。起点是 Rossoctl `v0.8.0`，提交 `b380fffd77bddb861f774f9e7a6aef0257216a2b`。Operator chart `0.4.0` 把 AuthBridge 固定在 `ghcr.io/rossoctl/cortex/authbridge:v0.7.0-rc.1`，所以示例用 cortex `v0.7.0-rc.1`（`520dc8a30534303f6279f79c4af15837d1683c94`），没有混用更新的 cortex。

## 这次实际执行的安装

```bash
export PATH="/Users/hulalala/Desktop/A/lab/bin:/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
cd /Users/hulalala/Desktop/A/src/rossoctl
KIND_CONFIG=/Users/hulalala/Desktop/A/lab/kind/kind-config.yaml \
scripts/kind/setup-rossoctl.sh \
  --cluster-name agent-identity-lab \
  --skip-cluster \
  --with-spire \
  --enable-spiffe-auth \
  --with-ui \
  --rossoctl-deps-values /Users/hulalala/Desktop/A/lab/helm/rossoctl-deps-values.yaml
```

集群本身用同一份 Kind 配置创建。`--skip-cluster` 是因为 cert-manager 和 Gateway API 已先装好。没有加 `--with-istio`，所以没有 Istio ambient mesh，也不能把 JWT-SVID 说成链路 mTLS。`--with-examples` 也没有加，那个基础天气示例的出站策略是透传。

AuthBridge 镜像和 SPIFFE 配置来自这次 Helm 安装，不是各仓库的 latest。`team1` 的 `CLIENT_AUTH_TYPE=federated-jwt`，JWT-SVID 的 audience 是 `http://keycloak.localtest.me:8080/realms/rossoctl`，和访问工具用的 OAuth token audience 不是一回事。

## 天气示例

官方脚本在 `src/cortex/authbridge/demos/weather-agent/deploy_and_verify_advanced.sh`。相对上游 v0.7.0-rc.1，应用前只改了两处，都写在清单注释里：

- `CLIENT_AUTH_TYPE` 从清单里的 `client-secret` 改成 `federated-jwt`。上游注释要求在安装覆盖了这个值时合并，否则会静默退回 client secret
- `weather_tool` / `weather_service` 的 `latest` 固定为当时拉到的 index digest

工作负载名保持 `team1`、`weather-service-advanced`、`weather-tool-advanced`、`weather-tool-advanced-mcp`。Agent 和工具 Pod 都是 2/2，容器为业务容器加 `authbridge-proxy`。`client-secret.txt` 是 0 字节。Keycloak 客户端认证器是 `federated-jwt`。

## 重启、再验收、只清理本实验

重启这个集群，不要动其他 Docker 容器：

```bash
docker start agent-identity-lab-control-plane
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
kubectl --context kind-agent-identity-lab get nodes
```

再验收公开端点和 Pod：

```bash
/Users/hulalala/Desktop/A/lab/scripts/recheck-platform.sh
```

只删除本实验集群：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$PATH"
kind delete cluster --name agent-identity-lab
```

这不会删除其他 Kind 集群，也不会执行 `docker system prune`。如果还要去掉为 GitHub Release 准备的 Helm 包装，把 `PATH` 里的 `lab/bin` 拿掉即可，`.tools/bin/helm` 仍是官方 Helm 3.22.1。

## 验收和下一步

矩阵、调用链和能力边界在 `lab/RESULTS.md`。下一步最小操作是提供一个允许使用的 OpenAI 兼容模型地址和密钥，放进 `team1` 的 Secret，再让 `weather-service-advanced` 真正发起一次天气查询。不要为了这一步改校验或改回透传。
