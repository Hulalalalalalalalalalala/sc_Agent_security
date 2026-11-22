# 固定版本

记录时间：2026-11-13。架构：linux/arm64。除特别注明外，digest 是 registry 返回的 manifest index。

## 源码

| 组件 | 版本 | 提交 |
| --- | --- | --- |
| rossoctl | v0.8.0 | `b380fffd77bddb861f774f9e7a6aef0257216a2b` |
| cortex 示例 | v0.7.0-rc.1 | `520dc8a30534303f6279f79c4af15837d1683c94` |
| rossoctl chart | 0.8.0 | 仓库内 `charts/rossoctl` |
| operator-chart | 0.4.0 | `oci://ghcr.io/rossoctl/operator/operator-chart`，拉取 digest `sha256:b43322b0d837d0aeb7a7f71401d545a30f74a6525ce50a08b4a93e24f7fcb090`。Chart.lock 记录 `sha256:5e128e9441bfe6328b0c2a2e53a80f27a736fccccecc37632522076296e99a93` |

Operator chart 0.4.0 自带 AuthBridge 镜像 tag `v0.7.0-rc.1`，因此示例不用 cortex v0.8/v0.9。

## 安装脚本钉死的依赖

| 组件 | 版本 |
| --- | --- |
| cert-manager | v1.17.2 |
| Gateway API | v1.4.0 |
| Istio | 1.28.0（只装了 base + istiod，没有 ambient） |
| SPIRE CRDs / SPIRE | 0.5.0 / 0.27.0（应用版本 1.13.0） |
| SPIFFE CSI driver | 0.2.13 |
| Kind 节点 | `kindest/node:v1.35.0`，digest `sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f`。本机镜像 `Id` 与该 digest 相同，`Architecture=arm64` |

## 平台镜像

| 镜像 | index digest |
| --- | --- |
| `ghcr.io/rossoctl/operator/rossoctl-operator:0.4.0` | `sha256:80c4d3f7c24522b15e7b1d3fc21c718e6c537e732bf1621e37ac03888b4f078a` |
| `ghcr.io/rossoctl/cortex/authbridge:v0.7.0-rc.1` | `sha256:8ada36b1e8bb24ab178fdc747ee828f9675a67fc829dbdf79bd4f6e04f03b916` |
| `ghcr.io/rossoctl/cortex/authbridge-lite:v0.7.0-rc.1` | `sha256:eb3ef724fa9b88bbbd31ff1455abdbe8e266c7faa1271177bda972917991573a` |
| `ghcr.io/rossoctl/cortex/proxy-init:v0.7.0-rc.1` | `sha256:2313eae23d6dce09980fbed78f407d113fbbed19da1ba92dd11bca803a1763bb` |
| `ghcr.io/rossoctl/rossoctl/ui-v2:v0.8.0` | `sha256:c480e1c0f20db67cbf598d599c3a0e442387530acc09022371611b39e88e1151` |
| `ghcr.io/rossoctl/rossoctl/backend:v0.8.0` | `sha256:9408dcb18356deb4d70325371f9c5fe992ed2f7a290eaff54a16a9e8c2f92c29` |
| `ghcr.io/rossoctl/rossoctl/operator-spiffe-bootstrap:v0.8.0` | `sha256:11683c5188a07dc12bcd98cbc0c0532ef643fbc66a150b03ddebc0e6c3941ba9` |
| `ghcr.io/rossoctl/rossoctl/spiffe-idp-setup:v0.8.0` | `sha256:4f746f3bbab59c190c513fae8a704ad333e638ff3b7ad8dc0f463f18dd24dc86` |
| `quay.io/keycloak/keycloak:26.5.2` | chart 钉死 tag；运行中的 Pod 已就绪 |
| Postgres | `public.ecr.aws/docker/library/postgres:17`，arm64 manifest `sha256:73cd1868ae15ef8c7f95d81219b47c92c884a8341bc05f41656f7b8a89e3efc1` |

## 示例镜像

上游清单写 `latest`。部署时固定为：

| 镜像 | index digest |
| --- | --- |
| `ghcr.io/rossoctl/examples/weather_tool` | `sha256:9ebbc02f679622fa7ddb612beaf0735add81f3ba85506eeed9dbf3b0d3a90700` |
| `ghcr.io/rossoctl/examples/weather_service` | `sha256:69816d73cdfd12e657f928373e20cb668d3fa3b4bc9916d2544a9869a2a6cffa` |

运行中的 sidecar 是 `ghcr.io/rossoctl/cortex/authbridge:v0.7.0-rc.1`，init 容器是 `proxy-init:v0.7.0-rc.1`。

## 与文档不一致、以代码和实际行为为准的地方

- 网站安装页示例仍写 `git checkout v0.7.0`。本次按任务使用已发布的 `v0.8.0`。
- advanced 清单把 `CLIENT_AUTH_TYPE` 写成 `client-secret`，同时注释说如果安装改过这个值就要合并。合并后的值是 `federated-jwt`。
- 官方 `deploy_and_verify_advanced.sh` 用 client secret 做交换。本集群的客户端认证器是 `federated-jwt`，该步骤返回 `invalid_client`。能通过的客户端断言类型是 `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`，不是通用的 `jwt-bearer`。
- SPIRE `jwt_issuer` 是 `https://oidc-discovery.localtest.me`。用集群内 Service 主机名访问 OIDC discovery 时，返回的 issuer 是该 Service 的 `http://` 地址。Keycloak 的 SPIFFE IdP 按客户端上的 `jwt.credential.issuer=spire-spiffe` 查找，不拿这个字符串和 JWT 的 `iss` 做相等比较。
- 公开地址 `spire-oidc.localtest.me` 不在 OIDC provider 的允许域名里，`/.well-known/openid-configuration` 返回 400 `domain is not allowed`。`/keys` 可以打开。
- 安装脚本在 Pod 未全部就绪时会因为 `set -e` 退出。第一次停在 SPIRE OIDC 拉 `docker.io` 镜像。镜像导入节点后重跑同一组参数才继续。
