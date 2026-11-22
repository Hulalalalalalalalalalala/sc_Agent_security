# 实验二能力核查

核查对象是当前集群里正在运行的组件，不是只看配置项是否存在。

| 组件 | 运行版本 | 来源 |
| --- | --- | --- |
| Keycloak | 26.5.2 | Pod `keycloak-0` 镜像 `quay.io/keycloak/keycloak:26.5.2`，`kc.sh --version` |
| AuthBridge | v0.7.0-rc.1 | 工具 Pod 镜像 `ghcr.io/rossoctl/cortex/authbridge:v0.7.0-rc.1` |
| SPIRE | 1.13.0 | `spire-agent:1.13.0`，`spire-server` 同版本线 |
| 后端镜像里的 JWT 库 | PyJWT 2.15.1，cryptography 46.0.7 | `rossoctl-backend` 的虚拟环境。天气 Agent 镜像里的 cryptography 是 48.0.0 |

## RFC 8705 证书绑定访问令牌

Keycloak 的发现文档把 `tls_client_certificate_bound_access_tokens` 标成 true，也列出了 `tls_client_auth`。同一份文档里的 `mtls_endpoint_aliases.token_endpoint` 却是 `http://keycloak-service.keycloak.svc:8080/...`。Service 只暴露 8080/TCP，没有 TLS 端口。

因此 Keycloak 在签发时看不到客户端证书，不能把证书指纹写进 `cnf.x5t#S256`。探针里所有令牌的 `x5t` 都是 ABSENT。SPIRE 1.13.0 会发 X.509 SVID，但现有令牌请求不把这份证书交给 Keycloak。

AuthBridge v0.7.0-rc.1 的入站校验在 `authbridge/authlib/plugins/jwtvalidation/validation/jwks.go`：只检查签名、过期、发行者和 audience，再取出 `azp`。`plugin.go` 用 `ExtractBearer` 读 Authorization。它不比较客户端证书和 `cnf.x5t#S256`。二进制里的 `x5t#S256` 字符串来自 JOSE 和 SPIFFE WIT 依赖，不是这条入站校验。

这条链路缺的是 Keycloak 的双向 TLS 令牌端点，以及资源服务器对证书指纹的校验。只打开 mTLS 也不能代替绑定校验。本轮不改 Keycloak 的 HTTP 入口，所以不选 RFC 8705。

## RFC 9449 DPoP

Keycloak 26.4 起把 DPoP 列为正式支持。26.5.2 的发现文档有 `dpop_signing_alg_values_supported`，其中包含 ES256。官方说明：<https://www.keycloak.org/securing-apps/dpop>。

实测三个环节都成立：

1. 客户端用 ES256 私钥签 DPoP proof，放在 `DPoP` 头里。proof 含 `typ=dpop+jwt`、公钥 JWK、`htm`、`htu`、`iat`、`jti`。访问资源时再加访问令牌的 `ath`。
2. Keycloak 校验 proof，并把该公钥的 RFC 7638 指纹写入签名令牌的 `cnf.jkt`。令牌响应的 `token_type` 是 `DPoP`。客户端认证仍是原来的 JWT-SVID `client_assertion`，没有改成 client secret。
3. 现有 AuthBridge 不校验这枚 proof。独立入口 `guard.py` 用 PyJWT 校验签名、过期、发行者和工具 audience，再用 pydpop 0.2.1 校验 proof，并比较 proof 指纹和 `cnf.jkt`。入口日志记录收到的令牌 SHA-256。

与连续交换的配合，见 `probe.log`：

- 未绑定的 T0 可以由 A 用 JWT-SVID 换出未绑定的 T1，再由 B 在交换请求里附上自己的 DPoP proof，换出面向工具、绑定到 B 的 T2。
- B 直接拿未绑定的 T0 做同样的交换，也能得到绑定到 B 的工具令牌。
- A 先把 T0 换成绑定到 A 的 T1 后，B 仍能用自己的 JWT-SVID 和自己的 DPoP 密钥把这枚 T1 换成新令牌。新令牌的 `cnf.jkt` 等于 B 的密钥，不是 A 的密钥。所以本集群的 Keycloak 没有拒绝“另一个已注册客户端交换一张已经绑定的令牌”。绑定约束的是谁能使用这一张令牌，不是阻止后续交换。

现有客户端没有打开 “Require DPoP bound tokens”。不带 DPoP 的交换仍然返回 Bearer 令牌，基线调用不受影响。
