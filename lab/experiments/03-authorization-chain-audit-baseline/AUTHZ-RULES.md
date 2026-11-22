# 当前授权规则

被测对象是常驻的 two-agent 系统。实验二的 `dpop-guard` 不在这条基线里。下表只记录已经生效的判断，以及本轮想研究、但没有配置的更强性质。本轮没有为了让测试通过而修改策略。

| 主体 | 目标资源 | 操作 | 当前许可条件 | 执行位置 | 更强性质，当前未配置 |
| --- | --- | --- | --- | --- | --- |
| lab-ny、lab-lon，客户端 `weather-lab-user` | 协调 Agent A | A2A SendMessage | 令牌签名和有效期有效，audience 含 A 的 SPIFFE ID | A 的 AuthBridge | 无 |
| 同上 | 天气 Agent B | A2A SendMessage | audience 含 B 的 SPIFFE ID。不要求来自 A | B 的 AuthBridge | 用户必须经过指定的 A |
| 持有工具 audience 的令牌 | 天气工具 | MCP 各方法 | audience 含工具 SPIFFE ID。方法之间没有不同规则 | 工具的 AuthBridge | MCP 方法级授权 |
| 同上 | 天气工具 | 从另一个工作负载重放令牌 | 只检查令牌声明。clientID 不是网络发送方证明 | 工具的 AuthBridge | 发送方绑定 |
| `weather-lab-user` | Keycloak 令牌端点 | token exchange | 该客户端不允许交换 | Keycloak | 无 |
| A、B 的 JWT-SVID 客户端 | Keycloak 令牌端点 | 向已配置 audience 交换 | JWT-SVID 客户端认证成功即可签发。新令牌没有 `act` | Keycloak | 可验证的委托链 |
| 用户访问令牌 T0 | 令牌声明中的主体 | 读取 `sub` | T0 没有 `sub`。下游主体是交换时由 Keycloak 重新写入的 | Keycloak 签发；AuthBridge 只读取已验证 JWT 的 `sub` | 原始令牌自带主体 |

身份对应关系：

- 用户 lab-ny、lab-lon 是 Keycloak 用户，只有 realm 默认角色。角色不参与工具入口判断。
- A 是 ServiceAccount `weather-coordinator`，SPIFFE ID `spiffe://localtest.me/ns/team1/sa/weather-coordinator`。它转发请求，不调用模型。
- B 是 ServiceAccount `weather-service-advanced`。它调用模型和工具。
- 工具是 ServiceAccount `weather-tool-advanced`。
- SPIRE 签发 JWT-SVID。Keycloak 签发用户令牌和交换后的访问令牌。
- `agent-team1-weather-service-advanced-aud` 与 `weather-tool-exchange-aud` 是用来把目标 SPIFFE ID 放进令牌 audience 的 scope。它们不是 MCP 方法权限。不能用 scope 的个数判断权限是否扩大。

A 是可选入口。用户直接调用 B 是当前规则允许的行为。
