# 补充：用户主体来源与凭据准备

本文件是 `two-agent-v1` 快照之后的补充，不改写 `SNAPSHOT.md`。没有重置用户密码，也没有改 audience 或交换权限。口令和完整令牌没有写入本文件。

## 令牌对照

检查的是密码模式返回的 `access_token`。响应里的 `token_type` 是 `Bearer`，JWT 头 `typ=JWT`、`alg=RS256`。T0 的 payload 键是：`aud`、`azp`、`email`、`exp`、`iat`、`iss`、`jti`、`name`、`preferred_username`、`realm_access`、`resource_access`、`scope`、`sid`、`typ`。键名 `sub` 不存在，不是脚本把空值滤掉。

T1、T2 是受控复现：用同一枚 T0 作为 `subject_token`，分别用协调 Agent 和天气 Agent 的 JWT-SVID 向 Keycloak 做 token exchange。它们不是从同一次业务请求里截下来的三枚令牌。业务日志只作为旁证。

| 记录 | iss | sub | aud | azp | scope | iat | exp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| lab-ny T0 | realm-issuer | ABSENT | weather-agent, coordinator, realm | weather-lab-user | profile email openid agent-team1-weather-service-advanced-aud agent-team1-weather-coordinator-aud | 1794751581 | 1794753381 |
| lab-ny T1 | realm-issuer | lab-ny | weather-agent | coordinator-spiffe | 含 openid、profile、email，以及三个 audience scope 名称 | 1794751581 | 1794753381 |
| lab-ny T2 | realm-issuer | lab-ny | tool | weather-agent-spiffe | 含 weather-tool-exchange-aud、openid、profile、email 和两个 audience scope 名称 | 1794751581 | 1794753381 |
| lab-lon T0 | realm-issuer | ABSENT | weather-agent, coordinator, realm | weather-lab-user | 与 lab-ny T0 相同 | 1794751581 | 1794753381 |
| lab-lon T1 | realm-issuer | lab-lon | weather-agent | coordinator-spiffe | 与 lab-ny T1 相同 | 1794751581 | 1794753381 |
| lab-lon T2 | realm-issuer | lab-lon | tool | weather-agent-spiffe | 与 lab-ny T2 相同 | 1794751581 | 1794753381 |

`lab-ny` 代表用户 ID `87d55f09-1648-49af-ab6c-103acd884ae4`，`lab-lon` 代表 `816acfdc-0eb3-4828-8ef0-6a7bc72a9d1e`。表里的 audience 名称是 SPIFFE ID 的缩写。T1 的 `aud` 数组只有天气 Agent，虽然 `scope` 字符串里出现了工具 audience scope 的名字。

## 结论

1. T0 没有 `sub`，因为这枚 access token 的声明来自已挂上的 client scope，而 realm 里不存在名为 `basic` 的 scope，`openid` scope 没有 protocol mapper，`profile` 只有 `username` 和 `full name`，`email` 只有邮箱相关 mapper。没有 mapper 把用户 ID 写成 `sub`。客户端属性只有 `access.token.lifespan=1800` 和 `realm_client=false`，realm JSON 里没有 lightweight access token 开关。此前删除的是工具 audience scope，不是 subject mapper。
2. 已证实：把 T0 交给 UserInfo 端点，Keycloak 返回的 `sub` 分别是 lab-ny 和 lab-lon 的用户 ID。因此授权服务器能把这枚没有 `sub` 的 access token 对应到登录用户。T0 里有 `sid` 和 `jti`。本轮没有 Keycloak 服务端源码证明它具体用哪一个键检索，这一步是推断。
3. T1 和 T2 的 `sub` 与同一枚 T0 的 UserInfo `sub` 相同，所以它们对应这次登录的用户。
4. 两个用户的 `sub` 不同，并且各自等于自己的用户 ID。
5. AuthBridge `v0.7.0-rc.1` 的 `jwks.go` 把已验证 JWT 的 `token.Subject()` 放进 `Claims.Subject`，`identity.go` 的 `Subject()` 返回该字段；`ClientID` 来自 `azp`。协调 Agent 入站日志对原始用户令牌是 `clientID=weather-lab-user`、`subject` 为空。入口验证了令牌签名、有效期和 audience，并识别了客户端，没有从令牌里得到用户 ID。用户 ID 出现在 Keycloak 新签发的 T1、T2 上，后续跳的 AuthBridge 才能记到 `subject`。

真实业务旁证：任务 `5e692fa4-283b-4acc-be24-3845d4072f10` 的工具入站 `subject` 是 lab-ny 的用户 ID，`clientID` 是天气 Agent。这与受控复现里 lab-ny 的 T2 一致，但不是同一次请求里采到的 T0/T1/T2。

这是当前 mapper 配置下的访问令牌形态，不是 audience 清理误删了 `sub`。本轮没有加 mapper。

## 凭据路径

`run-weather-agent-task.sh` 在 Mac 上执行。它把 `KC_PASSWORD_FILE` 这个字符串原样传进 `rossoctl-backend` 容器，再由容器内的 `run_agent_task.py` 打开。它不会读取 Mac 上同路径的文件。`check-two-agent-boundary.sh` 也在 Mac 上执行，令牌探针读取的是容器内的 `/tmp/lab-ny.pass`。

持久来源是集群 Secret `rossoctl-system/lab-user-credentials`，键为 `lab-ny` 和 `lab-lon`。它不在 git 中。

准备，不回显口令：

```bash
export PATH="/Users/hulalala/Desktop/A/.tools/bin:$HOME/.docker/bin:$PATH"
/Users/hulalala/Desktop/A/lab/scripts/prepare-lab-credentials.sh
```

脚本在容器内写入 `/tmp/lab-ny.pass` 和 `/tmp/lab-lon.pass`，权限 `600`。Pod 重建后这两个文件消失，重新执行同一脚本即可。清理：

```bash
kubectl --context kind-agent-identity-lab -n rossoctl-system exec deploy/rossoctl-backend -c backend -- rm -f /tmp/lab-ny.pass /tmp/lab-lon.pass
```

删除 Secret 会去掉这份凭据来源：`kubectl --context kind-agent-identity-lab -n rossoctl-system delete secret lab-user-credentials`。

文件缺失时，任务脚本打印 `password_file_unreadable` 或 `password_file_empty` 并退出；边界脚本打印容器内路径缺失和准备命令，不再静默跳过。

## 本轮验证

先删除容器内旧的口令文件，再只用 Secret 重新准备。之后的双 Agent 查询任务是 `51ae6126-62e1-401f-91da-1b02fccc0873`。工具 JSON 与回答都是 42.6°F、17.1 km/h、风向 319、代码 0、`timezone=GMT`、时间 `2026-11-15T14:00`。随后的边界检查里，诊断端口仍被拒绝，本机 `/stats` 为 200；同一新令牌访问 A 得到 `5d6c91d8-1569-41dd-ae12-18c4257c34ae`，直接访问 B 得到 `3a9d34e8-8928-4ea3-86ee-5b51c5adfe20`，直接访问工具是 401。
