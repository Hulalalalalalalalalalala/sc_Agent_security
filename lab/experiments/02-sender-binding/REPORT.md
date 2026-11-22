# 实验二：DPoP 发送方绑定

这是受控客户端的发送方绑定验证。天气 Agent 的业务进程没有改，也不会自己生成 DPoP proof。持有者脚本跑在天气 Agent B 的 Pod 里，ServiceAccount 是 `weather-service-advanced`。对照脚本跑在 `rossoctl-backend`，ServiceAccount 是 `rossoctl-backend`。对照方只拿到复制的访问令牌，没有 B 的私钥。

执行时间：`2026-11-15T16:20:18Z` 至 `16:20:36Z`。运行编号 `ny-1`、`lon-1`。两次都是新签发的令牌。

选定机制是 RFC 9449 DPoP，不是 RFC 8705。能力核查和取舍写在 `CAPABILITY.md`。

## 新增内容

没有修改 Keycloak 客户端、audience、路由、AuthBridge 配置或 `two-agent-v1` 快照。

新增并已在运行结束时删除的资源：

- ServiceAccount、Service、Pod `team1/dpop-guard`
- 镜像 `ghcr.io/rossoctl/rossoctl/backend:v0.8.0`
- 入口代码 `guard.py`
- 证明库 pydpop 0.2.1，wheel SHA-256 `f43a300638461857d9a5e8a51cc2829ed9385821c80c0cd40e79d819023f959c`，源码在 `vendor/pydpop/`，MIT

绑定声明是 `cnf.jkt`。客户端证明是 `Authorization: DPoP <token>` 加 `DPoP` proof。校验位置是 `dpop-guard`，不在 AuthBridge。校验顺序是 JWT 签名、过期、发行者、工具 audience，然后才是绑定。通过后入口才把同一枚令牌以 Bearer 转给现有工具，因为现有 AuthBridge 只认 Bearer。被拒绝的请求不会转发。

天气 Agent 出站对 `dpop-guard.team1.svc:8080` 记录的是 `outbound passthrough`，没有重新交换。入口收到的令牌指纹等于签发时的 T2 指纹。

## 结果

`ny-1` 的绑定令牌指纹是 `4bf243ec01dd94fd650cec68cef6f87ba67e5a2001275d506b0bb139b156a01e`，公钥指纹 `Xvv4S8h3CNbOSf_owJeIkd0ZYky5xHmVCMK4-BAeVF4`。

`lon-1` 的绑定令牌指纹是 `7dfd605fe10ee13d914296bbdaf9103384f5aeae330502ee91cffba9c75a0159`，公钥指纹 `tDAZf_mSXHGF0Oss1a1Vyycv0TQ8b9y4m7aLXpW9HdA`。

两次的第二次交换输入指纹都等于 T1。目标入口是 `http://dpop-guard.team1.svc:8080/mcp`。

| 运行 | 来源 | 令牌 | 证明 | HTTP | 阶段 | 结果 |
| --- | --- | --- | --- | --- | --- | --- |
| ny-1 / lon-1 | 天气 Agent Pod / `weather-service-advanced` | 绑定 T2 | 匹配的 B 密钥 | 200 | 绑定通过后进入 MCP | `initialize` 有会话，`tools/list` 返回 `get_weather`。入口指纹与签发指纹相同 |
| ny-1 / lon-1 | `rossoctl-backend` / `rossoctl-backend` | 同一枚绑定 T2 | 无 | 401 | 绑定 | `missing_proof`。JWT 已通过，请求未转发 |
| ny-1 / lon-1 | 同上 | 同一枚绑定 T2 | 对照方自己的合法 ES256 proof | 401 | 绑定 | `jkt_mismatch`。proof 指纹与 `cnf.jkt` 不同 |
| ny-1 / lon-1 | 同上 | 未绑定但 audience 正确的工具令牌 | 对照方自己的合法 proof | 401 | 绑定 | `missing_cnf`。JWT 已通过 |
| ny-1 / lon-1 | 同上 | 无 | 无 | 401 | JWT | `missing_token` |
| ny-1 / lon-1 | 同上 | 原始 T0 | 无 | 401 | JWT | `audience` |

持有者的三次转发分别是 `initialize` 200、`notifications/initialized` 202、`tools/list` 200。202 是通知被接受，不是失败。

防护前，同一枚绑定令牌和未绑定工具令牌直接访问现有工具 AuthBridge，都不带 DPoP proof，两次运行都是 HTTP 200 和 `tools/list`。缺令牌和原始 T0 在现有入口仍是 401。所以现有入口没有因为令牌里出现 `cnf` 就拒绝复制使用。

脱敏输出在 `run.log`。完整令牌、私钥、JWT-SVID 和口令没有写入日志。

## 重复执行和清理

```bash
/Users/hulalala/Desktop/A/lab/experiments/02-sender-binding/run-sender-binding.sh
```

脚本会创建 `dpop-guard`，跑完后调用 `rollback.sh`。中断时也可以单独执行 `rollback.sh`。它只删除 `team1` 的 `dpop-guard` Pod、Service、ServiceAccount，以及两个 Pod 里本轮的临时文件。不删除用户 Secret，不改基线 Deployment。

本次运行结束时这些临时资源已经删除。三个基线 Pod 仍是 Running。

## 尚未验证

- 真实 Weather Agent 业务代码仍不会生成 DPoP proof。不能把这次结果写成双 Agent 链已经完成改造。
- 现有工具 AuthBridge 仍然接受绑定令牌的 Bearer 用法。绑定只在独立入口生效。
- Keycloak 允许另一个已注册客户端交换一张已经绑定的令牌，并改绑到新客户端的 DPoP 密钥。见 `probe.log` 的 `B_exchange_bound_T1`。这次没有把 `rossoctl-backend` 配成可交换客户端再测这条路径。
- 没有单独重放同一枚 DPoP proof 来展示 `jti` 拒绝。入口使用了 pydpop 的内存 `jti` 缓存，但对照表没有这一行。
- RFC 8705 没有端到端实施。
- 没有打开 Keycloak 的 “Require DPoP”。基线客户端仍能取得未绑定令牌；独立入口会拒绝这种令牌。
