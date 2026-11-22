# 实验一：连续令牌交换与同一枚 T2 的跨工作负载使用

执行时间：`2026-11-15T15:49:13Z` 至 `2026-11-15T15:49:21Z`。

脚本：

- `lab/experiments/01-token-holder-binding/run-holder-binding.sh`
- `lab/experiments/01-token-holder-binding/exchange_chain.py`
- `lab/experiments/01-token-holder-binding/mcp_with_token.py`

脱敏日志：`lab/experiments/01-token-holder-binding/run.log`。完整令牌、JWT-SVID 和口令没有写入该日志。运行结束后已删除容器内临时文件。`lab/baseline/two-agent-v1/` 没有修改，访问策略没有修改。

## 连续交换

顺序是用户登录得到 T0，协调 Agent A 用自己的 JWT-SVID 把 T0 换成面向天气 Agent B 的 T1，天气 Agent B 再用自己的 JWT-SVID、以这枚 T1 为 `subject_token` 换成面向工具的 T2。指纹是完整令牌在内存中的 SHA-256。

| 运行 | 用户 | T0 | T1 | 第二次交换输入 | T2 | 输入等于 T1 | 交换状态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ny-1 | lab-ny | `297b29b6e3900d4dd89071f4ae472ee386934899d00b111f3732be4452913da1` | `7bce130ce232ac38b9bb77152cf30270cadef59ecdbce9f082aaeaedea35bc57` | 同 T1 | `8d06fbea42946675d74a3df0f07b35353102c9427b69213227efdfb80baadb48` | 是 | 200 |
| lon-1 | lab-lon | `94bec370313da1ef0b4fda3b484ae7dd0ecbd9b08d4ac416f815df4aee92a00b` | `e6d1a192bb81e3a8e161c81d1bae95b7c6ec8fa63342322f186d3d4c19c46b3e` | 同 T1 | `69f110e5d580e0bd307befab4f33e538b5dffbe00f943d498beee0da007d786e` | 是 | 200 |
| ny-2 | lab-ny，新签发 | `26155328538380ba36b7c4f5b1928189e2a603d3072c2f58591390e29c1336d0` | `e862a0de0153ed60c50dd1f28e460a6d72427fcc9a828fe6507a74fe2214aa7b` | 同 T1 | `8bd9d0981a29dccfa4750a1ff13ad1e5f95bd126657f58b5c107283160a70e30` | 是 | 200 |

三次都没有退回 T0。T0、T1、T2 的指纹互不相同。ny-2 的三枚指纹也与 ny-1 不同。T0 没有 `sub`；T1 和 T2 的主体分别是 lab-ny 或 lab-lon。T1 的 audience 是天气 Agent，T2 的 audience 是工具。

## 同一枚 T2 的调用

每个调用方各自执行 MCP `initialize`、建立自己的会话，再执行 `tools/list`。T2 文件从交换进程复制到天气 Agent Pod，两边使用同一份字节。天气 Agent 的出站代理对工具 Pod IP `10.244.0.33:8000` 记录的是 `outbound passthrough`、`no matching route`，没有 `outbound token exchanged`。三条 passthrough 分别对应 `initialize`、`notifications/initialized` 和 `tools/list`。

另一个调用方是 `rossoctl-backend`，ServiceAccount 为 `rossoctl-backend`，没有令牌交换代理。天气 Agent 的 ServiceAccount 是 `weather-service-advanced`。

| 运行 | 来源 | T2 指纹 | 目标入口 | HTTP | MCP | 工具认证日志 |
| --- | --- | --- | --- | --- | --- | --- |
| ny-1 | `rossoctl-backend` / `rossoctl-backend` | `8d06fbea…0baadb48` | `weather-tool-advanced-mcp.team1.svc:8000/mcp` | 200 | `tools/list` 返回 `get_weather` | `15:49:15Z` 三次 `inbound authorized`，subject lab-ny，clientID 为天气 Agent SPIFFE |
| ny-1 | `weather-service-advanced` / `weather-service-advanced` | 同一枚 | `10.244.0.33:8000/mcp` | 200 | `tools/list` 返回 `get_weather` | `15:49:16.678Z` 起三次 `inbound authorized`，主体和 clientID 相同；出站为 passthrough |
| lon-1 | `rossoctl-backend` / `rossoctl-backend` | `69f110e5…007d786e` | 服务入口 | 200 | `tools/list` 返回 `get_weather` | `15:49:17Z`，subject lab-lon |
| lon-1 | 天气 Agent Pod | 同一枚 | Pod IP `:8000/mcp` | 200 | `tools/list` 返回 `get_weather` | `15:49:19.009Z` 起三次授权；出站 passthrough |
| ny-2 | `rossoctl-backend` / `rossoctl-backend` | `8bd9d098…60a70e30` | 服务入口 | 200 | `tools/list` 返回 `get_weather` | `15:49:20.067Z` 起，subject lab-ny |
| ny-2 | 天气 Agent Pod | 同一枚 | Pod IP `:8000/mcp` | 200 | `tools/list` 返回 `get_weather` | `15:49:21.313Z` 起；出站 passthrough |

对照：

| 运行 | 缺令牌 | 原始 T0 |
| --- | --- | --- |
| ny-1 | 401，`missing Authorization header`，`15:49:15.963Z` | 401，audience 不含工具 SPIFFE，`15:49:16.377Z` |
| lon-1 | 401，`15:49:18.265Z` | 401，同样的 audience 错误，`15:49:18.680Z` |
| ny-2 | 401，`15:49:20.560Z` | 401，`15:49:21.057Z` |

ny-2 的日志窗口因时间戳只到秒，带上了 lon-1 在 `15:49:19Z` 的三条记录。上面按时间和主体分开，没有把 lon-1 算进 ny-2。

## 结论

连续交换成立：第二次输入指纹等于 T1，T2 换发成功。同一枚 T2 从两个不同 ServiceAccount 访问工具入站 AuthBridge 都被允许，并完成各自的 `tools/list`。缺令牌和原始 T0 仍被拒绝。

这次没有改路由。天气 Agent 如果访问服务名 `weather-tool-advanced-mcp`，现有路由仍会交换令牌；本轮为了比较同一枚 T2，访问的是工具 Pod IP，出站记录为 passthrough。

工具进程没有记录收到的令牌指纹，所以不能从工具侧重新计算哈希。同一枚令牌的判断来自复制的同一份字节，以及天气 Agent 出站没有重新交换。工具日志里的 subject 和 clientID 在重新交换后也会相同，单靠这两项不能证明令牌字节没变。
