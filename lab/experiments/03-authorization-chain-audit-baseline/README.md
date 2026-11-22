# 授权链与可审计性基线

被测对象是当前常驻系统。实验二的 DPoP 入口不在默认基线中。

前置条件：

- context `kind-agent-identity-lab`
- 协调 Agent、天气 Agent、工具和 Keycloak 都在运行
- 本机 Ollama 已加载 `qwen2.5:3b`，并监听 `127.0.0.1:11434`
- Secret `rossoctl-system/lab-user-credentials` 仍保存 lab-ny 和 lab-lon 的口令

执行：

```bash
/Users/hulalala/Desktop/A/lab/experiments/03-authorization-chain-audit-baseline/run-baseline.sh
```

脚本会检查工作负载、准备容器内口令、跑固定矩阵、导出脱敏证据、审计、评分，并在结束时删除本轮临时口令和令牌文件。常驻 Deployment 不会删除。

一次运行的结果写在 `runs/<时间>/`。`ground-truth/` 是实验真值，`audit-input/system/` 是给审计程序的系统证据，`auxiliary/` 是测试脚本的辅助观测。审计程序不读取真值和篡改清单。
