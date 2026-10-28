# 证据目录

本目录用于保存“可被第三方复现”的安全证据，而不是能力宣传。原则：

> 原始产物 > 运行证据 > 协议证据 > 总结文档。

## 状态定义

| 状态 | 含义 |
|---|---|
| `verified` | 有原始输入、脚本、输出和哈希，第三方可重跑 |
| `baseline` | 已记录当前基线，但样本/设备/外部环境有限 |
| `unverified` | 尚未验证，或缺少设备、账号、外部环境 |
| `stopped` | 已评估并决定不做，记录原因 |

## 目录

```text
docs/evidence/
  README.md
  threat-model.md
  attack-tree.md
  trust-boundaries.md
  metrics.md
  experiment-matrix.md
  chain-a-report.md
  chain-b-report.md
  artifacts/            # 本地生成，默认不提交敏感产物
```

## 运行入口

```bash
# 采集原始产物清单
python3 scripts/evidence/collect_artifacts.py \
  --input target/sample/input.apk \
  --input target/sample/protected.apk \
  --output docs/evidence/artifacts

# 运行一个可重复的恢复/工具命令并记录耗时
python3 scripts/evidence/recovery_benchmark.py \
  --name pvm2-art \
  --command "python3 tests/scripts/check-pvm2-art.py --min-api 26 --output target/evidence/pvm2-art" \
  --output docs/evidence/artifacts/pvm2-art-benchmark.json

# 检查证据结构是否满足发布候选基线
bash scripts/check-evidence-ready.sh --baseline
```

## 发布门禁

- `--baseline`：要求证据目录、模板、脚本和未验证项清单存在；允许外部项为 `unverified`。
- `--strict`：额外要求真实 APK/AAB 清单、Chain A/B 报告和负面测试结果；用于稳定版发布。

当前 1.10.0-rc.1 使用 `--baseline`，稳定版必须逐步收紧到 `--strict`。
