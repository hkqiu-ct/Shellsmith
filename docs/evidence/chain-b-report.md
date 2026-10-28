# Chain B 报告：BYOS 信任边界

状态：`baseline`。服务端单元测试已覆盖部分负面路径；真实 KMS/HSM/Play 和部署恢复仍未验证。

## 1. 已有自动化覆盖

| 测试 | 覆盖 | 位置 |
|---|---|---|
| `TestCanonicalDigestFixedVector` | 请求摘要固定向量 | `shellsmith-key-server/server_test.go` |
| `TestUnknownDevicePendingThenApproveThenRevoke` | 未知设备待批准、批准、撤销 | 同上 |
| `TestConcurrentReplayAllowsExactlyOne` | 并发重放唯一成功 | 同上 |
| `TestMasterKeyRotationPreservesTokenAndIKM` | 主密钥轮换 | 同上 |
| `TestFetchRejectsDuplicateJSONField` | 严格 JSON | 同上 |
| `TestRateLimiterRejectsBurst` | 限流 | 同上 |
| `TestPlayIntegrityCheckAndFetch` | Play 取钥 | 同上 |
| `TestPlayIntegrityRejectsPolicyMismatch` | Play 策略不匹配 | 同上 |
| `TestSchemaV1MigratesToV3` | 数据库迁移 | 同上 |
| `TestMigrateBackendAcrossKinds` | 密钥后端迁移 | 同上 |

## 2. 已有边界

- 单设备 IKM 泄漏：同一产物所有设备最终得到同一把 IKM；撤销只影响后续取钥。
- per-device payload 与当前单 APK 分发模式冲突，暂不排期。
- 设备批准当前为 sign-only，不提交并验证硬件密钥证明链。
- Play 模式依赖 Google API 可用性；失败不回退设备批准。
- 服务端、数据库、KMS/HSM 被攻破后，客户端无法保证 IKM 机密性。

## 3. 待执行实验

| ID | 实验 | 失败条件 |
|---|---|---|
| B-08 | 真实 AWS/GCP KMS/HSM | 无法解封/轮换 |
| B-09 | 备份恢复/密钥轮换演练 | 恢复后不可解封 |
| B-10 | 已授权设备 IKM 提取 | 无法记录边界/误称阻断 |
| B-11 | 部署限流与日志脱敏 | 敏感头/IKM 进入日志 |

## 4. 未验证项

- 真实 KMS/HSM 与 Play Integrity 生产验证。
- 多实例限流、数据库故障切换、备份恢复演练。
- 设备撤销与取钥并发竞态的真实部署验证。
- 已授权设备内存提取的定量边界。

## 5. 停止条件

- 如果单设备泄漏无法通过业务/分发方式接受，停止扩大 BYOS 承诺，改为服务端逻辑迁移。
- 如果外部 KMS/Play 验证长期缺失，稳定版不得宣称“已覆盖”。
