# 信任边界与数据流（证据基线）

状态：`baseline`。

```text
构建机
  ├─ 原始 APK/AAB、证书、keystore
  ├─ Packer / Stub / resources.zip
  └─ CI、更新签名密钥
        │
        ▼
发布产物 APK/AAB
  ├─ 壳 DEX + Native 库
  ├─ DEXB v6/v7 载荷
  ├─ PVM2 code.bin
  ├─ 路由 .rtap
  └─ PAS2/PSO2 资源
        │
        ▼
设备
  ├─ APK 签名校验
  ├─ Keystore/Keychain
  ├─ 私有目录缓存
  ├─ 进程内存（IKM/明文）
  └─ RASP 信号
        │
        ▼
BYOS 服务端
  ├─ TLS 终止 / 反向代理
  ├─ Go 服务
  ├─ PostgreSQL
  ├─ KMS/HSM
  ├─ Play Integrity
  └─ 审计日志
```

## 边界说明

| 边界 | 谁可信 | 不能假设 |
|---|---|---|
| APK | 无 | 包内材料不能视为秘密 |
| 设备 | 应用进程 + 系统 | Root/越狱/调试下私有目录不可信 |
| 服务端 | 运维控制的进程/数据库/KMS | 客户端不能替代服务端授权 |
| 网络 | TLS + 服务端校验 | 不能只靠客户端时间/nonce |
| 构建 | CI 与签名材料 | 构建链被控制则产物不可信 |
| 分发 | Play/App Store/更新清单 | 上传证书不等于最终安装证书 |

## 证据要求

- 每个边界至少有一个正常用例和一个负面用例。
- 负面用例必须记录：攻击前提、预期拒绝位置、实际结果、证据哈希。
- 外部环境缺失时标记 `unverified`，不能写成通过。
