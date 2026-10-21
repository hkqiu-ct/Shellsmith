# BYOS 密钥服务端参考实现

本文是 Shellsmith BYOS 的服务端参考实现与运维手册，对应独立服务端项目 `shellsmith-key-server`。协议字段、接口和错误语义以 [BYOS HTTPS 密钥服务接入协议](byos-key-server.md) 为准；本文说明如何实现、配置、部署、轮换和排障。

服务端使用 Go 标准库 `net/http`、PostgreSQL 和 `pgx`，同时支持 `device_approval`（设备批准）和 `play_integrity`（Google Play Integrity）两种授权方式。

它实现 Shellsmith BYOS 协议的三个接口：

| 接口 | 作用 |
|---|---|
| `POST /v1/keys/check` | 校验构建 API key、应用策略、授权方式、取钥协议和主密钥后端 |
| `POST /v1/keys/register` | 接收 Shellsmith 生成的 32 字节 IKM，使用服务端主密钥封存并返回 `token_id` |
| `POST /v1/keys/fetch` | 校验设备签名或 Play Integrity 证明，原子消费 nonce，使用本次请求的 RSA 公钥加密返回 IKM |

当前协议版本为 `fetch_protocol: 2`。接口路径里的 `/v1` 与协议号是两个不同标识。

## 设计范围

- 一个应用策略绑定租户、应用、包名、最终签名证书 SHA-256、授权方式、策略版本和启用状态。
- 每个产物 IKM 独立随机生成，由当前密钥后端封存：本机 `local_aead` 使用自有 32 字节主密钥和 AES-256-GCM；`aws_kms`、`gcp_kms` 使用云 KMS 的 Encrypt/Decrypt 与认证上下文；`hsm_pkcs11` 使用 HSM 内的 AES-256-GCM 密钥。主密钥/HSM 密钥不进入数据库，也不进入 APK。
- 设备公钥登记为待批准后，必须由管理员通过命令行批准；撤销、有效期和 token 撤销同样由管理员完成。
- Play 模式在服务端调用 Google Play Integrity Classic API 解码证明，校验包名、versionCode、证书摘要、nonce、时间窗、应用识别、许可和设备完整性。
- 构建 API key 只保存 SHA-256 哈希，原文只显示一次。构建凭据不能调用管理命令。
- 管理操作写入 `admin_audit`，不提供管理 HTTP 接口。
- 日志不记录 Authorization、请求正文、IKM、完整证明或响应密文。

服务端已包含 `local_aead`、AWS KMS、GCP KMS（含 Cloud HSM 密钥）和 PKCS#11 HSM 适配。AAB、iOS 属于 Shellsmith 客户端和构建链范围，不在本服务端参考实现内。`auth_mode` 或密钥后端不受支持时会拒绝，不会降级。

## 目录与仓库边界

服务端建议作为独立 Git 仓库放在 Shellsmith 仓库同级目录，例如：

```text
project-root/
├── mocika-shield/              Shellsmith 仓库
├── shellsmith-key-server/      服务端参考实现（独立 Git 仓库）
├── therouter-compat/
└── XopProtector/
```

不要将上级目录初始化成总仓库。服务端仓库的 `.gitignore` 只用于降低误提交概率；真实配置、主密钥、数据库备份必须放在仓库之外。

```text
/etc/shellsmith-key-server/
├── config.json
└── secrets/
    ├── database-url
    ├── master-2026-01.key              # local_aead 需要
    ├── gcp-kms-service-account.json    # gcp_kms 需要
    ├── hsm-pin                         # hsm_pkcs11 需要
    └── google-service-account.json     # play_integrity 需要
```

AWS KMS 默认使用 SDK 凭据链（环境变量、共享配置文件或 EC2/ECS 实例角色），不强制复制密钥文件。服务端仓库只提交 `config.example.json`、`config.*-kms.example.json`、`config.hsm-pkcs11.example.json`、代码、`schema.sql`、迁移、测试和部署模板。

## 架构

```text
Shellsmith / Android
        │ HTTPS
        ▼
Caddy / 反向代理 :443
        │ 本机连接
        ▼
Go 服务 127.0.0.1:8080
        ├── PostgreSQL
        ├── local_aead 本机主密钥
        ├── AWS KMS / GCP KMS / PKCS#11 HSM（按配置选择）
        └── Google Play Integrity API（仅 Play 模式）
```

- 反向代理负责 TLS、证书续期和 HTTPS 终结。
- Go 服务只监听本机回环地址。
- PostgreSQL 不对公网开放。
- 所有服务实例共享同一个 PostgreSQL；防重放唯一约束在数据库中完成。

## 环境要求

- Go 1.26 或更高版本。
- PostgreSQL 14 或更高版本。
- 生产环境使用 Caddy、Nginx 或云负载均衡器提供 HTTPS。
- 启用 Play Integrity 时需要系统 CA 证书，并能出站访问 Google HTTPS 服务。
- 启用 AWS KMS 时需要 AWS SDK 凭据链、目标区域和 KMS 密钥的 Encrypt/Decrypt/DescribeKey 权限。
- 启用 GCP KMS 时需要 `cloudkms` scope 的服务账号 JSON，以及目标 CryptoKey 的 Encrypt/Decrypt/Get 权限；GCP Cloud HSM 密钥也通过同一 API 使用。
- 启用 PKCS#11 HSM 时需要厂商 PKCS#11 模块、token、PIN 文件和支持 `CKM_AES_GCM` 的 AES-256 密钥；二进制必须用 `CGO_ENABLED=1` 和 `-tags pkcs11` 构建。
- Android 侧按 Shellsmith BYOS 接入要求使用 Android 10 及以上。

## 本地启动

### 1. 创建数据库

```bash
createdb shellsmith_keys
```

数据库用户需要拥有目标 schema 的建表和变更权限。服务启动时会幂等执行 `schema.sql`，并在检测到 v1 时自动迁移到 v2；也可以先由 DBA 手工执行。

### 2. 生成主密钥

```bash
mkdir -p ./secrets
chmod 700 ./secrets
go run . init-master-key --file ./secrets/master-2026-01.key
chmod 600 ./secrets/master-2026-01.key
```

命令使用 `O_EXCL` 创建文件，绝不覆盖已有主密钥。主密钥必须恰好为 32 字节。文件缺失、长度错误或同组/其他用户可读写时，服务会拒绝启动；数据库中存在未配置的旧密钥版本同样会拒绝启动。

### 3. 准备连接文件

```bash
printf '%s' 'postgres://shellsmith:change-me@127.0.0.1:5432/shellsmith_keys?sslmode=disable' \
  > ./secrets/database-url
chmod 600 ./secrets/database-url
```

### 4. 写配置

复制 `config.example.json` 为 `config.json`，把数据库、主密钥和（启用 Play 时的）Google 凭据路径改成绝对路径：

```json
{
  "listen": "127.0.0.1:8080",
  "public_base_url": "https://keys.example.com",
  "database_url_file": "/absolute/path/secrets/database-url",
  "key_backend": {
    "kind": "local_aead",
    "active_version": "master-2026-01",
    "key_files": {
      "master-2026-01": "/absolute/path/secrets/master-2026-01.key"
    }
  },
  "request_window_seconds": 300,
  "replay_retention_seconds": 600,
  "pending_device_limit": 500,
  "play_integrity": {
    "credentials_file": "/absolute/path/secrets/google-service-account.json",
    "request_timeout_seconds": 5
  }
}
```

`public_base_url` 必须与 Shellsmith 填写的 HTTPS 基础地址完全一致，末尾不能有 `/`，不能带查询参数、片段、用户信息或反斜线。可以带路径，例如 `https://keys.example.com/shellsmith`；服务同时接受带该路径和去掉该路径的 `/v1/keys/*` 请求，便于反向代理选择是否剥离前缀。

以上是本机 `local_aead` 起点。使用 AWS KMS、GCP KMS 或 PKCS#11 HSM 时，分别以 `config.aws-kms.example.json`、`config.gcp-kms.example.json`、`config.hsm-pkcs11.example.json` 为基础；一个服务进程只启用一个 `key_backend.kind`。多后端迁移见“主密钥与后端迁移”。

### 5. 创建应用策略

```bash
go run . admin --config ./config.json init-app \
  --tenant-id customer-001 \
  --application-id app-001 \
  --package-name com.example.app \
  --cert-sha256 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF \
  --policy-version 1
```

`--cert-sha256` 必须是最终安装 APK 所用签名证书的 SHA-256，64 位大写十六进制。不是上传证书，也不是调试证书。

Play Integrity 应用使用不同命令创建，并绑定允许的 versionCode：

```bash
go run . admin --config ./config.json init-app \
  --auth-mode play_integrity \
  --tenant-id customer-001 \
  --application-id app-play-001 \
  --package-name com.example.playapp \
  --cert-sha256 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF \
  --policy-version 1 \
  --version-codes 100,101 \
  --require-play-recognized=true \
  --require-licensed=true \
  --require-device-integrity MEETS_DEVICE_INTEGRITY
```

Play 应用创建后需要重启一次服务，使服务端在启动时初始化 Google 验证客户端。`play_integrity` 配置在数据库中没有 Play 应用时可以暂时不存在；一旦存在 `play_integrity` 策略，启动时必须提供有效配置。只使用设备批准时，可以从 `config.example.json` 中删除整个 `play_integrity` 块。

### 6. 创建构建 API key

```bash
go run . admin --config ./config.json create-api-key \
  --application-id app-001 \
  --label build-pc
```

输出类似：

```text
构建 API key 已创建，key_id=1。以下原文只显示这一次：
n9CPJcaKr2FemgKWeWP77MWPOiQaaJsmW2qLJzxQ8Z4
```

只把原文保存到加固电脑或 CI 的秘密存储，不要提交到仓库，不要写入 APK。

### 7. 启动

```bash
go run . serve --config ./config.json
```

服务默认监听 `127.0.0.1:8080`。生产环境前面应有一个提供 HTTPS 的反向代理。

### 8. 连接检查

```bash
API_KEY='上一步生成的 key'
curl -sS -X POST http://127.0.0.1:8080/v1/keys/check \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $API_KEY" \
  --data '{"auth_mode":"device_approval","fetch_protocol":2,"request_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
```

成功响应严格只有五个字段：

```json
{"service":"shellsmith-byos","authorized":true,"auth_mode":"device_approval","fetch_protocol":2,"request_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

主密钥缺失或无法完成自检时返回 HTTP 503，正文严格为：

```json
{"error":"KEY_BACKEND_UNAVAILABLE"}
```

## 密钥后端

服务端支持四种互斥的 `key_backend.kind`：

| kind | 封存方式 | 凭证/材料 |
|---|---|---|
| `local_aead` | 本机 AES-256-GCM，每次新 12 字节 nonce | `key_files` 指向的 32 字节主密钥 |
| `aws_kms` | AWS KMS `Encrypt`/`Decrypt`，AAD 作为 EncryptionContext | AWS SDK 凭据链、region、key ID/ARN |
| `gcp_kms` | GCP KMS `encrypt`/`decrypt`，AAD 作为 additionalAuthenticatedData | 服务账号 JSON、CryptoKey 资源名 |
| `hsm_pkcs11` | HSM 内 AES-256-GCM，AAD 作为 GCM AAD | PKCS#11 模块、token、PIN、AES 密钥标签 |

授权方式（`device_approval` / `play_integrity`）与密钥后端相互独立，可以组合使用。每个产物记录 `key_backend` 和 `key_version`。服务启动时要求数据库中所有产物的后端与当前配置一致、所有版本都在当前后端可用；否则拒绝启动并提示先执行迁移。

### AWS KMS

示例配置见 `config.aws-kms.example.json`：

```json
"key_backend": {
  "kind": "aws_kms",
  "active_version": "aws-2026-01",
  "aws_kms": {
    "region": "ap-northeast-1",
    "profile": "",
    "key_ids": {
      "aws-2026-01": "arn:aws:kms:ap-northeast-1:123456789012:key/REPLACE_WITH_KEY_ID"
    }
  }
}
```

- 使用 AWS SDK 默认凭据链，推荐 EC2/ECS 实例角色；`profile` 可指定共享配置文件中的 profile。
- 密钥必须是启用的对称 `ENCRYPT_DECRYPT` KMS 密钥。
- 运行身份需要 `kms:Encrypt`、`kms:Decrypt`、`kms:DescribeKey`。
- 服务启动和 `/v1/keys/check` 的就绪检查会调用 `DescribeKey` 并用活动密钥做一次 Encrypt/Decrypt 往返；结果缓存 30 秒。
- AAD 会编码进 KMS EncryptionContext，云审计日志可以看到上下文摘要，但不会看到 IKM。

### GCP KMS / Cloud HSM

示例配置见 `config.gcp-kms.example.json`：

```json
"key_backend": {
  "kind": "gcp_kms",
  "active_version": "gcp-2026-01",
  "gcp_kms": {
    "credentials_file": "/etc/shellsmith-key-server/secrets/gcp-kms-service-account.json",
    "request_timeout_seconds": 10,
    "key_names": {
      "gcp-2026-01": "projects/PROJECT/locations/global/keyRings/RING/cryptoKeys/KEY"
    }
  }
}
```

- 服务账号 JSON 权限必须为 `0600`，scope 为 `https://www.googleapis.com/auth/cloudkms`。
- CryptoKey 必须是 `ENCRYPT_DECRYPT`；如需 HSM 保护，在创建 CryptoKey 时选择 Cloud HSM。
- 运行身份需要 `cloudkms.cryptoKeys.get`、`cloudkms.cryptoKeyVersions.useToEncrypt`、`cloudkms.cryptoKeyVersions.useToDecrypt`。
- AAD 作为 `additionalAuthenticatedData` 发送。
- 就绪检查会读取每个 CryptoKey 并用活动密钥做一次 encrypt/decrypt 往返；结果缓存 30 秒。

### PKCS#11 HSM

示例配置见 `config.hsm-pkcs11.example.json`：

```json
"key_backend": {
  "kind": "hsm_pkcs11",
  "active_version": "hsm-2026-01",
  "hsm_pkcs11": {
    "module_path": "/usr/lib/softhsm/libsofthsm2.so",
    "token_label": "shellsmith",
    "slot": 0,
    "pin_file": "/etc/shellsmith-key-server/secrets/hsm-pin",
    "key_labels": {
      "hsm-2026-01": "byos-master-2026-01"
    }
  }
}
```

- 需要厂商 PKCS#11 模块；token 中每个版本必须有唯一的 AES-256 密钥对象，并支持 `CKM_AES_GCM`、加密和解密。
- 可用厂商工具或 `pkcs11-tool` 创建持久密钥对象：`CKO_SECRET_KEY`、`CKK_AES`、32 字节值、`CKA_ENCRYPT=true`、`CKA_DECRYPT=true`、`CKA_TOKEN=true`，标签与 `key_labels` 一致。
- 配置 `token_label` 时按 token 标签选槽；未配置时按 `slot` 索引选槽。
- PIN 文件权限必须为 `0600`，只保存 PIN 原文。
- HSM 后端使用 cgo 动态加载模块，必须单独构建：

  ```bash
  CGO_ENABLED=1 go build -tags pkcs11 -trimpath -o shellsmith-key-server .
  # 或
  make build-pkcs11
  ```

- 未使用 `-tags pkcs11` 构建时，`hsm_pkcs11` 会明确报错，不会静默回退。
- HSM 会话在进程内串行使用；高并发部署建议增加实例或使用厂商支持的会话池，当前实现优先保证正确性。
- SoftHSM 可用于本地联调；生产环境必须用实际 HSM 做封存/解封和故障恢复验收。

所有后端都必须满足：封存结果只能在相同 AAD 下解封；解封结果恰好 32 字节；缺失版本、权限不足、网络超时或认证失败都拒绝，不尝试默认密钥或其他租户配置。

## 配置字段

| 字段 | 说明 |
|---|---|
| `listen` | Go 服务监听地址，生产环境建议 `127.0.0.1:8080` |
| `public_base_url` | 与 Shellsmith 完全一致的 HTTPS 基础地址 |
| `database_url_file` | 保存一行 PostgreSQL 连接串的绝对路径；文件权限必须为 `0600` 或更严格 |
| `key_backend.kind` | `local_aead`、`aws_kms`、`gcp_kms` 或 `hsm_pkcs11` |
| `key_backend.active_version` | 新注册产物使用的当前版本 |
| `key_backend.key_files` | `local_aead` 的版本到 32 字节主密钥文件绝对路径映射 |
| `key_backend.aws_kms.region` | AWS KMS 区域 |
| `key_backend.aws_kms.profile` | 可选 AWS shared config profile |
| `key_backend.aws_kms.key_ids` | 版本到 KMS key ID/ARN 的映射 |
| `key_backend.gcp_kms.credentials_file` | GCP 服务账号 JSON 绝对路径，权限 `0600` |
| `key_backend.gcp_kms.key_names` | 版本到 CryptoKey 资源名的映射 |
| `key_backend.gcp_kms.request_timeout_seconds` | GCP KMS 调用超时，默认 10，范围 1..30 |
| `key_backend.hsm_pkcs11.module_path` | 厂商 PKCS#11 模块绝对路径 |
| `key_backend.hsm_pkcs11.token_label` | 可选 token 标签；与 `slot` 二选一优先 |
| `key_backend.hsm_pkcs11.slot` | token 槽索引 |
| `key_backend.hsm_pkcs11.pin_file` | PIN 文件绝对路径，权限 `0600` |
| `key_backend.hsm_pkcs11.key_labels` | 版本到 HSM AES 密钥标签的映射 |
| `request_window_seconds` | 取钥请求时间窗，默认 300，范围 1..3600 |
| `replay_retention_seconds` | 防重放记录保留时间，必须不小于时间窗，默认 600 |
| `pending_device_limit` | 每个应用/证书最多保留的待批准设备数，默认 500 |
| `play_integrity.credentials_file` | Google 服务账号 JSON 的绝对路径，权限 `0600`；仅 Play 应用需要 |
| `play_integrity.request_timeout_seconds` | 调用 Play Integrity API 的超时，默认 5，范围 1..10 |

配置文件本身使用严格 JSON 解析：重复字段、未知字段和错误类型都会导致启动失败。

## 管理员命令

管理命令通过 SSH 登录服务器执行。`--config` 必须放在子命令之前：

```bash
shellsmith-key-server admin --config /etc/shellsmith-key-server/config.json <command> [flags]
```

| 命令 | 作用 |
|---|---|
| `init-app` | 创建 `device_approval` 或 `play_integrity` 应用策略 |
| `update-cert` | 更新应用最终证书并要求递增 `--policy-version`；旧产物保留旧证书快照 |
| `update-play-policy` | 更新 Play 应用的 versionCode、许可、应用识别和设备完整性策略，必须递增 `--policy-version` |
| `list-apps` | 列出应用策略 |
| `enable-app` / `disable-app` | 启用或停用应用；停用后检查和注册都会被拒绝 |
| `create-api-key` | 生成构建 API key，原文只显示一次 |
| `revoke-api-key` | 按 `--key-id` 撤销构建凭据 |
| `list-api-keys` | 列出构建凭据，不显示原文 |
| `list-artifacts` | 列出产物 token、策略版本、主密钥版本和状态，不显示 IKM |
| `list-devices` | 列出设备，可按 `--status pending/approved/revoked` 过滤 |
| `approve-device` | 批准设备，可设置 `--expires-at` |
| `set-device-expiry` | 修改到期时间，`--expires-at never` 表示长期有效 |
| `revoke-device` | 撤销设备，后续取钥立即失败 |
| `revoke-artifact` | 按 token 撤销产物 |
| `rotate-artifacts` | 在同一密钥后端内重新封存到新版本，保持 token 和 IKM 不变 |
| `migrate-backend` | 用 `--from-config` 提供旧后端配置，把产物迁移到当前配置的目标后端/版本 |
| `list-audit` | 查看管理审计记录，默认最近 100 条 |

到期时间参数接受 RFC3339（例如 `2027-01-01T00:00:00Z`）或 Unix 秒。`approve-device` 不填到期时间表示长期有效。

管理命令的审计记录包含操作者（优先读取 `SUDO_USER`，否则 `USER`/`LOGNAME`）、动作、应用、目标、详情和时间。构建 API key 原文和 IKM 不会写入审计。

## 设备批准流程

1. Shellsmith 使用构建 API key 注册产物，获得 `token_id`。
2. APK 首次启动时，Android 生成或复用设备 EC P-256 密钥，并构造取钥请求。
3. 服务端验证请求摘要、设备签名和 token 策略；设备未知时登记为 `pending`，仍返回 403。
4. 管理员查看待批准设备：

   ```bash
   shellsmith-key-server admin --config /etc/shellsmith-key-server/config.json \
     list-devices --application-id app-001 --status pending
   ```

   输出中的 `device_key_id` 是设备公钥 DER SPKI 的 SHA-256 小写十六进制。

5. 核对设备来源后批准：

   ```bash
   shellsmith-key-server admin --config /etc/shellsmith-key-server/config.json \
     approve-device --application-id app-001 \
     --cert-sha256 <最终证书指纹> \
     --device-key-id <上面的 device_key_id> \
     --expires-at 2027-12-31T23:59:59Z
   ```

6. 应用重新发起取钥请求后成功。取钥响应只包含 RSA-OAEP 密文，不包含明文 IKM。
7. 撤销：

   ```bash
   shellsmith-key-server admin --config /etc/shellsmith-key-server/config.json \
     revoke-device --application-id app-001 \
     --cert-sha256 <最终证书指纹> \
     --device-key-id <device_key_id>
   ```

撤销影响后续取钥，不能收回已经进入授权进程的 IKM 或明文。

### 设备识别与复用

- 设备 ID 是 SPKI DER 的 SHA-256，不使用设备名称、IP 或客户端自报身份。
- 同一服务地址、包名和最终证书下可跨 APK 版本和 token 复用设备密钥。
- 清数据、卸载、密钥失效或证书变化后需要重新批准。
- 服务端核对完整公钥，不只核对设备 ID。

## Play Integrity 接入

### Google 侧准备

1. 在 Play Console 启用 Play Integrity，并把应用关联到 Google Cloud 项目。
2. 使用 Play Integrity Classic API；客户端不传 `cloudProjectNumber`。
3. 创建只具备 Play Integrity 调用权限的 Google 服务账号，下载 JSON 凭据。
4. 把凭据放到仓库外，例如 `/etc/shellsmith-key-server/secrets/google-service-account.json`，权限 `0600`。
5. 在 `config.json` 中配置 `play_integrity.credentials_file`，设置 `request_timeout_seconds`，默认 5 秒。
6. 服务器需要能出站访问 `oauth2.googleapis.com` 和 `playintegrity.googleapis.com`。

服务端使用 scope `https://www.googleapis.com/auth/playintegrity` 获取 OAuth access token，并调用：

```text
POST https://playintegrity.googleapis.com/v1/{服务端记录包名}:decodeIntegrityToken
```

请求体为 `{"integrity_token":"..."}`。Google 返回的 `tokenPayloadExternal` 才会被信任；服务端不会只解析客户端提交的 URL-safe token。

### 服务端校验

Play 取钥请求不携带 `device_public_key` 和 `device_signature`，改为携带字符串字段 `integrity_token`。其余字段和摘要规则不变，摘要最后一个字段为空字符串。

服务端按顺序校验：

| 校验项 | 要求 |
|---|---|
| 服务端策略 | 先按 token 读取产物策略快照，确认授权方式为 `play_integrity`、包名和证书匹配 |
| Google 调用 | 使用服务端包名调用 Classic API，不能让请求里的包名决定 Google 目标 |
| 请求绑定 | `requestDetails.requestPackageName`、`requestDetails.nonce` 与本次请求一致 |
| 时间 | `timestampMillis` 与当前时间、请求时间均不超过 300 秒 |
| 应用识别 | `appRecognitionVerdict` 为 `PLAY_RECOGNIZED`（策略开启 require 时强制） |
| 包名 | `appIntegrity.packageName` 与服务端策略一致 |
| 版本 | `appIntegrity.versionCode` 在策略的 `play_version_codes` 中 |
| 证书 | `appIntegrity.certificateSha256Digest` Base64URL 解码为 32 字节后，与策略 SHA-256 匹配 |
| 许可 | `appLicensingVerdict` 为 `LICENSED`（策略开启 require 时强制） |
| 设备完整性 | `deviceRecognitionVerdict` 包含策略要求的 `MEETS_DEVICE_INTEGRITY`、`MEETS_BASIC_INTEGRITY` 或 `MEETS_STRONG_INTEGRITY` |

缺字段、`UNEVALUATED`、未知结果、Google 拒绝、Google 超时、版本/证书/包名/许可/设备完整性不匹配都拒绝，不会回退到设备批准模式。Play 校验通过后才进入与设备模式相同的原子 nonce 消费、解封和 RSA-OAEP 加密流程。

### 策略更新

最终签名证书变化时，使用 `update-cert`，并且必须递增 `policy_version`：

```bash
shellsmith-key-server admin --config /etc/shellsmith-key-server/config.json \
  update-cert --application-id app-001 \
  --cert-sha256 <新的 64 位大写证书 SHA-256> \
  --policy-version 2
```

已有产物的证书快照不会改变；新注册产物使用新证书。旧 APK 仍按旧快照校验，避免证书轮换后已发布版本立即失效。

Play 策略更新必须递增 `policy_version`：

```bash
shellsmith-key-server admin --config /etc/shellsmith-key-server/config.json \
  update-play-policy --application-id app-play-001 \
  --policy-version 2 \
  --version-codes 100,101,102 \
  --require-play-recognized=true \
  --require-licensed=true \
  --require-device-integrity MEETS_DEVICE_INTEGRITY
```

已有产物的策略快照不会因为应用策略更新而改变；新注册产物使用新版本。若要让旧 token 采用新策略，需要重新注册并重新发布 APK。

### Play 验收

1. 最终签名、相同 versionCode 的加固 APK 通过 Play 测试轨道安装。
2. 允许结果取钥成功。
3. 错误包名、versionCode、证书、nonce、时间、许可、设备完整性或 `UNEVALUATED` 均失败。
4. Google 超时或 5xx 返回服务不可用，不返回 IKM。
5. 服务端、代理和 APM 日志没有完整 `integrity_token`。

## Shellsmith 接入

在 Shellsmith 的“密钥交付 → 新增服务”中填写：

| 字段 | 内容 |
|---|---|
| HTTPS 基础地址 | 与 `public_base_url` 完全一致，例如 `https://keys.example.com`，不要追加 `/v1/keys/fetch` |
| 构建 API key | 管理员生成的原文 |
| 授权方式 | `device_approval` 或 `play_integrity`，必须与服务端策略一致 |
| 最终证书指纹 | 最终安装 APK 所用签名证书的 SHA-256，与服务端策略一致 |

设备批准的验收顺序：

1. 测试连接通过，响应包含五个字段。
2. 加固并签名 APK，安装包的证书与策略一致。
3. 首次启动被拒绝，服务端出现 `pending` 设备。
4. 管理员批准。
5. 应用重新启动并成功取钥。
6. 撤销设备后再次取钥失败。
7. 并发重放同一请求只允许一次成功。
8. 核对服务端、反向代理和 APM 日志中没有构建 API key、请求正文或 IKM。

Play 模式还要按上文“Play 验收”完成真实测试轨道验证；模拟服务或单元测试不能替代 Google 实际返回。

## 主密钥与后端迁移

轮换保持 **token 和 IKM 不变**，只更换数据库中的封存材料。旧 APK 不需要重新加固。

### 同一后端内轮换版本

以 `local_aead` 为例：

1. 生成新主密钥：

   ```bash
   shellsmith-key-server init-master-key --file /etc/shellsmith-key-server/secrets/master-2026-02.key
   chown shellsmith:shellsmith /etc/shellsmith-key-server/secrets/master-2026-02.key
   chmod 600 /etc/shellsmith-key-server/secrets/master-2026-02.key
   ```

2. 在 `config.json` 的 `key_files` 中同时保留旧版本和新版本，把 `active_version` 改为新版本，然后重启服务。此时新注册产物使用新版本，旧产物仍按记录中的旧版本解封。

3. 执行重新封存：

   ```bash
   shellsmith-key-server admin --config /etc/shellsmith-key-server/config.json \
     rotate-artifacts --to-version master-2026-02
   ```

   命令要求 `active_version` 已经是目标版本，逐个产物解封、重新封存并用 compare-and-swap 更新记录。

4. 使用旧 token 做一次真实取钥验收，确认 IKM 未变化。

5. 完成数据库备份和恢复验证后，才从配置中移除旧版本材料。旧材料与旧备份要分开保管。

AWS KMS、GCP KMS 和 PKCS#11 HSM 的流程相同，只是新版本对应：

- AWS：新增 `key_ids` 版本，指向新的对称 KMS key ID/ARN。
- GCP：新增 `key_names` 版本，指向新的 CryptoKey 资源名。
- HSM：在 token 中创建新的 AES-256-GCM 密钥对象，新增 `key_labels` 版本。

`rotate-artifacts` 只处理当前后端。它要求所有产物的 `key_backend` 与当前配置一致，否则拒绝并提示使用 `migrate-backend`。

### 切换密钥后端

从本机主密钥迁到 AWS KMS、GCP KMS 或 HSM，或在云 KMS 之间迁移时，使用 `migrate-backend`。它需要同时加载旧后端和目标后端。

1. 准备旧配置 `config.old.json`（当前生产配置）和目标配置 `config.new.json`。两者使用同一个 `database_url_file`；命令使用 `--config` 指定的数据库，`--from-config` 的数据库连接不会被使用。
2. 目标配置写入目标后端、目标 `active_version` 和目标凭证/密钥引用。
3. 停止旧服务，或安排维护窗口，避免迁移期间继续注册新产物。
4. 执行迁移：

   ```bash
   shellsmith-key-server admin --config /etc/shellsmith-key-server/config.new.json \
     migrate-backend --from-config /etc/shellsmith-key-server/config.old.json
   ```

   命令会先用两个后端各自做就绪检查，再把所有不是“目标后端 + 目标版本”的产物逐个用旧后端解封、用目标后端封存，并用 compare-and-swap 更新 `key_backend`/`key_version`。

5. 用旧 token 在目标配置下做真实取钥验收，确认 IKM 未变化。
6. 将 `config.new.json` 替换为生产配置，启动服务。
7. 观察一个完整发布周期后，再撤销旧 KMS 权限、移除旧 HSM 密钥或删除旧本机主密钥。旧备份按保留策略继续保存。

`migrate-backend` 支持 `--to-version` 指定目标版本；不填时使用目标配置的 `active_version`。如果中途失败，已迁移的记录会保留，未迁移记录仍是旧后端，重复执行是安全的。

### 启动检查

服务启动时会检查：

- 数据库中的所有 `key_version` 是否都在当前后端可用；
- 数据库中的所有 `key_backend` 是否都等于当前 `key_backend.kind`；
- 当前后端所有已配置版本是否能完成封存/解封自检。

任一条件不满足都会拒绝启动，不会用默认密钥、其他版本或其他后端代替。

## 备份与恢复

需要同时备份：

- PostgreSQL 数据库（`pg_dump -Fc`）。
- 配置文件（含后端类型、版本映射和密钥引用，不含秘密原文）。
- `local_aead`：`secrets/` 下所有历史主密钥文件。
- `gcp_kms`：GCP 服务账号 JSON；同时确认 CryptoKey 未被删除且 IAM 权限可恢复。
- `aws_kms`：确认 KMS key/ARN 未被删除、key policy 和调用身份可恢复；AWS 凭据由实例角色或外部秘密管理，不应写进仓库。
- `hsm_pkcs11`：PIN 文件、token/密钥标签清单和 HSM 自身的密钥备份。只备份数据库和 PIN 不能恢复 HSM 内不可导出的密钥。
- 启用 Play 时的 Google 服务账号 JSON。

数据库备份和密钥材料必须分开控制访问权限。只有数据库而没有对应本机主密钥、KMS key 或 HSM 密钥，库中的 IKM 无法恢复；只有密钥而没有数据库，也无法恢复 token 映射。

恢复时把数据库、配置和对应版本的后端材料一起恢复，再启动服务。不要用新生成的密钥替换丢失的旧密钥；也不要删除仍被历史产物引用的 KMS key 或 HSM 密钥对象。

## 生产部署

### systemd

```bash
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin shellsmith
sudo install -d -m 0700 -o shellsmith -g shellsmith /etc/shellsmith-key-server
sudo install -d -m 0700 -o shellsmith -g shellsmith /etc/shellsmith-key-server/secrets
sudo install -m 0755 shellsmith-key-server /usr/local/bin/shellsmith-key-server
sudo install -m 0644 deploy/shellsmith-key-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shellsmith-key-server
```

`local_aead` 的主密钥应由服务账号生成，确保文件属主正确：

```bash
sudo -u shellsmith /usr/local/bin/shellsmith-key-server init-master-key \
  --file /etc/shellsmith-key-server/secrets/master-2026-01.key
```

### 密钥后端

- `local_aead`：安装普通静态二进制，`secrets/` 和主密钥归 `shellsmith` 所有。
- `aws_kms`：优先使用 EC2/ECS 实例角色；不要安装静态 AWS access key。确认实例角色有目标密钥的 Encrypt/Decrypt/DescribeKey 权限和出站 HTTPS。
- `gcp_kms`：把服务账号 JSON 放到 `secrets/`，`chown shellsmith`、`chmod 600`；确认服务账号有 CryptoKey 的 Get/Encrypt/Decrypt 权限和出站 HTTPS。
- `hsm_pkcs11`：必须使用带 PKCS#11 的二进制：

  ```bash
  CGO_ENABLED=1 go build -tags pkcs11 -trimpath -o shellsmith-key-server .
  sudo install -m 0755 shellsmith-key-server /usr/local/bin/shellsmith-key-server
  ```

  同时确认运行用户能读取厂商 PKCS#11 模块、能打开 token 会话，且 `hsm-pin` 权限为 `0600`。HSM 客户端库可能需要额外的系统包或 `LD_LIBRARY_PATH`。

### Caddy

`deploy/Caddyfile.example` 提供自动 HTTPS、HSTS 和日志过滤示例。Caddy 默认会把 `Authorization`、`Cookie` 等敏感头记为 `REDACTED`，示例仍显式删除这些字段，避免依赖版本默认行为。应用自身不会记录这些头。

如果 `public_base_url` 带路径 `/shellsmith`，反向代理既可以保留路径（本服务兼容），也可以剥离前缀。

### PostgreSQL

- 只监听本机或私网，不对公网开放。
- 使用独立数据库用户和强密码。
- 数据库连接串放在 `database-url` 文件，权限 `0600`。
- 生产环境启用定期备份和恢复演练。
- 多实例部署时，所有实例必须连接同一数据库；防重放和授权状态以数据库为准。

### 反向代理限流

服务内置单实例固定窗口限流：每个构建 API key 或设备密钥每分钟 60 次，并对每个应用/证书限制待批准设备数量。生产环境仍建议在 Caddy/Nginx/云防火墙配置基于来源 IP 的限流和告警，尤其是在公开暴露 `/v1/keys/fetch` 时。多实例部署时，内存限流器各自独立，边缘限流更重要。

## 安全设计

### 请求处理

- 检查 4 KiB、注册 16 KiB、取钥 64 KiB 的请求体上限。
- 严格拒绝重复 JSON 字段、未知字段、错误类型、顶层非对象和末尾多余内容。
- 只接受 `Content-Type: application/json`。
- 成功和失败响应都设置 `Cache-Control: no-store`，响应 `Content-Type` 固定为 `application/json`。
- 错误只返回固定代码，不返回内部异常、SQL、密钥版本或堆栈。

### 构建凭据

- API key 原文 32 字节随机值，Base64URL 无填充。
- 数据库只保存 SHA-256 哈希。
- `check` 和 `register` 都要求 `Authorization: Bearer <key>`。
- 凭据可被单独撤销；应用停用会同时阻止检查和注册。
- 构建凭据没有管理权限，管理操作只能通过数据库连接和 SSH 执行。

### IKM 封存

- `local_aead` 使用 AES-256-GCM，每次封存使用新的 12 字节随机 nonce。
- `aws_kms` 使用 KMS Encrypt/Decrypt，AAD 作为 EncryptionContext；`gcp_kms` 使用 KMS encrypt/decrypt，AAD 作为 additionalAuthenticatedData；`hsm_pkcs11` 使用 HSM 内 AES-256-GCM，AAD 作为 GCM AAD。
- 认证上下文使用固定字段、长度前缀编码，绑定租户、应用、token、包名、最终证书、授权方式和策略版本。
- 密文、nonce、密钥版本和后端类型写入数据库；本机主密钥、KMS 密钥材料和 HSM 密钥不写入数据库。
- 解封失败不尝试默认密钥、其他版本、其他后端或其他租户配置。
- 服务启动会检查所有产物的后端和版本都由当前配置覆盖。

### 取钥校验

- 校验 URL、包名、证书、授权方式、协议、时间窗、规范 Base64 和 32 字节 request_id/nonce。
- 响应公钥必须是 RSA-2048、指数 65537、DER SPKI；设备公钥必须是 P-256 DER SPKI。
- 设备签名是 DER ECDSA。客户端使用 `SHA256withECDSA` 对 32 字节请求摘要签名，因此服务端验证前再计算一次 `SHA256(digest)`，再交给 `ecdsa.VerifyASN1`。
- 响应加密使用 RSA-OAEP，摘要和 MGF1 都是 SHA-256，label 为空，明文为 `digest[32] || IKM[32]`。
- Play 模式先用服务端策略中的包名调用 Google Classic API，再校验 `tokenPayloadExternal` 的包名、nonce、时间、versionCode、证书、许可和设备完整性；不会信任客户端本地解析结果。
- 授权通过后，在数据库中原子插入 `(application_id, nonce)`；唯一约束保证并发重放最多一次成功。nonce 在解封和响应加密之前提交，后续失败不会恢复可用。
- 产物、应用策略和设备记录在事务中使用行共享锁；管理员撤销/停用使用行更新锁，避免“检查已通过但撤销同时发生”的竞态。
- Google 服务账号 JSON 按秘密文件读取，权限必须为 `0600`；Play 调用超时默认 5 秒。Google 400 视为证明被拒绝，401/403/429/5xx 和超时视为服务依赖不可用。

### 日志

- 不记录 Authorization、请求体、IKM、响应密文或完整证明。
- 请求日志只记录方法、路径、状态和耗时。
- 内部错误日志只记录错误类型和数据库错误，不打印秘密。
- 反向代理必须过滤 `Authorization`，示例 Caddyfile 已处理。

## 测试

只运行不需要数据库的单元测试：

```bash
go test ./...
```

运行 PostgreSQL 集成测试：

```bash
TEST_DATABASE_URL='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' \
  go test -race -count=2 ./...
```

测试覆盖：

- 协议附录的请求摘要固定向量。
- 严格 JSON：重复字段、未知字段、末尾内容和嵌套。
- 本机主密钥封存/解封、AAD 绑定和篡改拒绝。
- AWS KMS 和 GCP KMS 后端的封存、解封、上下文和就绪检查（使用模拟客户端，不需要云凭据）。
- 跨后端迁移：AWS KMS → GCP KMS 的 token/IKM 不变。
- PKCS#11 HSM 代码用 `CGO_ENABLED=1 go test -tags pkcs11 ./...` 编译验证；真实 HSM 需要硬件验收。
- 检查接口严格五个字段和后端不可用 503。
- 未知设备 pending → 管理员批准 → 取钥成功 → 撤销后失败。
- 同一请求 16 路并发重放只成功一次。
- 主密钥轮换后 token 和 IKM 不变。
- Play 模式：检查、注册、取钥、RSA-OAEP 解密、nonce 重放，以及包名、versionCode、证书、许可、设备完整性、应用识别和时间的拒绝分支。
- Play 策略和证书更新后，旧产物保留旧快照，新产物使用新快照。
- Play 证明载荷对证书摘要单值/数组、versionCode 字符串/数字的兼容解析。
- 构建 API key/设备速率限制。
- v1 schema 经 v2 到 v3 的迁移，以及旧设备策略、可变长 KMS 密文的约束。
- 配置安全校验和秘密文件权限。

没有设置 `TEST_DATABASE_URL` 时，集成测试会跳过，不会连接本地数据库。测试会为每个用例创建独立 schema 并在结束后删除。

只编译 PKCS#11 构建：

```bash
CGO_ENABLED=1 go test -tags pkcs11 ./...
```

有 SoftHSM 或真实 HSM 时可运行真实封存/解封测试：

```bash
SOFTHSM2_CONF=/path/softhsm2.conf \
TEST_HSM_MODULE=/path/libsofthsm2.so \
TEST_HSM_TOKEN=shellsmith \
TEST_HSM_PIN_FILE=/path/hsm-pin \
TEST_HSM_KEY_LABEL=byos-master-2026-01 \
CGO_ENABLED=1 go test -tags pkcs11 -run TestHSMPKCS11Backend -v
```

真实 AWS/GCP KMS 验收仍需要对应凭据、密钥和权限；模拟客户端只能验证适配逻辑和协议行为。

## 已知边界

- 支持 `device_approval` 和 `play_integrity`；支持 `local_aead`、AWS KMS、GCP KMS（含 Cloud HSM）和 PKCS#11 HSM 密钥后端。AAB、iOS 不在本服务端参考实现范围内。
- Play 模式依赖 Google Play Integrity Classic API、Google Cloud 服务账号和 Play Console 配置；本参考实现只包含服务端调用与校验，不代管 Google 配额或项目。
- 新增 Play 应用后需要重启服务，让启动检查初始化 Google 验证客户端。
- AWS/GCP KMS 依赖对应云服务、凭据、权限和网络；参考实现内测试使用模拟客户端，不代替真实云验收。
- PKCS#11 HSM 需要 `CGO_ENABLED=1`、`-tags pkcs11`、厂商模块和实际 token；参考实现只做编译和逻辑验证，不代替硬件验收。
- 不提供管理 HTTP 页面，管理操作通过 SSH 和命令行完成。
- 内存限流器是单实例的；多实例部署需要在反向代理或共享存储中做全局限流。Play 取钥请求不做共享 token 级限流，避免同一产物的大量正常用户被互相限流，生产环境应在边缘按来源限流。
- 主密钥轮换、`migrate-backend` 后端切换和 KMS/HSM 密钥轮换都是人工维护操作，没有自动调度。
- 服务启动自动执行 `schema.sql` 的幂等建表语句，并支持从 v1 经 v2 迁移到 v3；后续结构变更仍应继续添加迁移文件。
- 数据库与本机主密钥、KMS key 或 HSM 密钥同时泄漏/失控时，攻击者可以解封全部 IKM。访问权限和备份必须分开控制。

## 常见问题

| 现象 | 排查 |
|---|---|
| `401 UNAUTHORIZED` | API key 错误、被撤销，或应用被停用 |
| `403 ACCESS_DENIED` | 授权方式、协议、URL、包名、证书不匹配；设备未批准/过期/撤销；nonce 重放 |
| `503 KEY_BACKEND_UNAVAILABLE` | 活动版本缺失、密钥材料损坏、KMS/HSM 权限不足、后端类型不匹配或封存/解封自检失败 |
| `503 SERVICE_UNAVAILABLE` | 数据库、Play Integrity、AWS/GCP KMS 依赖或内部服务不可用；检查服务日志、PostgreSQL 和云服务配置 |
| 检查 200，但 Android 取钥失败 | 核对最终证书、包名、`public_base_url`、授权模式；设备模式检查批准状态，Play 模式检查 Google 返回和时间窗 |
| Play 取钥返回 503 | 检查服务账号 JSON 权限、Google 项目/API 启用状态、网络和超时 |
| Play 取钥返回 403 | 检查 nonce、包名、versionCode、证书、许可、设备完整性、应用识别和时间是否匹配策略 |
| 启动报“文件权限过宽” | `chmod 600` 秘密文件，确保主密钥、GCP/HSM/Play 凭据和数据库连接文件不是同组/其他用户可读写 |
| 启动报“产物仍使用其他密钥后端” | 用 `admin migrate-backend --from-config <旧配置>` 完成迁移后再启动 |
| 启动报“引用了未配置的主密钥版本” | 把历史 KMS key、GCP CryptoKey 或 HSM 密钥标签补回配置，或先完成迁移 |
| 启动报 PKCS#11 未编译 | 使用 `CGO_ENABLED=1 go build -tags pkcs11` 或 `make build-pkcs11` |
| AWS KMS 自检失败 | 检查 region、key ID/ARN、实例角色、`Encrypt`/`Decrypt`/`DescribeKey` 权限和出站网络 |
| GCP KMS 自检失败 | 检查服务账号 JSON 权限、CryptoKey 资源名、IAM 和 `cloudkms` API |
| HSM 自检失败 | 检查模块路径、token 标签/槽位、PIN、AES-256 密钥标签和 `CKM_AES_GCM` 支持 |
| 本机主密钥文件丢失 | 从独立备份恢复原文件；不要生成替换密钥，否则已有 IKM 无法解封 |
| KMS key/HSM 密钥丢失 | 从云端/HSM 备份恢复原密钥；新建密钥不能解封历史 IKM |
