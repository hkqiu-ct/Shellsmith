# 1.10.0 发布检查清单

> 本清单对应 `next` 集成分支。`main` 在全部条目完成前保持 1.9.0，不因普通 PR 合并触发 Release。

## 1. 分支与集成

- [ ] `next` 从最新 `main` 创建，并保持可构建。
- [ ] 所有计划进入 1.10.0 的 PR 目标分支为 `next`，不使用 `main`。
- [ ] 每个 PR 合入 `next` 前通过 `CI 通过` 门禁。
- [ ] 每个 PR 合入后在 `next` 上重新跑一次完整 CI，确认组合结果。
- [ ] 发布前创建 `next -> main` 的唯一发布 PR，禁止直接推送 `main`。

## 2. 功能与修复

- [ ] TheRouter 编译期注册兼容已合入，并通过 `check-therouter-compat.py` 三态检查。
- [ ] TheRouter 真实多模块样本完成一次页面跳转/服务注入设备验证。
- [ ] 启用 `--protect-route-assets` 的产物完成一次 ARouter/TheRouter 页面跳转和设备启动验证。
- [ ] 发布流程已改为手动触发，普通 PR 合并不再产生 Release。
- [ ] Dependabot 与 `cargo-deny` 已接入，首个扫描结果有处理记录。
- [ ] BYOS 威胁模型与边界文档已合入。
- [ ] 计划进入本版本的 iOS/路由 assets 等主题已完成对应验收；未完成项移出本版本，不阻塞补丁修复。

## 3. 自动化验证

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy -p shield-core -p shield-ios -p shield-cli --all-targets -- -D warnings`
- [ ] `cargo test -p shield-core`
- [ ] `cargo test -p shield-ios`
- [ ] `cargo test -p shield-cli`
- [ ] `cargo test --manifest-path shield-stub/src/main/rust/Cargo.toml`
- [ ] `python3 -m unittest discover -s scripts/tests -v`
- [ ] GUI：`node --test tests/*.test.mjs`、`npm run lint`、`npm run typecheck`、`npm run build`
- [ ] `make test-pvm2`
- [ ] `make test-pvm2-runtime`
- [ ] `make test-fusion`
- [ ] `make build-stub build-byos build-byos-play`
- [ ] `bash tests/scripts/run-protect-e2e.sh`
- [ ] `python3 tests/scripts/check-therouter-compat.py --cli target/release/shield`（脚本已启用 `--protect-route-assets`，断言只存在 `.rtap`、不存在明文 `.txt`）
- [ ] `bash scripts/check-release-ready.sh`
- [ ] `make audit-stub-dex`

## 4. 平台与产物

- [ ] Linux AppImage/deb 构建与启动冒烟。
- [ ] macOS Universal DMG 构建与启动冒烟；确认是否配置 Developer ID/公证。
- [ ] Windows x64 Setup 构建与启动冒烟；确认是否配置 Authenticode。
- [ ] Android runtime zip 包含标准资源、API 19 兼容资源和 PVM2 Packer。
- [ ] 三个平台的 SHA-256 校验文件齐全。
- [ ] `latest.json` 更新清单生成并通过签名校验。

## 5. 外部验证

- [ ] Android 真机矩阵：至少覆盖声明的最低 API、一个主流厂商 ROM、一个 16 KB 页大小设备。
- [ ] AAB：Google Play 内测轨道上传、Play App Signing 后的设备安装与启动。
- [ ] AAB：install-time、条件/按需 dynamic-feature 和 Asset Pack 生命周期。
- [ ] iOS：真实设备冷启动、后台恢复、深链、推送、权限和截图/录屏场景。
- [ ] BYOS：设备批准、撤销、Play Integrity、服务不可用和恢复流程。
- [ ] REA/白盒恢复回归按 `docs/design/rea-resilience.md` 记录，未验证项如实保留。

## 6. 发布动作

- [ ] 运行 `bash scripts/bump-version.sh 1.10.0`，同步全部版本文件和锁文件。
- [ ] 更新 `.github/release-notes/versions/1.10.0.md`，按实际合并内容补齐 PR 编号。
- [ ] 确认 `main` 上的发布 PR 已通过完整 CI（包括 `stub`、`linux-gui-bundle`、`windows-api19-resources`、`release-readiness`）。
- [ ] 合并发布 PR 到 `main`。
- [ ] 确认 GitHub Actions 中的 `Release` 工作流已启用（批量开发期间可手动禁用，避免 next 推送产生空运行）。
- [ ] 在 GitHub Actions 手动运行 `Release`，输入 `1.10.0`。
- [ ] 在 GitHub Actions 中确认 `Release` 工作流通过 `release` environment 审批，并由工作流创建 `v1.10.0` tag。
- [ ] 验证 Release 产物、更新清单和 `latest.json` 可下载且签名有效。
- [ ] 发布后删除已合并的临时分支，保留 `next` 或按下一版本重建。

## 7. 回滚

- [ ] 发布前保留上一稳定版本 `v1.9.0` 的产物和更新清单。
- [ ] 若发布后出现 P0 问题，优先修复并发布 1.10.1；不要覆盖已公开 Release。
- [ ] 若只是文档或说明错误，使用 Release 编辑修正，不重新构建产物。
