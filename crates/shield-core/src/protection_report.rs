//! 方法级验收记录。报告只包含标识和摘要，不包含密钥或明文镜像。
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MethodRecord {
    module: String,
    descriptor: String,
    required: bool,
    input_instruction_bytes: u64,
    input_dex: String,
    transform_status: String,
    reason: Option<String>,
    artifact_verified: bool,
    plaintext_policy: Option<String>,
    final_dex_index: Option<u32>,
    final_method_index: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DexRecord {
    pub module: String,
    input_sha256: String,
    output_sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct MethodReport {
    schema_version: u32,
    image_version: u32,
    code_version: u32,
    methods: Vec<MethodRecord>,
    pub dexes: BTreeMap<String, DexRecord>,
    code_sha256: String,
    #[serde(default)]
    pub build: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub metrics: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub artifact_dexes: BTreeMap<String, String>,
    #[serde(default)]
    pub output_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_vmp: Vec<crate::native_vmp::NativeRecord>,
}

pub(crate) fn sha256(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub(crate) fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// 自动报告位置；保留 APK/AAB 扩展名，避免同名产物互相覆盖。
pub fn report_path(artifact: &Path) -> PathBuf {
    let mut name = artifact.as_os_str().to_owned();
    name.push(".protection.json");
    PathBuf::from(name)
}

pub(crate) fn required_methods(path: Option<&Path>) -> Result<BTreeSet<String>> {
    let Some(path) = path else {
        return Ok(BTreeSet::new());
    };
    let text = fs::read_to_string(path).context("读取关键方法清单失败（需要 UTF-8）")?;
    let mut required = BTreeSet::new();
    for (line, value) in text.lines().enumerate() {
        let value = value.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let (module, signature) = value
            .split_once('\t')
            .with_context(|| format!("关键方法清单第 {} 行缺少制表符", line + 1))?;
        ensure!(
            !module.is_empty()
                && module
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "关键方法模块名无效：{module}"
        );
        ensure!(
            valid_signature(signature),
            "关键方法描述符无效：{signature}"
        );
        ensure!(required.insert(value.to_owned()), "关键方法重复：{value}");
    }
    ensure!(!required.is_empty(), "关键方法清单为空");
    Ok(required)
}

fn valid_signature(signature: &str) -> bool {
    fn take_type(s: &str, allow_void: bool) -> Option<&str> {
        let scalar = s.trim_start_matches('[');
        let dimensions = s.len() - scalar.len();
        if dimensions > 255 {
            return None;
        }
        match scalar.as_bytes().first()? {
            b'V' if allow_void && dimensions == 0 => Some(&scalar[1..]),
            b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D' => Some(&scalar[1..]),
            b'L' => {
                let end = scalar.find(';')?;
                let name = &scalar[1..end];
                if name.is_empty()
                    || name.split('/').any(str::is_empty)
                    || name
                        .chars()
                        .any(|c| c.is_whitespace() || ".;[()\t".contains(c))
                {
                    return None;
                }
                Some(&scalar[end + 1..])
            }
            _ => None,
        }
    }
    let Some((owner, method)) = signature.split_once("->") else {
        return false;
    };
    if !owner.starts_with('L') || take_type(owner, false) != Some("") {
        return false;
    }
    let Some((name, mut rest)) = method.split_once('(') else {
        return false;
    };
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || ".;/[()]".contains(c))
    {
        return false;
    }
    while !rest.starts_with(')') {
        let Some(tail) = take_type(rest, false) else {
            return false;
        };
        rest = tail;
    }
    take_type(&rest[1..], true) == Some("")
}

impl MethodReport {
    pub(crate) fn native_only() -> Self {
        // 未使用 PVM2 时版本为 0；不借 Native 记录虚构方法转换结果。
        Self {
            schema_version: 2,
            ..Self::default()
        }
    }
    pub(crate) fn read(path: &Path) -> Result<Self> {
        serde_json::from_slice(&fs::read(path).context("打包器未生成方法报告，请重建打包器")?)
            .context("方法报告格式无效")
    }

    pub(crate) fn validate(
        &mut self,
        dex_dir: &Path,
        code: &[u8],
        modules: &BTreeMap<String, String>,
        required: &BTreeSet<String>,
        transformed: usize,
        input_hashes: &BTreeMap<String, String>,
    ) -> Result<()> {
        ensure!(
            self.schema_version == 2
                && self.code_version == 4
                && matches!(self.image_version, 7 | 8),
            "方法报告协议版本不受支持"
        );
        ensure!(
            self.code_sha256 == sha256(code),
            "方法报告与 code.bin 不一致"
        );
        let mut seen = BTreeSet::new();
        let mut indices = BTreeSet::new();
        let mut declared = BTreeSet::new();
        let mut verified = 0usize;
        let mut input_bytes = 0u64;
        let mut protected_bytes = 0u64;
        for (name, dex) in &self.dexes {
            ensure!(
                modules.get(name) == Some(&dex.module),
                "方法报告的模块映射不一致：{name}"
            );
            ensure!(
                input_hashes.get(name) == Some(&dex.input_sha256),
                "报告与输入 DEX 摘要不一致：{name}"
            );
            ensure!(
                dex.output_sha256 == file_sha256(&dex_dir.join(name))?,
                "报告的 DEX 摘要不一致：{name}"
            );
        }
        ensure!(self.dexes.len() == modules.len(), "方法报告缺少 DEX");
        for row in &self.methods {
            let id = format!("{}\t{}", row.module, row.descriptor);
            ensure!(
                valid_signature(&row.descriptor) && seen.insert(id.clone()),
                "方法描述符无效或重复：{id}"
            );
            ensure!(
                modules.get(&row.input_dex) == Some(&row.module),
                "方法的模块/DEX 对应关系错误：{id}"
            );
            ensure!(
                row.required == required.contains(&id),
                "报告更改了关键方法标记：{id}"
            );
            if row.required {
                declared.insert(id.clone());
            }
            input_bytes = input_bytes
                .checked_add(row.input_instruction_bytes)
                .context("指令字节数溢出")?;
            match row.transform_status.as_str() {
                "transformed" => {
                    let dex_index = if row.input_dex == "classes.dex" {
                        Some(0)
                    } else {
                        row.input_dex
                            .strip_prefix("classes")
                            .and_then(|s| s.strip_suffix(".dex"))
                            .and_then(|n| n.parse::<u32>().ok())
                            .and_then(|n| n.checked_sub(1))
                    };
                    ensure!(
                        dex_index.is_some()
                            && row.artifact_verified
                            && row.plaintext_policy.as_deref()
                                == Some(if row.required {
                                    "clear_after_use"
                                } else {
                                    "bounded_cache"
                                })
                            && row.reason.is_none()
                            && row.final_dex_index == dex_index
                            && row.final_method_index.is_some(),
                        "方法未通过产物验证：{id}"
                    );
                    ensure!(
                        indices.insert((
                            row.final_dex_index.unwrap(),
                            row.final_method_index.unwrap()
                        )),
                        "产物方法索引重复"
                    );
                    verified += 1;
                    protected_bytes = protected_bytes
                        .checked_add(row.input_instruction_bytes)
                        .context("指令字节数溢出")?;
                }
                "skipped" => ensure!(
                    !row.artifact_verified
                        && row.plaintext_policy.is_none()
                        && !row.required
                        && row.reason.as_ref().is_some_and(|r| !r.is_empty())
                        && row.final_method_index.is_none()
                        && row.final_dex_index.is_none(),
                    "关键方法未转换或跳过记录无效：{id}"
                ),
                _ => bail!("未知方法转换状态：{id}"),
            }
        }
        ensure!(declared == *required, "方法报告遗漏了关键方法");
        ensure!(
            indices == crate::protect::xop_pvm2::code_bin_indices(code)?,
            "方法报告与 code.bin 索引不一致"
        );
        ensure!(verified == transformed, "方法报告与转换数量不一致");
        self.metrics
            .insert("selected_methods".into(), self.methods.len().into());
        self.metrics
            .insert("verified_methods".into(), verified.into());
        self.metrics
            .insert("selected_instruction_bytes".into(), input_bytes.into());
        self.metrics
            .insert("protected_instruction_bytes".into(), protected_bytes.into());
        self.metrics.insert(
            "method_coverage_percent".into(),
            ratio(verified as u64, self.methods.len() as u64),
        );
        self.metrics.insert(
            "instruction_coverage_percent".into(),
            ratio(protected_bytes, input_bytes),
        );
        self.metrics
            .insert("required_methods".into(), required.len().into());
        self.metrics.insert(
            "required_coverage_percent".into(),
            ratio(required.len() as u64, required.len() as u64),
        );
        Ok(())
    }

    pub(crate) fn write(&self, path: &Path) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        serde_json::to_writer_pretty(&mut file, self)?;
        file.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    pub(crate) fn bind(&mut self, artifact: &Path, aab: bool) -> Result<()> {
        crate::native_vmp::verify_packaged(&self.native_vmp, artifact, aab)?;
        let actual = archive_dexes(artifact)?;
        let expected = self
            .artifact_dexes
            .iter()
            .filter_map(|(name, hash)| {
                if aab {
                    Some((name.clone(), hash.clone()))
                } else {
                    name.strip_prefix("base/dex/")
                        .or_else(|| name.strip_prefix("base/"))
                        .map(|name| (name.to_owned(), hash.clone()))
                }
            })
            .collect::<BTreeMap<_, _>>();
        ensure!(
            !expected.is_empty() && actual == expected,
            "最终安装包 DEX 与验证产物不一致（缺失、重复、被修改或多出未验证的 DEX）"
        );
        self.output_sha256 = Some(file_sha256(artifact)?);
        self.build
            .insert("output_kind".into(), if aab { "aab" } else { "apk" }.into());
        Ok(())
    }
}

fn ratio(n: u64, d: u64) -> serde_json::Value {
    if d == 0 {
        serde_json::Value::Null
    } else {
        (100.0 * n as f64 / d as f64).into()
    }
}

fn archive_dexes(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut archive = checked_archive(path)?;
    let mut values = BTreeMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if !entry.name().ends_with(".dex") {
            continue;
        }
        let name = entry.name().to_owned();
        let mut hasher = Sha256::new();
        std::io::copy(&mut entry, &mut hasher)?;
        ensure!(
            values
                .insert(name, format!("{:x}", hasher.finalize()))
                .is_none(),
            "产物包含重复 DEX 条目"
        );
    }
    Ok(values)
}

/// zip 2.x 会按名称覆盖重复中央目录记录，必须在其去重后的视图之外核验条目数。
pub fn checked_archive(path: &Path) -> Result<zip::ZipArchive<File>> {
    let archive = zip::ZipArchive::new(File::open(path)?)?;
    let mut raw = File::open(path)?;
    let length = raw.metadata()?.len();
    raw.seek(SeekFrom::Start(archive.central_directory_start()))?;
    let mut count = 0;
    loop {
        let mut signature = [0u8; 4];
        raw.read_exact(&mut signature)?;
        if signature != *b"PK\x01\x02" {
            break;
        }
        let mut header = [0u8; 42];
        raw.read_exact(&mut header)?;
        let variable: u64 = [24, 26, 28]
            .into_iter()
            .map(|at| u16::from_le_bytes([header[at], header[at + 1]]) as u64)
            .sum();
        let end = raw
            .stream_position()?
            .checked_add(variable)
            .context("ZIP 中央目录溢出")?;
        ensure!(end <= length, "ZIP 中央目录越界");
        raw.seek(SeekFrom::Start(end))?;
        count += 1;
        ensure!(count <= archive.len(), "安装包包含重复 ZIP 条目");
    }
    ensure!(count == archive.len(), "ZIP 中央目录条目数量不一致");
    Ok(archive)
}

/// 签名/模块重组后重新比对 DEX，再绑定最终文件摘要；不能仅替换报告中的摘要。
pub fn rebind_report(
    source_artifact: &Path,
    final_artifact: &Path,
    output_report: &Path,
    aab: bool,
    original_input: Option<&Path>,
) -> Result<()> {
    let source = report_path(source_artifact);
    let mut report = MethodReport::read(&source)?;
    ensure!(
        report.output_sha256.as_deref() == Some(&file_sha256(source_artifact)?),
        "源安装包与方法报告的摘要不一致"
    );
    report.bind(final_artifact, aab)?;
    if let Some(input) = original_input {
        report
            .build
            .insert("bundle_input_sha256".into(), file_sha256(input)?.into());
    }
    report.write(output_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn archive(path: &Path, entries: &[(&str, &[u8])]) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, value) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(value).unwrap();
        }
        zip.finish().unwrap();
    }

    fn report() -> MethodReport {
        serde_json::from_value(serde_json::json!({
            "schema_version": 2, "image_version": 7, "code_version": 4,
            "methods": [], "dexes": {}, "code_sha256": "",
            "artifact_dexes": {"base/dex/classes.dex": sha256(b"stub"), "feature/dex/classes.dex": sha256(b"feature")}
        })).unwrap()
    }

    #[test]
    fn 清单严格区分模块重载并拒绝无效描述符() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("methods.tsv");
        fs::write(
            &list,
            "# 示例\nbase\tLa/A;->f(I[Ljava/lang/String;)Z\nfeature\tLa/A;->f()J\n",
        )
        .unwrap();
        assert_eq!(required_methods(Some(&list)).unwrap().len(), 2);
        for text in [
            "",
            "base La/A;->f()V",
            "../base\tLa/A;->f()V",
            "base\tLa/A;->f(V)V",
            "base\tLa/A;->f()[V",
            "base\tLa/A;->f()Vjunk",
            "base\tLa/A;->f()V\nbase\tLa/A;->f()V",
        ] {
            fs::write(&list, text).unwrap();
            assert!(required_methods(Some(&list)).is_err(), "{text}");
        }
        assert!(valid_signature("La/外部$Name;->f([[IJD)Ljava/lang/Object;"));
        assert!(ratio(0, 0).is_null());
    }

    #[test]
    fn 签名重组后重新核验全部_dex并拒绝错模块或备份() {
        let dir = tempfile::tempdir().unwrap();
        let apk = dir.path().join("input.apk");
        let aab = dir.path().join("output.aab");
        archive(
            &apk,
            &[
                ("classes.dex", b"stub"),
                ("META-INF/input.SF", b"signature"),
            ],
        );
        let mut report = report();
        report.bind(&apk, false).unwrap();
        report.write(&report_path(&apk)).unwrap();
        archive(
            &aab,
            &[
                ("base/dex/classes.dex", b"stub"),
                ("feature/dex/classes.dex", b"feature"),
                ("META-INF/output.SF", b"new signature"),
            ],
        );
        rebind_report(&apk, &aab, &report_path(&aab), true, None).unwrap();
        assert_eq!(
            MethodReport::read(&report_path(&aab))
                .unwrap()
                .output_sha256,
            Some(file_sha256(&aab).unwrap())
        );
        for entries in [
            vec![
                ("base/dex/classes.dex", &b"changed"[..]),
                ("feature/dex/classes.dex", &b"feature"[..]),
            ],
            vec![
                ("base/dex/classes.dex", &b"stub"[..]),
                ("wrong/dex/classes.dex", &b"feature"[..]),
            ],
            vec![
                ("base/dex/classes.dex", &b"stub"[..]),
                ("feature/dex/classes.dex", &b"feature"[..]),
                ("backup/classes.dex", &b"original"[..]),
            ],
        ] {
            archive(&aab, &entries);
            assert!(rebind_report(&apk, &aab, &report_path(&aab), true, None).is_err());
        }
        archive(&apk, &[("classes.dex", b"different source")]);
        assert!(rebind_report(&apk, &aab, &report_path(&aab), true, None).is_err());
    }

    #[test]
    fn 方法报告必须对应真实输入输出与_sidecar索引() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("classes.dex"), b"transformed").unwrap();
        let mut code = Vec::new();
        code.extend_from_slice(&[4, 0, 1, 0]);
        for n in [8u32, 0] {
            code.extend_from_slice(&n.to_le_bytes());
        }
        code.extend_from_slice(&1u16.to_le_bytes());
        for n in [7u32, 18, 46, 2] {
            code.extend_from_slice(&n.to_le_bytes());
        }
        code.extend_from_slice(&[0; 46]);
        let data = serde_json::json!({
            "schema_version": 2, "image_version": 7, "code_version": 4, "code_sha256": sha256(&code),
            "dexes": {"classes.dex": {"module": "base", "input_sha256": "input", "output_sha256": sha256(b"transformed")}},
            "methods": [{"module": "base", "descriptor": "La/A;->f()I", "required": false, "input_instruction_bytes": 16, "input_dex": "classes.dex", "transform_status": "transformed", "artifact_verified": true, "plaintext_policy": "bounded_cache", "final_dex_index": 0, "final_method_index": 7, "reason": null}]
        });
        let modules = BTreeMap::from([("classes.dex".into(), "base".into())]);
        let inputs = BTreeMap::from([("classes.dex".into(), "input".into())]);
        let mut report: MethodReport = serde_json::from_value(data.clone()).unwrap();
        report
            .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
            .unwrap();
        assert!(report.metrics["required_coverage_percent"].is_null());
        assert_eq!(report.metrics["instruction_coverage_percent"], 100.0);
        for mandatory in [false, true] {
            let required = if mandatory {
                BTreeSet::from(["base\tLa/A;->f()I".into()])
            } else {
                BTreeSet::new()
            };
            for policy in [
                None,
                Some("bounded_cache"),
                Some("clear_after_use"),
                Some("unknown"),
            ] {
                let mut candidate: MethodReport = serde_json::from_value(data.clone()).unwrap();
                candidate.methods[0].required = mandatory;
                candidate.methods[0].plaintext_policy = policy.map(str::to_owned);
                let accepted = candidate
                    .validate(dir.path(), &code, &modules, &required, 1, &inputs)
                    .is_ok();
                assert_eq!(
                    accepted,
                    policy
                        == Some(if mandatory {
                            "clear_after_use"
                        } else {
                            "bounded_cache"
                        })
                );
            }
        }
        for image in [7, 8] {
            let mut candidate: MethodReport = serde_json::from_value(data.clone()).unwrap();
            candidate.image_version = image;
            assert!(candidate
                .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
                .is_ok());
        }
        for (schema, image) in [(1, 7), (2, 6), (2, 9)] {
            let mut candidate: MethodReport = serde_json::from_value(data.clone()).unwrap();
            candidate.schema_version = schema;
            candidate.image_version = image;
            assert!(candidate
                .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
                .is_err());
        }
        report.methods[0].final_method_index = Some(8);
        assert!(report
            .validate(dir.path(), &code, &modules, &BTreeSet::new(), 1, &inputs)
            .is_err());
        let required = BTreeSet::from(["base\tLa/A;->missing()I".into()]);
        let mut report: MethodReport = serde_json::from_value(data).unwrap();
        assert!(report
            .validate(dir.path(), &code, &modules, &required, 1, &inputs)
            .is_err());
    }
}
