use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, str::FromStr};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdbPolicy {
    #[default]
    Off,
    Report,
    Block,
}

impl AdbPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Report => "report",
            Self::Block => "block",
        }
    }
}

impl FromStr for AdbPolicy {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "off" => Ok(Self::Off),
            "report" => Ok(Self::Report),
            "block" => Ok(Self::Block),
            _ => Err("调试环境策略仅支持 off、report、block".into()),
        }
    }
}

/// 加固器和运行时共用的可选界面保护策略，旧配置全部关闭。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeUiProtection {
    pub secure_screen: bool,
    pub screen_exempt_activities: Vec<String>,
    pub adb_policy: AdbPolicy,
    pub runtime_recheck: bool,
    pub obfuscate_resource_names: bool,
    pub resource_name_keep: Vec<String>,
}

impl RuntimeUiProtection {
    pub fn runtime_enabled(&self) -> bool {
        self.secure_screen || self.adb_policy != AdbPolicy::Off || self.runtime_recheck
    }

    pub fn enabled(&self) -> bool {
        self.runtime_enabled() || self.obfuscate_resource_names
    }

    pub fn validate(&self) -> Result<()> {
        if !self.secure_screen && !self.screen_exempt_activities.is_empty() {
            bail!("截图例外名单必须同时开启防截图");
        }
        if !self.obfuscate_resource_names && !self.resource_name_keep.is_empty() {
            bail!("资源名称保留名单必须同时开启资源名称混淆");
        }
        if self.screen_exempt_activities.len() > 256 || self.resource_name_keep.len() > 4096 {
            bail!("界面保护名单超出上限");
        }
        for name in &self.screen_exempt_activities {
            if name.len() > 512 || !name.contains('.') || !name.split('.').all(java_identifier) {
                bail!("截图例外需要完整 Activity 类名：{name}");
            }
        }
        for name in &self.resource_name_keep {
            if name.len() > 256 || !java_identifier(name) {
                bail!("资源保留名必须是单个条目名称：{name}");
            }
        }
        Ok(())
    }
}

fn java_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

#[derive(Deserialize)]
struct WindowReport {
    version: u32,
    rewritten: usize,
    unresolved: usize,
}
#[derive(Deserialize)]
struct NameReport {
    version: u32,
    renamed: usize,
    kept: usize,
    unsupported_packages: usize,
    skip_reason: String,
}

pub(crate) fn rewrite_windows(
    java: &Path,
    packer: &Path,
    dir: &Path,
    external_dex: Option<&Path>,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<String> {
    let report = tempfile::NamedTempFile::new()?;
    let mut command = crate::utils::no_window_command(java);
    command
        .args(["-jar"])
        .arg(packer)
        .args(["ui-transform", "--dir"])
        .arg(dir)
        .arg("--report")
        .arg(report.path());
    if let Some(external) = external_dex {
        command.arg("--external-dex").arg(external);
    }
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    crate::protect::xop_pvm2::run_ui_command(&mut command, cancel)?;
    let report: WindowReport = serde_json::from_slice(&fs::read(report.path())?)?;
    if report.version != 1 {
        bail!("不支持的窗口改写报告版本");
    }
    Ok(format!("窗口保护：{} 个 Dialog/Window 调用已改写，{} 个同名但类型无法确认的调用保留；反射/Native 窗口调用不在覆盖范围", report.rewritten, report.unresolved))
}

pub(crate) type ApkIndex = std::collections::BTreeMap<String, (u64, u32)>;
pub(crate) fn apk_index(path: &Path) -> Result<ApkIndex> {
    let mut archive = crate::protection_report::checked_archive(path)?;
    let mut index = ApkIndex::new();
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        if index
            .insert(entry.name().to_string(), (entry.size(), entry.crc32()))
            .is_some()
        {
            bail!("APK 包含重复条目");
        }
    }
    Ok(index)
}

pub(crate) fn rewrite_resource_names(
    java: &Path,
    packer: &Path,
    source: &Path,
    output: &Path,
    keep: &[String],
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<String> {
    let report = tempfile::NamedTempFile::new()?;
    let rewritten = tempfile::NamedTempFile::new_in(output.parent().unwrap_or(Path::new(".")))?;
    let mut command = crate::utils::no_window_command(java);
    command
        .arg("-jar")
        .arg(packer)
        .arg("resource-name-transform")
        .arg("--source")
        .arg(source)
        .arg("--input")
        .arg(output)
        .arg("--output")
        .arg(rewritten.path())
        .arg("--keep")
        .arg(keep.join(","))
        .arg("--report")
        .arg(report.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    crate::protect::xop_pvm2::run_ui_command(&mut command, cancel)?;
    let report: NameReport = serde_json::from_slice(&fs::read(report.path())?)?;
    if report.version != 1 {
        bail!("不支持的资源名称报告版本");
    }
    let mut before = apk_index(output)?;
    let mut after = apk_index(rewritten.path())?;
    let original_table = before.remove("resources.arsc");
    let rewritten_table = after.remove("resources.arsc");
    if before != after
        || original_table.is_some() != rewritten_table.is_some()
        || (report.renamed > 0 && original_table == rewritten_table)
        || (report.renamed == 0 && original_table != rewritten_table)
    {
        bail!("资源名称改写结果与报告不一致，或修改了资源表以外条目");
    }
    rewritten.persist(output).map_err(|e| e.error)?;
    let reason = match report.skip_reason.as_str() {
        "" => "无",
        "no_resource_table" => "无资源表",
        "dynamic_resource_lookup" => "存在动态资源名称查询/代码加载",
        "opaque_native_or_assets" => "包含无法证明名称引用范围的 Native/资产",
        _ => bail!("未知资源跳过原因"),
    };
    Ok(format!("资源名称保护：{} 个 id 名称改写，{} 个引用/共享/保留名称跳过，{} 个不支持的资源包跳过；整包跳过原因：{reason}", report.renamed, report.kept, report.unsupported_packages))
}

pub(crate) fn write_manifest(dir: &Path, options: &RuntimeUiProtection) -> Result<()> {
    options.validate()?;
    if !options.runtime_enabled() {
        return Ok(());
    }
    let path = dir.join("AndroidManifest.xml");
    let mut xml = fs::read_to_string(&path)?;
    if xml.contains("dev.mocika.shield.UI_") {
        bail!("Manifest 已占用界面保护策略字段");
    }
    let end = xml
        .find("</application>")
        .ok_or_else(|| anyhow::anyhow!("Manifest 缺少 application 结束标签"))?;
    let fields = [
        ("VERSION", "1".to_string()),
        ("SECURE_SCREEN", options.secure_screen.to_string()),
        ("SCREEN_EXEMPT", options.screen_exempt_activities.join(",")),
        ("ADB_POLICY", options.adb_policy.as_str().to_string()),
        ("RECHECK", options.runtime_recheck.to_string()),
    ];
    let metadata: String = fields.iter().map(|(key, value)| format!(
        "<meta-data android:name=\"dev.mocika.shield.UI_{key}\" android:value=\"{value}\" />\n        "
    )).collect();
    xml.insert_str(end, &metadata);
    fs::write(path, xml)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 旧配置默认关闭且非法名单拒绝写入() {
        let mut options: RuntimeUiProtection = serde_json::from_str("{}").unwrap();
        assert!(!options.enabled());
        assert!(
            serde_json::from_str::<RuntimeUiProtection>(r#"{"adb_policy":"unknown"}"#).is_err()
        );
        options.secure_screen = true;
        options
            .screen_exempt_activities
            .push("com.example.ShareActivity".into());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AndroidManifest.xml");
        fs::write(&path, "<manifest><application></application></manifest>").unwrap();
        write_manifest(dir.path(), &options).unwrap();
        let result = fs::read_to_string(&path).unwrap();
        assert!(result.contains("UI_SECURE_SCREEN\" android:value=\"true"));
        assert!(result.contains("com.example.ShareActivity"));
        assert!(write_manifest(dir.path(), &options).is_err());
        options
            .screen_exempt_activities
            .push("x\"/><meta-data".into());
        assert!(options.validate().is_err());
    }
}
