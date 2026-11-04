use anyhow::{Context, Result};
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use walkdir::WalkDir;
use zip::{ZipArchive, ZipWriter};

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const JPEG_SIGNATURE: [u8; 3] = [0xFF, 0xD8, 0xFF];
const WEBP_RIFF: [u8; 4] = *b"RIFF";
const WEBP_TAG: [u8; 4] = *b"WEBP";
const GIF87A: [u8; 6] = *b"GIF87a";
const GIF89A: [u8; 6] = *b"GIF89a";
const BMP_SIGNATURE: [u8; 2] = *b"BM";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageKind {
    Png,
    Jpeg,
    Webp,
    Gif,
    Bmp,
    Empty,
    Unknown,
}

impl ImageKind {
    fn label(self) -> &'static str {
        match self {
            Self::Png => "PNG",
            Self::Jpeg => "JPEG",
            Self::Webp => "WebP",
            Self::Gif => "GIF",
            Self::Bmp => "BMP",
            Self::Empty => "空文件",
            Self::Unknown => "未知格式",
        }
    }

    fn target_extension(self) -> Option<&'static str> {
        match self {
            Self::Jpeg => Some("jpg"),
            Self::Webp => Some("webp"),
            _ => None,
        }
    }
}

/// 修正 Apktool 3 对空资源表的包信息及无资源表时遗漏的 Android 框架引用。
pub(crate) fn normalize_empty_resource_metadata(apk_dir: &Path) -> Result<bool> {
    let path = apk_dir.join("apktool.yml");
    let metadata = fs::read_to_string(&path).context("读取 Apktool 资源元数据失败")?;
    // ponytail: 只修正 Apktool 3 已验证的空表输出格式；其他格式保持原样，不猜测资源 ID。
    let mut normalized = metadata
        .replace("resourcesInfo:\n  packageId: 0\n  packageName: \n", "")
        .replace(
            "resourcesInfo:\r\n  packageId: 0\r\n  packageName: \r\n",
            "",
        );
    // 完全无资源表时 Apktool 不记录框架，但重编 Manifest 的 android:* 属性仍需要它。
    if !apk_dir.join("res").exists()
        && !apk_dir.join("resources.arsc").exists()
        && !metadata
            .lines()
            .any(|line| line.starts_with("usesFramework:") || line.starts_with("resourcesInfo:"))
    {
        normalized.push_str("\nusesFramework:\n  ids:\n  - 1\n");
    }
    if normalized == metadata {
        return Ok(false);
    }
    fs::write(path, normalized).context("修正 Apktool 空资源元数据失败")?;
    Ok(true)
}

/// Apktool 必须重编 Manifest，但不能因此丢掉输入 APK 已有的资源名混淆。
/// 用输入 APK 的原始 `resources.arsc` 和 `res/` 条目覆盖重编结果，其他受保护
/// 条目（Manifest、Stub DEX、Native Runtime）保持不变。
pub(crate) fn restore_original_resources(original_apk: &Path, rebuilt_apk: &Path) -> Result<usize> {
    let original_file = fs::File::open(original_apk)
        .with_context(|| format!("打开原 APK 失败：{}", original_apk.display()))?;
    let rebuilt_file = fs::File::open(rebuilt_apk)
        .with_context(|| format!("打开重编 APK 失败：{}", rebuilt_apk.display()))?;
    let mut original = ZipArchive::new(original_file).context("解析原 APK ZIP 失败")?;
    let mut rebuilt = ZipArchive::new(rebuilt_file).context("解析重编 APK ZIP 失败")?;

    let original_resources = resource_index(&mut original)?;
    if original_resources.is_empty() {
        return Ok(0);
    }

    let parent = rebuilt_apk
        .parent()
        .with_context(|| format!("无法确定输出 APK 父目录：{}", rebuilt_apk.display()))?;
    let mut temp = NamedTempFile::new_in(parent).context("创建资源恢复临时 APK 失败")?;
    {
        let mut writer = ZipWriter::new(BufWriter::new(temp.as_file_mut()));
        // zip 9 移除了 raw ZIP64 注释 API；标准归档注释仍按原字节保留。
        writer
            .set_raw_comment(rebuilt.comment().to_vec().into_boxed_slice())
            .context("写入重编 APK 注释失败")?;

        for index in 0..rebuilt.len() {
            let entry = rebuilt
                .by_index(index)
                .with_context(|| format!("读取重编 APK 条目失败：index={index}"))?;
            let name = entry.name()?.into_owned();
            if !is_resource_entry(&name) {
                writer
                    .raw_copy_file(entry)
                    .context("复制受保护 APK 条目失败")?;
            }
        }
        for index in 0..original.len() {
            let entry = original
                .by_index(index)
                .with_context(|| format!("读取原 APK 资源条目失败：index={index}"))?;
            let name = entry.name()?.into_owned();
            if is_resource_entry(&name) {
                writer
                    .raw_copy_file(entry)
                    .context("恢复原 APK 混淆资源条目失败")?;
            }
        }

        let mut output = writer.finish().context("完成资源恢复 APK 写入失败")?;
        output.flush().context("刷新资源恢复 APK 失败")?;
    }
    drop(original);
    drop(rebuilt);

    temp.persist(rebuilt_apk).map_err(|error| {
        anyhow::anyhow!(
            "替换资源恢复后的 APK 失败：{} -> {}：{}",
            error.file.path().display(),
            rebuilt_apk.display(),
            error.error
        )
    })?;

    verify_original_resources(original_apk, rebuilt_apk)?;
    Ok(original_resources.len())
}

pub(crate) fn verify_original_resources(
    original_apk: &Path,
    protected_apk: &Path,
) -> Result<usize> {
    let original_file = fs::File::open(original_apk).context("打开原 APK 资源索引失败")?;
    let protected_file = fs::File::open(protected_apk).context("打开加固 APK 资源索引失败")?;
    let mut original = ZipArchive::new(original_file).context("解析原 APK 资源索引失败")?;
    let mut protected = ZipArchive::new(protected_file).context("解析加固 APK 资源索引失败")?;
    let expected = resource_index(&mut original)?;
    if resource_index(&mut protected)? != expected {
        anyhow::bail!("原 APK 资源名称或内容未被完整保留，拒绝继续签名");
    }
    Ok(expected.len())
}

fn is_resource_entry(name: &str) -> bool {
    name == "resources.arsc" || name.starts_with("res/")
}

fn resource_index<R: std::io::Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<(String, u64, u32)>> {
    let mut index = Vec::new();
    for position in 0..archive.len() {
        let entry = archive
            .by_index(position)
            .with_context(|| format!("读取 APK 资源索引失败：index={position}"))?;
        let name = entry.name()?.into_owned();
        if is_resource_entry(&name) {
            index.push((name, entry.size(), entry.crc32()));
        }
    }
    index.sort();
    Ok(index)
}

/// 修正 aapt2 无法编译的“有效图片伪装为 .png”资源。
///
/// 用户常见做法是把 JPEG/WebP 手动改名为 `.png`。图片查看器能打开，但 aapt2
/// 会按 PNG 签名解析并失败。这里只处理 `res/drawable*`、`res/mipmap*`，通过
/// 改名保留原始字节；九宫格、同名目标和未知格式拒绝处理，避免改变资源语义。
pub(crate) fn normalize_mislabeled_image_resources(apk_dir: &Path) -> Result<usize> {
    let resource_dir = apk_dir.join("res");
    if !resource_dir.is_dir() {
        return Ok(0);
    }

    let mut png_paths = Vec::<PathBuf>::new();
    for entry in WalkDir::new(&resource_dir).follow_links(false) {
        let entry =
            entry.with_context(|| format!("遍历资源目录失败：{}", resource_dir.display()))?;
        if entry.file_type().is_file()
            && is_png_extension(entry.path())
            && is_drawable_or_mipmap(entry.path(), &resource_dir)
        {
            png_paths.push(entry.into_path());
        }
    }

    let mut renamed = 0;
    let mut errors = Vec::<String>::new();
    for path in png_paths {
        let kind = detect_image_kind(&path)?;
        if kind == ImageKind::Png {
            continue;
        }
        let relative = path
            .strip_prefix(apk_dir)
            .unwrap_or(&path)
            .display()
            .to_string();
        if is_nine_patch(&path) {
            errors.push(format!(
                "{relative}: 九宫格 .9.png 实际为 {}，必须改为有效 PNG",
                kind.label()
            ));
            continue;
        }
        let Some(extension) = kind.target_extension() else {
            errors.push(format!(
                "{relative}: 实际为 {}，无法安全自动修正；请改为有效 PNG/JPEG/WebP",
                kind.label()
            ));
            continue;
        };
        let target = path.with_extension(extension);
        if target.exists() {
            errors.push(format!(
                "{relative}: 实际为 {}，但同名 .{extension} 已存在；请手动处理资源冲突",
                kind.label()
            ));
            continue;
        }
        fs::rename(&path, &target).with_context(|| {
            format!(
                "将 {} 伪装 PNG 资源改名失败：{} -> {}",
                kind.label(),
                path.display(),
                target.display()
            )
        })?;
        renamed += 1;
    }
    if !errors.is_empty() {
        anyhow::bail!(
            "检测到 {} 个 .png 资源内容不是 PNG：\n{}",
            errors.len(),
            errors.join("\n")
        );
    }
    Ok(renamed)
}

fn is_png_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("png"))
}

fn is_drawable_or_mipmap(path: &Path, resource_dir: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(resource_dir) else {
        return false;
    };
    let Some(first) = relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return false;
    };
    first == "drawable"
        || first.starts_with("drawable-")
        || first == "mipmap"
        || first.starts_with("mipmap-")
}

fn is_nine_patch(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.ends_with(".9"))
}

fn detect_image_kind(path: &Path) -> Result<ImageKind> {
    let mut file =
        fs::File::open(path).with_context(|| format!("读取资源文件失败：{}", path.display()))?;
    let mut prefix = [0u8; 12];
    let read = file
        .read(&mut prefix)
        .with_context(|| format!("读取资源文件头失败：{}", path.display()))?;
    if read == 0 {
        return Ok(ImageKind::Empty);
    }
    if read >= PNG_SIGNATURE.len() && prefix[..PNG_SIGNATURE.len()] == PNG_SIGNATURE {
        return Ok(ImageKind::Png);
    }
    if read >= JPEG_SIGNATURE.len() && prefix[..JPEG_SIGNATURE.len()] == JPEG_SIGNATURE {
        return Ok(ImageKind::Jpeg);
    }
    if read >= 12 && prefix[..4] == WEBP_RIFF && prefix[8..12] == WEBP_TAG {
        return Ok(ImageKind::Webp);
    }
    if read >= 6 && (prefix[..6] == GIF87A || prefix[..6] == GIF89A) {
        return Ok(ImageKind::Gif);
    }
    if read >= 2 && prefix[..2] == BMP_SIGNATURE {
        return Ok(ImageKind::Bmp);
    }
    Ok(ImageKind::Unknown)
}
