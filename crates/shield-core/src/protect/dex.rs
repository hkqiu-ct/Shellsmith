use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::protect::cache_identity::{self, CacheIdentity};
use crate::utils::{human_size, print_success};

pub(crate) fn process_dex(
    apk_dir: &Path,
    signature: &str,
    ikm: &[u8],
    compression_layers: u8,
    byos: Option<(&str, &str)>,
    protect_route_assets: bool,
) -> Result<CacheIdentity> {
    let mut dex_files = Vec::new();
    for entry in fs::read_dir(apk_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("dex") {
            dex_files.push(path);
        }
    }

    if dex_files.is_empty() {
        anyhow::bail!("未找到DEX文件");
    }
    let cache_identity = cache_identity::calculate(&dex_files)?;

    let dex_dir = apk_dir.parent().unwrap().join("dex");
    fs::create_dir_all(&dex_dir)?;

    for dex_file in &dex_files {
        let dest = dex_dir.join(dex_file.file_name().unwrap());
        fs::rename(dex_file, dest)?;
    }
    let pvm2_sidecar = apk_dir.join(crate::dex_packer::XOP_PVM2_SIDECAR_NAME);
    if pvm2_sidecar.is_file() {
        fs::rename(
            &pvm2_sidecar,
            dex_dir.join(crate::dex_packer::XOP_PVM2_SIDECAR_NAME),
        )?;
    }

    let assets_dir = apk_dir.join("assets");
    fs::create_dir_all(&assets_dir)?;
    let route_key = protect_route_assets
        .then(|| crate::dex_packer::crypto::derive_route_assets_key(ikm, signature.as_bytes()));
    let arouter_rtap = assets_dir.join("arouter_routes.rtap");
    let arouter_txt = assets_dir.join("arouter_routes.txt");
    let router_rtap = assets_dir.join("therouter_registry.rtap");
    let router_txt = assets_dir.join("therouter_registry.txt");

    let routes = crate::dex_packer::route_scanner::scan_arouter_routes(&dex_dir)?;
    if !routes.is_empty() {
        let plaintext = routes.join("\n");
        if let Some(key) = &route_key {
            let blob = crate::dex_packer::crypto::encrypt_route_asset(plaintext.as_bytes(), key, 1);
            fs::write(&arouter_rtap, blob)?;
            let _ = fs::remove_file(&arouter_txt);
        } else {
            fs::write(&arouter_txt, plaintext)?;
        }
        print_success(&format!(
            "扫描到 ARouter 路由表类 {} 个（{}）",
            routes.len(),
            if route_key.is_some() {
                "RTA1"
            } else {
                "明文"
            }
        ));
    }
    let therouter = crate::dex_packer::route_scanner::scan_therouter_registry(&dex_dir)?;
    if !therouter.is_empty() && therouter.asm_registered {
        let _ = fs::remove_file(&router_rtap);
        let _ = fs::remove_file(&router_txt);
        print_success("TheRouter 已启用编译期注册，保留原注册链路，无需运行时索引");
    } else if !therouter.is_empty() {
        let holder = therouter
            .holder
            .as_ref()
            .context("THEROUTER_REGISTRATION_UNRESOLVED：检测到 TheRouter 生成类，但既未确认编译期注册标记，也未找到可用的运行时索引。此为加固兼容性限制，不代表原 App 存在 bug；请核对 TheRouter 插件与运行库版本、编译期注册和混淆结果，不能仅忽略此检查后继续加固")?;
        let plaintext = therouter.to_index_text();
        if let Some(key) = &route_key {
            let blob = crate::dex_packer::crypto::encrypt_route_asset(plaintext.as_bytes(), key, 2);
            fs::write(&router_rtap, blob)?;
            let _ = fs::remove_file(&router_txt);
        } else {
            fs::write(&router_txt, plaintext)?;
        }
        print_success(&format!(
            "扫描到 TheRouter 注册项 {} 个（索引 {}）",
            therouter.services.len() + therouter.routes.len() + therouter.autowired.len(),
            holder,
        ));
    }

    let tmp_bin = apk_dir.parent().unwrap().join("app.bin.tmp");
    if let Some((token, endpoint)) = byos {
        crate::dex_packer::pack_dex_files_byos(
            &dex_dir,
            &tmp_bin,
            ikm,
            signature,
            token,
            endpoint,
            compression_layers,
        )?;
    } else {
        crate::dex_packer::pack_dex_files_with_layers(
            &dex_dir,
            &tmp_bin,
            ikm,
            signature,
            compression_layers,
        )?;
    }

    let bin_size = fs::metadata(&tmp_bin)?.len();
    print_success(&format!("DEX打包完成: {}", human_size(bin_size)));

    Ok(cache_identity)
}

pub(crate) fn patch_dex_header(dex_path: &Path) -> Result<()> {
    use sha1::{Digest, Sha1};
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dex_path)
        .context("打开 classes.dex 读写失败")?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .context("读取 classes.dex 全量失败")?;

    if data.len() < 36 {
        anyhow::bail!("classes.dex 过短，无法修复 header（{}字节）", data.len());
    }

    let total_len =
        u32::try_from(data.len()).context("classes.dex 超过 4GiB，无法写入 file_size")?;

    data[32..36].copy_from_slice(&total_len.to_le_bytes());

    let sig = Sha1::digest(&data[32..]);
    data[12..32].copy_from_slice(&sig);

    let checksum = adler32_checksum(&data[12..]);
    data[8..12].copy_from_slice(&checksum.to_le_bytes());

    file.seek(SeekFrom::Start(0))
        .context("定位 classes.dex 写入位置失败")?;
    file.write_all(&data)
        .context("回写 classes.dex header 失败")?;

    Ok(())
}

fn adler32_checksum(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_empty_input_returns_one() {
        assert_eq!(adler32_checksum(b""), 1);
    }

    #[test]
    fn adler32_wikipedia_known_value() {
        assert_eq!(adler32_checksum(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn patch_dex_header把追加载荷计入最终_file_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("classes.dex");
        let mut dex = vec![0u8; 64];
        dex[0..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&(64u32).to_le_bytes());
        dex.extend_from_slice(b"MSHDpayload");
        fs::write(&path, &dex).unwrap();

        patch_dex_header(&path).unwrap();
        let patched = fs::read(&path).unwrap();
        let file_size = u32::from_le_bytes(patched[32..36].try_into().unwrap()) as usize;
        assert_eq!(file_size, patched.len());
    }
}
