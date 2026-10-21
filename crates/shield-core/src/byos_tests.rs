//! 直接使用发布运行时解析器验收打包器，避免只证明两份测试模拟代码互相兼容。
#[allow(dead_code)]
#[path = "../../../shield-stub/src/main/rust/src/bin_loader.rs"]
mod bin_loader;
#[allow(dead_code)]
#[path = "../../../shield-stub/src/main/rust/src/crypto.rs"]
mod crypto;

#[test]
fn v7_requires_external_key_and_authenticates_header_and_payload() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir(&input).unwrap();
    std::fs::write(input.join("classes.dex"), b"authorized-test-dex").unwrap();
    std::fs::write(input.join("xop-pvm2.bin"), b"test-sidecar").unwrap();
    let output = dir.path().join("payload");
    let cert = "A".repeat(64);
    let (key, _, salt) = crate::project_protection::build_material(
        &dir.path().join("project"),
        "com.example.byos",
        &cert,
        true,
    )
    .unwrap();
    assert!(salt.is_none());
    let (project_key, _, _) = crate::project_protection::build_material(
        &dir.path().join("project"),
        "com.example.byos",
        &cert,
        false,
    )
    .unwrap();
    for layers in 1..=3 {
        crate::dex_packer::pack_dex_files_byos(
            &input,
            &output,
            &key,
            &cert,
            "test-token",
            "https://keys.example/app",
            layers,
        )
        .unwrap();
        let data = std::fs::read(&output).unwrap();
        assert_eq!(&data[..8], b"DEXB\x07\0\0\0");
        assert!(!data.windows(key.len()).any(|bytes| bytes == key));
        assert_eq!(
            bin_loader::parse_and_decompress_payload(&data, cert.as_bytes())
                .err()
                .unwrap(),
            "BYOS_IKM_REQUIRED"
        );
        let fetch = |url: &str, token: &str, fingerprint: &str| {
            assert_eq!(url, "https://keys.example/app");
            assert_eq!(token, "test-token");
            assert_eq!(fingerprint, cert);
            Ok(key.to_vec())
        };
        let decoded =
            bin_loader::parse_and_decompress_payload_with_fetch(&data, cert.as_bytes(), fetch)
                .unwrap();
        assert_eq!(decoded.dex_files, [b"authorized-test-dex".to_vec()]);
        assert_eq!(decoded.xop_pvm2.as_ref().unwrap().0, b"test-sidecar");
        let cache =
            bin_loader::parse_xop_pvm2_payload_with_fetch(&data, cert.as_bytes(), fetch).unwrap();
        assert_eq!(cache.1, decoded.xop_pvm2);
        assert_eq!(cache.2, decoded.assets_pas2_key);
        assert_eq!(cache.3, decoded.native_so_key);
        assert!(bin_loader::parse_xop_pvm2_payload(&data, cert.as_bytes()).is_err());
        for wrong_key in [[0; 32], project_key] {
            assert!(bin_loader::parse_and_decompress_payload_with_fetch(
                &data,
                cert.as_bytes(),
                |_, _, _| Ok(wrong_key.to_vec())
            )
            .is_err());
        }
        let public_key =
            crypto::derive_envelope_key(cert.as_bytes(), data[81..97].try_into().unwrap());
        assert!(bin_loader::parse_and_decompress_payload_with_fetch(
            &data,
            cert.as_bytes(),
            |_, _, _| Ok(public_key.to_vec())
        )
        .is_err());
        for offset in [81, data.len() - 1] {
            let mut bad = data.clone();
            bad[offset] ^= 1;
            assert!(bin_loader::parse_and_decompress_payload_with_fetch(
                &bad,
                cert.as_bytes(),
                fetch
            )
            .is_err());
        }
        assert!(bin_loader::parse_and_decompress_payload_with_fetch(
            &data,
            b"wrong",
            |_, _, _| panic!("签名不匹配时不得请求服务")
        )
        .is_err());
        for end in 0..data.len() {
            assert!(bin_loader::parse_and_decompress_payload_with_fetch(
                &data[..end],
                cert.as_bytes(),
                fetch
            )
            .is_err());
        }
    }
}

#[test]
fn v7_cache_without_pvm2_still_requires_a_key() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("classes.dex"), b"cache-test").unwrap();
    let output = dir.path().join("payload");
    let cert = "A".repeat(64);
    crate::dex_packer::pack_dex_files_byos(
        dir.path(),
        &output,
        &[8; 32],
        &cert,
        "cache-test",
        "https://keys.example",
        1,
    )
    .unwrap();
    let bytes = std::fs::read(output).unwrap();
    assert!(bin_loader::parse_xop_pvm2_payload(&bytes, cert.as_bytes()).is_err());
    let decoded =
        bin_loader::parse_xop_pvm2_payload_with_fetch(&bytes, cert.as_bytes(), |_, _, _| {
            Ok(vec![8; 32])
        })
        .unwrap();
    assert!(decoded.1.is_none());
}

#[test]
#[ignore = "需要 JDK 17 与已构建的 Xop Packer；执行 Java 白盒检查的跨语言协议回归"]
fn v7_java_whitebox_recognizes_external_key_requirement() {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir(&input).unwrap();
    std::fs::write(input.join("classes.dex"), b"protocol-only-fixture").unwrap();
    let output = dir.path().join("payload");
    let cert = "A".repeat(64);
    crate::dex_packer::pack_dex_files_byos(
        &input,
        &output,
        &[8; 32],
        &cert,
        "test",
        "https://keys.example",
        1,
    )
    .unwrap();
    let payload = std::fs::read(&output).unwrap();
    assert!(bin_loader::parse_and_decompress_payload_with_fetch(
        &payload,
        cert.as_bytes(),
        |_, _, _| Ok(vec![8; 32])
    )
    .is_ok());
    let jar = root.join("tools/xop-pvm2-packer.jar");
    let classes = dir.path().join("checker");
    std::fs::create_dir(&classes).unwrap();
    let mut javac = crate::utils::no_window_command("javac");
    javac
        .args(["--release", "17", "-cp"])
        .arg(&jar)
        .arg("-d")
        .arg(&classes);
    for name in [
        "Pvm2ProtectionCheck",
        "Pvm2RuntimeImages",
        "ApkRecoveryCheck",
    ] {
        javac.arg(root.join(format!("tests/java/com/yqsh/protector/packer/{name}.java")));
    }
    assert!(javac.status().unwrap().success());
    let classpath = std::env::join_paths([&classes, &jar]).unwrap();
    for (label, data, valid) in [
        ("valid", payload.clone(), true),
        ("truncated", payload[..100].to_vec(), false),
        (
            "unknown",
            {
                let mut p = payload;
                p[4] = 8;
                p
            },
            false,
        ),
    ] {
        let mut dex = b"MSHD".to_vec();
        dex.extend_from_slice(&(data.len() as u32).to_le_bytes());
        dex.extend_from_slice(&data);
        let apk = dir.path().join(format!("{label}.apk"));
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&apk).unwrap());
        zip.start_file("classes.dex", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&dex).unwrap();
        zip.finish().unwrap();
        let restored = dir.path().join(label);
        let result = crate::utils::no_window_command("java")
            .args(["-ea", "-cp"])
            .arg(&classpath)
            .arg("com.yqsh.protector.packer.ApkRecoveryCheck")
            .arg(apk)
            .arg(&restored)
            .arg("unused-for-v7")
            .output()
            .unwrap();
        assert_eq!(
            result.status.success(),
            valid,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if valid {
            let report: serde_json::Value =
                serde_json::from_slice(&std::fs::read(restored.join("recovery.json")).unwrap())
                    .unwrap();
            assert_eq!(report["status"], "external_key_required");
            assert_eq!(
                report["aead_authentication"],
                "not_verified_without_external_key"
            );
        } else {
            assert!(!restored.join("recovery.json").exists());
        }
    }
}
