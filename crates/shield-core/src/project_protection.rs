//! 自动按包名和运行证书保存项目身份；每次构建派生独立材料，不改变手机安装即用的契约。
use crate::local_secret::{
    decode_hex, decrypt_secret, derive_crypto_key, encode_hex, encrypt_secret,
};
use crate::protection_report::sha256;
use anyhow::{ensure, Context, Result};
use hkdf::Hkdf;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub schema_version: u32,
    pub id: String,
    pub package_name: String,
    pub certificate_sha256: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    identity: ProjectIdentity,
    private_seed: String,
}

pub fn default_directory() -> Result<PathBuf> {
    Ok(directories::BaseDirs::new()
        .context("无法确定本机应用数据目录")?
        .data_dir()
        .join("dev.mocika.shield-gui"))
}

fn connection(directory: &Path) -> Result<Connection> {
    fs::create_dir_all(directory).context("创建项目保护目录失败")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let path = directory.join("shield.db");
    let conn = Connection::open(&path).context("打开本地项目保护存储失败")?;
    conn.busy_timeout(Duration::from_secs(5))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS protection_projects (
        package_name TEXT NOT NULL, certificate_sha256 TEXT NOT NULL,
        identity TEXT NOT NULL, secret TEXT NOT NULL,
        PRIMARY KEY(package_name, certificate_sha256));",
    )?;
    Ok(conn)
}

fn validate_scope(package: &str, certificate: &str) -> Result<()> {
    ensure!(
        package.len() <= 255
            && package.contains('.')
            && package.split('.').all(|part| {
                !part.is_empty()
                    && part.as_bytes()[0].is_ascii_alphabetic()
                    && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }),
        "项目包名无效"
    );
    ensure!(
        certificate.len() == 64
            && certificate
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "项目运行证书指纹无效"
    );
    Ok(())
}

fn identity_id(package: &str, certificate: &str, seed: &[u8]) -> String {
    sha256(
        &[
            b"shellsmith-project-v1\0".as_slice(),
            package.as_bytes(),
            b"\0",
            certificate.as_bytes(),
            seed,
        ]
        .concat(),
    )
}

fn checked(backup: &Backup) -> Result<[u8; 32]> {
    let info = &backup.identity;
    validate_scope(&info.package_name, &info.certificate_sha256)?;
    let seed: [u8; 32] = decode_hex(&backup.private_seed)
        .map_err(anyhow::Error::msg)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("项目保护种子长度无效"))?;
    ensure!(
        info.schema_version == 1
            && info.id == identity_id(&info.package_name, &info.certificate_sha256, &seed),
        "项目保护资料版本或身份校验失败"
    );
    Ok(seed)
}

fn storage_key(directory: &Path) -> [u8; 32] {
    derive_crypto_key(&directory.join("shield.db"), &directory.join("keystores"))
}

fn read(
    conn: &Connection,
    directory: &Path,
    package: &str,
    certificate: &str,
) -> Result<Option<Backup>> {
    let row: Option<(String, String)> = conn.query_row(
        "SELECT identity, secret FROM protection_projects WHERE package_name=?1 AND certificate_sha256=?2",
        params![package, certificate], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
    row.map(|(metadata, secret)| {
        let backup = Backup {
            identity: serde_json::from_str(&metadata)?,
            private_seed: decrypt_secret(&storage_key(directory), &secret)
                .map_err(anyhow::Error::msg)?,
        };
        checked(&backup)?;
        ensure!(
            backup.identity.package_name == package
                && backup.identity.certificate_sha256 == certificate,
            "项目保护资料与索引不一致"
        );
        Ok(backup)
    })
    .transpose()
}

fn insert(conn: &Connection, directory: &Path, backup: &Backup) -> Result<()> {
    checked(backup)?;
    conn.execute(
        "INSERT INTO protection_projects VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(package_name, certificate_sha256) DO UPDATE SET identity=excluded.identity, secret=excluded.secret",
        params![
            backup.identity.package_name,
            backup.identity.certificate_sha256,
            serde_json::to_string(&backup.identity)?,
            encrypt_secret(&storage_key(directory), &backup.private_seed)
                .map_err(anyhow::Error::msg)?
        ],
    )?;
    Ok(())
}

fn load_or_create(directory: &Path, package: &str, certificate: &str) -> Result<Backup> {
    validate_scope(package, certificate)?;
    let mut conn = connection(directory)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let backup = match read(&tx, directory, package, certificate)? {
        Some(existing) => existing,
        None => {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            let backup = Backup {
                identity: ProjectIdentity {
                    schema_version: 1,
                    id: identity_id(package, certificate, &seed),
                    package_name: package.into(),
                    certificate_sha256: certificate.into(),
                    created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                },
                private_seed: encode_hex(&seed),
            };
            insert(&tx, directory, &backup)?;
            backup
        }
    };
    tx.commit()?;
    Ok(backup)
}

pub(crate) fn build_material(
    directory: &Path,
    package: &str,
    certificate: &str,
) -> Result<([u8; 32], ProjectIdentity, String)> {
    let certificate = crate::apk_inspect::normalize_fingerprint(certificate).to_ascii_lowercase();
    let backup = load_or_create(directory, package, &certificate)?;
    let seed = checked(&backup)?;
    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &seed)
        .expand(b"shellsmith-build-ikm-v1", &mut ikm)
        .map_err(|_| anyhow::anyhow!("派生项目构建材料失败"))?;
    Ok((ikm, backup.identity, encode_hex(&salt)))
}

pub fn list(directory: &Path) -> Result<Vec<ProjectIdentity>> {
    let conn = connection(directory)?;
    let mut query = conn.prepare(
        "SELECT identity FROM protection_projects ORDER BY package_name, certificate_sha256",
    )?;
    let rows = query.query_map([], |row| row.get::<_, String>(0))?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

/// 备份含项目种子，仅在用户主动导出时写入选定文件；不向前端返回秘密。
pub fn export(directory: &Path, id: &str, destination: &Path) -> Result<()> {
    let info = list(directory)?
        .into_iter()
        .find(|p| p.id == id)
        .context("项目保护身份不存在")?;
    let backup = read(
        &connection(directory)?,
        directory,
        &info.package_name,
        &info.certificate_sha256,
    )?
    .context("项目保护资料不存在")?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut file, &backup)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist_noclobber(destination)
        .map_err(|e| anyhow::anyhow!("备份写入失败（不覆盖已有文件）：{}", e.error))?;
    Ok(())
}

pub fn import(directory: &Path, source: &Path) -> Result<ProjectIdentity> {
    let mut bytes = Vec::new();
    fs::File::open(source)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 * 1024, "项目保护备份超过大小限制");
    let backup: Backup = serde_json::from_slice(&bytes).context("项目保护备份格式无效")?;
    checked(&backup)?;
    let mut conn = connection(directory)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // 用已校验备份修复同身份的密文损坏，不要求先解密已经损坏的记录。
    let existing: Option<String> = tx.query_row(
        "SELECT identity FROM protection_projects WHERE package_name=?1 AND certificate_sha256=?2",
        params![backup.identity.package_name, backup.identity.certificate_sha256],
        |row| row.get(0),
    ).optional()?;
    if let Some(metadata) = existing {
        let info: ProjectIdentity = serde_json::from_str(&metadata)?;
        ensure!(
            info.id == backup.identity.id
                && info.package_name == backup.identity.package_name
                && info.certificate_sha256 == backup.identity.certificate_sha256,
            "该项目已有不同保护身份，拒绝覆盖"
        );
    }
    insert(&tx, directory, &backup)?;
    tx.commit()?;
    Ok(backup.identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_identity_is_isolated_atomic_and_backup_safe() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let certificate = "a".repeat(64);
        let (key, info, _) = build_material(dir.path(), "com.example.one", &certificate)?;
        let (next, same, _) =
            build_material(dir.path(), "com.example.one", &("AA:".repeat(31) + "AA"))?;
        assert_eq!(info, same);
        assert_ne!(key, next);
        assert_ne!(
            info.id,
            build_material(dir.path(), "com.example.two", &certificate)?
                .1
                .id
        );
        assert_ne!(
            info.id,
            build_material(dir.path(), "com.example.one", &"b".repeat(64))?
                .1
                .id
        );
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = dir.path().to_owned();
                let cert = certificate.clone();
                std::thread::spawn(move || {
                    build_material(&path, "com.example.concurrent", &cert)
                        .unwrap()
                        .1
                })
            })
            .collect();
        let concurrent: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(concurrent.iter().all(|p| p == &concurrent[0]));
        let backup = dir.path().join("backup.json");
        export(dir.path(), &info.id, &backup)?;
        assert!(export(dir.path(), &info.id, &backup).is_err());
        let other = tempfile::tempdir()?;
        assert_eq!(info, import(other.path(), &backup)?);
        assert_eq!(
            info,
            build_material(other.path(), "com.example.one", &certificate)?.1
        );
        let conflict = tempfile::tempdir()?;
        build_material(conflict.path(), "com.example.one", &certificate)?;
        assert!(import(conflict.path(), &backup).is_err());
        let conn = connection(dir.path())?;
        let stored: String=conn.query_row("SELECT secret FROM protection_projects WHERE package_name=?1 AND certificate_sha256=?2", params!["com.example.one",certificate], |r| r.get(0))?;
        assert!(stored.starts_with("enc:v1:"));
        conn.execute(
            "UPDATE protection_projects SET secret='corrupted' WHERE package_name=?1",
            ["com.example.one"],
        )?;
        assert!(build_material(dir.path(), "com.example.one", &certificate).is_err());
        assert_eq!(info, import(dir.path(), &backup)?);
        assert_eq!(
            info,
            build_material(dir.path(), "com.example.one", &certificate)?.1
        );
        assert!(build_material(dir.path(), "../bad", &certificate).is_err());
        Ok(())
    }
}
