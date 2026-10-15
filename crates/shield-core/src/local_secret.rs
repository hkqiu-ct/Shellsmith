//! 本地存储的既有 enc:v1 格式；不以设备路径派生的存储密钥抵抗本机账户被控制。
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{env, path::Path};
const SECRET_PREFIX: &str = "enc:v1:";

pub fn derive_crypto_key(db_path: &Path, keystore_dir: &Path) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mocika-shield-gui-cert-store-v1");
    hasher.update(db_path.to_string_lossy().as_bytes());
    hasher.update(keystore_dir.to_string_lossy().as_bytes());
    if let Some(home) = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        hasher.update(home.to_string_lossy().as_bytes());
    }
    if let Some(user) = env::var_os("USER").or_else(|| env::var_os("USERNAME")) {
        hasher.update(user.to_string_lossy().as_bytes());
    }
    hasher.finalize().into()
}

pub fn encrypt_secret(key: &[u8; 32], value: &str) -> Result<String, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "初始化本地秘密加密器失败".to_string())?;
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), value.as_bytes())
        .map_err(|_| "加密本地秘密失败".to_string())?;
    Ok(format!(
        "{}{}:{}",
        SECRET_PREFIX,
        encode_hex(&nonce),
        encode_hex(&ciphertext)
    ))
}

pub fn decrypt_secret(key: &[u8; 32], value: &str) -> Result<String, String> {
    let rest = value
        .strip_prefix(SECRET_PREFIX)
        .ok_or_else(|| "本地记录包含未加密秘密".to_string())?;
    let (nonce_hex, cipher_hex) = rest
        .split_once(':')
        .ok_or_else(|| "本地秘密字段格式无效".to_string())?;
    let nonce = decode_hex(nonce_hex)?;
    if nonce.len() != 12 {
        return Err("本地秘密 nonce 长度无效".to_string());
    }
    let ciphertext = decode_hex(cipher_hex)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "初始化本地秘密解密器失败".to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "解密本地秘密失败，请从有效备份恢复".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "本地秘密不是合法 UTF-8".to_string())
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("本地秘密字段 hex 长度无效".to_string());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = decode_hex_nibble(pair[0])?;
        let lo = decode_hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("本地秘密字段包含非法 hex 字符".to_string()),
    }
}
