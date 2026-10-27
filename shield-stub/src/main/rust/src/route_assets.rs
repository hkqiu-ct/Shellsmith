use std::sync::Mutex;

use super::crypto;

const MAGIC: &[u8; 4] = b"RTA1";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 12 + 4;
const MAX_ROUTE_ASSET_LEN: usize = 16 * 1024 * 1024;

static KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

pub fn initialize(key: [u8; 32]) -> Result<(), String> {
    *KEY.lock()
        .map_err(|_| "route asset key state poisoned".to_string())? = Some(key);
    Ok(())
}

pub fn decrypt(data: &[u8], kind: u8) -> Result<Vec<u8>, String> {
    if data.len() < HEADER_LEN + 16 || &data[..4] != MAGIC {
        return Err("invalid route asset header".to_string());
    }
    if data[4] != VERSION {
        return Err(format!("unsupported route asset version {}", data[4]));
    }
    if data.len() > MAX_ROUTE_ASSET_LEN {
        return Err("route asset exceeds size limit".to_string());
    }
    let nonce: [u8; 12] = data[5..17]
        .try_into()
        .map_err(|_| "invalid route asset nonce".to_string())?;
    let ciphertext_len =
        u32::from_le_bytes(data[17..21].try_into().map_err(|_| "invalid length")?) as usize;
    if ciphertext_len != data.len() - HEADER_LEN {
        return Err("route asset length mismatch".to_string());
    }
    let key = KEY
        .lock()
        .map_err(|_| "route asset key state poisoned".to_string())?
        .ok_or_else(|| "route asset key is not initialized".to_string())?;
    let mut aad = b"mocika-shield/route-assets/v1".to_vec();
    aad.push(kind);
    crypto::decrypt_with_aad(&data[HEADER_LEN..], &key, &nonce, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn blob(plaintext: &[u8], key: &[u8; 32], kind: u8) -> Vec<u8> {
        let nonce = [7u8; 12];
        let mut aad = b"mocika-shield/route-assets/v1".to_vec();
        aad.push(kind);
        let cipher = ChaCha20Poly1305::new(key.into());
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn decrypts_authenticated_route_asset() {
        let _guard = TEST_LOCK.lock().unwrap();
        let key = [9u8; 32];
        initialize(key).unwrap();
        let plaintext = b"com.example.Route\n";
        let data = blob(plaintext, &key, 1);
        assert_eq!(decrypt(&data, 1).unwrap(), plaintext);
        assert!(decrypt(&data, 2).is_err());
    }

    #[test]
    fn rejects_tampered_blob_and_wrong_version() {
        let _guard = TEST_LOCK.lock().unwrap();
        let key = [3u8; 32];
        initialize(key).unwrap();
        let mut data = blob(b"route", &key, 1);
        let last = data.len() - 1;
        data[last] ^= 0xff;
        assert!(decrypt(&data, 1).is_err());

        let mut wrong = blob(b"route", &key, 1);
        wrong[4] = VERSION + 1;
        assert!(decrypt(&wrong, 1).is_err());
    }
}
