use anyhow::{Context, Result};

/// Uploads an IKM to the BYOS key server during the protect step.
/// Returns the token_id assigned by the server.
pub fn register_ikm(endpoint: &str, ikm: &[u8], api_key: &str) -> Result<String> {
    let url = format!("{}/v1/keys/register", endpoint.trim_end_matches('/'));
    let body = serde_json::json!({
        "ikm": base64_encode(ikm),
        "api_key": api_key,
    });
    let resp = ureq::post(&url)
        .header("Content-Type", "application/json")
        .send_json(&body)
        .context("BYOS 服务端注册 IKM 失败")?;
    let json: serde_json::Value = resp.into_body().read_json()
        .context("BYOS 服务端返回非 JSON 响应")?;
    json["token_id"]
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| anyhow::anyhow!("BYOS 服务端响应缺少 token_id 字段"))
}

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
