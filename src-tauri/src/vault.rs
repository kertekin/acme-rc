#![allow(deprecated)]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;

use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const ENC_PREFIX: &str = "enc:v1:";
const NONCE_SIZE: usize = 12;

/// Retrieves unique machine identifier (Linux machine-id, macOS IOPlatformUUID, or Windows Machine GUID)
fn get_machine_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = fs::read_to_string("/etc/machine-id") {
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if let Ok(id) = fs::read_to_string("/var/lib/dbus/machine-id") {
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let str_out = String::from_utf8_lossy(&output.stdout);
            for line in str_out.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        return uuid.to_string();
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["csproduct", "get", "UUID"])
            .output()
        {
            let str_out = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = str_out.lines().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            if lines.len() > 1 {
                return lines[1].to_string();
            }
        }
    }

    // Fallback: hostname + OS const
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "acme_rc_node".to_string());
    format!("machine_{}_{}", std::env::consts::OS, host)
}

/// Retrieves user identifier ($USER + User Home directory)
fn get_user_id() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "default_user".to_string());

    let home = dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    format!("{}:{}", user, home)
}

use std::sync::OnceLock;

static CACHED_SALT: OnceLock<Vec<u8>> = OnceLock::new();
static CACHED_KEY: OnceLock<Key<Aes256Gcm>> = OnceLock::new();

/// Retrieves or securely generates a 32-byte salt file with 0600 permissions
fn get_or_create_salt() -> Vec<u8> {
    CACHED_SALT
        .get_or_init(|| {
            let base_dir = dirs::config_dir()
                .map(|p| p.join("acme-rc"))
                .unwrap_or_else(|| PathBuf::from("."));

            let _ = fs::create_dir_all(&base_dir);
            let salt_path = base_dir.join(".vault.salt");

            if let Ok(salt) = fs::read(&salt_path) {
                if salt.len() == 32 {
                    return salt;
                }
            }

            // Generate new 32-byte random salt
            let mut new_salt = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut new_salt);

            let _ = fs::write(&salt_path, &new_salt);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&salt_path, fs::Permissions::from_mode(0o600));
            }

            new_salt
        })
        .clone()
}

/// Derives a 256-bit AES-GCM encryption key using Dual-Bound (Machine + User + Salt)
pub fn derive_vault_key() -> Key<Aes256Gcm> {
    *CACHED_KEY.get_or_init(|| {
        let machine_id = get_machine_id();
        let user_id = get_user_id();
        let salt = get_or_create_salt();

        let mut hasher = Sha256::new();
        hasher.update(b"ACME.rc::Vault::DualBound::v1::");
        hasher.update(machine_id.as_bytes());
        hasher.update(b"::");
        hasher.update(user_id.as_bytes());
        hasher.update(b"::");
        hasher.update(&salt);

        let result = hasher.finalize();
        *Key::<Aes256Gcm>::from_slice(&result)
    })
}


/// Encrypts sensitive string using AES-256-GCM.
/// Returns "enc:v1:<base64(nonce + ciphertext + tag)>"
pub fn encrypt_secret(plain: &str) -> Result<String, String> {
    let trimmed = plain.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.starts_with(ENC_PREFIX) {
        return Ok(plain.to_string());
    }

    let key = derive_vault_key();
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plain.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    let b64 = BASE64.encode(&combined);
    Ok(format!("{}{}", ENC_PREFIX, b64))
}

/// Decrypts sensitive string if it is encrypted with "enc:v1:".
/// If it is plaintext (legacy / unencrypted), returns as-is.
pub fn decrypt_secret(cipher_text: &str) -> Result<String, String> {
    let trimmed = cipher_text.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed.starts_with(ENC_PREFIX) {
        // Plaintext backwards compatibility
        return Ok(cipher_text.to_string());
    }

    let b64_payload = &trimmed[ENC_PREFIX.len()..];
    let raw_bytes = BASE64
        .decode(b64_payload)
        .map_err(|e| format!("Base64 decoding failed: {}", e))?;

    if raw_bytes.len() <= NONCE_SIZE {
        return Err("Ciphertext is too short".to_string());
    }

    let (nonce_bytes, ciphertext) = raw_bytes.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_vault_key();
    let cipher = Aes256Gcm::new(&key);

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Failed to decrypt secret: Device/User authentication tag mismatch".to_string())?;

    String::from_utf8(decrypted).map_err(|e| format!("Decrypted bytes are not valid UTF-8: {}", e))
}

/// Helper to encrypt an optional string
pub fn encrypt_opt(opt: &Option<String>) -> Option<String> {
    match opt {
        Some(s) if !s.trim().is_empty() => encrypt_secret(s).ok(),
        _ => None,
    }
}

pub fn decrypt_opt(opt: &Option<String>) -> Option<String> {
    match opt {
        Some(s) if !s.trim().is_empty() => {
            let trimmed = s.trim();
            if trimmed.starts_with(ENC_PREFIX) {
                match decrypt_secret(trimmed) {
                    Ok(plain) => Some(plain),
                    Err(e) => {
                        eprintln!("[ACME.rc Vault Warning] Could not decrypt secret on this device/user: {}. Secret needs to be re-entered.", e);
                        None
                    }
                }
            } else {
                Some(s.clone())
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = r#"{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk..."}"#;
        let encrypted = encrypt_secret(original).expect("Encryption failed");

        assert!(encrypted.starts_with(ENC_PREFIX));
        assert_ne!(encrypted, original);

        let decrypted = decrypt_secret(&encrypted).expect("Decryption failed");
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_plaintext_backwards_compatibility() {
        let legacy_plain = "my_legacy_hmac_secret_12345";
        let decrypted = decrypt_secret(legacy_plain).expect("Should accept plaintext");
        assert_eq!(decrypted, legacy_plain);
    }

    #[test]
    fn test_unique_nonces_produce_different_ciphertexts() {
        let secret = "cloudflare_api_token_super_secret";
        let enc1 = encrypt_secret(secret).unwrap();
        let enc2 = encrypt_secret(secret).unwrap();

        assert_ne!(enc1, enc2);
        assert_eq!(decrypt_secret(&enc1).unwrap(), secret);
        assert_eq!(decrypt_secret(&enc2).unwrap(), secret);
    }
}
