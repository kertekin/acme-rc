use crate::vault::{decrypt_opt, encrypt_opt};
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub id: Option<i64>,
    pub profile_name: String,
    pub ca_type: String,
    pub is_staging: bool,
    pub email: String,
    pub eab_key_id: Option<String>,
    pub eab_hmac_key: Option<String>,
    pub gcp_sa_json: Option<String>,
    pub zerossl_api_key: Option<String>,
    pub custom_ca_url: Option<String>,
    pub domain: String,
    pub include_www: bool,
    pub is_wildcard: bool,
    pub key_type: String,
    pub server_preset: Option<String>,
    pub dns_provider: Option<String>,
    pub dns_api_token: Option<String>,
    pub dns_server_url: Option<String>,
    pub dns_custom_config: Option<String>,
    pub deploy_target: Option<String>,
    pub deploy_custom_path: Option<String>,
    pub deploy_hook_cmd: Option<String>,
    pub deploy_ssh_host: Option<String>,
    pub deploy_ssh_port: Option<u16>,
    pub deploy_ssh_user: Option<String>,
    pub deploy_ssh_key: Option<String>,
    pub deploy_ssh_pass: Option<String>,
    pub output_dir: Option<String>,
    pub updated_at: Option<String>,
}



#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertHistory {
    pub id: Option<i64>,
    pub domain: String,
    pub ca_used: String,
    pub is_staging: bool,
    pub certificate_path: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub sans: String,
    pub profile_name: Option<String>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppSettings {
    pub default_ca: String,
    pub default_is_staging: bool,
    pub default_email: String,
    pub default_key_type: String,
    pub default_server_preset: String,
    pub default_dns_provider: String,
    pub default_dns_api_token: Option<String>,
    pub default_dns_server_url: Option<String>,
    pub default_dns_custom_config: Option<String>,
    pub default_deploy_target: String,
    pub default_deploy_custom_path: Option<String>,
    pub default_deploy_hook_cmd: Option<String>,
    pub default_output_dir: Option<String>,
    pub global_gcp_sa_json: Option<String>,
    pub global_zerossl_api_key: Option<String>,
    pub theme_mode: Option<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            default_ca: "GoogleTrustServices".to_string(),
            default_is_staging: false,
            default_email: "".to_string(),
            default_key_type: "ECDSA_P256".to_string(),
            default_server_preset: "all".to_string(),
            default_dns_provider: "manual".to_string(),
            default_dns_api_token: None,
            default_dns_server_url: None,
            default_dns_custom_config: None,
            default_deploy_target: "none".to_string(),
            default_deploy_custom_path: None,
            default_deploy_hook_cmd: None,
            default_output_dir: None,
            global_gcp_sa_json: None,
            global_zerossl_api_key: None,
            theme_mode: Some("dark".to_string()),
        }
    }
}


pub struct Database {
    db_path: PathBuf,
}

impl Database {
    pub fn new() -> Result<Self, String> {
        let base = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        let config_dir = base.join("acme-rc");
        
        fs::create_dir_all(&config_dir).map_err(|e| format!("Failed to create config dir: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700));
        }

        let db_path = config_dir.join("acme_rc.db");

        let db = Database { db_path: db_path.clone() };
        db.init_schema().map_err(|e| format!("DB init failed: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600));
        }

        Ok(db)
    }

    fn get_conn(&self) -> Result<Connection> {
        Connection::open(&self.db_path)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.get_conn()?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_name TEXT NOT NULL UNIQUE,
                ca_type TEXT NOT NULL,
                is_staging INTEGER NOT NULL DEFAULT 0,
                email TEXT NOT NULL,
                eab_key_id TEXT,
                eab_hmac_key TEXT,
                gcp_sa_json TEXT,
                zerossl_api_key TEXT,
                custom_ca_url TEXT,
                domain TEXT NOT NULL,
                include_www INTEGER NOT NULL DEFAULT 1,
                is_wildcard INTEGER NOT NULL DEFAULT 0,
                key_type TEXT NOT NULL DEFAULT 'ECDSA_P256',
                server_preset TEXT NOT NULL DEFAULT 'all',
                dns_provider TEXT DEFAULT 'manual',
                dns_api_token TEXT,
                dns_server_url TEXT,
                dns_custom_config TEXT,
                deploy_target TEXT DEFAULT 'none',
                deploy_custom_path TEXT,
                deploy_hook_cmd TEXT,
                deploy_ssh_host TEXT,
                deploy_ssh_port INTEGER DEFAULT 22,
                deploy_ssh_user TEXT,
                deploy_ssh_key TEXT,
                output_dir TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Try adding column if upgrading from earlier schema
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN server_preset TEXT DEFAULT 'all'", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN gcp_sa_json TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN zerossl_api_key TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN dns_provider TEXT DEFAULT 'manual'", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN dns_api_token TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN dns_server_url TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN dns_custom_config TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_target TEXT DEFAULT 'none'", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_custom_path TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_hook_cmd TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_ssh_host TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_ssh_port INTEGER DEFAULT 22", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_ssh_user TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_ssh_key TEXT", []);
        let _ = conn.execute("ALTER TABLE profiles ADD COLUMN deploy_ssh_pass TEXT", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS cert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                ca_used TEXT NOT NULL,
                is_staging INTEGER NOT NULL,
                certificate_path TEXT NOT NULL,
                issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                sans TEXT NOT NULL,
                profile_name TEXT
            )",
            [],
        )?;

        let _ = conn.execute("ALTER TABLE cert_history ADD COLUMN profile_name TEXT", []);


        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                default_ca TEXT NOT NULL DEFAULT 'GoogleTrustServices',
                default_is_staging INTEGER NOT NULL DEFAULT 0,
                default_email TEXT NOT NULL DEFAULT '',
                default_key_type TEXT NOT NULL DEFAULT 'ECDSA_P256',
                default_server_preset TEXT NOT NULL DEFAULT 'all',
                default_dns_provider TEXT NOT NULL DEFAULT 'manual',
                default_dns_api_token TEXT,
                default_dns_server_url TEXT,
                default_dns_custom_config TEXT,
                default_deploy_target TEXT NOT NULL DEFAULT 'none',
                default_deploy_custom_path TEXT,
                default_deploy_hook_cmd TEXT,
                default_output_dir TEXT,
                global_gcp_sa_json TEXT,
                global_zerossl_api_key TEXT,
                theme_mode TEXT DEFAULT 'dark',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        let _ = conn.execute("ALTER TABLE app_settings ADD COLUMN theme_mode TEXT DEFAULT 'dark'", []);

        // Ensure default row exists
        let _ = conn.execute(
            "INSERT OR IGNORE INTO app_settings (id) VALUES (1)",
            [],
        );

        Ok(())
    }

    pub fn save_profile(&self, profile: &Profile) -> Result<i64, String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;
        let preset = profile.server_preset.clone().unwrap_or_else(|| "all".to_string());
        let provider = profile.dns_provider.clone().unwrap_or_else(|| "manual".to_string());
        let deploy_tgt = profile.deploy_target.clone().unwrap_or_else(|| "none".to_string());
        let ssh_port = profile.deploy_ssh_port.unwrap_or(22) as i64;
        
        // Encrypt sensitive secrets with Dual-Bound AES-256-GCM Vault
        let enc_eab_hmac = encrypt_opt(&profile.eab_hmac_key);
        let enc_gcp_sa = encrypt_opt(&profile.gcp_sa_json);
        let enc_zerossl_key = encrypt_opt(&profile.zerossl_api_key);
        let enc_dns_token = encrypt_opt(&profile.dns_api_token);
        let enc_ssh_key = encrypt_opt(&profile.deploy_ssh_key);
        let enc_ssh_pass = encrypt_opt(&profile.deploy_ssh_pass);

        conn.execute(
            "INSERT INTO profiles (
                profile_name, ca_type, is_staging, email, eab_key_id, eab_hmac_key,
                gcp_sa_json, zerossl_api_key,
                custom_ca_url, domain, include_www, is_wildcard, key_type, server_preset,
                dns_provider, dns_api_token, dns_server_url, dns_custom_config,
                deploy_target, deploy_custom_path, deploy_hook_cmd, deploy_ssh_host, deploy_ssh_port, deploy_ssh_user, deploy_ssh_key, deploy_ssh_pass,
                output_dir, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, datetime('now'))
            ON CONFLICT(profile_name) DO UPDATE SET
                ca_type = excluded.ca_type,
                is_staging = excluded.is_staging,
                email = excluded.email,
                eab_key_id = excluded.eab_key_id,
                eab_hmac_key = excluded.eab_hmac_key,
                gcp_sa_json = excluded.gcp_sa_json,
                zerossl_api_key = excluded.zerossl_api_key,
                custom_ca_url = excluded.custom_ca_url,
                domain = excluded.domain,
                include_www = excluded.include_www,
                is_wildcard = excluded.is_wildcard,
                key_type = excluded.key_type,
                server_preset = excluded.server_preset,
                dns_provider = excluded.dns_provider,
                dns_api_token = excluded.dns_api_token,
                dns_server_url = excluded.dns_server_url,
                dns_custom_config = excluded.dns_custom_config,
                deploy_target = excluded.deploy_target,
                deploy_custom_path = excluded.deploy_custom_path,
                deploy_hook_cmd = excluded.deploy_hook_cmd,
                deploy_ssh_host = excluded.deploy_ssh_host,
                deploy_ssh_port = excluded.deploy_ssh_port,
                deploy_ssh_user = excluded.deploy_ssh_user,
                deploy_ssh_key = excluded.deploy_ssh_key,
                deploy_ssh_pass = excluded.deploy_ssh_pass,
                output_dir = excluded.output_dir,
                updated_at = datetime('now')",
            params![
                profile.profile_name,
                profile.ca_type,
                profile.is_staging as i32,
                profile.email,
                profile.eab_key_id,
                enc_eab_hmac,
                enc_gcp_sa,
                enc_zerossl_key,
                profile.custom_ca_url,
                profile.domain,
                profile.include_www as i32,
                profile.is_wildcard as i32,
                profile.key_type,
                preset,
                provider,
                enc_dns_token,
                profile.dns_server_url,
                profile.dns_custom_config,
                deploy_tgt,
                profile.deploy_custom_path,
                profile.deploy_hook_cmd,
                profile.deploy_ssh_host,
                ssh_port,
                profile.deploy_ssh_user,
                enc_ssh_key,
                enc_ssh_pass,
                profile.output_dir,
            ],
        ).map_err(|e| e.to_string())?;

        Ok(conn.last_insert_rowid())
    }

    pub fn get_profiles(&self) -> Result<Vec<Profile>, String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT id, profile_name, ca_type, is_staging, email, eab_key_id, eab_hmac_key, gcp_sa_json, zerossl_api_key, custom_ca_url, domain, include_www, is_wildcard, key_type, server_preset, dns_provider, dns_api_token, dns_server_url, dns_custom_config, deploy_target, deploy_custom_path, deploy_hook_cmd, deploy_ssh_host, deploy_ssh_port, deploy_ssh_user, deploy_ssh_key, deploy_ssh_pass, output_dir, updated_at FROM profiles ORDER BY updated_at DESC")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Profile {
                    id: Some(row.get(0)?),
                    profile_name: row.get(1)?,
                    ca_type: row.get(2)?,
                    is_staging: row.get::<_, i32>(3)? == 1,
                    email: row.get(4)?,
                    eab_key_id: row.get(5)?,
                    eab_hmac_key: decrypt_opt(&row.get(6)?),
                    gcp_sa_json: decrypt_opt(&row.get(7)?),
                    zerossl_api_key: decrypt_opt(&row.get(8)?),
                    custom_ca_url: row.get(9)?,
                    domain: row.get(10)?,
                    include_www: row.get::<_, i32>(11)? == 1,
                    is_wildcard: row.get::<_, i32>(12)? == 1,
                    key_type: row.get(13)?,
                    server_preset: row.get(14)?,
                    dns_provider: row.get(15)?,
                    dns_api_token: decrypt_opt(&row.get(16)?),
                    dns_server_url: row.get(17)?,
                    dns_custom_config: row.get(18)?,
                    deploy_target: row.get(19)?,
                    deploy_custom_path: row.get(20)?,
                    deploy_hook_cmd: row.get(21)?,
                    deploy_ssh_host: row.get(22)?,
                    deploy_ssh_port: row.get::<_, Option<i64>>(23)?.map(|p| p as u16),
                    deploy_ssh_user: row.get(24)?,
                    deploy_ssh_key: decrypt_opt(&row.get(25)?),
                    deploy_ssh_pass: decrypt_opt(&row.get(26)?),
                    output_dir: row.get(27)?,
                    updated_at: row.get(28)?,
                })
            })
            .map_err(|e| e.to_string())?;









        let profiles: Vec<Profile> = rows.flatten().collect();
        Ok(profiles)
    }

    pub fn delete_profile(&self, profile_name: &str) -> Result<(), String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM profiles WHERE profile_name = ?1", params![profile_name])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn add_history(&self, history: &CertHistory) -> Result<(), String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO cert_history (domain, ca_used, is_staging, certificate_path, issued_at, expires_at, sans, profile_name)
             VALUES (?1, ?2, ?3, ?4, datetime('now'), ?5, ?6, ?7)",
            params![
                history.domain,
                history.ca_used,
                history.is_staging as i32,
                history.certificate_path,
                history.expires_at,
                history.sans,
                history.profile_name,
            ],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_history(&self) -> Result<Vec<CertHistory>, String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT id, domain, ca_used, is_staging, certificate_path, issued_at, expires_at, sans, profile_name FROM cert_history ORDER BY id DESC")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                Ok(CertHistory {
                    id: Some(row.get(0)?),
                    domain: row.get(1)?,
                    ca_used: row.get(2)?,
                    is_staging: row.get::<_, i32>(3)? == 1,
                    certificate_path: row.get(4)?,
                    issued_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    sans: row.get(7)?,
                    profile_name: row.get(8)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let history: Vec<CertHistory> = rows.flatten().collect();
        Ok(history)
    }


    pub fn delete_history(&self, id: i64) -> Result<Option<String>, String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;
        
        let path: Option<String> = conn
            .query_row("SELECT certificate_path FROM cert_history WHERE id = ?1", params![id], |r| r.get(0))
            .ok();

        conn.execute("DELETE FROM cert_history WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;

        Ok(path)
    }

    pub fn get_app_settings(&self) -> Result<AppSettings, String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT default_ca, default_is_staging, default_email, default_key_type, default_server_preset, default_dns_provider, default_dns_api_token, default_dns_server_url, default_dns_custom_config, default_deploy_target, default_deploy_custom_path, default_deploy_hook_cmd, default_output_dir, global_gcp_sa_json, global_zerossl_api_key, theme_mode FROM app_settings WHERE id = 1")
            .map_err(|e| e.to_string())?;

        let settings = stmt
            .query_row([], |row| {
                Ok(AppSettings {
                    default_ca: row.get(0)?,
                    default_is_staging: row.get::<_, i32>(1)? == 1,
                    default_email: row.get(2)?,
                    default_key_type: row.get(3)?,
                    default_server_preset: row.get(4)?,
                    default_dns_provider: row.get(5)?,
                    default_dns_api_token: decrypt_opt(&row.get(6)?),
                    default_dns_server_url: row.get(7)?,
                    default_dns_custom_config: row.get(8)?,
                    default_deploy_target: row.get(9)?,
                    default_deploy_custom_path: row.get(10)?,
                    default_deploy_hook_cmd: row.get(11)?,
                    default_output_dir: row.get(12)?,
                    global_gcp_sa_json: decrypt_opt(&row.get(13)?),
                    global_zerossl_api_key: decrypt_opt(&row.get(14)?),
                    theme_mode: row.get(15)?,
                })
            })
            .unwrap_or_default();

        Ok(settings)
    }

    pub fn save_app_settings(&self, s: &AppSettings) -> Result<(), String> {
        let conn = self.get_conn().map_err(|e| e.to_string())?;

        let enc_dns_token = encrypt_opt(&s.default_dns_api_token);
        let enc_gcp_sa = encrypt_opt(&s.global_gcp_sa_json);
        let enc_zerossl_key = encrypt_opt(&s.global_zerossl_api_key);

        conn.execute(
            "INSERT INTO app_settings (
                id, default_ca, default_is_staging, default_email, default_key_type, default_server_preset,
                default_dns_provider, default_dns_api_token, default_dns_server_url, default_dns_custom_config,
                default_deploy_target, default_deploy_custom_path, default_deploy_hook_cmd, default_output_dir,
                global_gcp_sa_json, global_zerossl_api_key, theme_mode, updated_at
            ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, datetime('now'))
            ON CONFLICT(id) DO UPDATE SET
                default_ca = excluded.default_ca,
                default_is_staging = excluded.default_is_staging,
                default_email = excluded.default_email,
                default_key_type = excluded.default_key_type,
                default_server_preset = excluded.default_server_preset,
                default_dns_provider = excluded.default_dns_provider,
                default_dns_api_token = excluded.default_dns_api_token,
                default_dns_server_url = excluded.default_dns_server_url,
                default_dns_custom_config = excluded.default_dns_custom_config,
                default_deploy_target = excluded.default_deploy_target,
                default_deploy_custom_path = excluded.default_deploy_custom_path,
                default_deploy_hook_cmd = excluded.default_deploy_hook_cmd,
                default_output_dir = excluded.default_output_dir,
                global_gcp_sa_json = excluded.global_gcp_sa_json,
                global_zerossl_api_key = excluded.global_zerossl_api_key,
                theme_mode = excluded.theme_mode,
                updated_at = datetime('now')",
            params![
                s.default_ca,
                s.default_is_staging as i32,
                s.default_email,
                s.default_key_type,
                s.default_server_preset,
                s.default_dns_provider,
                enc_dns_token,
                s.default_dns_server_url,
                s.default_dns_custom_config,
                s.default_deploy_target,
                s.default_deploy_custom_path,
                s.default_deploy_hook_cmd,
                s.default_output_dir,
                enc_gcp_sa,
                enc_zerossl_key,
                s.theme_mode.clone().unwrap_or_else(|| "dark".to_string()),
            ],
        ).map_err(|e| e.to_string())?;

        Ok(())
    }


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_settings_default() {
        let s = AppSettings::default();
        assert_eq!(s.default_ca, "GoogleTrustServices");
        assert_eq!(s.default_key_type, "ECDSA_P256");
        assert_eq!(s.default_deploy_target, "none");
    }

    #[test]
    fn test_profile_serialization() {
        let p = Profile {
            id: None,
            profile_name: "test_prof".to_string(),
            ca_type: "LetsEncrypt".to_string(),
            is_staging: true,
            email: "test@example.com".to_string(),
            eab_key_id: None,
            eab_hmac_key: None,
            gcp_sa_json: None,
            zerossl_api_key: None,
            custom_ca_url: None,
            domain: "example.com".to_string(),
            include_www: true,
            is_wildcard: false,
            key_type: "ECDSA_P256".to_string(),
            server_preset: Some("nginx".to_string()),
            dns_provider: Some("cloudflare".to_string()),
            dns_api_token: Some("secret_token".to_string()),
            dns_server_url: None,
            dns_custom_config: None,
            deploy_target: Some("local_nginx".to_string()),
            deploy_custom_path: None,
            deploy_hook_cmd: Some("systemctl reload nginx".to_string()),
            deploy_ssh_host: None,
            deploy_ssh_port: Some(22),
            deploy_ssh_user: None,
            deploy_ssh_key: None,
            deploy_ssh_pass: None,
            output_dir: None,
            updated_at: None,
        };


        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("test_prof"));
        assert!(json.contains("cloudflare"));
    }

    #[test]
    fn test_encrypted_profile_db_roundtrip() {
        let db = Database::new().expect("In-memory/local DB should init");
        let secret_hmac = "my_super_secret_hmac_key_987654";
        let secret_gcp = r#"{"client_email":"test@gcp.iam.gserviceaccount.com","private_key":"SECRET_KEY"}"#;
        let secret_ssh_pass = "my_super_secret_ssh_root_pass";

        let prof = Profile {
            id: None,
            profile_name: "test_vault_prof".to_string(),
            ca_type: "GoogleTrustServices".to_string(),
            is_staging: false,
            email: "admin@example.com".to_string(),
            eab_key_id: Some("key_123".to_string()),
            eab_hmac_key: Some(secret_hmac.to_string()),
            gcp_sa_json: Some(secret_gcp.to_string()),
            zerossl_api_key: None,
            custom_ca_url: None,
            domain: "example.com".to_string(),
            include_www: true,
            is_wildcard: true,
            key_type: "ECDSA_P256".to_string(),
            server_preset: Some("all".to_string()),
            dns_provider: Some("cloudflare".to_string()),
            dns_api_token: Some("cf_api_secret_token_123".to_string()),
            dns_server_url: None,
            dns_custom_config: None,
            deploy_target: Some("none".to_string()),
            deploy_custom_path: None,
            deploy_hook_cmd: None,
            deploy_ssh_host: None,
            deploy_ssh_port: Some(22),
            deploy_ssh_user: None,
            deploy_ssh_key: None,
            deploy_ssh_pass: Some(secret_ssh_pass.to_string()),
            output_dir: None,
            updated_at: None,
        };

        db.save_profile(&prof).expect("Save should succeed");

        // Verify raw DB content is encrypted (starts with "enc:v1:")
        let conn = db.get_conn().unwrap();
        let raw_hmac: String = conn.query_row(
            "SELECT eab_hmac_key FROM profiles WHERE profile_name = 'test_vault_prof'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert!(raw_hmac.starts_with("enc:v1:"));
        assert_ne!(raw_hmac, secret_hmac);

        let raw_ssh_pass: String = conn.query_row(
            "SELECT deploy_ssh_pass FROM profiles WHERE profile_name = 'test_vault_prof'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert!(raw_ssh_pass.starts_with("enc:v1:"));
        assert_ne!(raw_ssh_pass, secret_ssh_pass);

        // Verify decrypted via get_profiles
        let profiles = db.get_profiles().expect("Get profiles should succeed");
        let fetched = profiles.iter().find(|p| p.profile_name == "test_vault_prof").unwrap();
        assert_eq!(fetched.eab_hmac_key.as_deref(), Some(secret_hmac));
        assert_eq!(fetched.gcp_sa_json.as_deref(), Some(secret_gcp));
        assert_eq!(fetched.dns_api_token.as_deref(), Some("cf_api_secret_token_123"));
        assert_eq!(fetched.deploy_ssh_pass.as_deref(), Some(secret_ssh_pass));


        // Cleanup
        let _ = db.delete_profile("test_vault_prof");
    }
}




