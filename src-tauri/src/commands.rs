use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::acme::{
    start_acme_order, verify_and_finalize_order, AcmeInitRequest, CertificateResult,
    DnsChallengeInfo, SharedSession,
};
use crate::db::{CertHistory, Database, Profile};
use crate::dns::DnsPropagationReport;



pub struct AppState {
    pub db: Database,
    pub session: SharedSession,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogPayload {
    pub level: String,
    pub message: String,
    pub timestamp: String,
}

pub fn emit_log(app: &AppHandle, level: &str, message: &str) {
    let payload = LogPayload {
        level: level.to_string(),
        message: message.to_string(),
        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
    };
    let _ = app.emit("cert-log", payload);
}

#[tauri::command]
pub async fn get_profiles(state: State<'_, AppState>) -> Result<Vec<Profile>, String> {
    state.db.get_profiles()
}

#[tauri::command]
pub async fn save_profile(profile: Profile, state: State<'_, AppState>) -> Result<i64, String> {
    state.db.save_profile(&profile)
}

#[tauri::command]
pub async fn delete_profile(name: String, state: State<'_, AppState>) -> Result<(), String> {
    state.db.delete_profile(&name)
}

#[tauri::command]
pub async fn get_history(state: State<'_, AppState>) -> Result<Vec<CertHistory>, String> {
    state.db.get_history()
}

fn is_safe_cert_dir_to_delete(dir: &std::path::Path) -> bool {
    if !dir.exists() || !dir.is_dir() {
        return false;
    }

    // Canonicalize to resolve symlinks and relative paths
    let canonical = match dir.canonicalize() {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Refuse deleting filesystem root or root parent
    if canonical == std::path::Path::new("/") || canonical.parent().is_none() {
        return false;
    }

    // Refuse deleting home directory directly
    if let Some(home) = dirs::home_dir() {
        if canonical == home {
            return false;
        }
    }

    // Refuse deleting protected system paths and common server root directories directly
    let protected = [
        "/etc", "/usr", "/var", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys", "/root", "/home",
        "/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/ssl", "/etc/ssl/certs", "/var/www", "/var/log",
    ];
    for p in &protected {
        if canonical == std::path::Path::new(p) {
            return false;
        }
    }

    // Never delete generic container folder names directly (e.g. certificates, ssl, certs)
    if let Some(name) = canonical.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_lowercase();
        if lower == "certificates" || lower == "ssl" || lower == "certs" || lower == "nginx" || lower == "apache" {
            return false;
        }
    }

    // ACME.rc generated directories always contain README_DEPLOYMENT.txt or known certificate markers
    let has_readme_marker = canonical.join("README_DEPLOYMENT.txt").exists();

    let cert_markers = [
        "cert.pem",
        "privkey.pem",
        "fullchain.pem",
        "chain.pem",
        "certificate.crt",
        "private.key",
        "ca_bundle.crt",
    ];

    let has_cert_marker = cert_markers.iter().any(|m| canonical.join(m).exists());
    let has_subfolder_marker = canonical.join("plesk").exists()
        || canonical.join("cpanel").exists()
        || canonical.join("nginx_apache").exists();

    has_readme_marker || has_cert_marker || has_subfolder_marker
}

#[tauri::command]
pub async fn delete_history_item(
    id: i64,
    delete_files: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let path = state.db.delete_history(id)?;
    if delete_files {
        if let Some(folder_path) = path {
            let p = std::path::PathBuf::from(&folder_path);
            let dir_to_delete = if p.is_file() {
                p.parent().map(|parent| parent.to_path_buf())
            } else {
                Some(p)
            };

            if let Some(d) = dir_to_delete {
                if is_safe_cert_dir_to_delete(&d) {
                    let _ = std::fs::remove_dir_all(&d);
                }
            }
        }
    }
    Ok(())
}


#[tauri::command]
pub async fn start_acme_request(
    request: AcmeInitRequest,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<DnsChallengeInfo>, String> {
    let app_handle = app.clone();
    let log_cb = move |lvl: &str, msg: &str| {
        emit_log(&app_handle, lvl, msg);
    };

    emit_log(&app, "INFO", "Initializing ACME DNS-01 certificate request...");

    let (new_session, challenges) = start_acme_order(request, log_cb).await?;

    // Store the active session in AppState
    let mut guard = state.session.lock().await;
    let mut new_guard = new_session.lock().await;
    *guard = new_guard.take();

    Ok(challenges)
}


#[tauri::command]
pub async fn check_dns(
    txt_host: String,
    expected_value: String,
    app: AppHandle,
) -> Result<DnsPropagationReport, String> {
    emit_log(&app, "INFO", &format!("Checking DNS propagation for: {}", txt_host));
    let report = crate::dns::check_dns_propagation(&txt_host, &expected_value).await;
    
    if report.fully_propagated {
        emit_log(&app, "SUCCESS", &format!("DNS TXT record fully propagated for {}", txt_host));
    } else {
        emit_log(&app, "WARN", &format!("DNS TXT record not yet fully propagated on all resolvers for {}", txt_host));
    }

    Ok(report)
}

#[tauri::command]
pub async fn finalize_certificate(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CertificateResult, String> {
    let app_handle = app.clone();
    let log_cb = move |lvl: &str, msg: &str| {
        emit_log(&app_handle, lvl, msg);
    };

    emit_log(&app, "INFO", "Starting final verification and certificate download...");
    let cert_result = verify_and_finalize_order(state.session.clone(), log_cb).await?;

    // Add to DB History
    let history_entry = CertHistory {
        id: None,
        domain: cert_result.domain.clone(),
        ca_used: cert_result.ca_used.clone(),
        is_staging: cert_result.is_staging,
        certificate_path: cert_result.output_dir.clone(),
        issued_at: cert_result.issued_at.clone(),
        expires_at: cert_result.expires_at.clone(),
        sans: cert_result.sans.join(", "),
        profile_name: cert_result.profile_name.clone(),
    };

    let _ = state.db.add_history(&history_entry);


    emit_log(&app, "SUCCESS", &format!("Certificate successfully generated for {}", cert_result.domain));
    Ok(cert_result)
}

#[tauri::command]
pub async fn select_directory() -> Result<Option<String>, String> {
    let folder = rfd::AsyncFileDialog::new()
        .set_title("Select Certificate Output Directory")
        .pick_folder()
        .await;

    Ok(folder.map(|f| f.path().to_string_lossy().to_string()))
}

#[tauri::command]
pub async fn open_folder(path: String, _app: AppHandle) -> Result<(), String> {
    let mut target = std::path::PathBuf::from(&path);

    // If target is a file (e.g. cert.pem was passed), get its parent directory
    if target.is_file() {
        if let Some(parent) = target.parent() {
            target = parent.to_path_buf();
        }
    }

    // If path does not exist directly, try finding it relative to current_dir or src-tauri
    if !target.exists() {
        if let Ok(cur) = std::env::current_dir() {
            let candidates = vec![
                cur.join(&path),
                cur.join("src-tauri").join(&path),
                cur.join("certificates").join(&path),
                if cur.ends_with("src-tauri") {
                    cur.parent().map(|p| p.join(&path)).unwrap_or_else(|| cur.join(&path))
                } else {
                    cur.join(&path)
                },
            ];

            for cand in candidates {
                let actual = if cand.is_file() {
                    cand.parent().map(|p| p.to_path_buf()).unwrap_or(cand)
                } else {
                    cand
                };
                if actual.exists() {
                    target = actual;
                    break;
                }
            }
        }
    }

    if !target.exists() {
        return Err(format!("Directory path does not exist on disk: {}", path));
    }

    let target_str = target.to_string_lossy().to_string();

    // 1. Try xdg-open detached
    if std::process::Command::new("xdg-open")
        .arg(&target_str)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
    {
        return Ok(());
    }

    // 2. Try dolphin directly on KDE
    if std::process::Command::new("dolphin")
        .arg(&target_str)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
    {
        return Ok(());
    }

    // 3. Try gio open
    if std::process::Command::new("gio")
        .args(["open", &target_str])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
    {
        return Ok(());
    }

    // 4. Fallback open crate
    open::that_detached(&target_str).map_err(|e| format!("Failed to open directory: {}", e))
}

#[tauri::command]
pub async fn select_json_file() -> Result<Option<String>, String> {
    let file = rfd::AsyncFileDialog::new()
        .set_title("Select Google Cloud Service Account JSON File")
        .add_filter("JSON File", &["json"])
        .pick_file()
        .await;

    if let Some(f) = file {
        let content = std::fs::read_to_string(f.path())
            .map_err(|e| format!("Failed to read JSON file: {}", e))?;
        Ok(Some(content))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn select_key_file() -> Result<Option<String>, String> {
    let file = rfd::AsyncFileDialog::new()
        .set_title("Select SSH Private Key File (~/.ssh/id_rsa, *.pem, *.key)")
        .pick_file()
        .await;

    if let Some(f) = file {
        Ok(Some(f.path().to_string_lossy().to_string()))
    } else {
        Ok(None)
    }
}


#[tauri::command]
pub async fn fetch_google_eab(
    sa_json: String,
    is_staging: Option<bool>,
    app: AppHandle,
) -> Result<crate::eab_api::EabResult, String> {
    let staging = is_staging.unwrap_or(false);
    let env_name = if staging { "Staging/Preprod" } else { "Production" };
    emit_log(&app, "INFO", &format!("Requesting Google Public CA ({}) EAB credentials via GCP API...", env_name));
    match crate::eab_api::fetch_google_eab_from_sa(&sa_json, staging).await {
        Ok(res) => {
            emit_log(&app, "SUCCESS", &format!("Successfully generated Google Public CA ({}) EAB Key ID & HMAC!", env_name));
            Ok(res)
        }
        Err(e) => {
            emit_log(&app, "ERROR", &format!("Failed to fetch Google EAB: {}", e));
            Err(e)
        }
    }
}


#[tauri::command]
pub async fn fetch_zerossl_eab(
    api_key: String,
    app: AppHandle,
) -> Result<crate::eab_api::EabResult, String> {
    emit_log(&app, "INFO", "Requesting ZeroSSL EAB credentials via ZeroSSL API...");
    match crate::eab_api::fetch_zerossl_eab_from_api_key(&api_key).await {
        Ok(res) => {
            emit_log(&app, "SUCCESS", "Successfully retrieved ZeroSSL EAB Key ID & HMAC!");
            Ok(res)
        }
        Err(e) => {
            emit_log(&app, "ERROR", &format!("Failed to fetch ZeroSSL EAB: {}", e));
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn add_dns_txt_record(
    provider: String,
    token: String,
    host: String,
    value: String,
    server_url: Option<String>,
    _custom_config: Option<String>,
    app: AppHandle,
) -> Result<crate::dns_api::CreatedDnsRecord, String> {

    let p = provider.to_lowercase();
    emit_log(&app, "INFO", &format!("Adding DNS TXT record for '{}' via {}...", host, provider));

    let res = match p.as_str() {
        "cloudflare" => crate::dns_api::create_cloudflare_txt_record(&token, &host, &value, _custom_config.as_deref()).await,
        "hetzner" => crate::dns_api::create_hetzner_txt_record(&token, &host, &value).await,

        "digitalocean" => crate::dns_api::create_digitalocean_txt_record(&token, &host, &value).await,
        "plesk" => {
            let s_url = server_url.ok_or_else(|| "Plesk Server URL is required".to_string())?;
            crate::dns_api::create_plesk_txt_record(&s_url, &token, &host, &value).await
        }
        "webhook" => {
            let add_url = server_url.ok_or_else(|| "Webhook Add URL is required".to_string())?;
            crate::dns_api::create_custom_webhook_txt_record(&add_url, Some(&token), &host, &value).await
        }
        _ => Err(format!("Unsupported DNS API provider: {}", provider)),
    };

    match res {
        Ok(rec) => {
            emit_log(&app, "SUCCESS", &format!("Successfully created DNS TXT record on {}", provider));
            Ok(rec)
        }
        Err(e) => {
            emit_log(&app, "ERROR", &format!("Failed to create DNS record via {}: {}", provider, e));
            Err(e)
        }
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn delete_dns_txt_record(
    provider: String,
    token: String,
    host: String,
    record_id: String,
    zone_id: Option<String>,
    server_url: Option<String>,
    custom_config: Option<String>,
    app: AppHandle,
) -> Result<(), String> {
    let p = provider.to_lowercase();
    emit_log(&app, "INFO", &format!("Cleaning up DNS TXT record on {}...", provider));

    let res = match p.as_str() {
        "cloudflare" => {
            let z_id = zone_id.ok_or_else(|| "Missing Zone ID for Cloudflare cleanup".to_string())?;
            crate::dns_api::delete_cloudflare_txt_record(&token, &z_id, &record_id).await
        }
        "hetzner" => crate::dns_api::delete_hetzner_txt_record(&token, &record_id).await,
        "digitalocean" => {
            let domain = zone_id.unwrap_or_else(|| host.clone());
            crate::dns_api::delete_digitalocean_txt_record(&token, &domain, &record_id).await
        }
        "plesk" => {
            let s_url = server_url.ok_or_else(|| "Plesk Server URL is required".to_string())?;
            crate::dns_api::delete_plesk_txt_record(&s_url, &token, &record_id).await
        }
        "webhook" => {
            let del_url = custom_config.unwrap_or_default();
            crate::dns_api::delete_custom_webhook_txt_record(&del_url, Some(&token), &host, &record_id).await
        }
        _ => Err(format!("Unsupported DNS API provider: {}", provider)),
    };

    match res {
        Ok(_) => {
            emit_log(&app, "SUCCESS", &format!("Cleaned up DNS TXT record on {}", provider));
            Ok(())
        }
        Err(e) => {
            emit_log(&app, "WARN", &format!("Could not clean up DNS record: {}", e));
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn deploy_certificate(

    domain: String,
    cert_dir: String,
    config: crate::deploy::DeployConfig,
    app: AppHandle,
) -> Result<String, String> {
    let target = config.target.to_lowercase();
    if target == "none" || target.is_empty() {
        return Ok("No deployment target configured (download only).".to_string());
    }

    emit_log(&app, "INFO", &format!("Starting auto-deployment for domain '{}' to target '{}'...", domain, target));
    let path = std::path::PathBuf::from(&cert_dir);

    let res = if target.starts_with("local_") {
        crate::deploy::execute_local_deploy(&domain, &path, &config).await
    } else if target == "remote_ssh" {
        crate::deploy::execute_ssh_deploy(&domain, &path, &config).await
    } else {
        Err(format!("Unknown deployment target: {}", target))
    };

    match res {
        Ok(summary) => {
            emit_log(&app, "SUCCESS", &format!("Deployment completed: {}", summary));
            Ok(summary)
        }
        Err(e) => {
            emit_log(&app, "ERROR", &format!("Deployment failed: {}", e));
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn get_app_settings(

    state: tauri::State<'_, AppState>,
) -> Result<crate::db::AppSettings, String> {
    state.db.get_app_settings()
}

#[tauri::command]
pub async fn save_app_settings(
    settings: crate::db::AppSettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.db.save_app_settings(&settings)
}

#[derive(serde::Serialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub build_number: u32,
    pub full_version: String,
    pub description: String,
    pub rustc_version: String,
    pub os: String,
}

#[tauri::command]
pub fn get_app_info() -> AppInfo {
    let version = env!("CARGO_PKG_VERSION").to_string();
    let build_num: u32 = option_env!("APP_BUILD_NUMBER")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let full_version = option_env!("APP_VERSION_FULL")
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("v{} (build {})", version, build_num));

    AppInfo {
        name: "ACME.rc".to_string(),
        version,
        build_number: build_num,
        full_version,
        description: "Modern ACME SSL/TLS Certificate Engine & Auto-Deployment Manager".to_string(),
        rustc_version: "Rust 2021 Edition".to_string(),
        os: std::env::consts::OS.to_string(),
    }
}










