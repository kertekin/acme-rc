use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use instant_acme::{
    Account, ChallengeType, ExternalAccountKey, Identifier,
    NewAccount, NewOrder, OrderStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::crypto::{generate_key_pair_and_csr, GeneratedKeys, KeyType};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum CaProvider {
    GoogleTrustServices,
    LetsEncrypt,
    ZeroSSL,
    Custom(String),
}

impl CaProvider {
    pub fn directory_url(&self, is_staging: bool) -> String {
        match self {
            CaProvider::GoogleTrustServices => {
                if is_staging {
                    "https://dv.acme-v02.test-api.pki.goog/directory".to_string()
                } else {
                    "https://dv.acme-v02.api.pki.goog/directory".to_string()
                }
            }

            CaProvider::LetsEncrypt => {
                if is_staging {
                    "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
                } else {
                    "https://acme-v02.api.letsencrypt.org/directory".to_string()
                }
            }
            CaProvider::ZeroSSL => "https://acme.zerossl.com/v2/DV90".to_string(),
            CaProvider::Custom(url) => url.clone(),
        }
    }

    pub fn display_name(&self, is_staging: bool) -> String {
        match self {
            CaProvider::GoogleTrustServices => {
                if is_staging {
                    "Google Trust Services (Test/Staging)".to_string()
                } else {
                    "Google Trust Services (Production)".to_string()
                }
            }
            CaProvider::LetsEncrypt => {
                if is_staging {
                    "Let's Encrypt (Staging)".to_string()
                } else {
                    "Let's Encrypt (Production)".to_string()
                }
            }
            CaProvider::ZeroSSL => "ZeroSSL (Production)".to_string(),
            CaProvider::Custom(url) => format!("Custom CA ({})", url),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsChallengeInfo {
    pub domain: String,
    pub txt_host: String,
    pub txt_value: String,
    pub token: String,
    pub challenge_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeInitRequest {
    pub ca_type: String,
    pub is_staging: bool,
    pub email: String,
    pub eab_key_id: Option<String>,
    pub eab_hmac_key: Option<String>,
    pub custom_ca_url: Option<String>,
    pub domain: String,
    pub include_www: bool,
    pub is_wildcard: bool,
    pub key_type: String,
    pub server_preset: Option<String>,
    pub output_dir: Option<String>,
    pub profile_name: Option<String>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateResult {
    pub domain: String,
    pub sans: Vec<String>,
    pub ca_used: String,
    pub is_staging: bool,
    pub cert_path: String,
    pub privkey_path: String,
    pub chain_path: String,
    pub fullchain_path: String,
    pub output_dir: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub profile_name: Option<String>,
}



pub struct ActiveAcmeSession {
    pub account: Account,
    pub order_url: String,
    pub domains: Vec<String>,
    pub keys: GeneratedKeys,
    pub challenges: Vec<DnsChallengeInfo>,
    pub request: AcmeInitRequest,
}

pub type SharedSession = Arc<Mutex<Option<ActiveAcmeSession>>>;

pub fn calculate_key_authorization_digest(key_auth: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key_auth.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}

/// Validates domain name against RFC 1035 / RFC 1123 standards
/// Prevents shell injection, command injection, and invalid domain requests
pub fn validate_domain(domain: &str) -> Result<(), String> {
    let d = domain.trim();
    if d.is_empty() {
        return Err("Domain name cannot be empty".to_string());
    }
    if d.len() > 253 {
        return Err("Domain name exceeds maximum length of 253 characters".to_string());
    }

    let core_domain = if let Some(stripped) = d.strip_prefix("*.") {
        stripped
    } else {
        d
    };

    if core_domain.is_empty() {
        return Err("Wildcard domain must specify a root domain (e.g. *.example.com)".to_string());
    }

    let labels: Vec<&str> = core_domain.split('.').collect();
    if labels.len() < 2 {
        return Err("Domain must contain at least one dot (e.g. example.com)".to_string());
    }

    for label in labels {
        if label.is_empty() {
            return Err("Domain labels cannot be empty (consecutive dots are not allowed)".to_string());
        }
        if label.len() > 63 {
            return Err(format!("Domain label '{}' exceeds maximum 63 characters", label));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("Domain label '{}' cannot start or end with a hyphen", label));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("Domain label '{}' contains invalid characters. Only alphanumeric and hyphens are allowed.", label));
        }
    }

    Ok(())
}

pub async fn start_acme_order(
    req: AcmeInitRequest,
    log_cb: impl Fn(&str, &str),
) -> Result<(SharedSession, Vec<DnsChallengeInfo>), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    log_cb("INFO", &format!("Starting ACME order for domain: {}", req.domain));

    // Validate domain before proceeding
    validate_domain(&req.domain)?;

    let ca_provider = match req.ca_type.as_str() {
        "LetsEncrypt" => CaProvider::LetsEncrypt,
        "ZeroSSL" => CaProvider::ZeroSSL,
        "Custom" => {
            let url = req
                .custom_ca_url
                .clone()
                .unwrap_or_default();
            if url.is_empty() {
                return Err("Custom CA URL cannot be empty".to_string());
            }
            CaProvider::Custom(url)
        }
        _ => CaProvider::GoogleTrustServices,
    };

    let dir_url = ca_provider.directory_url(req.is_staging);
    log_cb("INFO", &format!("Connecting to CA Directory: {}", dir_url));



    // Calculate domain list
    let mut domains = Vec::new();
    let root_domain = req.domain.trim().to_lowercase();
    if root_domain.is_empty() {
        return Err("Domain cannot be empty".to_string());
    }

    let clean_root = root_domain.trim_start_matches("*.").to_string();

    // 1. Root domain
    if !domains.contains(&clean_root) {
        domains.push(clean_root.clone());
    }

    // 2. WWW domain (When wildcard is active, *.domain already covers www.domain, avoiding extra subzone CNAME issues)
    if req.include_www && !clean_root.starts_with("www.") {
        if !req.is_wildcard {
            let www_domain = format!("www.{}", clean_root);
            if !domains.contains(&www_domain) {
                domains.push(www_domain);
            }
        } else {
            log_cb("INFO", "Note: Wildcard (*.domain) automatically covers www.domain; omitting redundant subzone challenge.");
        }
    }


    // 3. Wildcard domain
    if req.is_wildcard {
        let wildcard_domain = format!("*.{}", clean_root);
        if !domains.contains(&wildcard_domain) {
            domains.push(wildcard_domain);
        }
    }


    log_cb("INFO", &format!("Target Identifiers (SANs): {:?}", domains));


    // EAB Credentials if provided
    let eab = if let (Some(kid), Some(hmac)) = (&req.eab_key_id, &req.eab_hmac_key) {
        if !kid.trim().is_empty() && !hmac.trim().is_empty() {
            log_cb("INFO", "Using External Account Binding (EAB) credentials");
            let hmac_bytes = URL_SAFE_NO_PAD
                .decode(hmac.trim())
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(hmac.trim()))
                .map_err(|e| format!("Failed to decode HMAC Key (must be valid Base64/Base64URL): {}", e))?;

            Some(ExternalAccountKey::new(kid.trim().to_string(), &hmac_bytes))
        } else {


            None
        }
    } else {
        None
    };

    if (ca_provider == CaProvider::GoogleTrustServices || ca_provider == CaProvider::ZeroSSL) && eab.is_none() {
        let ca_name = if ca_provider == CaProvider::ZeroSSL { "ZeroSSL" } else { "Google Trust Services" };
        return Err(format!("{} requires EAB (Key ID & HMAC Key). Please enter them manually or fetch via API.", ca_name));
    }


    // Create or retrieve ACME account
    log_cb("INFO", "Creating / Registering ACME Account with CA...");
    let email_contact = if !req.email.trim().is_empty() {
        vec![format!("mailto:{}", req.email.trim())]
    } else {
        Vec::new()
    };

    let new_account = NewAccount {
        contact: &email_contact.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, _creds) = Account::builder()
        .map_err(|e| format!("Failed to initialize Account builder: {}", e))?
        .create(&new_account, dir_url, eab.as_ref())
        .await
        .map_err(|e| format!("ACME Account creation failed: {}", e))?;

    log_cb("SUCCESS", "ACME Account authenticated successfully");

    // Generate Private Key and CSR
    let key_type = KeyType::from_str(&req.key_type);
    log_cb("INFO", &format!("Generating cryptographic key pair ({:?})...", key_type));
    let keys = generate_key_pair_and_csr(&domains, &key_type, None)?;
    log_cb("SUCCESS", "Key pair and Certificate Signing Request (CSR) generated");

    // Create New Order
    log_cb("INFO", "Submitting new Certificate Order to ACME server...");
    let identifiers: Vec<Identifier> = domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();

    let new_order = NewOrder::new(&identifiers);
    let mut order = account
        .new_order(&new_order)
        .await
        .map_err(|e| format!("Failed to create ACME order: {}", e))?;

    let order_url = order.url().to_string();
    log_cb("SUCCESS", &format!("Order created with URL: {}", order_url));

    // Fetch authorizations and DNS-01 challenges with retry for slow CAs (e.g. ZeroSSL)
    log_cb("INFO", "Retrieving DNS-01 authorizations and challenge tokens...");
    
    // Give ZeroSSL / slow CAs a brief moment to initialize authorization objects
    if ca_provider == CaProvider::ZeroSSL {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    let mut challenge_infos = Vec::new();
    let mut auth_success = false;
    let mut last_err = String::new();

    for retry in 1..=3 {
        challenge_infos.clear();
        let mut auth_iter = order.authorizations();
        let mut loop_ok = true;

        while let Some(auth_res) = auth_iter.next().await {
            match auth_res {
                Ok(mut auth_handle) => {
                    if let Some(ch_handle) = auth_handle.challenge(ChallengeType::Dns01) {
                        let key_auth = ch_handle.key_authorization();
                        let txt_value = key_auth.dns_value();
                        let domain_str = ch_handle.identifier().to_string();
                        let host_clean = domain_str.trim_start_matches("*.").to_string();
                        let txt_host = format!("_acme-challenge.{}", host_clean);
                        let challenge_url = ch_handle.url.to_string();

                        challenge_infos.push(DnsChallengeInfo {
                            domain: domain_str,
                            txt_host,
                            txt_value,
                            token: String::new(),
                            challenge_url,
                        });
                    }
                }
                Err(e) => {
                    last_err = format!("{}", e);
                    loop_ok = false;
                    break;
                }
            }
        }

        if loop_ok && !challenge_infos.is_empty() {
            auth_success = true;
            break;
        }

        if retry < 3 {
            log_cb(
                "WARN",
                &format!("CA authorization retrieval delayed/timed out (attempt {}/3), retrying in 3s...", retry),
            );
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if let Ok(refreshed) = account.order(order_url.clone()).await {
                order = refreshed;
            }
        }
    }

    if !auth_success {
        if last_err.contains("expected value at line 1 column 1") {
            return Err(format!(
                "ZeroSSL API returned an empty/non-JSON response (504 Gateway Timeout or Rate Limit). ZeroSSL free tier is limited to 3 active certificates, or their API is experiencing high latency. Raw error: {}",
                last_err
            ));
        }
        return Err(format!("Failed to retrieve authorizations from CA: {}", last_err));
    }


    log_cb(
        "SUCCESS",
        &format!("Generated {} DNS-01 challenge(s). Please add TXT records to your DNS provider.", challenge_infos.len()),
    );

    let session = ActiveAcmeSession {
        account,
        order_url,
        domains,
        keys,
        challenges: challenge_infos.clone(),
        request: req,
    };

    Ok((Arc::new(Mutex::new(Some(session))), challenge_infos))
}

pub async fn verify_and_finalize_order(
    session_arc: SharedSession,
    log_cb: impl Fn(&str, &str),
) -> Result<CertificateResult, String> {
    let mut guard = session_arc.lock().await;
    let session = guard.as_mut().ok_or("No active ACME session found. Please start an order first.")?;

    log_cb("INFO", "Starting challenge verification with CA...");

    let mut order = session
        .account
        .order(session.order_url.clone())
        .await
        .map_err(|e| format!("Failed to fetch order: {}", e))?;

    // Inform CA to check each DNS-01 challenge
    let mut auth_iter = order.authorizations();
    while let Some(auth_res) = auth_iter.next().await {
        let mut auth_handle = auth_res.map_err(|e| format!("Failed to get auth: {}", e))?;
        if let Some(mut ch_handle) = auth_handle.challenge(ChallengeType::Dns01) {
            log_cb("INFO", &format!("Notifying CA for DNS challenge: {}", ch_handle.identifier()));
            ch_handle
                .set_ready()
                .await
                .map_err(|e| format!("Failed to notify CA for challenge: {}", e))?;
        }
    }


    log_cb("INFO", "Waiting for CA authorizations to become valid (polling status)...");

    let max_attempts = 30;
    let mut attempt = 0;

    while attempt < max_attempts {
        attempt += 1;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let mut refreshed = session
            .account
            .order(session.order_url.clone())
            .await
            .map_err(|e| format!("Failed to refresh order status: {}", e))?;

        log_cb("INFO", &format!("Order status: {:?} (Attempt {}/{})", refreshed.state().status, attempt, max_attempts));

        match refreshed.state().status {
            OrderStatus::Ready => {
                log_cb("SUCCESS", "All DNS challenges validated! Order is ready for finalization.");
                order = refreshed;
                break;
            }
            OrderStatus::Valid => {
                log_cb("SUCCESS", "Order is already valid.");
                order = refreshed;
                break;
            }
            OrderStatus::Invalid => {
                let mut err_details = Vec::new();
                let mut auth_iter = refreshed.authorizations();
                while let Some(Ok(mut auth_handle)) = auth_iter.next().await {
                    if let Some(ch) = auth_handle.challenge(ChallengeType::Dns01) {
                        if let Some(err) = &ch.error {
                            err_details.push(format!("{}: {:?}", ch.identifier(), err));
                        }
                    }
                }
                let detail_msg = if !err_details.is_empty() {
                    format!(" Details: {}", err_details.join(" | "))
                } else {
                    "".to_string()
                };
                return Err(format!("Order authorization failed at Certificate Authority. Please verify TXT records and DNS propagation.{}", detail_msg));
            }




            OrderStatus::Pending | OrderStatus::Processing => {
                // Keep polling
            }
        }

        if attempt == max_attempts {
            return Err("Timed out waiting for CA challenge validation. Please check DNS propagation and retry.".to_string());
        }
    }

    // Finalize order with CSR
    log_cb("INFO", "Submitting CSR to finalize order and generate certificate...");
    order
        .finalize_csr(&session.keys.csr_der)
        .await
        .map_err(|e| format!("Failed to finalize order with CSR: {}", e))?;

    // Poll until certificate is ready (with 30 attempts / 60 seconds max timeout)
    log_cb("INFO", "Downloading signed SSL/TLS certificate chain...");
    let mut cert_poll_attempts = 0;
    let max_cert_poll = 30;

    let cert_pem = loop {
        cert_poll_attempts += 1;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let mut refreshed = session
            .account
            .order(session.order_url.clone())
            .await
            .map_err(|e| format!("Failed to refresh order: {}", e))?;

        if refreshed.state().status == OrderStatus::Valid {
            let cert_data = refreshed
                .certificate()
                .await
                .map_err(|e| format!("Failed to download certificate: {}", e))?;
            
            if let Some(data) = cert_data {
                break data;
            }
        } else if refreshed.state().status == OrderStatus::Invalid {
            return Err("Order became invalid while waiting for certificate issuance.".to_string());
        }

        if cert_poll_attempts >= max_cert_poll {
            return Err("Timed out waiting for CA to issue certificate after 60 seconds.".to_string());
        }
    };

    log_cb("SUCCESS", "Certificate and full chain downloaded successfully!");

    // Prepare Output Directory
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let sanitized_domain = session.request.domain.replace('*', "wildcard").replace('.', "_");
    let dir_name = format!("{}_{}", sanitized_domain, timestamp);

    let base_dir = if let Some(custom_dir) = &session.request.output_dir {
        if !custom_dir.trim().is_empty() {
            PathBuf::from(custom_dir)
        } else {
            get_default_base_dir()
        }
    } else {
        get_default_base_dir()
    };

    let output_path = base_dir.join(&dir_name);
    fs::create_dir_all(&output_path).map_err(|e| format!("Failed to create output directory {}: {}", output_path.display(), e))?;
    let canonical_output_dir = output_path.canonicalize().unwrap_or(output_path.clone());

    // Parse cert.pem, chain.pem, fullchain.pem
    let fullchain_pem = cert_pem.clone();
    let (leaf_cert, intermediate_chain) = split_cert_chain(&fullchain_pem);
    let expires_at = parse_certificate_expiry(&leaf_cert);

    let clean_domain_name = session.request.domain.trim_start_matches("*.").to_string();
    let preset = session.request.server_preset.as_deref().unwrap_or("all");


    let (cert_path, privkey_path, chain_path, fullchain_path) = match preset.to_lowercase().as_str() {

        "plesk" => (
            canonical_output_dir.join(format!("{}.crt", clean_domain_name)),
            canonical_output_dir.join(format!("{}.key", clean_domain_name)),
            canonical_output_dir.join(format!("{}-ca.crt", clean_domain_name)),
            canonical_output_dir.join(format!("{}.fullchain.crt", clean_domain_name)),
        ),
        "cpanel" => (
            canonical_output_dir.join("certificate.crt"),
            canonical_output_dir.join("private.key"),
            canonical_output_dir.join("ca_bundle.crt"),
            canonical_output_dir.join("certificate.crt"),
        ),
        _ => (
            canonical_output_dir.join("cert.pem"),
            canonical_output_dir.join("privkey.pem"),
            canonical_output_dir.join("chain.pem"),
            canonical_output_dir.join("fullchain.pem"),
        ),
    };

    match preset.to_lowercase().as_str() {

        "plesk" => {
            // Write ONLY Plesk-specific files
            let _ = fs::write(canonical_output_dir.join(format!("{}.crt", clean_domain_name)), &leaf_cert);
            let _ = fs::write(canonical_output_dir.join(format!("{}.cer", clean_domain_name)), &leaf_cert);
            let _ = fs::write(canonical_output_dir.join(format!("{}.key", clean_domain_name)), &session.keys.private_key_pem);
            let _ = fs::write(canonical_output_dir.join(format!("{}-ca.crt", clean_domain_name)), &intermediate_chain);
            let _ = fs::write(canonical_output_dir.join(format!("{}.fullchain.crt", clean_domain_name)), &fullchain_pem);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(
                    canonical_output_dir.join(format!("{}.key", clean_domain_name)),
                    fs::Permissions::from_mode(0o600),
                );
            }
        }
        "cpanel" => {
            // Write ONLY cPanel-specific files
            let _ = fs::write(canonical_output_dir.join("certificate.crt"), &leaf_cert);
            let _ = fs::write(canonical_output_dir.join("private.key"), &session.keys.private_key_pem);
            let _ = fs::write(canonical_output_dir.join("ca_bundle.crt"), &intermediate_chain);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(
                    canonical_output_dir.join("private.key"),
                    fs::Permissions::from_mode(0o600),
                );
            }
        }
        "nginx" | "apache" | "pem" => {
            // Write ONLY standard PEM files
            fs::write(canonical_output_dir.join("cert.pem"), &leaf_cert)
                .map_err(|e| format!("Failed to write cert.pem: {}", e))?;
            fs::write(canonical_output_dir.join("privkey.pem"), &session.keys.private_key_pem)
                .map_err(|e| format!("Failed to write privkey.pem: {}", e))?;
            fs::write(canonical_output_dir.join("chain.pem"), &intermediate_chain)
                .map_err(|e| format!("Failed to write chain.pem: {}", e))?;
            fs::write(canonical_output_dir.join("fullchain.pem"), &fullchain_pem)
                .map_err(|e| format!("Failed to write fullchain.pem: {}", e))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(
                    canonical_output_dir.join("privkey.pem"),
                    fs::Permissions::from_mode(0o600),
                );
            }
        }
        _ => {
            // "all": Standard PEM files in root + organized subdirectories
            let _ = fs::write(canonical_output_dir.join("cert.pem"), &leaf_cert);
            let _ = fs::write(canonical_output_dir.join("privkey.pem"), &session.keys.private_key_pem);
            let _ = fs::write(canonical_output_dir.join("chain.pem"), &intermediate_chain);
            let _ = fs::write(canonical_output_dir.join("fullchain.pem"), &fullchain_pem);

            let plesk_dir = canonical_output_dir.join("plesk");
            let cpanel_dir = canonical_output_dir.join("cpanel");
            let pem_dir = canonical_output_dir.join("nginx_apache");

            let _ = fs::create_dir_all(&plesk_dir);
            let _ = fs::create_dir_all(&cpanel_dir);
            let _ = fs::create_dir_all(&pem_dir);

            // 1. Plesk Directory
            let _ = fs::write(plesk_dir.join(format!("{}.crt", clean_domain_name)), &leaf_cert);
            let _ = fs::write(plesk_dir.join(format!("{}.cer", clean_domain_name)), &leaf_cert);
            let _ = fs::write(plesk_dir.join(format!("{}.key", clean_domain_name)), &session.keys.private_key_pem);
            let _ = fs::write(plesk_dir.join(format!("{}-ca.crt", clean_domain_name)), &intermediate_chain);
            let _ = fs::write(plesk_dir.join(format!("{}.fullchain.crt", clean_domain_name)), &fullchain_pem);

            // 2. cPanel Directory
            let _ = fs::write(cpanel_dir.join("certificate.crt"), &leaf_cert);
            let _ = fs::write(cpanel_dir.join("private.key"), &session.keys.private_key_pem);
            let _ = fs::write(cpanel_dir.join("ca_bundle.crt"), &intermediate_chain);

            // 3. Nginx / Apache / PEM Directory
            let _ = fs::write(pem_dir.join("cert.pem"), &leaf_cert);
            let _ = fs::write(pem_dir.join("privkey.pem"), &session.keys.private_key_pem);
            let _ = fs::write(pem_dir.join("chain.pem"), &intermediate_chain);
            let _ = fs::write(pem_dir.join("fullchain.pem"), &fullchain_pem);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(canonical_output_dir.join("privkey.pem"), fs::Permissions::from_mode(0o600));
                let _ = fs::set_permissions(plesk_dir.join(format!("{}.key", clean_domain_name)), fs::Permissions::from_mode(0o600));
                let _ = fs::set_permissions(cpanel_dir.join("private.key"), fs::Permissions::from_mode(0o600));
                let _ = fs::set_permissions(pem_dir.join("privkey.pem"), fs::Permissions::from_mode(0o600));
            }
        }
    }


    // Quick Deployment Guide Text
    let readme_content = format!(
r#"================================================================================
ACME.rc — SSL/TLS Certificate Deployment Guide for {}
================================================================================

1. PLESK CONTROL PANEL (see 'plesk/' folder):
   - Private Key (.key)      : {}.key  (or privkey.pem)
   - Certificate (.crt/.cer) : {}.crt  (or {}.cer / cert.pem)
   - CA Certificate (Bundle) : {}-ca.crt (or chain.pem)

2. CPANEL / WHM (see 'cpanel/' folder):
   - Private Key (KEY)       : private.key
   - Certificate (CRT)       : certificate.crt
   - Certificate Authority   : ca_bundle.crt

3. NGINX / APACHE / HAPROXY / DOCKER (see 'nginx_apache/' folder):
   - ssl_certificate         : fullchain.pem
   - ssl_certificate_key     : privkey.pem

Domains Covered (SANs): {:?}
Issued At: {}
Expires At: {}
"#,
        clean_domain_name,
        clean_domain_name,
        clean_domain_name,
        clean_domain_name,
        clean_domain_name,
        session.domains,
        chrono::Local::now().to_rfc3339(),
        expires_at.as_deref().unwrap_or("Unknown")
    );
    let _ = fs::write(canonical_output_dir.join("README_DEPLOYMENT.txt"), readme_content);

    let abs_path_str = canonical_output_dir.to_string_lossy().to_string();
    log_cb("SUCCESS", &format!("Certificate files generated successfully with preset '{}' in: {}", preset, abs_path_str));

    let ca_used = CaProvider::from_type_str(&session.request.ca_type).display_name(session.request.is_staging);

    let result = CertificateResult {
        domain: session.request.domain.clone(),
        sans: session.domains.clone(),
        ca_used,
        is_staging: session.request.is_staging,
        cert_path: cert_path.to_string_lossy().to_string(),
        privkey_path: privkey_path.to_string_lossy().to_string(),
        chain_path: chain_path.to_string_lossy().to_string(),
        fullchain_path: fullchain_path.to_string_lossy().to_string(),
        output_dir: abs_path_str,
        issued_at: chrono::Local::now().to_rfc3339(),
        expires_at,
        profile_name: session.request.profile_name.clone(),
    };


    Ok(result)
}

pub fn parse_certificate_expiry(cert_pem: &str) -> Option<String> {
    use x509_parser::pem::parse_x509_pem;
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
    let not_after = cert.validity().not_after;
    let dt = chrono::DateTime::from_timestamp(not_after.timestamp(), 0)?;
    Some(dt.to_rfc3339())
}

impl CaProvider {
    pub fn from_type_str(s: &str) -> Self {
        match s {
            "LetsEncrypt" => CaProvider::LetsEncrypt,
            "ZeroSSL" => CaProvider::ZeroSSL,
            "Custom" => CaProvider::Custom(String::new()),
            _ => CaProvider::GoogleTrustServices,
        }
    }
}

fn split_cert_chain(fullchain: &str) -> (String, String) {
    let parts: Vec<&str> = fullchain
        .split("-----END CERTIFICATE-----")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() > 1 {
        let first = format!("{}\n-----END CERTIFICATE-----\n", parts[0]);
        let rest = parts[1..]
            .iter()
            .map(|p| format!("{}\n-----END CERTIFICATE-----\n", p))
            .collect::<Vec<_>>()
            .join("");
        (first, rest)
    } else if !parts.is_empty() {
        (format!("{}\n-----END CERTIFICATE-----\n", parts[0]), String::new())
    } else {
        (fullchain.to_string(), String::new())
    }
}


fn get_default_base_dir() -> PathBuf {
    if let Ok(current) = std::env::current_dir() {
        if current.ends_with("src-tauri") {
            if let Some(parent) = current.parent() {
                return parent.join("certificates");
            }
        }
        current.join("certificates")
    } else {
        PathBuf::from("certificates")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Live ACME network integration test"]
    async fn test_acme_letsencrypt_staging_order() {
        let req = AcmeInitRequest {
            ca_type: "LetsEncrypt".to_string(),
            is_staging: true,
            email: "test@example.com".to_string(),
            eab_key_id: None,
            eab_hmac_key: None,
            custom_ca_url: None,
            domain: "example.com".to_string(),
            include_www: true,
            is_wildcard: true,
            key_type: "ECDSA_P256".to_string(),
            server_preset: Some("all".to_string()),
            output_dir: None,
            profile_name: Some("test_profile".to_string()),
        };



        let result = start_acme_order(req, |lvl, msg| {
            println!("[{}] {}", lvl, msg);
        }).await;

        match result {
            Ok((_session, challenges)) => { 
                println!("SUCCESS! Challenges count: {}", challenges.len());
                for c in challenges {
                    println!("Domain: {} -> TXT Host: {} -> TXT Val: {}", c.domain, c.txt_host, c.txt_value);
                }
            }
            Err(e) => {
                eprintln!("FAILED: {}", e);
                panic!("ACME Order failed: {}", e);
            }
        }
    }

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("*.example.com").is_ok());
        assert!(validate_domain("sub.domain.co.uk").is_ok());

        assert!(validate_domain("").is_err());
        assert!(validate_domain("example").is_err());
        assert!(validate_domain("example.com; rm -rf /").is_err());
        assert!(validate_domain("example.com' && touch evil").is_err());
        assert!(validate_domain("-example.com").is_err());
        assert!(validate_domain("example..com").is_err());
        assert!(validate_domain("*.com").is_err());
    }
}


