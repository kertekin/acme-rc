use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EabResult {
    pub key_id: String,
    pub hmac_key: String,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountJson {
    project_id: Option<String>,
    client_email: Option<String>,
    private_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct GoogleClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleExternalAccountKeyResponse {
    #[serde(rename = "keyId")]
    key_id: Option<String>,
    #[serde(rename = "b64MacKey")]
    b64_mac_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZeroSslEabResponse {
    success: Option<bool>,
    eab_kid: Option<String>,
    eab_hmac_key: Option<String>,
    error: Option<ZeroSslError>,
}

#[derive(Debug, Deserialize)]
struct ZeroSslError {
    info: Option<String>,
    #[serde(rename = "type")]
    error_type: Option<String>,
}

/// Fetches Google Trust Services (Public CA) EAB Credentials using GCP Service Account JSON.
/// Supports both Staging (preprod-publicca.googleapis.com) and Production (publicca.googleapis.com).
pub async fn fetch_google_eab_from_sa(sa_json_str: &str, is_staging: bool) -> Result<EabResult, String> {
    let sa: ServiceAccountJson = serde_json::from_str(sa_json_str)
        .map_err(|e| format!("Invalid Service Account JSON format: {}", e))?;

    let project_id = sa
        .project_id
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "Service Account JSON is missing 'project_id'".to_string())?;

    let client_email = sa
        .client_email
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "Service Account JSON is missing 'client_email'".to_string())?;

    let private_key_pem = sa
        .private_key
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "Service Account JSON is missing 'private_key'".to_string())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let claims = GoogleClaims {
        iss: client_email.clone(),
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        aud: "https://oauth2.googleapis.com/token".to_string(),
        iat: now,
        exp: now + 3600,
    };

    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| format!("Failed to parse private key from Service Account JSON: {}", e))?;

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());

    let jwt = encode(&header, &claims, &encoding_key)
        .map_err(|e| format!("Failed to sign OAuth2 JWT token: {}", e))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client initialization failed: {}", e))?;

    // 1. Request Google OAuth2 Access Token
    let token_resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Google OAuth2 token endpoint: {}", e))?;

    let token_data: GoogleTokenResponse = token_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse OAuth2 token response: {}", e))?;

    if let Some(err) = token_data.error {
        let desc = token_data.error_description.unwrap_or_default();
        return Err(format!("Google OAuth2 error: {} - {}", err, desc));
    }

    let access_token = token_data
        .access_token
        .ok_or_else(|| "Google OAuth2 token endpoint returned empty access_token".to_string())?;

    // 2. Call Google Public CA External Account Keys API (Preprod for Staging, Live for Production)
    let api_host = if is_staging {
        "preprod-publicca.googleapis.com"
    } else {
        "publicca.googleapis.com"
    };

    let publicca_url = format!(
        "https://{}/v1/projects/{}/locations/global/externalAccountKeys",
        api_host, project_id
    );

    let ca_resp = client
        .post(&publicca_url)
        .bearer_auth(access_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Google Public CA API ({}): {}", api_host, e))?;


    let status = ca_resp.status();
    let ca_text = ca_resp.text().await.map_err(|e| e.to_string())?;

    if !status.is_success() {
        return Err(format!(
            "Google Public CA API error (Status: {}). Ensure 'Public Certificate Authority API' (publicca.googleapis.com) is enabled for project '{}': {}",
            status, project_id, ca_text
        ));
    }

    let ca_data: GoogleExternalAccountKeyResponse = serde_json::from_str(&ca_text)
        .map_err(|e| format!("Failed to parse Google Public CA response: {}", e))?;

    let key_id = ca_data
        .key_id
        .ok_or_else(|| "Google Public CA response did not include 'keyId'".to_string())?;

    let hmac_key = ca_data
        .b64_mac_key
        .ok_or_else(|| "Google Public CA response did not include 'b64MacKey'".to_string())?;

    Ok(EabResult {
        key_id,
        hmac_key,
    })
}

/// Fetches ZeroSSL ACME EAB Credentials using ZeroSSL API Access Key.
pub async fn fetch_zerossl_eab_from_api_key(api_key: &str) -> Result<EabResult, String> {
    let clean_key = api_key.trim();
    if clean_key.is_empty() {
        return Err("ZeroSSL API Key cannot be empty".to_string());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client initialization failed: {}", e))?;

    let url = format!(
        "https://api.zerossl.com/acme/eab-credentials?access_key={}",
        clean_key
    );

    let resp = client
        .post(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to ZeroSSL API: {}", e))?;

    let text = resp.text().await.map_err(|e| e.to_string())?;
    let data: ZeroSslEabResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse ZeroSSL response: {}", e))?;

    if data.success == Some(false) {
        if let Some(err) = data.error {
            let msg = err.info.unwrap_or_else(|| err.error_type.unwrap_or_else(|| "Unknown ZeroSSL error".to_string()));
            return Err(format!("ZeroSSL API error: {}", msg));
        }
        return Err(format!("ZeroSSL API request unsuccessful: {}", text));
    }

    let key_id = data
        .eab_kid
        .ok_or_else(|| "ZeroSSL response missing 'eab_kid'".to_string())?;

    let hmac_key = data
        .eab_hmac_key
        .ok_or_else(|| "ZeroSSL response missing 'eab_hmac_key'".to_string())?;

    Ok(EabResult {
        key_id,
        hmac_key,
    })
}
