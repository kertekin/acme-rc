use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreatedDnsRecord {
    pub provider: String,
    pub host: String,
    pub record_id: String,
    pub zone_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CfZoneListResponse {
    success: bool,
    result: Vec<CfZone>,
    errors: Option<Vec<CfError>>,
}


#[derive(Debug, Deserialize)]
struct CfZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CfDnsRecordResponse {
    success: bool,
    result: Option<CfRecordResult>,
    errors: Option<Vec<CfError>>,
}

#[derive(Debug, Deserialize)]
struct CfRecordResult {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CfError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct HetznerZoneListResponse {
    zones: Vec<HetznerZone>,
}

#[derive(Debug, Deserialize)]
struct HetznerZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct HetznerRecordResponse {
    record: Option<HetznerRecordResult>,
}

#[derive(Debug, Deserialize)]
struct HetznerRecordResult {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DoRecordResponse {
    domain_record: Option<DoRecordResult>,
}

#[derive(Debug, Deserialize)]
struct DoRecordResult {
    id: u64,
}

pub fn extract_root_zone_name(host: &str) -> String {
    let clean = host.trim().trim_end_matches('.');
    let parts: Vec<&str> = clean.split('.').collect();
    let n = parts.len();
    if n <= 2 {
        return clean.to_string();
    }

    let tld = parts[n - 1].to_lowercase();
    let sld = parts[n - 2].to_lowercase();

    // Check for common two-part public suffixes (e.g. .com.tr, .co.uk, .org.uk, .com.au, .gov.tr, etc.)
    let is_known_two_part_tld = (tld.len() == 2 && matches!(
        sld.as_str(),
        "com" | "net" | "org" | "gov" | "edu" | "mil" | "co" | "ac" | "or" | "ne" | "go" | "biz" | "info" | "gen" | "k12" | "bel" | "nom" | "me"
    )) || (tld == "uk" && matches!(sld.as_str(), "co" | "org" | "me" | "ac" | "gov" | "net" | "sch" | "plc" | "ltd"))
       || (tld == "tr" && matches!(sld.as_str(), "com" | "net" | "org" | "gov" | "edu" | "k12" | "bel" | "av" | "dr" | "biz" | "info" | "gen" | "pol" | "kep"))
       || (tld == "au" && matches!(sld.as_str(), "com" | "net" | "org" | "edu" | "gov" | "asn" | "id"))
       || (tld == "nz" && matches!(sld.as_str(), "co" | "net" | "org" | "govt" | "ac" | "school" | "geek" | "kiwi"))
       || (tld == "jp" && matches!(sld.as_str(), "co" | "ne" | "or" | "ac" | "ed" | "go" | "lg"))
       || (tld == "br" && matches!(sld.as_str(), "com" | "net" | "org" | "gov" | "edu" | "ind" | "art"))
       || (tld == "za" && matches!(sld.as_str(), "co" | "org" | "net" | "ac" | "gov"));

    if is_known_two_part_tld && n >= 3 {
        format!("{}.{}.{}", parts[n - 3], parts[n - 2], parts[n - 1])
    } else {
        format!("{}.{}", parts[n - 2], parts[n - 1])
    }
}

async fn find_cloudflare_zone(
    client: &reqwest::Client,
    token: &str,
    target_host: &str,
) -> Result<(String, String), String> {
    let clean_host = target_host.trim().trim_end_matches('.');
    let parts: Vec<&str> = clean_host.split('.').collect();

    // 1. Try candidate suffixes from most specific to least specific
    for i in 1..parts.len() {
        let candidate_zone = parts[i..].join(".");
        if candidate_zone.is_empty() || !candidate_zone.contains('.') {
            continue;
        }
        let zone_resp = client
            .get("https://api.cloudflare.com/client/v4/zones")
            .bearer_auth(token)
            .query(&[("name", &candidate_zone), ("status", &"active".to_string())])
            .send()
            .await;

        if let Ok(resp) = zone_resp {
            if let Ok(zone_data) = resp.json::<CfZoneListResponse>().await {
                if zone_data.success && !zone_data.result.is_empty() {
                    return Ok((zone_data.result[0].id.clone(), clean_host.to_string()));
                }
            }
        }
    }

    // 2. List all accessible zones in the account / token
    let all_zones_resp = client
        .get("https://api.cloudflare.com/client/v4/zones")
        .bearer_auth(token)
        .query(&[("status", &"active".to_string()), ("per_page", &"50".to_string())])
        .send()
        .await
        .map_err(|e| format!("Cloudflare API connection failed: {}", e))?;

    let all_zones_data: CfZoneListResponse = all_zones_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Cloudflare zone list: {}", e))?;

    // 2a. Suffix matching across all available zones
    let mut best_match: Option<(String, usize, String)> = None;
    for zone in &all_zones_data.result {
        if clean_host == zone.name || clean_host.ends_with(&format!(".{}", zone.name)) {
            let len = zone.name.len();
            if best_match.as_ref().is_none_or(|(_, max_len, _)| len > *max_len) {
                best_match = Some((zone.id.clone(), len, clean_host.to_string()));
            }
        }
    }

    if let Some((zone_id, _, record_name)) = best_match {
        return Ok((zone_id, record_name));
    }

    // 2b. Single-Zone or Delegated Zone Fallback:
    // If the Cloudflare token has access to only 1 zone, or a delegated zone exists,
    // provision the record inside that zone (e.g. _acme-challenge.<zone_name>)
    if all_zones_data.result.len() == 1 {
        let single_zone = &all_zones_data.result[0];
        let delegated_record_name = if clean_host.starts_with("_acme-challenge") {
            format!("_acme-challenge.{}", single_zone.name)
        } else {
            format!("{}.{}", clean_host, single_zone.name)
        };
        return Ok((single_zone.id.clone(), delegated_record_name));
    }

    if all_zones_data.result.is_empty() {
        return Err("No active zones found in your Cloudflare account or API token lacks Zone:Read permissions".to_string());
    }

    let available_zones: Vec<String> = all_zones_data.result.into_iter().map(|z| z.name).collect();
    Err(format!(
        "No matching Cloudflare zone found for host '{}'. Available zones in token: [{}]",
        target_host,
        available_zones.join(", ")
    ))
}

/// Creates a DNS-01 TXT record using Cloudflare DNS API (supports CNAME delegation)
pub async fn create_cloudflare_txt_record(
    api_token: &str,
    txt_host: &str,
    txt_value: &str,
    custom_config: Option<&str>,
) -> Result<CreatedDnsRecord, String> {
    let token = api_token.trim();
    if token.is_empty() {
        return Err("Cloudflare API Token cannot be empty".to_string());
    }

    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    // Check for CNAME Delegation (e.g., _acme-challenge.domain.com -> _acme-challenge.delegated.com)
    let mut target_host = txt_host.to_string();
    if let Some(cfg) = custom_config {
        let trimmed_cfg = cfg.trim();
        if !trimmed_cfg.is_empty() {
            target_host = trimmed_cfg.to_string();
        }
    } else if let Some(cname_target) = crate::dns::resolve_cname_target(txt_host).await {
        target_host = cname_target;
    }

    let (zone_id, record_name) = find_cloudflare_zone(&client, token, &target_host).await?;

    // 2. Create TXT Record
    let create_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
        zone_id
    );

    let create_resp = client
        .post(&create_url)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "type": "TXT",
            "name": record_name.trim_end_matches('.'),
            "content": txt_value.trim(),
            "ttl": 120
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to create DNS record on Cloudflare: {}", e))?;

    let create_data: CfDnsRecordResponse = create_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Cloudflare DNS create response: {}", e))?;

    if !create_data.success || create_data.result.is_none() {
        let err_msg = create_data
            .errors
            .and_then(|errs| errs.into_iter().next())
            .map(|e| e.message)
            .unwrap_or_else(|| "Unknown Cloudflare record creation error".to_string());
        return Err(format!("Cloudflare DNS create error: {}", err_msg));
    }

    let record_id = create_data.result.unwrap().id;

    Ok(CreatedDnsRecord {
        provider: "cloudflare".to_string(),
        host: record_name,
        record_id,
        zone_id: Some(zone_id.clone()),
    })
}


/// Deletes a DNS TXT record from Cloudflare
pub async fn delete_cloudflare_txt_record(
    api_token: &str,
    zone_id: &str,
    record_id: &str,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
        zone_id, record_id
    );

    let resp = client
        .delete(&url)
        .bearer_auth(api_token.trim())
        .send()
        .await
        .map_err(|e| format!("Cloudflare delete failed: {}", e))?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Cloudflare failed to delete TXT record: {}", text));
    }

    Ok(())
}

/// Creates a DNS-01 TXT record using Hetzner DNS API
pub async fn create_hetzner_txt_record(
    api_token: &str,
    txt_host: &str,
    txt_value: &str,
) -> Result<CreatedDnsRecord, String> {
    let token = api_token.trim();
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let zone_name = extract_root_zone_name(txt_host);

    // 1. Get Zones
    let zones_resp = client
        .get("https://dns.hetzner.com/api/v1/zones")
        .header("Auth-API-Token", token)
        .send()
        .await
        .map_err(|e| format!("Hetzner API connection error: {}", e))?;

    let zones_data: HetznerZoneListResponse = zones_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Hetzner zone list: {}", e))?;

    let zone = zones_data
        .zones
        .into_iter()
        .find(|z| z.name.eq_ignore_ascii_case(&zone_name))
        .ok_or_else(|| format!("Hetzner DNS Zone '{}' not found", zone_name))?;

    // 2. Relative record name for Hetzner
    let clean_host = txt_host.trim_end_matches('.');
    let relative_name = if clean_host == zone_name {
        "@".to_string()
    } else {
        clean_host.trim_end_matches(&format!(".{}", zone_name)).to_string()
    };

    let create_resp = client
        .post("https://dns.hetzner.com/api/v1/records")
        .header("Auth-API-Token", token)
        .json(&serde_json::json!({
            "zone_id": zone.id,
            "type": "TXT",
            "name": relative_name,
            "value": txt_value.trim(),
            "ttl": 120
        }))
        .send()
        .await
        .map_err(|e| format!("Hetzner create record failed: {}", e))?;

    let rec_data: HetznerRecordResponse = create_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Hetzner create response: {}", e))?;

    let record_id = rec_data
        .record
        .map(|r| r.id)
        .ok_or_else(|| "Hetzner DNS creation returned empty record ID".to_string())?;

    Ok(CreatedDnsRecord {
        provider: "hetzner".to_string(),
        host: txt_host.to_string(),
        record_id,
        zone_id: Some(zone.id),
    })
}

/// Deletes a DNS TXT record from Hetzner
pub async fn delete_hetzner_txt_record(
    api_token: &str,
    record_id: &str,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let url = format!("https://dns.hetzner.com/api/v1/records/{}", record_id);
    let resp = client
        .delete(&url)
        .header("Auth-API-Token", api_token.trim())
        .send()
        .await
        .map_err(|e| format!("Hetzner delete failed: {}", e))?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Hetzner failed to delete TXT record: {}", text));
    }

    Ok(())
}

/// Creates a DNS-01 TXT record using DigitalOcean API
pub async fn create_digitalocean_txt_record(
    api_token: &str,
    txt_host: &str,
    txt_value: &str,
) -> Result<CreatedDnsRecord, String> {
    let token = api_token.trim();
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let domain = extract_root_zone_name(txt_host);
    let clean_host = txt_host.trim_end_matches('.');
    let relative_name = if clean_host == domain {
        "@".to_string()
    } else {
        clean_host.trim_end_matches(&format!(".{}", domain)).to_string()
    };

    let url = format!("https://api.digitalocean.com/v2/domains/{}/records", domain);
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "type": "TXT",
            "name": relative_name,
            "data": txt_value.trim(),
            "ttl": 120
        }))
        .send()
        .await
        .map_err(|e| format!("DigitalOcean record creation failed: {}", e))?;

    let data: DoRecordResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse DigitalOcean create response: {}", e))?;

    let record_id = data
        .domain_record
        .map(|r| r.id.to_string())
        .ok_or_else(|| "DigitalOcean returned empty record ID".to_string())?;

    Ok(CreatedDnsRecord {
        provider: "digitalocean".to_string(),
        host: txt_host.to_string(),
        record_id,
        zone_id: Some(domain),
    })
}

/// Deletes a DNS TXT record from DigitalOcean
pub async fn delete_digitalocean_txt_record(
    api_token: &str,
    domain: &str,
    record_id: &str,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let url = format!(
        "https://api.digitalocean.com/v2/domains/{}/records/{}",
        domain, record_id
    );

    let resp = client
        .delete(&url)
        .bearer_auth(api_token.trim())
        .send()
        .await
        .map_err(|e| format!("DigitalOcean delete failed: {}", e))?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("DigitalOcean failed to delete TXT record: {}", text));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct PleskZone {
    id: i64,
    name: String,
}

#[derive(Debug, Deserialize)]
struct PleskRecordResponse {
    id: Option<i64>,
    message: Option<String>,
}

/// Creates a DNS-01 TXT record using Plesk REST API
pub async fn create_plesk_txt_record(
    server_url: &str,
    api_key: &str,
    txt_host: &str,
    txt_value: &str,
) -> Result<CreatedDnsRecord, String> {
    let base = server_url.trim().trim_end_matches('/');
    let key = api_key.trim();

    if base.is_empty() || key.is_empty() {
        return Err("Plesk Server URL and API Key cannot be empty".to_string());
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Allow self-signed panel certs
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let zone_name = extract_root_zone_name(txt_host);

    // 1. Get DNS Zones to resolve zone_id
    let zones_url = format!("{}/api/v2/dns/zones", base);
    let zones_resp = client
        .get(&zones_url)
        .header("X-API-Key", key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Plesk connection failed (check server URL): {}", e))?;

    if !zones_resp.status().is_success() {
        let err_text = zones_resp.text().await.unwrap_or_default();
        return Err(format!("Plesk API authentication failed: {}", err_text));
    }

    let zones_list: Vec<PleskZone> = zones_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Plesk DNS zones: {}", e))?;

    let zone = zones_list
        .into_iter()
        .find(|z| z.name.eq_ignore_ascii_case(&zone_name))
        .ok_or_else(|| format!("DNS Zone '{}' not found on Plesk server", zone_name))?;

    // 2. Relative host name (e.g. "_acme-challenge")
    let clean_host = txt_host.trim_end_matches('.');
    let relative_host = if clean_host == zone_name {
        "".to_string()
    } else {
        clean_host.trim_end_matches(&format!(".{}", zone_name)).trim_end_matches('.').to_string()
    };

    // 3. Create TXT Record
    let create_url = format!("{}/api/v2/dns/records", base);
    let create_resp = client
        .post(&create_url)
        .header("X-API-Key", key)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "type": "TXT",
            "host": relative_host,
            "value": txt_value.trim(),
            "opt": "",
            "zone_id": zone.id
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to create DNS record in Plesk: {}", e))?;

    let rec_text = create_resp.text().await.map_err(|e| e.to_string())?;
    let rec_data: PleskRecordResponse = serde_json::from_str(&rec_text)
        .map_err(|e| format!("Failed to parse Plesk record response ({}): {}", rec_text, e))?;

    let record_id = rec_data
        .id
        .map(|id| id.to_string())
        .ok_or_else(|| format!("Plesk record creation error: {}", rec_data.message.unwrap_or(rec_text)))?;

    Ok(CreatedDnsRecord {
        provider: "plesk".to_string(),
        host: txt_host.to_string(),
        record_id,
        zone_id: Some(zone.id.to_string()),
    })
}

/// Deletes a DNS TXT record from Plesk
pub async fn delete_plesk_txt_record(
    server_url: &str,
    api_key: &str,
    record_id: &str,
) -> Result<(), String> {
    let base = server_url.trim().trim_end_matches('/');
    let key = api_key.trim();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let url = format!("{}/api/v2/dns/records/{}", base, record_id);
    let resp = client
        .delete(&url)
        .header("X-API-Key", key)
        .send()
        .await
        .map_err(|e| format!("Plesk delete failed: {}", e))?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Plesk failed to delete TXT record: {}", text));
    }

    Ok(())
}

/// Creates a DNS TXT record via Generic Custom Webhook
pub async fn create_custom_webhook_txt_record(
    add_url: &str,
    auth_header: Option<&str>,
    txt_host: &str,
    txt_value: &str,
) -> Result<CreatedDnsRecord, String> {
    let url = add_url.trim();
    if url.is_empty() {
        return Err("Webhook Add URL cannot be empty".to_string());
    }

    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let zone_name = extract_root_zone_name(txt_host);

    let mut req = client.post(url).json(&serde_json::json!({
        "action": "create",
        "domain": zone_name,
        "host": txt_host.trim_end_matches('.'),
        "value": txt_value.trim(),
        "type": "TXT",
        "ttl": 120
    }));

    if let Some(auth) = auth_header.filter(|s| !s.trim().is_empty()) {
        req = req.header("Authorization", auth.trim());
    }

    let resp = req.send().await.map_err(|e| format!("Webhook request failed: {}", e))?;
    let text = resp.text().await.unwrap_or_default();

    // Try parsing record_id from JSON, or fallback to host string as ID
    let rec_id = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("record_id")
                .or_else(|| v.get("id"))
                .and_then(|id| id.as_str().map(|s| s.to_string()).or_else(|| id.as_i64().map(|n| n.to_string())))
        })
        .unwrap_or_else(|| txt_host.to_string());

    Ok(CreatedDnsRecord {
        provider: "webhook".to_string(),
        host: txt_host.to_string(),
        record_id: rec_id,
        zone_id: Some(zone_name),
    })
}

/// Deletes a DNS TXT record via Generic Custom Webhook
pub async fn delete_custom_webhook_txt_record(
    del_url: &str,
    auth_header: Option<&str>,
    txt_host: &str,
    record_id: &str,
) -> Result<(), String> {
    let url = del_url.trim();
    if url.is_empty() {
        return Ok(()); // Optional deletion URL
    }

    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let zone_name = extract_root_zone_name(txt_host);

    let mut req = client.post(url).json(&serde_json::json!({
        "action": "delete",
        "domain": zone_name,
        "host": txt_host.trim_end_matches('.'),
        "record_id": record_id,
        "type": "TXT"
    }));

    if let Some(auth) = auth_header.filter(|s| !s.trim().is_empty()) {
        req = req.header("Authorization", auth.trim());
    }

    let _ = req.send().await;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_root_zone_name() {
        assert_eq!(extract_root_zone_name("_acme-challenge.example.com"), "example.com");
        assert_eq!(extract_root_zone_name("_acme-challenge.sub.example.com"), "example.com");
        assert_eq!(extract_root_zone_name("example.com"), "example.com");
        assert_eq!(extract_root_zone_name("single"), "single");

        // Two-part TLDs tests (.com.tr, .co.uk, etc.)
        assert_eq!(extract_root_zone_name("_acme-challenge.example.com.tr"), "example.com.tr");
        assert_eq!(extract_root_zone_name("_acme-challenge.sub.domain.co.uk"), "domain.co.uk");
        assert_eq!(extract_root_zone_name("portal.gov.tr"), "portal.gov.tr");
        assert_eq!(extract_root_zone_name("_acme-challenge.brand.com.au"), "brand.com.au");
    }
}


