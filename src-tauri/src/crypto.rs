use pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
use rsa::RsaPrivateKey;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub enum KeyType {
    #[serde(rename = "ECDSA_P256")]
    #[default]
    EcdsaP256,
    #[serde(rename = "ECDSA_P384")]
    EcdsaP384,
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "RSA_4096")]
    Rsa4096,
}

impl KeyType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "ECDSA_P384" => KeyType::EcdsaP384,
            "RSA_2048" => KeyType::Rsa2048,
            "RSA_4096" => KeyType::Rsa4096,
            _ => KeyType::EcdsaP256,
        }
    }
}

#[derive(Clone)]
pub struct GeneratedKeys {
    pub private_key_pem: String,
    pub csr_der: Vec<u8>,
    pub csr_pem: String,
}

pub fn generate_key_pair_and_csr(
    domains: &[String],
    key_type: &KeyType,
    organization: Option<&str>,
) -> Result<GeneratedKeys, String> {
    if domains.is_empty() {
        return Err("Domains list cannot be empty".to_string());
    }

    let key_pair = match key_type {
        KeyType::EcdsaP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("Failed to generate ECDSA P-256 key: {}", e))?,
        KeyType::EcdsaP384 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
            .map_err(|e| format!("Failed to generate ECDSA P-384 key: {}", e))?,
        KeyType::Rsa2048 => {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|e| format!("Failed to generate RSA 2048 key: {}", e))?;
            let pem = priv_key
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .map_err(|e| format!("Failed to encode PKCS8 RSA 2048 key: {}", e))?;
            KeyPair::from_pem(&pem)
                .map_err(|e| format!("Failed to load RSA 2048 key into KeyPair: {}", e))?
        }
        KeyType::Rsa4096 => {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, 4096)
                .map_err(|e| format!("Failed to generate RSA 4096 key: {}", e))?;
            let pem = priv_key
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .map_err(|e| format!("Failed to encode PKCS8 RSA 4096 key: {}", e))?;
            KeyPair::from_pem(&pem)
                .map_err(|e| format!("Failed to load RSA 4096 key into KeyPair: {}", e))?
        }
    };



    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|e| format!("Failed to create certificate params: {}", e))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &domains[0]);
    if let Some(org) = organization {
        if !org.trim().is_empty() {
            dn.push(DnType::OrganizationName, org);
        }
    }
    params.distinguished_name = dn;

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("Failed to serialize CSR: {}", e))?;

    let csr_pem = csr.pem().map_err(|e| format!("Failed to get CSR PEM: {}", e))?;
    let csr_der = csr.der().to_vec();
    let private_key_pem = key_pair.serialize_pem();

    Ok(GeneratedKeys {
        private_key_pem,
        csr_der,
        csr_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ecdsa_p256_keys() {
        let domains = vec!["example.com".to_string(), "www.example.com".to_string()];
        let keys = generate_key_pair_and_csr(&domains, &KeyType::EcdsaP256, None).unwrap();
        assert!(keys.private_key_pem.contains("PRIVATE KEY"));
        assert!(keys.csr_pem.contains("CERTIFICATE REQUEST"));
        assert!(!keys.csr_der.is_empty());
    }

    #[test]
    fn test_generate_rsa_2048_keys() {
        let domains = vec!["*.test.com".to_string(), "test.com".to_string()];
        let keys = generate_key_pair_and_csr(&domains, &KeyType::Rsa2048, Some("ACME.rc")).unwrap();
        assert!(keys.private_key_pem.contains("PRIVATE KEY"));
        assert!(keys.csr_pem.contains("CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_generate_ecdsa_p384_keys() {
        let domains = vec!["secure.test.com".to_string()];
        let keys = generate_key_pair_and_csr(&domains, &KeyType::EcdsaP384, None).unwrap();
        assert!(keys.private_key_pem.contains("PRIVATE KEY"));
        assert!(keys.csr_pem.contains("CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_generate_rsa_4096_keys() {
        let domains = vec!["enterprise.test.com".to_string()];
        let keys = generate_key_pair_and_csr(&domains, &KeyType::Rsa4096, None).unwrap();
        assert!(keys.private_key_pem.contains("PRIVATE KEY"));
        assert!(keys.csr_pem.contains("CERTIFICATE REQUEST"));
    }
}


