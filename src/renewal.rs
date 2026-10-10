use std::sync::Arc;

use crate::{Directory, error::*};
use chrono::{DateTime, Utc};
use openssl::x509::X509Ref;
use serde::Deserialize;

pub struct Renewal {
  directory: Arc<Directory>,
  cert_id: CertificateAriId,
}

impl Renewal {
  pub fn new(
    directory: Arc<Directory>,
    subject: &X509Ref,
  ) -> Result<Self, Error> {
    Ok(Self {
      directory,
      cert_id: CertificateAriId::new(subject)?,
    })
  }

  pub async fn query(&self) -> Result<RenewalInfo, Error> {
    let renewal_url =
      self
        .directory
        .renewal_info_url
        .as_ref()
        .ok_or(Error::Validation(
          "ACME directory does not support ARI extension",
        ))?;

    let response = self
      .directory
      .http_client
      .get(format!("{}/{}", renewal_url, self.cert_id.as_str()))
      .send()
      .await?
      .error_for_status()?;

    let retry_after = response
      .headers()
      .get("retry-after")
      .and_then(|v| v.to_str().ok())
      .and_then(|v| v.parse::<u32>().ok())
      .map(|secs| Utc::now() + chrono::Duration::seconds(secs as i64));

    let mut renewal_info: RenewalInfo = response.json().await?;
    renewal_info.retry_after = retry_after;

    Ok(renewal_info)
  }
}

#[derive(Debug, Clone)]
pub(crate) struct CertificateAriId(String);

impl CertificateAriId {
  pub(crate) fn new(subject: &X509Ref) -> Result<Self, Error> {
    let mut cert_id = String::new();

    let aki = subject
      .authority_key_id()
      .ok_or(Error::Validation("subject certificate requires aki field"))?
      .as_slice();
    base64::encode_config_buf(aki, base64::URL_SAFE_NO_PAD, &mut cert_id);

    cert_id.push('.');

    let mut serial = subject.serial_number().to_bn()?.to_vec();
    // Prevent encoding a negative value as a serial
    if let Some(first) = serial.get(0) {
      if first & 0x80 != 0 {
        serial.insert(0, 0);
      }
    }
    base64::encode_config_buf(serial, base64::URL_SAFE_NO_PAD, &mut cert_id);

    Ok(Self(cert_id))
  }

  pub(crate) fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RenewalInfo {
  #[serde(rename = "suggestedWindow")]
  pub suggested_window: RenewalWindow,
  #[serde(rename = "explanationURL")]
  pub explanation_url: Option<String>,
  #[serde(skip_deserializing)]
  pub retry_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RenewalWindow {
  pub start: DateTime<Utc>,
  pub end: DateTime<Utc>,
}

#[test]
fn test_cert_id() {
  let subject_pem = br#"
-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----
"#;

  let subject_cert = openssl::x509::X509::from_pem(subject_pem).unwrap();

  let expected_cert_id = CertificateAriId::new(&subject_cert).unwrap();

  let cert_id = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";
  assert_eq!(cert_id, expected_cert_id.as_str());
}

#[test]
fn test_deserialize_renewal_info() {
  use chrono::TimeZone;

  let expected_window = RenewalWindow {
    start: Utc.with_ymd_and_hms(2025, 1, 2, 4, 0, 0).unwrap(),
    end: Utc.with_ymd_and_hms(2025, 1, 3, 4, 0, 0).unwrap(),
  };

  let response = r#"{
    "suggestedWindow": {
        "start": "2025-01-02T04:00:00Z",
        "end": "2025-01-03T04:00:00Z"
    }
}"#;

  let result: RenewalInfo = serde_json::from_str(response).unwrap();

  assert_eq!(result.suggested_window, expected_window);
  assert!(result.explanation_url.is_none());

  let response = r#"{
    "suggestedWindow": {
        "start": "2025-01-02T04:00:00Z",
        "end": "2025-01-03T04:00:00Z"
    },
    "explanationURL": "https://acme.example.com/docs/ari"
}"#;

  let result: RenewalInfo = serde_json::from_str(response).unwrap();

  assert_eq!(result.suggested_window, expected_window);
  assert_eq!(
    result.explanation_url.unwrap(),
    "https://acme.example.com/docs/ari"
  );
}
