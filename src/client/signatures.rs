/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod dummy_verifier;

#[cfg(feature = "ring_verifier")]
pub mod ring_verifier;

#[cfg(feature = "rc_crypto_verifier")]
pub mod rc_crypto_verifier;

pub mod x509;

use crate::client::Collection;
use log::debug;
use serde_json::json;
use thiserror::Error;
use url::{ParseError as URLParseError, Url};
use viaduct::{Error as ViaductError, Request, Response};

#[cfg(not(test))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(test))]
fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap() // Time won't go backwards.
        .as_secs()
}

#[cfg(test)]
use mock_instant;

#[cfg(test)]
fn epoch_seconds() -> u64 {
    mock_instant::MockClock::time().as_secs()
}

/// A trait for signature verification of collection data.
///
/// You may want to use your own verification implementation (eg. using OpenSSL instead of `ring` or `rc_crypto`).
///
/// # How can I implement ```Verification```?
/// ```rust
/// # use remote_settings_client::client::{Client, Collection, SignatureError, Verification};
///
/// struct SignatureVerifier {}
///
/// impl Verification for SignatureVerifier {
///     fn verify_nist384p_chain(
///         &self,
///         epoch_seconds: u64,
///         pem_bytes: &[u8],
///         root_hash:&str,
///         subject_cn: &str,
///         message: &[u8],
///         signature: &[u8],
///     ) -> Result<(), SignatureError> {
///         Ok(()) // unreachable.
///     }
/// }
///
/// # fn main() {
/// let client = Client::builder()
///    .collection_name("cid")
///    .verifier(Box::new(SignatureVerifier {}))
///    .build();
/// # }
/// ```
pub trait Verification: Send {
    fn fetch_certificate_chain(&self, collection: &Collection) -> Result<Vec<u8>, SignatureError> {
        // Get public key from collection metadata (PEM URL is `x5u` field).
        let x5u = collection.metadata["signature"]["x5u"]
            .as_str()
            .ok_or(SignatureError::MissingSignatureField())?;
        // Fetch certificate from URL (certificate chain).
        debug!("Fetching certificate {}", x5u);
        let response = Request::get(Url::parse(&x5u)?).send()?;
        if !response.is_success() {
            return Err(SignatureError::CertificateDownloadError { response });
        }
        // TODO: read server time from headers to compute clock skew and return along
        Ok(response.body)
    }

    fn serialize_data(&self, collection: &Collection) -> Result<Vec<u8>, SignatureError> {
        let mut sorted_records = collection.records.to_vec();
        sorted_records.sort_by_cached_key(|r| r.id().to_owned());
        let serialized = canonical_json::to_string(&json!({
            "data": sorted_records,
            "last_modified": collection.timestamp.to_string()
        }))?;
        let data = format!("Content-Signature:\x00{}", serialized);
        Ok(data.as_bytes().to_vec())
    }

    /// Verifies signature for a given ```Collection``` struct.
    /// 1. Fetch and parse the chain of PEM-format certificates linked to in the "x5u" property.
    /// 2. Serialize the collection data in canonical JSON format.
    /// 3. Verify the certificates chain of trust using root_hash and signer name, and that the ECDSA P384 SHA384 signature matches the data.
    /// # Errors
    /// If all the steps are performed without errors, but the specified collection data
    /// does not match its signature, then a [`SignatureError::MismatchError`] is returned.
    ///
    /// If errors occur during certificate download, parsing, or data serialization, then
    /// the corresponding error is returned.
    fn verify(&self, collection: &Collection, root_hash: &str) -> Result<(), SignatureError> {
        let pem_bytes = self.fetch_certificate_chain(&collection)?;

        let signature_bytes = collection.metadata["signature"]["signature"]
            .as_str()
            .unwrap_or("")
            .as_bytes();

        let data_bytes = self.serialize_data(&collection)?;

        let now = epoch_seconds();
        self.verify_nist384p_chain(
            now,
            &pem_bytes,
            &root_hash,
            &collection.signer,
            &data_bytes,
            &signature_bytes,
        )
    }

    /// Verify chain of trust.
    /// 1. Parse the PEM bytes as DER-encoded X.509 Certificate.
    /// 2. Verify that root hash matches the SHA256 fingerprint of the root certificate (DER content)
    /// 3. Verify that each certificate of the chain is currently valid (revocation support is optional)
    /// 4. Verify that each child signature matches its parent's public key for each pair in the chain
    /// 5. Verify that the subject alternate name of the end-entity certificate matches the collection signer name.
    /// 6. Use the chain's end-entity (leaf) certificate to verify that the "signature" property matches the contents of the data.
    fn verify_nist384p_chain(
        &self,
        epoch_seconds: u64,
        pem_bytes: &[u8],
        root_hash: &str,
        subject_cn: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError>;
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("signature mismatch: {0}")]
    MismatchError(String),
    #[error("certificate could not be downloaded from {}: HTTP {}", response.url, response.status)]
    CertificateDownloadError { response: Response },
    #[error("certificate content could not be parsed: {0}")]
    CertificateContentError(#[from] x509::X509Error),
    #[error("root certificate fingerprint has bad format: {0}")]
    RootHashFormatError(String),
    #[error("root certificate fingerprint does not match: {0}")]
    CertificateHasWrongRoot(String),
    #[error("certificate alternate subject does not match: {0}")]
    WrongSignerName(String),
    #[error("certificate expired")]
    CertificateExpired,
    #[error("certificate chain could not be verified")]
    CertificateTrustError,
    #[error("certificate chain was signed with unsupported algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("could not hash message: {0}")]
    HashingError(String),
    #[error("signature contains invalid base64: {0}")]
    BadSignatureContent(String),
    #[error("signature payload has no x5u field")]
    MissingSignatureField(),
    #[error("HTTP backend issue: {0}")]
    HTTPBackendError(#[from] ViaductError),
    #[error("bad URL format: {0}")]
    URLError(#[from] URLParseError),
    #[error("data could not be serialized: {0}")]
    SerializationError(#[from] canonical_json::CanonicalJSONError),
}

#[cfg(test)]
mod tests {
    use super::dummy_verifier::DummyVerifier;
    use super::x509;
    use crate::{Collection, Record, SignatureError, Verification};
    use env_logger;
    use httpmock::MockServer;
    use mock_instant::MockClock;
    use serde_json::json;
    use std::time::Duration;
    use viaduct::set_backend;
    use viaduct_reqwest::ReqwestBackend;

    impl PartialEq for SignatureError {
        fn eq(&self, other: &Self) -> bool {
            std::mem::discriminant(self) == std::mem::discriminant(other)
        }
    }

    fn verify_signature(
        mock_server: &MockServer,
        collection: Collection,
        certificate: &str,
        expected_result: Result<(), SignatureError>,
    ) {
        let mut get_pem_certificate = mock_server.mock(|when, then| {
            when.path(
                "/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain",
            );
            then.body(certificate);
        });

        let mut verifiers: Vec<Box<dyn Verification>> = Vec::new();

        #[cfg(feature = "ring_verifier")]
        verifiers.push(Box::new(super::ring_verifier::RingVerifier {}));

        #[cfg(feature = "rc_crypto_verifier")]
        verifiers.push(Box::new(super::rc_crypto_verifier::RcCryptoVerifier {}));

        let root_hash = "3C:01:44:6A:BE:90:36:CE:A9:A0:9A:CA:A3:A5:20:AC:62:8F:20:A7:AE:32:CE:86:1C:B2:EF:B7:0F:A0:C7:45";

        for verifier in &verifiers {
            assert_eq!(verifier.verify(&collection, root_hash), expected_result);
        }

        get_pem_certificate.assert_hits(verifiers.len());
        get_pem_certificate.delete();
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _ = set_backend(&ReqwestBackend);
    }

    #[test]
    fn test_missing_x5u() {
        let verifier = DummyVerifier {};
        let collection = Collection {
            bid: "".to_string(),
            cid: "".to_string(),
            metadata: json!({}),
            records: vec![],
            timestamp: 0,
            signer: "".to_string(),
        };
        let err = verifier.fetch_certificate_chain(&collection).unwrap_err();
        match err {
            SignatureError::MissingSignatureField() => assert!(true),
            e => assert!(false, "Unexpected error type: {:?}", e),
        };
    }

    #[test]
    fn test_bad_x5u_urls() {
        let verifier = DummyVerifier {};

        let _ = set_backend(&ReqwestBackend);
        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("/file.pem");
        let mut pem_mock = mock_server.mock(|when, then| {
            when.path("/file.pem");
            then.status(404);
        });

        let expectations: Vec<(&str, &str)> = vec![
            ("%^", "bad URL format: relative URL without a base"),
            (
                "http://localhost:9999/bad",
                "Network error: error sending request",
            ),
            (&mock_server_address, "/file.pem: HTTP 404"),
        ];

        for (url, error) in expectations {
            let collection = Collection {
                bid: "".to_string(),
                cid: "".to_string(),
                metadata: json!({
                    "signature": {
                        "x5u": url
                    }
                }),
                records: vec![],
                timestamp: 0,
                signer: "".to_string(),
            };
            let err = verifier.fetch_certificate_chain(&collection).unwrap_err();
            assert!(err.to_string().contains(error), "{}", err.to_string());
        }

        pem_mock.delete();
    }

    #[test]
    fn test_verify_signature() {
        init();

        let mock_server: MockServer = MockServer::start();

        const VALID_CERTIFICATE: &str = "\
-----BEGIN CERTIFICATE-----
MIIDBjCCAougAwIBAgIIFml6g0ldRGowCgYIKoZIzj0EAwMwgaMxCzAJBgNVBAYT
AlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3pp
bGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTFFMEMGA1UEAww8Q29u
dGVudCBTaWduaW5nIEludGVybWVkaWF0ZS9lbWFpbEFkZHJlc3M9Zm94c2VjQG1v
emlsbGEuY29tMB4XDTIxMDIwMzE1MDQwNVoXDTIxMDQyNDE1MDQwNVowgakxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFp
biBWaWV3MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcwFQYDVQQLEw5D
bG91ZCBTZXJ2aWNlczE2MDQGA1UEAxMtcmVtb3RlLXNldHRpbmdzLmNvbnRlbnQt
c2lnbmF0dXJlLm1vemlsbGEub3JnMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8pKb
HX4IiD0SCy+NO7gwKqRRZ8IhGd8PTaIHIBgM6RDLRyDeswXgV+2kGUoHyzkbNKZt
zlrS3AhqeUCtl1g6ECqSmZBbRTjCpn/UCpCnMLL0T0goxtAB8Rmi3CdM0cBUo4GD
MIGAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSME
GDAWgBQlZawrqt0eUz/t6OdN45oKfmzy6DA4BgNVHREEMTAvgi1yZW1vdGUtc2V0
dGluZ3MuY29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwCgYIKoZIzj0EAwMD
aQAwZgIxAPh43Bxl4MxPT6Ra1XvboN5O2OvIn2r8rHvZPWR/jJ9vcTwH9X3F0aLJ
9FiresnsLAIxAOoAcREYB24gFBeWxbiiXaG7TR/yM1/MXw4qxbN965FFUaoB+5Bc
fS8//SQGTlCqKQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF2jCCA8KgAwIBAgIEAQAAADANBgkqhkiG9w0BAQsFADCBqTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQK
ExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5zaWdu
aW5nLnJvb3QuY2ExMTAvBgkqhkiG9w0BCQEWInNlY29wcytzdGFnZXJvb3RhZGRv
bnNAbW96aWxsYS5jb20wHhcNMjEwMTExMDAwMDAwWhcNMjQxMTE0MjA0ODU5WjCB
ozELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAt
BgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMUUw
QwYDVQQDDDxDb250ZW50IFNpZ25pbmcgSW50ZXJtZWRpYXRlL2VtYWlsQWRkcmVz
cz1mb3hzZWNAbW96aWxsYS5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARw1dyE
xV5aNiHJPa/fVHO6kxJn3oZLVotJ0DzFZA9r1sQf8i0+v78Pg0/c3nTAyZWfkULz
vOpKYK/GEGBtisxCkDJ+F3NuLPpSIg3fX25pH0LE15fvASBVcr8tKLVHeOmjggG6
MIIBtjAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8EDDAK
BggrBgEFBQcDAzAdBgNVHQ4EFgQUJWWsK6rdHlM/7ejnTeOaCn5s8ugwgdkGA1Ud
IwSB0TCBzoAUhtg0HE5Y0RNcmV/YQpjtFA8Z8l2hga+kgawwgakxCzAJBgNVBAYT
AlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UE
ChMTQWRkb25zIFRlc3QgU2lnbmluZzEkMCIGA1UEAxMbdGVzdC5hZGRvbnMuc2ln
bmluZy5yb290LmNhMTEwLwYJKoZIhvcNAQkBFiJzZWNvcHMrc3RhZ2Vyb290YWRk
b25zQG1vemlsbGEuY29tggRgJZg7MDMGCWCGSAGG+EIBBAQmFiRodHRwOi8vYWRk
b25zLmFsbGl6b20ub3JnL2NhL2NybC5wZW0wTgYDVR0eBEcwRaBDMCCCHi5jb250
ZW50LXNpZ25hdHVyZS5tb3ppbGxhLm9yZzAfgh1jb250ZW50LXNpZ25hdHVyZS5t
b3ppbGxhLm9yZzANBgkqhkiG9w0BAQsFAAOCAgEAtGTTzcPzpcdf07kIeRs9vPMx
qiF8ylW5L/IQ2NzT3sFFAvPW1vW1wZC0xAHMsuVyo+BTGrv+4mlD0AUR9acRfiTZ
9qyZ3sJbyhQwJAXLKU4YpnzuFOf58T/yOnOdwpH2ky/0FuHskMyfXaAz2Az4JXJH
TCgggqfdZNvsZ5eOnQlKoC5NadMa8oTI5sd4SyR5ANUPAtYok931MvVSz3IMbwTr
v4PPWXdl9SGXuOknSqdY6/bS1LGvC2KprsT+PBlvVtS6YgZOH0uCgTTLpnrco87O
ErzC2PJBA1Ftn3Mbaou6xy7O+YX+reJ6soNUV+0JHOuKj0aTXv0c+lXEAh4Y8nea
UGhW6+MRGYMOP2NuKv8s2+CtNH7asPq3KuTQpM5RerjdouHMIedX7wpNlNk0CYbg
VMJLxZfAdwcingLWda/H3j7PxMoAm0N+eA24TGDQPC652ZakYk4MQL/45lm0A5f0
xLGKEe6JMZcTBQyO7ANWcrpVjKMiwot6bY6S2xU17mf/h7J32JXZJ23OPOKpMS8d
mljj4nkdoYDT35zFuS1z+5q6R5flLca35vRHzC3XA0H/XJvgOKUNLEW/IiJIqLNi
ab3Ao0RubuX+CAdFML5HaJmkyuJvL3YtwIOwe93RGcGRZSKZsnMS+uY5QN8+qKQz
LC4GzWQGSCGDyD+JCVw=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIHbDCCBVSgAwIBAgIEYCWYOzANBgkqhkiG9w0BAQwFADCBqTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQK
ExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5zaWdu
aW5nLnJvb3QuY2ExMTAvBgkqhkiG9w0BCQEWInNlY29wcytzdGFnZXJvb3RhZGRv
bnNAbW96aWxsYS5jb20wHhcNMjEwMjExMjA0ODU5WhcNMjQxMTE0MjA0ODU5WjCB
qTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBW
aWV3MRwwGgYDVQQKExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0
LmFkZG9ucy5zaWduaW5nLnJvb3QuY2ExMTAvBgkqhkiG9w0BCQEWInNlY29wcytz
dGFnZXJvb3RhZGRvbnNAbW96aWxsYS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDKRVty/FRsO4Ech6EYleyaKgAueaLYfMSsAIyPC/N8n/P8QcH8
rjoiMJrKHRlqiJmMBSmjUZVzZAP0XJku0orLKWPKq7cATt+xhGY/RJtOzenMMsr5
eN02V3GzUd1jOShUpERjzXdaO3pnfZqhdqNYqP9ocqQpyno7bZ3FZQ2vei+bF52k
51uPioTZo+1zduoR/rT01twGtZm3QpcwU4mO74ysyxxgqEy3kpojq8Nt6haDwzrj
khV9M6DGPLHZD71QaUiz5lOhD9CS8x0uqXhBhwMUBBkHsUDSxbN4ZhjDDWpCmwaD
OtbJMUJxDGPCr9qj49QESccb367OeXLrfZ2Ntu/US2Bw9EDfhyNsXr9dg9NHj5yf
4sDUqBHG0W8zaUvJx5T2Ivwtno1YZLyJwQW5pWeWn8bEmpQKD2KS/3y2UjlDg+YM
NdNASjFe0fh6I5NCFYmFWA73DpDGlUx0BtQQU/eZQJ+oLOTLzp8d3dvenTBVnKF+
uwEmoNfZwc4TTWJOhLgwxA4uK+Paaqo4Ap2RGS2ZmVkPxmroB3gL5n3k3QEXvULh
7v8Psk4+MuNWnxudrPkN38MGJo7ju7gDOO8h1jLD4tdfuAqbtQLduLXzT4DJPA4y
JBTFIRMIpMqP9CovaS8VPtMFLTrYlFh9UnEGpCeLPanJr+VEj7ae5sc8YwIDAQAB
o4IBmDCCAZQwDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0lAQH/
BAwwCgYIKwYBBQUHAwMwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVk
IENlcnRpZmljYXRlMDMGCWCGSAGG+EIBBAQmFiRodHRwOi8vYWRkb25zLm1vemls
bGEub3JnL2NhL2NybC5wZW0wHQYDVR0OBBYEFIbYNBxOWNETXJlf2EKY7RQPGfJd
MIHZBgNVHSMEgdEwgc6AFIbYNBxOWNETXJlf2EKY7RQPGfJdoYGvpIGsMIGpMQsw
CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcx
HDAaBgNVBAoTE0FkZG9ucyBUZXN0IFNpZ25pbmcxJDAiBgNVBAMTG3Rlc3QuYWRk
b25zLnNpZ25pbmcucm9vdC5jYTExMC8GCSqGSIb3DQEJARYic2Vjb3BzK3N0YWdl
cm9vdGFkZG9uc0Btb3ppbGxhLmNvbYIEYCWYOzANBgkqhkiG9w0BAQwFAAOCAgEA
nowyJv8UaIV7NA0B3wkWratq6FgA1s/PzetG/ZKZDIW5YtfUvvyy72HDAwgKbtap
Eog6zGI4L86K0UGUAC32fBjE5lWYEgsxNM5VWlQjbgTG0dc3dYiufxfDFeMbAPmD
DzpIgN3jHW2uRqa/MJ+egHhv7kGFL68uVLboqk/qHr+SOCc1LNeSMCuQqvHwwM0+
AU1GxhzBWDkealTS34FpVxF4sT5sKLODdIS5HXJr2COHHfYkw2SW/Sfpt6fsOwaF
2iiDaK4LPWHWhhIYa6yaynJ+6O6KPlpvKYCChaTOVdc+ikyeiSO6AakJykr5Gy7d
PkkK7MDCxuY6psHj7iJQ59YK7ujQB8QYdzuXBuLLo5hc5gBcq3PJs0fLT2YFcQHA
dj+olGaDn38T0WI8ycWaFhQfKwATeLWfiQepr8JfoNlC2vvSDzGUGfdAfZfsJJZ8
5xZxahHoTFGS0mDRfXqzKH5uD578GgjOZp0fULmzkcjWsgzdpDhadGjExRZFKlAy
iKv8cXTONrGY0fyBDKennuX0uAca3V0Qm6v2VRp+7wG/pywWwc5n+04qgxTQPxgO
6pPB9UUsNbaLMDR5QPYAWrNhqJ7B07XqIYJZSwGP5xB9NqUZLF4z+AOMYgWtDpmg
IKdcFKAt3fFrpyMhlfIKkLfmm0iDjmfmIXbDGBJw9SE=
-----END CERTIFICATE-----";

        const INVALID_CERTIFICATE: &str = "\
-----BEGIN CERTIFICATE-----
invalidCertificategIFiJLFfdxFlYwCgYIKoZIzj0EAwMwgaMxCzAJBgNVBAYT
AlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3pp
bGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTFFMEMGA1UEAww8Q29u
dGVudCBTaWduaW5nIEludGVybWVkaWF0ZS9lbWFpbEFkZHJlc3M9Zm94c2VjQG1v
emlsbGEuY29tMB4XDTIwMDYxNjE3MTYxNVoXDTIwMDkwNDE3MTYxNVowgakxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFp
biBWaWV3MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcwFQYDVQQLEw5D
bG91ZCBTZXJ2aWNlczE2MDQGA1UEAxMtcmVtb3RlLXNldHRpbmdzLmNvbnRlbnQt
c2lnbmF0dXJlLm1vemlsbGEub3JnMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDmOX
N5IGlUqCvu6xkOKr020Eo3kY2uPdJO0ZihVUoglk1ktQPss184OajFOMKm/BJX4W
IsZUzQoRL8NgGfZDwBjT95Q87lhOWEWs5AU/nMXIYwDp7rpUPaUqw0QLMikdo4GD
MIGAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSME
GDAWgBSgHUoXT4zCKzVF8WPx2nBwp8744TA4BgNVHREEMTAvgi1yZW1vdGUtc2V0
dGluZ3MuY29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwCgYIKoZIzj0EAwMD
aQAwZgIxAJvyynyPqRmRMqf95FPH5xfcoT3jb/2LOkUifGDtjtZ338ScpT2glUK8
HszKVANqXQIxAIygMaeTiD9figEusmHMthBdFoIoHk31x4MHukAy+TWZ863X6/V2
6/ZrZMpinvalid==
-----END CERTIFICATE-----";

        const VALID_SIGNATURE: &str = r#"fJJcOpwdnkjEWFeHXfdOJN6GaGLuDTPGzQOxA2jn6ldIleIk6KqMhZcy2GZv2uYiGwl6DERWwpaoUfQFLyCAOcVjck1qlaaEFZGY1BQba9p99xEc9FNQ3YPPfvSSZqsw"#;

        const INVALID_SIGNATURE: &str = r#"invalid-signature: oPRadsg_5wnnUXlRIjamXKPWyyGe4VLt-KR4-PJTK2hq4hF196L3nbvne1_7-HfpoVRR4BLsHWtnnt6700CTt5kNgwvrE8aJ3nXFa0vJBoOvIRco-vCt-rJ7acEu0IFG"#;

        // Adjust current time, since the above certificate has expired.
        let march_12_2021 = Duration::from_secs(1615559719);
        MockClock::set_time(march_12_2021);

        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": mock_server.url("/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain"),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1603992731957,
                records: vec![],
                signer: "remote-settings.content-signature.mozilla.org".to_string(),
            },
            VALID_CERTIFICATE,
            Ok(()),
        );

        // signature verification should fail with invalid message
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": mock_server.url("/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain"),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![Record::new(json!({"id": "bad-record"}))],
                signer: "remote-settings.content-signature.mozilla.org".to_string(),
            },
            VALID_CERTIFICATE,
            Err(SignatureError::MismatchError("".to_string())),
        );

        // signature verification should fail with invalid signature
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": mock_server.url("/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain"),
                        "signature": INVALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![],
                signer: "remote-settings.content-signature.mozilla.org".to_string(),
            },
            VALID_CERTIFICATE,
            Err(SignatureError::BadSignatureContent(
                base64::DecodeError::InvalidByte(17, 58).to_string(),
            )),
        );

        // signature verification should fail with invalid certificate
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": mock_server.url("/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain"),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![],
                signer: "remote-settings.content-signature.mozilla.org".to_string(),
            },
            INVALID_CERTIFICATE,
            Err(SignatureError::CertificateContentError(
                x509::X509Error::WrongPEMType("".to_string()),
            )),
        );

        // signature verification should fail if signer name is wrong
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": mock_server.url("/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain"),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![],
                signer: "normandy.content-signature.mozilla.org".to_string(),
            },
            VALID_CERTIFICATE,
            Err(SignatureError::WrongSignerName(
                "normandy.content-signature.mozilla.org".to_string(),
            )),
        );

        // signature verification should fail if certificate has expired.
        MockClock::set_time(Duration::default());
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": mock_server.url("/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain"),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1603992731957,
                records: vec![],
                signer: "remote-settings.content-signature.mozilla.org".to_string(),
            },
            VALID_CERTIFICATE,
            Err(SignatureError::CertificateExpired),
        );
    }
}
