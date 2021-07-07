/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{x509, SignatureError, Verification};
use hex;
use ring::digest::{Context, SHA256};
use ring::signature;
use x509_parser::time::ASN1Time;

pub struct RingVerifier {}

impl RingVerifier {}

impl Verification for RingVerifier {
    fn verify_nist384p_chain(
        &self,
        epoch_seconds: u64,
        pem_bytes: &[u8],
        root_hash: &str,
        subject_cn: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        // 1. Parse the PEM bytes as DER-encoded X.509 Certificate.
        let pems = match x509::parse_certificate_chain(&pem_bytes) {
            Ok(pems) => pems,
            Err(err) => return Err(SignatureError::CertificateContentError(err.to_string())),
        };
        let certs: Vec<x509::X509Certificate> = match pems
            .iter()
            .map(|pem| match x509::parse_x509_certificate(&pem) {
                Ok(cert) => Ok(cert),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<x509::X509Certificate>, _>>()
        {
            Ok(certs) => certs,
            Err(err) => return Err(SignatureError::CertificateContentError(err.to_string())),
        };

        // 2. Verify that root hash matches the SHA256 fingerprint of the root certificate (DER content)
        let root_hash_bytes = hex::decode(&root_hash.replace(":", ""))
            .or_else(|err| Err(SignatureError::RootHashFormatError(err.to_string())))?;

        let root_pem = pems.first().unwrap();

        let mut root_fingerprint_hash = Context::new(&SHA256);
        root_fingerprint_hash.update(&root_pem.contents);
        let root_fingerprint_bytes = root_fingerprint_hash.finish().as_ref().to_vec();
        if root_fingerprint_bytes != root_hash_bytes {
            return Err(SignatureError::InvalidCertificateIssuer(hex::encode(
                root_fingerprint_bytes,
            )));
        }

        // 3. Verify that each certificate of the chain is currently valid (no revocation support)
        // TODO: take clock skew into account
        let now = ASN1Time::from_timestamp(epoch_seconds as i64);
        for cert in &certs {
            if !cert.tbs_certificate.validity.is_valid_at(now) {
                return Err(SignatureError::CertificateExpired);
            }
        }

        // 4. Verify that each child signature matches its parent's public key for each pair in the chain
        for pair in certs.windows(2) {
            if let [parent, child] = pair {
                let signature_alg = &child.signature_algorithm.algorithm;
                let verification_alg: &dyn signature::VerificationAlgorithm =
                    if *signature_alg == oid_registry::OID_PKCS1_SHA256WITHRSA {
                        &signature::RSA_PKCS1_2048_8192_SHA256
                    } else if *signature_alg == oid_registry::OID_PKCS1_SHA384WITHRSA {
                        &signature::RSA_PKCS1_2048_8192_SHA384
                    } else if *signature_alg == oid_registry::OID_PKCS1_SHA512WITHRSA {
                        &signature::RSA_PKCS1_2048_8192_SHA512
                    } else if *signature_alg == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
                        &signature::ECDSA_P256_SHA256_ASN1
                    } else if *signature_alg == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
                        &signature::ECDSA_P384_SHA384_ASN1
                    } else {
                        return Err(SignatureError::UnsupportedSignatureAlgorithm);
                    };

                let parent_pk_bytes = parent.tbs_certificate.subject_pki.subject_public_key.data;
                let child_der_bytes = child.tbs_certificate.as_ref();
                let child_sig_bytes = child.signature_value.data;

                let public_key =
                    signature::UnparsedPublicKey::new(verification_alg, &parent_pk_bytes);
                public_key
                    .verify(&child_der_bytes, &child_sig_bytes)
                    .or(Err(SignatureError::CertificateTrustError))?;
            }
        }

        let leaf_cert = certs.last().unwrap(); // PEM parse fails if len == 0.

        // 5. Verify that the subject alternate name of the end-entity certificate matches the collection signer name.
        let leaf_subject = leaf_cert
            .tbs_certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("")
            .to_string();
        if leaf_subject != subject_cn {
            return Err(SignatureError::InvalidCertificateSubject(leaf_subject));
        }
        // 6. Use the chain's end-entity (leaf) certificate to verify that the "signature" property matches the contents of the data.
        let public_key_bytes = leaf_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        let signature_alg = &signature::ECDSA_P384_SHA384_FIXED;
        let public_key = signature::UnparsedPublicKey::new(signature_alg, &public_key_bytes);

        let decoded_signature = match base64::decode_config(&signature, base64::URL_SAFE) {
            Ok(s) => s,
            Err(err) => return Err(SignatureError::BadSignatureContent(err.to_string())),
        };

        match public_key.verify(&message, &decoded_signature) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::MismatchError(err.to_string())),
        }
    }
}
