//! Adobe ADEPT user-key extraction (the RSA private key DER, "adobekey.der").
//!
//! The portable artifact both ADEPT decryptors consume is a PKCS#1
//! `RSAPrivateKey` DER (§7.1). Two hosts store it differently:
//!
//! * **macOS** ([`macos`]) — fully reproducible offline. `activation.dat` holds
//!   the key base64-encoded behind a fixed 26-byte header; it is *not* encrypted,
//!   so extraction is parse + decode + strip ([`parse_activation_dat`]).
//! * **Windows** ([`windows`]) — the key is AES-wrapped under a DPAPI-protected
//!   `keykey` bound to the machine (volume serial + CPUID + username). The
//!   *algorithm* (entropy layout + AES-CBC decrypt) is implemented and tested
//!   here, but the live gathering (`CryptUnprotectData`, registry) needs the
//!   user's Windows profile and is **not reproducible offline** — mirroring the
//!   Kindle `.kinf2011` v5 path, [`extract_keys`] returns [`KeyError::Unsupported`]
//!   there rather than shipping untestable FFI.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.2. Original: `adobekey.py`.

#[cfg(target_os = "macos")]
mod macos;
mod windows;

pub use windows::{decrypt_private_license_key, pack_entropy};

use base64::Engine;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

use crate::{KeyError, Result};

/// The fixed header length stripped from the decoded license blob (both OSes).
pub const HEADER_STRIP_LEN: usize = 26;

/// The Adobe ADEPT XML namespace URI (`activation.dat` and `rights.xml`).
pub const NS_ADEPT: &[u8] = b"http://ns.adobe.com/adept";

/// Extract Adobe ADEPT user keys (PKCS#1 `RSAPrivateKey` DERs) from the local
/// Adobe Digital Editions install.
///
/// macOS reads `~/Library/Application Support/Adobe/Digital Editions/**/
/// activation.dat`. Every other host returns [`KeyError::Unsupported`]: the
/// Windows path needs live DPAPI plus the user's profile and cannot run offline
/// (§7.2); the portable Windows crypto is still exposed as [`pack_entropy`] /
/// [`decrypt_private_license_key`] for a future host-bound caller.
pub fn extract_keys() -> Result<Vec<Vec<u8>>> {
    #[cfg(target_os = "macos")]
    {
        macos::extract_keys()
    }
    #[cfg(target_os = "windows")]
    {
        Err(KeyError::Unsupported(
            "adobe::extract_keys on Windows needs live DPAPI + the user's profile \
             (not reproducible offline); see adobe::pack_entropy / \
             decrypt_private_license_key and docs §7.2",
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(KeyError::Unsupported(
            "adobe::extract_keys is only supported on macOS (activation.dat) and \
             Windows (DPAPI); see docs §7.2",
        ))
    }
}

/// Parse an `activation.dat` document into ADEPT user keys (DERs).
///
/// Pulls every `adept:credentials/adept:privateLicenseKey`, base64-decodes it,
/// strips the fixed 26-byte header (the macOS blob is *not* encrypted), and
/// validates each result parses as a PKCS#1 `RSAPrivateKey`. Namespace-aware,
/// matching the reference `//adept:credentials/adept:privateLicenseKey` XPath:
/// only `privateLicenseKey` elements nested in a `credentials` element (both in
/// the ADEPT namespace) are taken. Reference: §7.2 (`adobekey.py`, `isosx`).
pub fn parse_activation_dat(xml: &str) -> Result<Vec<Vec<u8>>> {
    let mut reader = NsReader::from_reader(xml.as_bytes());
    let mut buf = Vec::new();
    let mut credentials_depth = 0usize;
    let mut capturing = false;
    let mut text = String::new();
    let mut keys = Vec::new();

    loop {
        let (ns, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|e| KeyError::Invalid(format!("activation.dat xml: {e}")))?;
        match event {
            Event::Start(ref e) => {
                let local = e.local_name();
                if is_named(&ns, local.as_ref(), b"credentials") {
                    credentials_depth += 1;
                } else if credentials_depth > 0
                    && is_named(&ns, local.as_ref(), b"privateLicenseKey")
                {
                    capturing = true;
                    text.clear();
                }
            }
            Event::Text(ref e) if capturing => {
                let chunk = e
                    .unescape()
                    .map_err(|e| KeyError::Invalid(format!("activation.dat xml: {e}")))?;
                text.push_str(&chunk);
            }
            Event::End(ref e) => {
                let local = e.local_name();
                if capturing && is_named(&ns, local.as_ref(), b"privateLicenseKey") {
                    keys.push(decode_key(&text)?);
                    capturing = false;
                } else if is_named(&ns, local.as_ref(), b"credentials") {
                    credentials_depth = credentials_depth.saturating_sub(1);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    // Reject anything that isn't a well-formed RSA key before handing it on.
    for key in &keys {
        flamberge_crypto::rsa::private_key_modulus_len(key)?;
    }
    Ok(keys)
}

/// True if a resolved element is `{adept}local`.
fn is_named(resolved: &ResolveResult, local: &[u8], want: &[u8]) -> bool {
    matches!(resolved, ResolveResult::Bound(bound) if bound.as_ref() == NS_ADEPT) && local == want
}

/// base64-decode a `privateLicenseKey` and strip the fixed 26-byte header.
fn decode_key(b64: &str) -> Result<Vec<u8>> {
    let raw = decode_b64(b64)?;
    if raw.len() <= HEADER_STRIP_LEN {
        return Err(KeyError::Invalid(format!(
            "privateLicenseKey too short: {} bytes",
            raw.len()
        )));
    }
    Ok(raw[HEADER_STRIP_LEN..].to_vec())
}

/// base64-decode, tolerating embedded whitespace as the reference codec does.
fn decode_b64(s: &str) -> Result<Vec<u8>> {
    let compact: String = s.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| KeyError::Invalid(format!("privateLicenseKey base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::RsaPrivateKey;

    /// Build an `activation.dat`-shaped document whose privateLicenseKey wraps
    /// `der` behind a 26-byte header, base64-encoded.
    fn activation_dat(der: &[u8]) -> String {
        let mut blob = vec![0xEEu8; HEADER_STRIP_LEN];
        blob.extend_from_slice(der);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        format!(
            "<?xml version=\"1.0\"?>\n\
             <activationInfo xmlns=\"http://ns.adobe.com/adept\">\n\
             <adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">\n\
             <adept:user>urn:uuid:deadbeef</adept:user>\n\
             <adept:privateLicenseKey>{b64}</adept:privateLicenseKey>\n\
             </adept:credentials>\n\
             </activationInfo>\n"
        )
    }

    #[test]
    fn parses_and_strips_header_to_valid_der() {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        let der = key.to_pkcs1_der().expect("der").as_bytes().to_vec();

        let keys = parse_activation_dat(&activation_dat(&der)).unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], der);
        // The recovered DER parses as an RSA private key (1024-bit → 128 bytes).
        assert_eq!(
            flamberge_crypto::rsa::private_key_modulus_len(&keys[0]).unwrap(),
            128
        );
    }

    #[test]
    fn ignores_private_license_key_outside_credentials() {
        // A privateLicenseKey not nested in credentials must be skipped.
        let xml = "<activationInfo xmlns:adept=\"http://ns.adobe.com/adept\">\
                   <adept:privateLicenseKey>AAAA</adept:privateLicenseKey>\
                   </activationInfo>";
        assert!(parse_activation_dat(xml).unwrap().is_empty());
    }

    #[test]
    fn rejects_non_rsa_der_blob() {
        // A well-formed XML whose stripped payload is not a valid RSA key.
        let mut blob = vec![0u8; HEADER_STRIP_LEN];
        blob.extend_from_slice(b"not a der key at all");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let xml = format!(
            "<a xmlns:adept=\"http://ns.adobe.com/adept\">\
             <adept:credentials>\
             <adept:privateLicenseKey>{b64}</adept:privateLicenseKey>\
             </adept:credentials></a>"
        );
        assert!(parse_activation_dat(&xml).is_err());
    }

    #[test]
    fn tolerates_whitespace_in_base64() {
        let der = [0x30u8, 0x82, 0x00, 0x10]; // arbitrary bytes; decode-only test
        let mut blob = vec![0u8; HEADER_STRIP_LEN];
        blob.extend_from_slice(&der);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let wrapped = format!("{}\n  {}", &b64[..4], &b64[4..]);
        assert_eq!(decode_key(&wrapped).unwrap(), der);
    }

    #[test]
    fn rejects_blob_shorter_than_header() {
        assert!(decode_key("AAAA").is_err());
    }

    #[test]
    fn non_macos_extract_is_unsupported_not_panic() {
        // On this CI matrix, only macOS returns keys; other hosts must degrade to
        // a clear Unsupported error (never a panic).
        #[cfg(not(target_os = "macos"))]
        assert!(matches!(extract_keys(), Err(KeyError::Unsupported(_))));
    }
}
