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
/// keeps only entries that parse as a PKCS#1 `RSAPrivateKey`. Namespace-aware
/// and **direct-child only**, matching the reference `//adept:credentials/
/// adept:privateLicenseKey` XPath (both elements in the ADEPT namespace).
///
/// A single malformed or non-RSA `privateLicenseKey` is skipped rather than
/// failing the whole call, so a stray/legacy credential can't hide the other
/// valid keys in the same file. Reference: §7.2 (`adobekey.py`, `isosx`).
pub fn parse_activation_dat(xml: &str) -> Result<Vec<Vec<u8>>> {
    let mut reader = NsReader::from_reader(xml.as_bytes());
    let mut buf = Vec::new();
    // One entry per open element: whether it is an `adept:credentials`. The top
    // of this stack is the parent of the element currently being started, which
    // lets us enforce the XPath's direct-child requirement.
    let mut open_is_credentials: Vec<bool> = Vec::new();
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
                let parent_is_credentials = *open_is_credentials.last().unwrap_or(&false);
                if !capturing
                    && parent_is_credentials
                    && is_named(&ns, local.as_ref(), b"privateLicenseKey")
                {
                    capturing = true;
                    text.clear();
                }
                open_is_credentials.push(is_named(&ns, local.as_ref(), b"credentials"));
            }
            Event::Text(ref e) if capturing => {
                let chunk = e
                    .unescape()
                    .map_err(|e| KeyError::Invalid(format!("activation.dat xml: {e}")))?;
                text.push_str(&chunk);
            }
            // A CDATA-wrapped key carries its base64 verbatim (unescaped).
            Event::CData(ref e) if capturing => {
                let raw: &[u8] = e;
                text.push_str(&String::from_utf8_lossy(raw));
            }
            Event::End(ref e) => {
                if capturing && is_named(&ns, e.local_name().as_ref(), b"privateLicenseKey") {
                    if let Some(key) = decode_valid_key(&text) {
                        keys.push(key);
                    }
                    capturing = false;
                }
                open_is_credentials.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(keys)
}

/// True if a resolved element is `{adept}local`.
fn is_named(resolved: &ResolveResult, local: &[u8], want: &[u8]) -> bool {
    matches!(resolved, ResolveResult::Bound(bound) if bound.as_ref() == NS_ADEPT) && local == want
}

/// Decode + strip a `privateLicenseKey`, keeping it only if it is a valid RSA
/// key DER. Returns `None` for anything malformed so the caller can skip it.
fn decode_valid_key(b64: &str) -> Option<Vec<u8>> {
    let der = decode_key(b64).ok()?;
    flamberge_crypto::rsa::private_key_modulus_len(&der).ok()?;
    Some(der)
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

    /// A real 1024-bit RSA key's PKCS#1 DER.
    fn fresh_der() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        key.to_pkcs1_der().expect("der").as_bytes().to_vec()
    }

    /// base64 of a `privateLicenseKey` value: 26-byte header ‖ `payload`.
    fn key_b64(payload: &[u8]) -> String {
        let mut blob = vec![0xEEu8; HEADER_STRIP_LEN];
        blob.extend_from_slice(payload);
        base64::engine::general_purpose::STANDARD.encode(&blob)
    }

    /// Build an `activation.dat`-shaped document whose privateLicenseKey wraps
    /// `der` behind a 26-byte header, base64-encoded.
    fn activation_dat(der: &[u8]) -> String {
        let b64 = key_b64(der);
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
        let der = fresh_der();
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
    fn ignores_private_license_key_nested_below_credentials() {
        // Direct-child only: a privateLicenseKey one level below credentials
        // (grandchild) is not the XPath target and must be ignored.
        let b64 = key_b64(&fresh_der());
        let xml = format!(
            "<a xmlns:adept=\"http://ns.adobe.com/adept\"><adept:credentials><wrapper>\
             <adept:privateLicenseKey>{b64}</adept:privateLicenseKey>\
             </wrapper></adept:credentials></a>"
        );
        assert!(parse_activation_dat(&xml).unwrap().is_empty());
    }

    #[test]
    fn skips_non_rsa_key_but_keeps_valid_one() {
        // Two credentials blocks: the first payload is garbage, the second is a
        // real key. The bad entry must be skipped, not abort the whole parse.
        let good = fresh_der();
        let bad_b64 = key_b64(b"not a der key at all");
        let good_b64 = key_b64(&good);
        let xml = format!(
            "<a xmlns:adept=\"http://ns.adobe.com/adept\">\
             <adept:credentials><adept:privateLicenseKey>{bad_b64}</adept:privateLicenseKey></adept:credentials>\
             <adept:credentials><adept:privateLicenseKey>{good_b64}</adept:privateLicenseKey></adept:credentials>\
             </a>"
        );
        assert_eq!(parse_activation_dat(&xml).unwrap(), vec![good]);
    }

    #[test]
    fn parses_key_wrapped_in_cdata() {
        let der = fresh_der();
        let b64 = key_b64(&der);
        let xml = format!(
            "<a xmlns:adept=\"http://ns.adobe.com/adept\"><adept:credentials>\
             <adept:privateLicenseKey><![CDATA[{b64}]]></adept:privateLicenseKey>\
             </adept:credentials></a>"
        );
        assert_eq!(parse_activation_dat(&xml).unwrap(), vec![der]);
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
