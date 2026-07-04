//! Host-specific Kobo discovery: locate the library DB, enumerate NIC MAC
//! addresses, and read the device serial from `device.xml` (§9.1).
//!
//! Mirrors `obok.py` `KoboLibrary.__init__` / `__getmacaddrs`. The OS glue
//! (mount scanning, shelling out to `ifconfig`/`ip`/`getmac`) is inherently
//! non-reproducible in CI, so the parsing is factored into the pure
//! [`parse_macaddrs`] and [`parse_device_serial`], which the tests exercise.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §9.1.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{KeyError, Result};

/// A located Kobo library DB plus, when it came from a mounted device, that
/// device's root (so [`device_serial`] can read `device.xml` beside it).
pub(super) struct LocatedDb {
    pub db_bytes: Vec<u8>,
    pub device_root: Option<PathBuf>,
}

/// Locate the Kobo library DB: first a mounted e-ink device
/// (`<mount>/.kobo/KoboReader.sqlite`), then the desktop app
/// (`.../Kobo Desktop Edition/Kobo.sqlite`). `NotFound` when neither exists.
pub(super) fn find_kobo_db() -> Result<LocatedDb> {
    for root in mount_roots() {
        let db = root.join(".kobo").join("KoboReader.sqlite");
        if db.is_file() {
            let db_bytes = read_db(&db)?;
            return Ok(LocatedDb {
                db_bytes,
                device_root: Some(root),
            });
        }
    }
    if let Some(db) = desktop_db_path() {
        if db.is_file() {
            let db_bytes = read_db(&db)?;
            return Ok(LocatedDb {
                db_bytes,
                device_root: None,
            });
        }
    }
    Err(KeyError::NotFound(
        "no Kobo database found (mount a Kobo device or install Kobo Desktop)".into(),
    ))
}

fn read_db(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| KeyError::Invalid(format!("read {}: {e}", path.display())))
}

/// The desktop-app DB path for the current OS, if the platform is known.
fn desktop_db_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(
            Path::new(&home)
                .join("Library/Application Support/Kobo/Kobo Desktop Edition/Kobo.sqlite"),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var_os("LOCALAPPDATA")?;
        Some(Path::new(&local).join(r"Kobo\Kobo Desktop Edition\Kobo.sqlite"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Candidate removable-media mount roots to probe for a mounted Kobo device.
fn mount_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(target_os = "macos")]
    {
        collect_subdirs(Path::new("/Volumes"), &mut roots);
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(user) = std::env::var_os("USER") {
            collect_subdirs(&Path::new("/media").join(&user), &mut roots);
            collect_subdirs(&Path::new("/run/media").join(&user), &mut roots);
        }
        collect_subdirs(Path::new("/media"), &mut roots);
        collect_subdirs(Path::new("/mnt"), &mut roots);
    }
    #[cfg(target_os = "windows")]
    {
        // Removable drives are unpredictable; probe drive letters D:..Z:.
        for letter in b'D'..=b'Z' {
            roots.push(PathBuf::from(format!("{}:\\", letter as char)));
        }
    }
    roots
}

/// Push each immediate subdirectory of `dir` onto `out` (best-effort).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn collect_subdirs(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                out.push(entry.path());
            }
        }
    }
}

/// Read the device serial from `<root>/.adobe-digital-editions/device.xml`.
pub(super) fn device_serial(root: &Path) -> Option<String> {
    let xml =
        std::fs::read_to_string(root.join(".adobe-digital-editions").join("device.xml")).ok()?;
    parse_device_serial(&xml)
}

/// Extract the `deviceSerial` element text from a `device.xml`. Namespace- and
/// attribute-agnostic: matches any tag whose local name is `deviceSerial`
/// (obok matches on `"deviceSerial" in node.tag`).
pub(super) fn parse_device_serial(xml: &str) -> Option<String> {
    // Find an opening tag ending in `deviceSerial` and return its text content.
    let mut search = xml;
    while let Some(lt) = search.find('<') {
        let after = &search[lt + 1..];
        let gt = after.find('>')?;
        let tag = &after[..gt];
        // Skip closing tags / declarations / comments.
        let name_end = tag
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(tag.len());
        let name = &tag[..name_end];
        if !tag.starts_with('/')
            && !tag.starts_with('?')
            && !tag.starts_with('!')
            && local_name(name) == "deviceSerial"
        {
            let text = &after[gt + 1..];
            let end = text.find('<')?;
            let serial = text[..end].trim();
            if !serial.is_empty() {
                return Some(serial.to_string());
            }
        }
        search = &after[gt..];
    }
    None
}

/// The local part of a possibly namespace-prefixed tag name (`adept:foo` → `foo`).
fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Enumerate the host's NIC MAC addresses (upper-case, colon-separated) by
/// shelling out per-OS, exactly as obok does. Returns an empty vec if the tool
/// is unavailable — the caller treats "no inputs" as `NotFound`.
pub(super) fn enumerate_macaddrs() -> Vec<String> {
    let output = macaddr_command();
    match output {
        Some(text) => parse_macaddrs(&text),
        None => Vec::new(),
    }
}

/// Run the platform tool that prints NIC info and capture its stdout.
fn macaddr_command() -> Option<String> {
    #[cfg(target_os = "macos")]
    let cmd = Command::new("/sbin/ifconfig").arg("-a").output();
    #[cfg(target_os = "linux")]
    let cmd = Command::new("ip").args(["-br", "link"]).output();
    #[cfg(target_os = "windows")]
    let cmd = Command::new("getmac").output();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let cmd: std::io::Result<std::process::Output> = Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "unsupported",
    ));

    let out = cmd.ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Scan free-form NIC-tool output for 6-octet MAC addresses, normalising `-` to
/// `:` and upper-casing. De-duplicated, order preserved. Handles both
/// `ifconfig`/`ip` (`aa:bb:...`) and Windows `getmac` (`AA-BB-...`) forms.
pub(super) fn parse_macaddrs(text: &str) -> Vec<String> {
    let mut macs: Vec<String> = Vec::new();
    for raw in text.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
        if let Some(mac) = normalize_mac(raw) {
            if !macs.contains(&mac) {
                macs.push(mac);
            }
        }
    }
    macs
}

/// Recognise a bare `hh:hh:hh:hh:hh:hh` or `hh-hh-hh-hh-hh-hh` token and return
/// it as upper-case colon form, or `None` if the token is not a MAC.
fn normalize_mac(token: &str) -> Option<String> {
    let sep = if token.contains(':') {
        ':'
    } else if token.contains('-') {
        '-'
    } else {
        return None;
    };
    let octets: Vec<&str> = token.split(sep).collect();
    if octets.len() != 6 {
        return None;
    }
    if octets
        .iter()
        .any(|o| o.len() != 2 || !o.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(octets.join(":").to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ifconfig_macs() {
        let sample = "\
en0: flags=8863<UP,BROADCAST> mtu 1500
	ether a4:83:e7:1b:2c:3d
	inet 192.168.1.5 netmask 0xffffff00
lo0: flags=8049<UP,LOOPBACK>
en1: flags=8863 ether 00:11:22:33:44:55";
        let macs = parse_macaddrs(sample);
        assert_eq!(
            macs,
            vec![
                "A4:83:E7:1B:2C:3D".to_string(),
                "00:11:22:33:44:55".to_string()
            ]
        );
    }

    #[test]
    fn parses_getmac_dash_form_and_dedups() {
        let sample = "Physical Address    Transport Name
=================== ==========================================
A4-83-E7-1B-2C-3D   \\Device\\Tcpip_{GUID}
A4-83-E7-1B-2C-3D   \\Device\\Tcpip_{GUID}";
        let macs = parse_macaddrs(sample);
        assert_eq!(macs, vec!["A4:83:E7:1B:2C:3D".to_string()]);
    }

    #[test]
    fn ignores_non_mac_tokens() {
        // IPv6 and times have colons but are not 6 two-hex-digit octets.
        let sample = "inet6 fe80::1 12:34:56 netmask 0xffffff00 aa:bb:cc";
        assert!(parse_macaddrs(sample).is_empty());
    }

    #[test]
    fn parses_device_serial_namespaced() {
        let xml = r#"<?xml version="1.0"?>
<adept:deviceInfo xmlns:adept="http://ns.adobe.com/adept">
  <adept:deviceSerial>N1234567890ABC</adept:deviceSerial>
  <adept:deviceName>Kobo</adept:deviceName>
</adept:deviceInfo>"#;
        assert_eq!(parse_device_serial(xml), Some("N1234567890ABC".to_string()));
    }

    #[test]
    fn parses_device_serial_unprefixed() {
        let xml = "<deviceInfo><deviceSerial>ABC123</deviceSerial></deviceInfo>";
        assert_eq!(parse_device_serial(xml), Some("ABC123".to_string()));
    }

    #[test]
    fn no_device_serial_returns_none() {
        let xml = "<deviceInfo><deviceName>Kobo</deviceName></deviceInfo>";
        assert_eq!(parse_device_serial(xml), None);
    }
}
