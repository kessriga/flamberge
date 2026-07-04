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

use quick_xml::events::Event;
use quick_xml::reader::Reader;

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
    // On Windows, probing drive letters D:–Z: would otherwise pop the OS
    // critical-error dialog for an empty removable drive; suppress it first.
    #[cfg(target_os = "windows")]
    suppress_removable_drive_dialogs();

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
        // `find_kobo_db` first suppresses the empty-drive error dialog.
        for letter in b'D'..=b'Z' {
            roots.push(PathBuf::from(format!("{}:\\", letter as char)));
        }
    }
    roots
}

/// Prevent the Windows critical-error handler from popping a modal "There is no
/// disk in the drive" dialog when [`find_kobo_db`] stats an empty removable
/// drive. `SEM_FAILCRITICALERRORS` makes such failures return as errors instead.
#[cfg(target_os = "windows")]
fn suppress_removable_drive_dialogs() {
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetThreadErrorMode(new_mode: u32, old_mode: *mut u32) -> i32;
    }
    // Safety: a plain kernel32 call; null out-pointer, previous mode ignored.
    unsafe {
        SetThreadErrorMode(SEM_FAILCRITICALERRORS, std::ptr::null_mut());
    }
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

/// Extract the `deviceSerial` element text from a `device.xml`. Matches any
/// element whose local name is `deviceSerial`, regardless of namespace prefix
/// (obok matches on `"deviceSerial" in node.tag`). Uses `quick-xml`, as the
/// sibling `adobe` module does, rather than hand-rolling a scanner.
pub(super) fn parse_device_serial(xml: &str) -> Option<String> {
    let mut reader = Reader::from_reader(xml.as_bytes());
    let mut buf = Vec::new();
    let mut capturing = false;
    let mut serial = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.local_name().as_ref() == b"deviceSerial" => {
                capturing = true;
                serial.clear();
            }
            Ok(Event::Text(ref e)) if capturing => {
                if let Ok(chunk) = e.unescape() {
                    serial.push_str(&chunk);
                }
            }
            Ok(Event::CData(ref e)) if capturing => {
                serial.push_str(&String::from_utf8_lossy(e));
            }
            Ok(Event::End(ref e)) if e.local_name().as_ref() == b"deviceSerial" => {
                let trimmed = serial.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
                capturing = false;
            }
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
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

/// Run the first available platform tool that prints NIC info and capture its
/// stdout. Tries candidates in order so a host missing one tool still resolves
/// (e.g. Linux with net-tools `ifconfig` but no iproute2 `ip`), mirroring obok's
/// multiple fallbacks.
fn macaddr_command() -> Option<String> {
    for (bin, args) in candidate_nic_commands() {
        if let Ok(out) = Command::new(bin).args(&args).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout).into_owned();
                if !text.trim().is_empty() {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// Ordered NIC-listing commands to try for the current OS (first success wins).
fn candidate_nic_commands() -> Vec<(&'static str, Vec<&'static str>)> {
    #[cfg(target_os = "macos")]
    {
        vec![("/sbin/ifconfig", vec!["-a"])]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            ("ip", vec!["-br", "link"]),
            ("/sbin/ifconfig", vec!["-a"]),
            ("ifconfig", vec!["-a"]),
        ]
    }
    #[cfg(target_os = "windows")]
    {
        vec![("getmac", vec![])]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
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

    #[test]
    fn ignores_device_serial_inside_a_comment() {
        // A fake tag inside an XML comment must not be picked up as the serial.
        let xml = "<deviceInfo><!-- <deviceSerial>FAKE</deviceSerial> -->\
                   <deviceSerial>REAL123</deviceSerial></deviceInfo>";
        assert_eq!(parse_device_serial(xml), Some("REAL123".to_string()));
    }

    #[test]
    fn self_closing_device_serial_has_no_text() {
        // A self-closing element carries no serial; the real one still wins.
        let xml = "<deviceInfo><deviceSerial/><deviceSerial>REAL</deviceSerial></deviceInfo>";
        assert_eq!(parse_device_serial(xml), Some("REAL".to_string()));
    }
}
