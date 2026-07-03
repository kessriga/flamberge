//! `dedrm` — command-line DRM removal for ebooks.
//!
//! Dispatch mirrors the Calibre plugin: format is chosen by file extension, then
//! every candidate key is tried. Key discovery and generation live under the
//! `keys` subcommand. Reference: `docs/DEDRM_SCHEMES.md`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use dedrm_keys::KeyStore;

#[derive(Parser)]
#[command(name = "dedrm", version, about = "Remove DRM from ebooks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decrypt a DRM-protected ebook.
    Decrypt(DecryptArgs),
    /// Generate or extract decryption keys.
    #[command(subcommand)]
    Keys(KeysCommand),
}

#[derive(Args)]
struct DecryptArgs {
    /// Input ebook file.
    input: PathBuf,
    /// Output file (defaults to `<stem>_nodrm.<ext>` next to the input).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Explicit Mobipocket/Topaz/KFX PID (repeatable).
    #[arg(short, long)]
    pid: Vec<String>,
    /// Kindle device serial number (repeatable).
    #[arg(short, long)]
    serial: Vec<String>,
    /// Barnes & Noble 28-char user key / ccHash (repeatable).
    #[arg(long = "bandn-key")]
    bandn_key: Vec<String>,
    /// Adobe ADEPT user key: path to a DER RSA private key (repeatable).
    #[arg(long = "adept-key")]
    adept_key: Vec<PathBuf>,
    /// eReader user key as 16 hex chars / 8 bytes (repeatable).
    #[arg(long = "ereader-key")]
    ereader_key: Vec<String>,
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Generate a Barnes & Noble user key from name + credit-card number.
    Ignoble {
        #[arg(long)]
        name: String,
        #[arg(long)]
        cc: String,
    },
    /// Derive an eReader user key from name + credit-card number.
    Ereader {
        #[arg(long)]
        name: String,
        #[arg(long)]
        cc: String,
    },
    /// Compute the PID for a standalone eInk Kindle serial number.
    EinkPid {
        #[arg(long)]
        serial: String,
    },
    /// Extract Adobe ADEPT keys from the local install (not yet implemented).
    Adobe,
    /// Extract Kindle keys from the local install (not yet implemented).
    Kindle,
    /// Derive Kobo user keys from this host (not yet implemented).
    Kobo,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Decrypt(args) => run_decrypt(args),
        Command::Keys(cmd) => run_keys(cmd),
    }
}

fn run_decrypt(args: DecryptArgs) -> Result<()> {
    let data = std::fs::read(&args.input)
        .with_context(|| format!("reading {}", args.input.display()))?;
    let ext = args
        .input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    let mut keys = KeyStore::new();
    keys.pids = args.pid;
    keys.serials = args.serial;
    keys.bandn_keys = args.bandn_key;
    for path in &args.adept_key {
        keys.adept_keys.push(
            std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        );
    }
    for hexkey in &args.ereader_key {
        let bytes = hex::decode(hexkey).context("eReader key must be hex")?;
        let arr: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("eReader key must be 8 bytes"))?;
        keys.ereader_keys.push(arr);
    }

    let book = dedrm_schemes::decrypt(&data, ext, &keys)
        .with_context(|| format!("decrypting {}", args.input.display()))?;

    let out = args.output.unwrap_or_else(|| default_output(&args.input, &book.extension));
    std::fs::write(&out, &book.data).with_context(|| format!("writing {}", out.display()))?;
    println!("Wrote {}", out.display());
    Ok(())
}

fn default_output(input: &Path, ext: &str) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("book");
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}_nodrm.{ext}"))
}

fn run_keys(cmd: KeysCommand) -> Result<()> {
    match cmd {
        KeysCommand::Ignoble { name, cc } => {
            let key = dedrm_keys::ignoble::generate_key(&name, &cc)?;
            println!("{key}");
        }
        KeysCommand::Ereader { name, cc } => {
            let key = dedrm_keys::ereader::user_key(&name, &cc);
            println!("{}", hex::encode(key));
        }
        KeysCommand::EinkPid { serial } => {
            let pid = dedrm_keys::pid::eink_pid_from_serial(&serial);
            println!("{pid}");
        }
        KeysCommand::Adobe => bail!("adobe key extraction not yet implemented (see docs §7.2)"),
        KeysCommand::Kindle => bail!("kindle key extraction not yet implemented (see docs §6)"),
        KeysCommand::Kobo => bail!("kobo key derivation not yet implemented (see docs §9.2)"),
    }
    Ok(())
}
