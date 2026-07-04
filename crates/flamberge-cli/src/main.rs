//! `flamberge` — command-line DRM removal for ebooks.
//!
//! Dispatch mirrors the Calibre plugin: format is chosen by file extension, then
//! every candidate key is tried. Key discovery and generation live under the
//! `keys` subcommand. Reference: `docs/DEDRM_SCHEMES.md`.

mod autokeys;
mod decrypt;
mod keys;
mod naming;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use keys::KindleArgs;

#[derive(Parser)]
#[command(name = "flamberge", version, about = "Remove DRM from ebooks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decrypt one or more DRM-protected ebooks (a file, several files, or a
    /// directory of files).
    // Boxed: `DecryptArgs` holds many key-source vectors and dwarfs the other
    // variant, which trips `clippy::large_enum_variant`.
    Decrypt(Box<DecryptArgs>),
    /// Generate or extract decryption keys.
    #[command(subcommand)]
    Keys(KeysCommand),
}

/// Options for `flamberge decrypt`. Shared by the single-file and batch paths;
/// the driver lives in [`decrypt`].
#[derive(Args)]
pub struct DecryptArgs {
    /// Input ebook file(s) or directory. A directory is expanded to its
    /// immediate files (non-recursive); unsupported files are skipped.
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<PathBuf>,
    /// Output file (single input only; defaults to `<stem>_nodrm.<ext>`).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Output directory for batch runs (defaults to each input's own folder).
    #[arg(long = "output-dir")]
    pub output_dir: Option<PathBuf>,
    /// Discover local Adobe/Kindle/Kobo keys on this host and add them to the
    /// key set before decrypting (best-effort; failures are non-fatal).
    #[arg(long = "auto-keys")]
    pub auto_keys: bool,
    /// Explicit Mobipocket/Topaz/KFX PID (repeatable).
    #[arg(short, long)]
    pub pid: Vec<String>,
    /// Kindle device serial number (repeatable).
    #[arg(short, long)]
    pub serial: Vec<String>,
    /// Barnes & Noble 28-char user key / ccHash (repeatable).
    #[arg(long = "bandn-key")]
    pub bandn_key: Vec<String>,
    /// Adobe ADEPT user key: path to a DER RSA private key (repeatable).
    #[arg(long = "adept-key")]
    pub adept_key: Vec<PathBuf>,
    /// eReader user key as 16 hex chars / 8 bytes (repeatable).
    #[arg(long = "ereader-key")]
    pub ereader_key: Vec<String>,
    /// Kobo user key as 32 hex chars / 16 bytes (repeatable).
    #[arg(long = "kobo-key")]
    pub kobo_key: Vec<String>,
    /// Kobo library SQLite DB (KoboReader.sqlite / Kobo.sqlite); required for
    /// `.kepub` input since the page keys live there, not in the book.
    #[arg(long = "kobo-db")]
    pub kobo_db: Option<PathBuf>,
    /// Kobo volume id (book) to decrypt; inferred when the DB has one volume.
    #[arg(long = "kobo-volumeid")]
    pub kobo_volumeid: Option<String>,
    /// Kindle `.k4i` key database (JSON) to load; its DSN + account token expand
    /// the candidate PID list for Mobipocket/Topaz (repeatable).
    #[arg(long = "k4i")]
    pub k4i: Vec<PathBuf>,
    /// Android artifact to mine for candidate serials — `backup.ab`,
    /// `AmazonSecureStorage.xml`, or `map_data_storage.db` (repeatable).
    #[arg(long = "android")]
    pub android: Vec<PathBuf>,
}

#[derive(Subcommand)]
pub enum KeysCommand {
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
    /// Extract Adobe ADEPT keys from the local install (macOS `activation.dat`).
    Adobe,
    /// Decode Kindle key artifacts: `.k4i` databases, `.kinf` files, or Android
    /// backups. (On-host machine-value gathering is not yet supported.)
    // Boxed to keep the enum variants similarly sized (clippy::large_enum_variant).
    Kindle(Box<KindleArgs>),
    /// Derive Kobo user keys from this host (device/desktop DB + NIC MACs).
    Kobo,
}

/// Which Kindle app a `.kinf` file came from (its char maps differ).
#[derive(Clone, Copy, ValueEnum)]
pub enum KinfPlatform {
    /// Kindle for Mac.
    Mac,
    /// Kindle for PC.
    Pc,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Decrypt(args) => decrypt::run(*args),
        Command::Keys(cmd) => keys::run(cmd),
    }
}
