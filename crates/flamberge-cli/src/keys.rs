//! The `keys` subcommand: generate offline keys and extract keys from local
//! DRM-app state. Reference: `docs/DEDRM_SCHEMES.md` §6 (Kindle), §7 (Adobe),
//! §8.2 (eReader), §9 (Kobo).

use anyhow::{bail, Context, Result};
use flamberge_keys::kindle::{KindleDb, Platform};

use crate::{KeysCommand, KinfPlatform};

/// Entry point for `flamberge keys <...>`.
pub fn run(cmd: KeysCommand) -> Result<()> {
    match cmd {
        KeysCommand::Ignoble { name, cc } => {
            let key = flamberge_keys::ignoble::generate_key(&name, &cc)?;
            println!("{key}");
        }
        KeysCommand::Ereader { name, cc } => {
            let key = flamberge_keys::ereader::user_key(&name, &cc);
            println!("{}", hex::encode(key));
        }
        KeysCommand::EinkPid { serial } => {
            let pid = flamberge_keys::pid::eink_pid_from_serial(&serial);
            println!("{pid}");
        }
        KeysCommand::Adobe => {
            let keys = flamberge_keys::adobe::extract_keys()?;
            for key in &keys {
                println!("{}", hex::encode(key));
            }
            eprintln!("Found {} ADEPT key(s)", keys.len());
        }
        KeysCommand::Kindle(args) => run_kindle(*args)?,
        KeysCommand::Kobo => {
            let keys = flamberge_keys::kobo::discover_userkeys()?;
            for key in &keys {
                println!("{}", hex::encode(key));
            }
            eprintln!("Derived {} candidate Kobo user key(s)", keys.len());
        }
    }
    Ok(())
}

/// Args for `keys kindle`. Defined here (not in `main`) because it is the only
/// key subcommand with structured options.
#[derive(clap::Args)]
pub struct KindleArgs {
    /// `.k4i` key database (JSON) to decode (repeatable).
    #[arg(long = "k4i")]
    pub k4i: Vec<std::path::PathBuf>,
    /// `.kinf2011`/`.kinf2018` file to decrypt (repeatable). Requires
    /// `--user-name` and at least one `--id-string`.
    #[arg(long = "kinf")]
    pub kinf: Vec<std::path::PathBuf>,
    /// Account/user name for `.kinf` decryption (the Kindle app's `UserName`).
    #[arg(long = "user-name")]
    pub user_name: Option<String>,
    /// Machine `IDString` candidate for `.kinf` decryption (repeatable; the Mac
    /// branch enumerates several).
    #[arg(long = "id-string")]
    pub id_string: Vec<String>,
    /// Which Kindle app the `.kinf` came from.
    #[arg(long = "platform", value_enum, default_value_t = KinfPlatform::Mac)]
    pub platform: KinfPlatform,
    /// Android artifact to mine for candidate serials — `backup.ab`,
    /// `AmazonSecureStorage.xml`, or `map_data_storage.db` (repeatable).
    #[arg(long = "android")]
    pub android: Vec<std::path::PathBuf>,
}

/// Wire `keys kindle` to the offline Kindle extraction (TASK-15): decode `.k4i`
/// databases, decrypt `.kinf` files given the host's `UserName`/`IDString`, and
/// mine Android artifacts for serials. On-host machine-value gathering
/// ([`extract_local_keys`](flamberge_keys::kindle::extract_local_keys)) remains a
/// stub; with no artifacts supplied we surface that so the user knows to pass one.
fn run_kindle(args: KindleArgs) -> Result<()> {
    let no_artifacts = args.k4i.is_empty() && args.kinf.is_empty() && args.android.is_empty();
    if no_artifacts {
        // Nothing to work from: attempt on-host discovery. It is currently a stub
        // (returns an error, surfaced with a hint at the flags), but if it is ever
        // implemented, print whatever databases it finds.
        match flamberge_keys::kindle::extract_local_keys() {
            Ok(dbs) => {
                print_dbs(&dbs);
                eprintln!(
                    "Decoded {} Kindle key database(s) from this host",
                    dbs.len()
                );
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context("no artifacts supplied — pass --k4i/--kinf/--android (see docs §6)"));
            }
        }
    }

    let mut dbs: Vec<KindleDb> = Vec::new();
    for path in &args.k4i {
        dbs.push(
            flamberge_keys::kindle::load_k4i(path)
                .with_context(|| format!("loading .k4i {}", path.display()))?,
        );
    }
    if !args.kinf.is_empty() {
        let user = args
            .user_name
            .as_deref()
            .context("--kinf requires --user-name")?;
        if args.id_string.is_empty() {
            bail!("--kinf requires at least one --id-string");
        }
        let ids: Vec<Vec<u8>> = args
            .id_string
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        let platform = match args.platform {
            KinfPlatform::Mac => Platform::Mac,
            KinfPlatform::Pc => Platform::Pc,
        };
        for path in &args.kinf {
            let data =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            let db = flamberge_keys::kindle::decrypt_kinf_candidates(
                &data,
                platform,
                user.as_bytes(),
                &ids,
            )
            .with_context(|| format!("decrypting {}", path.display()))?;
            dbs.push(db);
        }
    }

    let mut serials: Vec<String> = Vec::new();
    for path in &args.android {
        serials.extend(
            flamberge_keys::kindle::serials_from_android(path)
                .with_context(|| format!("extracting serials from {}", path.display()))?,
        );
    }

    print_dbs(&dbs);
    for serial in &serials {
        println!("serial {serial}");
    }
    eprintln!(
        "Decoded {} Kindle key database(s), {} Android serial(s)",
        dbs.len(),
        serials.len()
    );
    Ok(())
}

/// Print each decoded database as sorted `name value` (hex) lines. These are the
/// account secrets the Kindle schemes turn into candidate PIDs (with a book's
/// record-209 metadata) at decrypt time.
fn print_dbs(dbs: &[KindleDb]) {
    for (i, db) in dbs.iter().enumerate() {
        if dbs.len() > 1 {
            println!("# database {}", i + 1);
        }
        let mut entries: Vec<_> = db.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (name, value) in entries {
            println!("{name} {value}");
        }
    }
}
