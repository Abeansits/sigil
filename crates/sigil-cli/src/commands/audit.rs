//! The `audit` command group — audit log operations and HMAC key management.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};

use sigil_audit::key::{self, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE, KeychainError};

use crate::{AuditCommands, AuditKeyCommands, KeyFormat};

/// Run the appropriate audit subcommand.
///
/// # Errors
///
/// Returns an error if the chosen subcommand fails.
pub async fn run(cmd: AuditCommands) -> Result<()> {
    match cmd {
        AuditCommands::Verify { path } => verify(path).await,
        AuditCommands::Key(sub) => run_key(sub),
    }
}

// ---------------------------------------------------------------------------
// `audit verify`
// ---------------------------------------------------------------------------

async fn verify(path: Option<String>) -> Result<()> {
    let audit_path = if let Some(p) = path {
        crate::expand_tilde(&p)?
    } else {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        PathBuf::from(home).join(".sigil").join("audit.jsonl")
    };

    let loaded = key::load_audit_key().context("failed to resolve audit HMAC key")?;
    tracing::info!(source = loaded.source.label(), "loaded audit HMAC key");

    let result = sigil_audit::verify_log(&audit_path, &loaded.bytes)
        .await
        .context("failed to verify audit log")?;

    println!("Audit log: {}", audit_path.display());
    println!("Key source: {}", loaded.source.label());
    println!("Total entries: {}", result.total_entries);

    if let Some(broken) = &result.first_broken {
        println!(
            "Chain: BROKEN at entry {} ({})",
            broken.index, broken.event_id
        );
        println!("Reason: {}", broken.reason);
        println!("Valid entries before break: {}", result.valid_entries);
    } else {
        println!("Chain: valid ({} entries verified)", result.valid_entries);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `audit key ...`
// ---------------------------------------------------------------------------

fn run_key(cmd: AuditKeyCommands) -> Result<()> {
    match cmd {
        AuditKeyCommands::Generate { force } => key_generate(force),
        AuditKeyCommands::Show { yes } => key_show(yes),
        AuditKeyCommands::Import {
            path,
            force,
            format,
        } => key_import(&path, force, format),
        AuditKeyCommands::Delete { yes } => key_delete(yes),
    }
}

fn key_generate(force: bool) -> Result<()> {
    ensure_macos()?;

    let existing = key::keychain::read().map_err(|e| keychain_anyhow(&e))?;
    if existing.is_some() && !force {
        bail!(
            "A `{KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT}` Keychain entry already exists. \
             Re-run with --force to overwrite."
        );
    }

    let new_key = key::generate_key().map_err(|e| anyhow!("failed to generate key: {e}"))?;
    key::keychain::write(&new_key).map_err(|e| keychain_anyhow(&e))?;

    println!(
        "Generated {} bytes and stored in Keychain ({}/{}).",
        new_key.len(),
        KEYCHAIN_SERVICE,
        KEYCHAIN_ACCOUNT,
    );
    println!("Fingerprint (SHA-256): {}", fingerprint(&new_key));
    Ok(())
}

fn key_show(yes: bool) -> Result<()> {
    ensure_macos()?;

    let bytes = key::keychain::read()
        .map_err(|e| keychain_anyhow(&e))?
        .context("no Keychain entry found — run `sigil audit key generate` first")?;

    if !yes && !confirm("Print the audit key (hex) to stdout?")? {
        println!("aborted");
        return Ok(());
    }

    println!("{}", hex(&bytes));
    Ok(())
}

fn key_import(path: &str, force: bool, format: KeyFormat) -> Result<()> {
    ensure_macos()?;

    let resolved = crate::expand_tilde(path)?;
    let raw = std::fs::read(&resolved)
        .with_context(|| format!("failed to read {}", resolved.display()))?;
    let bytes = decode_key_bytes(&raw, format)?;
    if bytes.is_empty() {
        bail!("key file is empty");
    }

    let existing = key::keychain::read().map_err(|e| keychain_anyhow(&e))?;
    if existing.is_some() && !force {
        bail!(
            "A `{KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT}` Keychain entry already exists. \
             Re-run with --force to overwrite."
        );
    }

    key::keychain::write(&bytes).map_err(|e| keychain_anyhow(&e))?;
    println!(
        "Imported {} bytes from {} into Keychain ({}/{}).",
        bytes.len(),
        resolved.display(),
        KEYCHAIN_SERVICE,
        KEYCHAIN_ACCOUNT,
    );
    println!("Fingerprint (SHA-256): {}", fingerprint(&bytes));
    Ok(())
}

fn decode_key_bytes(raw: &[u8], format: KeyFormat) -> Result<Vec<u8>> {
    match format {
        KeyFormat::Raw => Ok(raw.to_vec()),
        KeyFormat::Hex => decode_hex(raw),
    }
}

fn decode_hex(raw: &[u8]) -> Result<Vec<u8>> {
    let stripped: String = std::str::from_utf8(raw)
        .context("hex key file is not valid UTF-8")?
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if stripped.len() % 2 != 0 {
        bail!("hex key has an odd number of digits");
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    let mut chars = stripped.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi = hi
            .to_digit(16)
            .with_context(|| format!("invalid hex digit '{hi}'"))?;
        let lo = lo
            .to_digit(16)
            .with_context(|| format!("invalid hex digit '{lo}'"))?;
        #[allow(clippy::cast_possible_truncation)]
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn key_delete(yes: bool) -> Result<()> {
    ensure_macos()?;

    if !yes
        && !confirm(&format!(
            "Delete Keychain entry {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT}? \
             Existing audit logs will no longer verify."
        ))?
    {
        println!("aborted");
        return Ok(());
    }

    match key::keychain::delete() {
        Ok(()) => {
            println!("Deleted {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} from Keychain.");
            Ok(())
        }
        Err(KeychainError::NotFound) => {
            println!("No Keychain entry to delete.");
            Ok(())
        }
        Err(e) => Err(keychain_anyhow(&e)),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn ensure_macos() -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        bail!("`audit key` subcommands require macOS (Keychain backend)")
    }
}

fn keychain_anyhow(e: &KeychainError) -> anyhow::Error {
    anyhow!("keychain: {e}")
}

fn confirm(prompt: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        bail!("refusing to prompt: stdin is not a TTY (re-run with --yes to skip the prompt)");
    }

    print!("{prompt} [y/N] ");
    io::stdout().flush().ok();

    let mut line = String::new();
    let read = io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read confirmation from stdin")?;
    if read == 0 {
        // EOF without input.
        return Ok(false);
    }
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    hex(&digest)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn decode_raw_is_byte_exact_including_trailing_newline() {
        let input = b"abc\n";
        let out = decode_key_bytes(input, KeyFormat::Raw).expect("raw decode");
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn decode_hex_strips_whitespace_and_decodes() {
        let input = b"de ad\nbe\tef\n";
        let out = decode_key_bytes(input, KeyFormat::Hex).expect("hex decode");
        assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_hex_rejects_odd_digits() {
        assert!(decode_key_bytes(b"abc", KeyFormat::Hex).is_err());
    }

    #[test]
    fn decode_hex_rejects_non_hex_digit() {
        assert!(decode_key_bytes(b"zz", KeyFormat::Hex).is_err());
    }

    #[test]
    fn hex_encodes_known_input() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn fingerprint_matches_known_sha256() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            fingerprint(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
