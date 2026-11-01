use std::path::PathBuf;
use std::time::Duration;

use crate::error::MigrateError;

pub const USAGE: &str = "\
zns-migrate — move a sealed ZNS seed to the next measured guest

USAGE:
    zns-migrate source --manifest <TOML> --upgrade-document <BYTES> \\
                       --attestation-bundle <BUNDLE> --transport-dir <DIR> \\
                       --input-capsule <PATH>
    zns-migrate target --manifest <TOML> --upgrade-document <BYTES> \\
                       --attestation-bundle <BUNDLE> --transport-dir <DIR> \\
                       --output-capsule <PATH> [--replace-after-verified-migration]
    zns-migrate cutover source --manifest <TOML> --upgrade-document <BYTES> \\
                       --attestation-bundle <BUNDLE> --transport-dir <DIR>
    zns-migrate cutover target --manifest <TOML> --upgrade-document <BYTES> \\
                       --attestation-bundle <BUNDLE> --transport-dir <DIR> \\
                       --output-capsule <PATH>

Source and target may start in either order. Target waits until source marks
the transport directory, then publishes an attested offer before source
unseals anything. The directory is an untrusted one-shot channel:

    source.ready
    offer.bin
    attestation.bin
    encrypted_seed.bin
    source_attestation.bin
    zns_custody_manifest.toml
    receipt.bin
    receipt_attestation.bin

Source copies the custody manifest in the open from the input capsule's
directory and publishes it beside the ciphertext; it is the only ceremony
file on the channel. The seed stays sealed.
Use a fresh directory for each attempt. The capsule stays outside it.
Target will not overwrite an existing capsule unless
--replace-after-verified-migration is set.

--timeout-secs <N> is how long to wait for the peer (default 120, max 86400).

The manifest TOML, the canonical upgrade document, and the Sigstore bundle
stay outside the transport directory. Both sides require the zns-deployment
release workflow to have attested that document before a sealing key is
derived. Source requires the target report's measurement to equal
to_measurement and its guest policy to equal to_guest_policy. It also
requires its own report to match from_measurement and from_guest_policy, and
the input capsule's file hash and fingerprint to match the manifest, before
it unseals. Target requires the source report's measurement to equal
from_measurement and its guest policy to equal from_guest_policy, and that
report must bind the offer, the ciphertext, and the custody manifest,
before it installs a capsule.
Source accepts the receipt only when receipt_attestation.bin binds that offer
and that receipt, and the report measurement equals to_measurement and its
guest policy equals to_guest_policy.

cutover runs after a finished handoff to another release, on the same
channel. It adds one file:

    source_stopped_attestation.bin

cutover source publishes a report over the offer and the receipt. Run it
only once this guest's mint has stopped for good. cutover target requires the
receipt to name its own capsule. It waits for that report and requires its
measurement to equal from_measurement and its guest policy to equal
from_guest_policy. Start the target mint only after it succeeds. Both read
the offer and receipt once; the handoff must have finished.
";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Source,
    Target,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub role: Role,
    pub manifest: PathBuf,
    pub upgrade_document: PathBuf,
    pub attestation_bundle: PathBuf,
    pub transport_dir: PathBuf,
    pub input_capsule: Option<PathBuf>,
    pub output_capsule: Option<PathBuf>,
    pub replace_after_verified_migration: bool,
    pub timeout: Duration,
    pub cutover: bool,
}

#[derive(Debug)]
pub enum Command {
    Help,
    Run(Args),
}

pub fn parse<I, S>(args: I) -> Result<Command, MigrateError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter().map(|arg| arg.as_ref().to_string());
    let _program = args.next();
    let mut first = args.next();
    let cutover = first.as_deref() == Some("cutover");
    if cutover {
        first = args.next();
    }
    let role = match first.as_deref() {
        None => return Err(MigrateError::usage("missing role: source or target")),
        Some("-h" | "--help") => return Ok(Command::Help),
        Some("source") => Role::Source,
        Some("target") => Role::Target,
        Some(other) => {
            return Err(MigrateError::usage(format!(
                "unknown role {other}; expected source or target"
            )));
        }
    };

    let mut manifest = None;
    let mut upgrade_document = None;
    let mut attestation_bundle = None;
    let mut transport_dir = None;
    let mut input_capsule = None;
    let mut output_capsule = None;
    let mut replace = false;
    let mut timeout = DEFAULT_TIMEOUT;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--manifest" => set_once(&mut manifest, "--manifest", value("--manifest", &mut args)?)?,
            "--upgrade-document" => set_once(
                &mut upgrade_document,
                "--upgrade-document",
                value("--upgrade-document", &mut args)?,
            )?,
            "--attestation-bundle" => set_once(
                &mut attestation_bundle,
                "--attestation-bundle",
                value("--attestation-bundle", &mut args)?,
            )?,
            "--transport-dir" => set_once(
                &mut transport_dir,
                "transport",
                value("--transport-dir", &mut args)?,
            )?,
            "--input-capsule" => set_once(
                &mut input_capsule,
                "--input-capsule",
                value("--input-capsule", &mut args)?,
            )?,
            "--output-capsule" => set_once(
                &mut output_capsule,
                "--output-capsule",
                value("--output-capsule", &mut args)?,
            )?,
            "--replace-after-verified-migration" => {
                if replace {
                    return Err(MigrateError::usage(
                        "--replace-after-verified-migration was given twice",
                    ));
                }
                replace = true;
            }
            "--timeout-secs" => {
                let text = value("--timeout-secs", &mut args)?;
                let secs: u64 = text.parse().map_err(|_| {
                    MigrateError::usage(format!("--timeout-secs {text} is not an integer"))
                })?;
                if secs == 0 || secs > MAX_TIMEOUT_SECS {
                    return Err(MigrateError::usage(format!(
                        "--timeout-secs must be 1..={MAX_TIMEOUT_SECS}"
                    )));
                }
                timeout = Duration::from_secs(secs);
            }
            other => {
                return Err(MigrateError::usage(format!("unknown argument {other}")));
            }
        }
    }

    let manifest = manifest.ok_or_else(|| MigrateError::usage("--manifest is required"))?;
    let upgrade_document =
        upgrade_document.ok_or_else(|| MigrateError::usage("--upgrade-document is required"))?;
    let attestation_bundle = attestation_bundle
        .ok_or_else(|| MigrateError::usage("--attestation-bundle is required"))?;
    let transport_dir =
        transport_dir.ok_or_else(|| MigrateError::usage("--transport-dir is required"))?;

    match role {
        _ if cutover => {
            if input_capsule.is_some() || replace {
                return Err(MigrateError::usage(
                    "cutover takes only --output-capsule, on target",
                ));
            }
            if (role == Role::Target) != output_capsule.is_some() {
                return Err(MigrateError::usage(
                    "cutover target needs --output-capsule; cutover source takes none",
                ));
            }
        }
        Role::Source => {
            if output_capsule.is_some() {
                return Err(MigrateError::usage("source does not take --output-capsule"));
            }
            if replace {
                return Err(MigrateError::usage(
                    "source does not take --replace-after-verified-migration",
                ));
            }
            if input_capsule.is_none() {
                return Err(MigrateError::usage("--input-capsule is required"));
            }
        }
        Role::Target => {
            if input_capsule.is_some() {
                return Err(MigrateError::usage("target does not take --input-capsule"));
            }
            if output_capsule.is_none() {
                return Err(MigrateError::usage("--output-capsule is required"));
            }
        }
    }

    Ok(Command::Run(Args {
        role,
        manifest: PathBuf::from(manifest),
        upgrade_document: PathBuf::from(upgrade_document),
        attestation_bundle: PathBuf::from(attestation_bundle),
        transport_dir: PathBuf::from(transport_dir),
        input_capsule: input_capsule.map(PathBuf::from),
        output_capsule: output_capsule.map(PathBuf::from),
        replace_after_verified_migration: replace,
        timeout,
        cutover,
    }))
}

fn set_once(slot: &mut Option<String>, flag: &str, value: String) -> Result<(), MigrateError> {
    if slot.is_some() {
        return Err(MigrateError::usage(format!("{flag} was given twice")));
    }
    *slot = Some(value);
    Ok(())
}

fn value(flag: &str, args: &mut impl Iterator<Item = String>) -> Result<String, MigrateError> {
    let Some(value) = args.next() else {
        return Err(MigrateError::usage(format!("{flag} needs a value")));
    };
    if value.starts_with('-') || value.is_empty() {
        return Err(MigrateError::usage(format!(
            "{flag} needs a value, got {value}"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_source_and_target() {
        let Command::Run(args) = parse([
            "zns-migrate",
            "source",
            "--manifest",
            "upgrade.toml",
            "--upgrade-document",
            "upgrade.bin",
            "--attestation-bundle",
            "bundle.jsonl",
            "--transport-dir",
            "/migration",
            "--input-capsule",
            "/state/keys/zns_seed.capsule",
            "--timeout-secs",
            "30",
        ])
        .unwrap() else {
            panic!("source command");
        };
        assert_eq!(args.role, Role::Source);
        assert_eq!(args.transport_dir, PathBuf::from("/migration"));
        assert_eq!(args.timeout, Duration::from_secs(30));

        let Command::Run(args) = parse([
            "zns-migrate",
            "target",
            "--output-capsule",
            "/state/keys/zns_seed.capsule",
            "--manifest",
            "upgrade.toml",
            "--upgrade-document",
            "upgrade.bin",
            "--attestation-bundle",
            "bundle.jsonl",
            "--transport-dir",
            "/migration",
            "--replace-after-verified-migration",
        ])
        .unwrap() else {
            panic!("target command");
        };
        assert!(args.replace_after_verified_migration);
        assert!(matches!(
            parse(["zns-migrate", "--help"]).unwrap(),
            Command::Help
        ));
    }

    #[test]
    fn rejects_a_source_overwrite_flag() {
        let err = parse([
            "zns-migrate",
            "source",
            "--manifest",
            "m",
            "--upgrade-document",
            "d",
            "--attestation-bundle",
            "b",
            "--transport-dir",
            "t",
            "--input-capsule",
            "c",
            "--replace-after-verified-migration",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("does not take"));
    }

    #[test]
    fn parses_cutover() {
        let base = [
            "zns-migrate",
            "cutover",
            "target",
            "--manifest",
            "m",
            "--upgrade-document",
            "d",
            "--attestation-bundle",
            "b",
            "--transport-dir",
            "/migration",
        ];
        let err = parse(base).unwrap_err();
        assert!(err.to_string().contains("needs --output-capsule"));
        let Command::Run(args) = parse(base.iter().chain(&["--output-capsule", "c"])).unwrap()
        else {
            panic!("cutover target");
        };
        assert_eq!(args.output_capsule, Some(PathBuf::from("c")));
        let mut source = base;
        source[2] = "source";
        parse(source).unwrap();
        let err = parse(source.iter().chain(&["--output-capsule", "c"])).unwrap_err();
        assert!(err.to_string().contains("cutover source takes none"));
    }
}
