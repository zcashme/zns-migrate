//! M2. The attested ephemeral key is published before any seed arrives.
//!
//! A source publishes the custody manifest and binds it. The source report
//! must match this offer, the ciphertext, and that manifest, with
//! measurement `from_measurement` and the manifest's guest policy. Only the
//! custody manifest is installed beside the new capsule. The receipt is
//! published only after the resealed capsule unseals to the same seed,
//! attested for `to_measurement`.

use std::path::{Path, PathBuf};

use rand::rngs::SysRng;
use rand::TryRng;
use secrecy::Secret;
use tracing::info;
use zns_canon::capsule::{self, SEED_LEN};
use zns_canon::migration::{self, MigrationOffer};
use zns_canon::sealing::SealingKey;
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::attest::{self, Side};
use crate::cli::Args;
use crate::error::MigrateError;
use crate::handoff::{self, MigrationReceipt};
use crate::persist;
use crate::transport::{self, DirTransport};

pub fn run(
    sealing_key: &SealingKey,
    args: &Args,
    manifest: &UpgradeManifest,
    transport: &DirTransport,
) -> Result<(), MigrateError> {
    let output = args
        .output_capsule
        .as_deref()
        .ok_or_else(|| MigrateError::usage("--output-capsule is required"))?;
    transport::capsule_outside_transport(output, transport.dir())?;
    guard_outputs(output, args.replace_after_verified_migration)?;

    info!(
        manifest = hex::encode(upgrade::manifest_hash(manifest)),
        "target waiting"
    );
    transport.target_begin()?;
    guard_outputs(output, args.replace_after_verified_migration)?;

    let mut rng = SysRng;
    let keypair = migration::generate_ephemeral_keypair(&mut rng)?;
    let mut nonce = [0u8; 32];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| MigrateError::Rng)?;
    let manifest_hash = upgrade::manifest_hash(manifest);
    let offer = MigrationOffer {
        ephemeral_pubkey: keypair.public,
        nonce,
        manifest_hash,
    };
    let report_data = migration::migration_report_data(&offer);
    let attestation = attest::own_report(&report_data, manifest, Side::Target)?;
    transport.publish_offer(&handoff::encode_offer(&offer))?;
    transport.publish_attestation(&attestation)?;
    info!("offer attested");

    let transfer_bytes = transport.wait_encrypted_seed()?;
    let source_report = transport.wait_source_attestation()?;
    let custody_manifest = transport.wait_custody_manifest()?;
    let transfer = handoff::decode_transfer(&transfer_bytes)?;
    let expected = handoff::transfer_report_data(&offer, &transfer, &custody_manifest);
    attest::require_report(&source_report, &expected, manifest, Side::Source)?;
    let seed = {
        let seed = migration::decrypt_seed(&keypair.secret, &offer, &transfer)?;
        drop(keypair);
        seed
    };

    let capsule = capsule::seal_seed(sealing_key, &seed, &mut rng)?;
    let bytes = capsule::serialize_capsule(&capsule)?;
    let staged = persist::stage(output, &bytes)?;
    prove_persisted(
        sealing_key,
        &seed,
        &capsule::read_capsule_file(staged.path())?,
    )?;
    let mut pending = vec![(staged, output.to_path_buf())];
    pending.push(stage_custody_manifest(output, &custody_manifest)?);
    persist::commit_files(pending, args.replace_after_verified_migration)?;

    let persisted = capsule::read_capsule_file(output)?;
    let parsed = prove_persisted(sealing_key, &seed, &persisted)?;
    drop(seed);
    info!(path = %output.display(), "capsule reopened");

    let receipt = MigrationReceipt {
        manifest_hash,
        new_capsule_hash: handoff::hash_capsule(&persisted),
        seed_fingerprint: parsed.fingerprint,
    };
    let receipt_report = handoff::receipt_report_data(&offer, &receipt);
    let receipt_attestation = attest::own_report(&receipt_report, manifest, Side::Target)?;
    transport.publish_receipt(&handoff::encode_receipt(&receipt))?;
    transport.publish_receipt_attestation(&receipt_attestation)?;
    info!(
        capsule = hex::encode(receipt.new_capsule_hash),
        fingerprint = hex::encode(receipt.seed_fingerprint),
        "receipt published"
    );
    Ok(())
}

fn guard_outputs(output: &Path, replace: bool) -> Result<(), MigrateError> {
    persist::guard_output(output, replace)?;
    let dir = persist::containing_dir(output);
    persist::guard_output(&dir.join(transport::CUSTODY_MANIFEST_FILE), replace)
}

/// The custody manifest beside the capsule, public (0644) like keygen writes it.
fn stage_custody_manifest(
    capsule: &Path,
    bytes: &[u8],
) -> Result<(persist::StagedCapsule, PathBuf), MigrateError> {
    let dest = persist::containing_dir(capsule).join(transport::CUSTODY_MANIFEST_FILE);
    Ok((persist::stage_file(&dest, bytes, 0o644)?, dest))
}

fn prove_persisted(
    sealing_key: &SealingKey,
    seed: &Secret<[u8; SEED_LEN]>,
    bytes: &[u8],
) -> Result<zns_canon::capsule::Capsule, MigrateError> {
    let parsed = capsule::parse_capsule(bytes)?;
    let opened = capsule::unseal_seed(sealing_key, &parsed)?;
    handoff::ensure_same_seed(seed, &opened)?;
    Ok(parsed)
}
