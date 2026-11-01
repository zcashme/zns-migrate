//! After a handoff to another release, one attested message: the source
//! mint has stopped for good.
//!
//! ```text
//! source: publish a from_measurement report over offer || receipt
//! target: wait for it and check it
//! ```
//!
//! The caller stops the source mint before `cutover source`, and starts the
//! target mint only after `cutover target` succeeds. Only this step is
//! attested: a forged one could let two mints serve. The target also
//! requires the receipt to name its own capsule, so a stop report from an
//! earlier handoff does not pass.

use tracing::info;
use zns_canon::capsule;
use zns_canon::migration::MigrationOffer;
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::attest::{self, Side};
use crate::cli::Args;
use crate::error::MigrateError;
use crate::handoff::{self, HandoffError, MigrationReceipt, OFFER_LEN, RECEIPT_LEN};
use crate::transport::{self, DirTransport, OFFER_FILE, RECEIPT_FILE};

pub fn source(manifest: &UpgradeManifest, channel: &DirTransport) -> Result<(), MigrateError> {
    let (offer, receipt) = finished_handoff(manifest, channel)?;
    let report = attest::own_report(
        &handoff::stopped_report_data(&offer, &receipt),
        manifest,
        Side::Source,
    )?;
    channel.publish_source_stopped(&report)?;
    info!("source stopped published");
    Ok(())
}

pub fn target(
    args: &Args,
    manifest: &UpgradeManifest,
    channel: &DirTransport,
) -> Result<(), MigrateError> {
    let own_capsule = args
        .output_capsule
        .as_deref()
        .ok_or_else(|| MigrateError::usage("--output-capsule is required"))?;
    let (offer, receipt) = finished_handoff(manifest, channel)?;
    let persisted = capsule::read_capsule_file(own_capsule)?;
    if receipt.new_capsule_hash != handoff::hash_capsule(&persisted) {
        return Err(HandoffError::ReceiptNotThisCapsule.into());
    }
    let stopped = channel.wait_source_stopped()?;
    attest::require_report(
        &stopped,
        &handoff::stopped_report_data(&offer, &receipt),
        manifest,
        Side::Source,
    )?;
    info!("source mint stopped");
    Ok(())
}

/// The offer and receipt of a finished handoff for this manifest. Read once:
/// they are already in the channel.
fn finished_handoff(
    manifest: &UpgradeManifest,
    channel: &DirTransport,
) -> Result<(MigrationOffer, MigrationReceipt), MigrateError> {
    let offer = transport::read_regular(&channel.dir().join(OFFER_FILE), OFFER_LEN)?;
    let receipt = transport::read_regular(&channel.dir().join(RECEIPT_FILE), RECEIPT_LEN)?;
    let offer = handoff::decode_offer(&offer)?;
    let receipt = handoff::decode_receipt(&receipt)?;
    let manifest_hash = upgrade::manifest_hash(manifest);
    if offer.manifest_hash != manifest_hash || receipt.manifest_hash != manifest_hash {
        return Err(MigrateError::ManifestHash);
    }
    Ok((offer, receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn target_refuses_a_receipt_for_another_capsule() {
        let manifest = UpgradeManifest {
            version: 1,
            sequence: 1,
            from_measurement: [0x11; 48],
            to_measurement: [0x22; 48],
            from_guest_policy: 0x30000,
            to_guest_policy: 0x30000,
            seed_fingerprint: [0x44; 32],
            source_capsule_hash: [0x55; 32],
            artifact_hash: [0x33; 32],
            release: "v0.1.2".into(),
        };
        let root = std::env::temp_dir().join(format!("zns-migrate-cutover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("channel");
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_hash = upgrade::manifest_hash(&manifest);
        let offer = MigrationOffer {
            ephemeral_pubkey: [1; 32],
            nonce: [2; 32],
            manifest_hash,
        };
        let receipt = MigrationReceipt {
            manifest_hash,
            new_capsule_hash: handoff::hash_capsule(b"another capsule"),
            seed_fingerprint: [0x44; 32],
        };
        std::fs::write(dir.join(OFFER_FILE), handoff::encode_offer(&offer)).unwrap();
        std::fs::write(dir.join(RECEIPT_FILE), handoff::encode_receipt(&receipt)).unwrap();
        let capsule = root.join("zns_seed.capsule");
        std::fs::write(&capsule, [7u8; 114]).unwrap();

        let Ok(crate::cli::Command::Run(args)) = crate::cli::parse([
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
            dir.to_str().unwrap(),
            "--output-capsule",
            capsule.to_str().unwrap(),
        ]) else {
            panic!("cutover target");
        };
        let channel = DirTransport::open(&dir, Duration::from_millis(10)).unwrap();
        let err = target(&args, &manifest, &channel).unwrap_err();
        assert!(err.to_string().contains("this target's capsule"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
