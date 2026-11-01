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
//! attested: a forged one could let two mints serve.

use tracing::info;
use zns_canon::migration::MigrationOffer;
use zns_canon::sealing::get_attestation;
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::attest::{self, require_measurement, require_policy};
use crate::error::MigrateError;
use crate::handoff::{self, MigrationReceipt};
use crate::transport::{DirTransport, SOURCE_STOPPED_FILE};

pub fn source(manifest: &UpgradeManifest, channel: &DirTransport) -> Result<(), MigrateError> {
    let (offer, receipt) = finished_handoff(manifest, channel)?;
    if channel.contains(SOURCE_STOPPED_FILE)? {
        return Ok(());
    }
    let report_data = handoff::stopped_report_data(&offer, &receipt);
    let report = get_attestation(&report_data)?;
    if report.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    let own = attest::verified_report(report.as_bytes(), &report_data)?;
    require_measurement(
        &own.measurement,
        &manifest.from_measurement,
        MigrateError::SourceMeasurement,
    )?;
    require_policy(
        own.guest_policy,
        manifest.from_guest_policy,
        MigrateError::SourceGuestPolicy,
    )?;
    channel.publish_source_stopped(report.as_bytes())?;
    info!("source stopped published");
    Ok(())
}

pub fn target(manifest: &UpgradeManifest, channel: &DirTransport) -> Result<(), MigrateError> {
    let (offer, receipt) = finished_handoff(manifest, channel)?;
    let stopped = channel.wait_source_stopped()?;
    let report_data = handoff::stopped_report_data(&offer, &receipt);
    let source = attest::verified_report(&stopped, &report_data)?;
    require_measurement(
        &source.measurement,
        &manifest.from_measurement,
        MigrateError::SourceMeasurement,
    )?;
    require_policy(
        source.guest_policy,
        manifest.from_guest_policy,
        MigrateError::SourceGuestPolicy,
    )?;
    info!("source mint stopped");
    Ok(())
}

/// The offer and receipt of a handoff for this manifest.
fn finished_handoff(
    manifest: &UpgradeManifest,
    channel: &DirTransport,
) -> Result<(MigrationOffer, MigrationReceipt), MigrateError> {
    let offer = handoff::decode_offer(&channel.wait_offer()?)?;
    let receipt = handoff::decode_receipt(&channel.wait_receipt()?)?;
    let manifest_hash = upgrade::manifest_hash(manifest);
    if offer.manifest_hash != manifest_hash || receipt.manifest_hash != manifest_hash {
        return Err(MigrateError::ManifestHash);
    }
    Ok((offer, receipt))
}
