//! After a handoff to another release. The source mint serves while the
//! target syncs, and only one of them serves at a time.
//!
//! ```text
//! target: wait for --after (Zebra ready)
//!         publish a to_measurement report over offer || receipt
//! source: check that report, write --hold
//!         wait for --after (mint stopped)
//!         publish a from_measurement report over offer || receipt
//! target: check that report, remove --hold
//! ```
//!
//! Source clears --after before it writes --hold, so a leftover file cannot
//! stand for a mint that is still running.
//!
//! Both guests can rerun this after a reboot. It reads only the public offer
//! and receipt from the channel, and never publishes a report twice.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use tracing::info;
use zns_canon::migration::MigrationOffer;
use zns_canon::sealing::get_attestation;
use zns_canon::upgrade::{self, UpgradeManifest};

use crate::attest::{self, require_measurement, require_policy};
use crate::cli::Args;
use crate::error::MigrateError;
use crate::handoff::{self, MigrationReceipt};
use crate::persist;
use crate::transport::{self, DirTransport, SOURCE_STOPPED_FILE, TARGET_READY_FILE};

const LOCAL_POLL: Duration = Duration::from_secs(1);

pub fn target(
    args: &Args,
    manifest: &UpgradeManifest,
    channel: &DirTransport,
) -> Result<(), MigrateError> {
    let (hold, after) = local_paths(args, channel)?;
    let (offer, receipt) = finished_handoff(manifest, channel)?;

    if !channel.contains(TARGET_READY_FILE)? {
        wait_local(after, args.timeout)?;
        let report = own_report(
            &handoff::ready_report_data(&offer, &receipt),
            &manifest.to_measurement,
            manifest.to_guest_policy,
            MigrateError::Measurement,
            MigrateError::GuestPolicy,
        )?;
        channel.publish_target_ready(&report)?;
        info!("target ready published");
    }

    let stopped = channel.wait_source_stopped()?;
    let source =
        attest::verified_report(&stopped, &handoff::stopped_report_data(&offer, &receipt))?;
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
    remove_hold(hold)?;
    info!("source mint stopped; hold removed");
    Ok(())
}

pub fn source(
    args: &Args,
    manifest: &UpgradeManifest,
    channel: &DirTransport,
) -> Result<(), MigrateError> {
    let (hold, after) = local_paths(args, channel)?;
    let (offer, receipt) = finished_handoff(manifest, channel)?;

    let ready = channel.wait_target_ready()?;
    let target = attest::verified_report(&ready, &handoff::ready_report_data(&offer, &receipt))?;
    require_measurement(
        &target.measurement,
        &manifest.to_measurement,
        MigrateError::Measurement,
    )?;
    require_policy(
        target.guest_policy,
        manifest.to_guest_policy,
        MigrateError::GuestPolicy,
    )?;
    if channel.contains(SOURCE_STOPPED_FILE)? {
        return write_hold(hold);
    }
    // A leftover --after can predate the hold. Clear it first, so the one
    // we wait for was written by a pass that saw the hold.
    remove_local(after)?;
    write_hold(hold)?;
    info!("target is ready; hold written");
    wait_local(after, args.timeout)?;
    let report = own_report(
        &handoff::stopped_report_data(&offer, &receipt),
        &manifest.from_measurement,
        manifest.from_guest_policy,
        MigrateError::SourceMeasurement,
        MigrateError::SourceGuestPolicy,
    )?;
    channel.publish_source_stopped(&report)?;
    info!("source stopped published");
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

fn local_paths<'a>(
    args: &'a Args,
    channel: &DirTransport,
) -> Result<(&'a Path, &'a Path), MigrateError> {
    let hold = args
        .hold
        .as_deref()
        .ok_or_else(|| MigrateError::usage("--hold is required"))?;
    let after = args
        .after
        .as_deref()
        .ok_or_else(|| MigrateError::usage("--after is required"))?;
    transport::trusted_outside_transport(hold, channel.dir(), "hold")?;
    transport::trusted_outside_transport(after, channel.dir(), "after")?;
    Ok((hold, after))
}

fn own_report(
    report_data: &[u8; 64],
    measurement: &[u8; 48],
    guest_policy: u64,
    wrong_measurement: MigrateError,
    wrong_policy: MigrateError,
) -> Result<Vec<u8>, MigrateError> {
    let report = get_attestation(report_data)?;
    if report.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    let own = attest::verified_report(report.as_bytes(), report_data)?;
    require_measurement(&own.measurement, measurement, wrong_measurement)?;
    require_policy(own.guest_policy, guest_policy, wrong_policy)?;
    Ok(report.as_bytes().to_vec())
}

fn wait_local(path: &Path, timeout: Duration) -> Result<(), MigrateError> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(MigrateError::io(
                    format!("inspect {}", path.display()),
                    error,
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(MigrateError::transport(format!(
                "timed out waiting for {}",
                path.display()
            )));
        }
        thread::sleep(LOCAL_POLL);
    }
}

fn write_hold(path: &Path) -> Result<(), MigrateError> {
    if fs::symlink_metadata(path).is_ok() {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|error| MigrateError::io(format!("create {}", path.display()), error))?;
    file.write_all(b"hold\n")
        .and_then(|()| file.sync_all())
        .map_err(|error| MigrateError::io(format!("write {}", path.display()), error))?;
    persist::sync_parent(path)
}

fn remove_hold(path: &Path) -> Result<(), MigrateError> {
    remove_local(path)
}

fn remove_local(path: &Path) -> Result<(), MigrateError> {
    match fs::remove_file(path) {
        Ok(()) => persist::sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(MigrateError::io(
            format!("remove {}", path.display()),
            error,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zns-migrate-cutover-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn hold_write_and_remove_are_idempotent() {
        let dir = scratch("hold");
        let hold = dir.join("migrate-source.hold");
        write_hold(&hold).unwrap();
        write_hold(&hold).unwrap();
        assert_eq!(fs::read(&hold).unwrap(), b"hold\n");
        remove_hold(&hold).unwrap();
        remove_hold(&hold).unwrap();
        assert!(!hold.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wait_local_returns_once_the_file_exists() {
        let dir = scratch("after");
        let after = dir.join("zebra-ready");
        let err = wait_local(&after, Duration::from_millis(10)).unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        fs::write(&after, b"").unwrap();
        wait_local(&after, Duration::from_millis(10)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
