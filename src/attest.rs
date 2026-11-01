//! Read a measurement and guest policy out of an attestation report.
//!
//! Calls `zns_canon::attestation::stored`: parse the SNP report, fetch
//! AMD endorsement material, and check the pinned ARK before `report_data`
//! is accepted. There is no development path: migration is a ceremony.

use zns_canon::sealing::get_attestation;
use zns_canon::upgrade::UpgradeManifest;

use crate::error::MigrateError;

pub(crate) struct VerifiedReport {
    pub measurement: [u8; 48],
    pub guest_policy: u64,
}

pub(crate) fn verified_report(
    report: &[u8],
    expected: &[u8; 64],
) -> Result<VerifiedReport, MigrateError> {
    let attestation = zns_canon::attestation::stored(report.to_vec(), expected)?;
    Ok(VerifiedReport {
        measurement: attestation.measurement,
        guest_policy: attestation.guest_policy,
    })
}

/// Which guest of the manifest a report must come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    /// `from_measurement` and `from_guest_policy`.
    Source,
    /// `to_measurement` and `to_guest_policy`.
    Target,
}

/// `report` is over `report_data`, from the manifest's `side`.
pub(crate) fn require_report(
    report: &[u8],
    report_data: &[u8; 64],
    manifest: &UpgradeManifest,
    side: Side,
) -> Result<(), MigrateError> {
    let got = verified_report(report, report_data)?;
    require_side(&got.measurement, got.guest_policy, manifest, side)
}

/// This guest's report over `report_data`, required to come from `side`.
pub(crate) fn own_report(
    report_data: &[u8; 64],
    manifest: &UpgradeManifest,
    side: Side,
) -> Result<Vec<u8>, MigrateError> {
    let report = get_attestation(report_data)?;
    if report.as_bytes().is_empty() {
        return Err(MigrateError::transport("TEE returned an empty attestation"));
    }
    require_report(report.as_bytes(), report_data, manifest, side)?;
    Ok(report.as_bytes().to_vec())
}

pub(crate) fn require_side(
    measurement: &[u8; 48],
    guest_policy: u64,
    manifest: &UpgradeManifest,
    side: Side,
) -> Result<(), MigrateError> {
    match side {
        Side::Source => {
            require_measurement(
                measurement,
                &manifest.from_measurement,
                MigrateError::SourceMeasurement,
            )?;
            require_policy(
                guest_policy,
                manifest.from_guest_policy,
                MigrateError::SourceGuestPolicy,
            )
        }
        Side::Target => {
            require_measurement(
                measurement,
                &manifest.to_measurement,
                MigrateError::Measurement,
            )?;
            require_policy(
                guest_policy,
                manifest.to_guest_policy,
                MigrateError::GuestPolicy,
            )
        }
    }
}

pub(crate) fn require_measurement(
    got: &[u8; 48],
    expected: &[u8; 48],
    mismatch: MigrateError,
) -> Result<(), MigrateError> {
    if got.iter().all(|byte| *byte == 0) {
        return Err(MigrateError::ZeroMeasurement);
    }
    if got != expected {
        return Err(mismatch);
    }
    Ok(())
}

pub(crate) fn require_policy(
    got: u64,
    expected: u64,
    mismatch: MigrateError,
) -> Result<(), MigrateError> {
    if got == 0 {
        return Err(MigrateError::ZeroGuestPolicy);
    }
    if got != expected {
        return Err(mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_policy_must_match_and_must_not_be_zero() {
        require_policy(0x30000, 0x30000, MigrateError::GuestPolicy).unwrap();
        assert!(matches!(
            require_policy(0, 0x30000, MigrateError::GuestPolicy),
            Err(MigrateError::ZeroGuestPolicy)
        ));
        assert!(matches!(
            require_policy(0x70000, 0x30000, MigrateError::GuestPolicy),
            Err(MigrateError::GuestPolicy)
        ));
    }
}
