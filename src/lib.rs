// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::AttestDataError as OxAttestDataError;
use dice_verifier::{
    Attest as OxAttest, AttestError as OxAttestError,
    AttestMock as OxAttestMock, Attestation as OxAttestation, Log,
};
use hubpack::SerializedSize;
use sha2::{Digest, Sha256};
use x509_cert::PkiPath;

/// User chosen value. Probably random data. Must not be reused.
#[derive(Debug)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn from_platform_rng() -> Result<Self, getrandom::Error> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce[..])?;
        let nonce = nonce;

        Ok(Self(nonce))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub enum RotType {
    OxideHardware,
}

pub struct Attestation {
    rot: RotType,
    data: Vec<u8>,
}

pub struct MeasurementLog {
    rot: RotType,
    data: Vec<u8>,
}

/// An interface for obtaining an attestation from the Oxide RoT
///
/// An attestation from the Oxide RoT is an ed25519::Signature.
/// In the future, we may change algorithms and that will result in a new trait,
/// because the signature and hash lengths may change. The alternative is to
/// instead return a serialized signature and specify the algorithms used per
/// version.
pub trait AttestationSigner {
    type Error;

    /// Get an attestation from the Oxide RoT entangled with the provided nonce & data.
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Vec<Attestation>, Self::Error>;

    /// Return all relevant measurement logs, in order of concatenation.
    fn get_measurement_logs(&self) -> Result<Vec<MeasurementLog>, Self::Error>;

    /// Return the cert chain for the given RotType.
    fn get_cert_chain(&self, rot: RotType) -> Result<PkiPath, Self::Error>;
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum AttestMockError {
    #[error("error deserializing data")]
    Serialize,
    #[error("error from Oxide attestation interface")]
    OxideAttestError(#[from] OxAttestError),
    #[error("error from Oxide attestation data")]
    OxideAttestDataError(#[from] OxAttestDataError),
}

/// This type mocks the `propolis` process that backs a VM.
pub struct AttestMock {
    oxattest_mock: OxAttestMock,
}

impl AttestMock {
    pub fn new(oxattest_mock: OxAttestMock) -> Self {
        Self { oxattest_mock }
    }
}

impl AttestationSigner for AttestMock {
    type Error = AttestMockError;

    /// `propolis` receives the nonce & user data from the caller.
    /// It then combines this data w/ attributes describing the VM (rootfs,
    /// instance UUID etc) and attestations from other RoTs on the platform.
    /// The format of each attestation is dependent on the associated `RotType`.
    /// NOTE: the order of the attestations returned is significant
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Vec<Attestation>, Self::Error> {
        let mut msg = Sha256::new();
        // msg.update w/
        // - attestations from platform RoTs
        // - VM cfg data
        msg.update(nonce);
        msg.update(user_data);
        let msg = msg.finalize();

        let nonce = attest_data::Array::<32>(msg.into());
        let attest = self.oxattest_mock.attest(&nonce)?;

        let mut data = vec![0u8; OxAttestation::MAX_SIZE];
        let len = hubpack::serialize(&mut data, &attest)
            .map_err(|_| AttestMockError::Serialize)?;
        data.truncate(len);
        let data = data;

        let mut attestations = Vec::new();
        let rot = RotType::OxideHardware;
        attestations.push(Attestation { rot, data });

        Ok(attestations)
    }

    /// Get all measurement logs from the various RoTs on the platform.
    fn get_measurement_logs(&self) -> Result<Vec<MeasurementLog>, Self::Error> {
        let oxide_log = self.oxattest_mock.get_measurement_log()?;

        let mut data = vec![0u8; Log::MAX_SIZE];
        let len = hubpack::serialize(&mut data, &oxide_log)
            .map_err(|_| AttestMockError::Serialize)?;
        data.truncate(len);

        let mut logs = Vec::new();
        let rot = RotType::OxideHardware;
        logs.push(MeasurementLog { rot, data });

        Ok(logs)
    }

    fn get_cert_chain(&self, rot: RotType) -> Result<PkiPath, Self::Error> {
        match rot {
            RotType::OxideHardware => {
                Ok(self.oxattest_mock.get_certificates()?)
            }
        }
    }
}

// get file paths into build.rs & exported through generated source
// mod build {
//    include!(concat!(env!("OUT_DIR"), "/config.rs"));
//}

#[cfg(test)]
mod test {
    use crate::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    fn setup() -> AttestMock {
        let out_dir = env::var("OUT_DIR").expect("Could not get OUT_DIR");
        let out_dir = PathBuf::from(out_dir);
        if !fs::exists(&out_dir)
            .expect(&format!("fs exists: {}", out_dir.display()))
        {
            panic!("required file missing: {}", out_dir.display());
        }

        let mut pki_path = out_dir.clone();
        pki_path.push("test-alias.certlist.pem");
        let pki_path = pki_path;

        let mut log_path = out_dir.clone();
        log_path.push("log.bin");
        let log_path = log_path;

        let mut signer_path = out_dir.clone();
        signer_path.push("test-alias.key.pem");
        let signer_path = signer_path;

        let oxattest_mock =
            OxAttestMock::load(&pki_path, &log_path, &signer_path)
                .expect("failed to create OxAttestMock from inputs");

        AttestMock::new(oxattest_mock)
    }

    #[test]
    fn get_measurement_logs() {
        let attest = setup();

        let logs = attest.get_measurement_logs().expect("get_measurement_logs");
        for log in logs {
            match log.rot {
                RotType::OxideHardware => assert!(!log.data.is_empty()),
            }
        }
    }

    #[test]
    fn get_cert_chain() {
        let attest = setup();

        let _ = attest.get_cert_chain(RotType::OxideHardware);
    }

    #[test]
    fn attest() {
        let attest = setup();

        let nonce =
            Nonce::from_platform_rng().expect("Nonce from platform RNG");
        // TODO: should be a crypto key
        let user_data = vec![0u8, 1];

        let _ = attest
            .attest(&nonce, &user_data)
            .expect("AttestMock attest");
    }

    #[test]
    fn verify_signature() {
        todo!("get attestation & verify signature over it");
    }

    #[test]
    fn verify_cert_chain() {
        todo!("get cert chain & \"verify\" it");
    }

    #[test]
    fn appraise_log() {
        todo!("get log and appraise it");
    }
}
