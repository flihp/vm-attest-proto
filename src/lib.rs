use dice_verifier::{Attest as OxAttest, AttestMock as OxAttestMock};
use ed25519_dalek::Signature;
use x509_cert::PkiPath;

/// User chosen value. Probably random data. Must not be reused.
#[derive(Debug)]
pub struct Nonce([u8; 32]);

#[derive(Debug)]
pub enum RotType {
    OxideHardware,
}

pub struct MeasurementLog {
    rot: RotType,
    data: Vec<u8>,
}

/// Errors returned when trying to sign an attestation
pub enum AttestationSignerError {
    UnknownRoT,
    CommunicationError,
}

/// An interface for obtaining an attestation from the Oxide RoT
///
/// An attestation from the Oxide RoT is an ed25519::Signature.
/// In the future, we may change algorithms and that will result in a new trait,
/// because the signature and hash lengths may change. The alternative is to
/// instead return a serialized signature and specify the algorithms used per
/// version.
pub trait AttestationSigner {
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Signature, AttestationSignerError>;

    /// Return all relevant measurement logs, in order of concatenation.
    fn get_measurement_logs(&self) -> Vec<MeasurementLog>;

    /// Return the cert chain for the given RotType.
    fn get_cert_chain(&self, rot: &RotType) -> PkiPath;
}

pub struct AttestMock {
    oxattest_mock: OxAttestMock,
}

impl AttestMock {
    pub fn new(oxattest_mock: OxAttestMock) -> Self {
        Self { oxattest_mock }
    }
}

impl AttestationSigner for AttestMock {
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Signature, AttestationSignerError> {
        todo!("AttestMock::attest: {nonce:?}, {user_data:?}");
    }

    fn get_measurement_logs(&self) -> Vec<MeasurementLog> {
        todo!("AttestMock::get_measurement_logs");
    }

    fn get_cert_chain(&self, rot: &RotType) -> PkiPath {
        todo!("AttestMock::get_cert_chain: {rot:?}");
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

    #[test]
    fn construct() {
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
        let attest = AttestMock::new(oxattest_mock);
    }
}
