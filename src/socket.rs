// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::unix::net::{UnixListener, UnixStream},
};

use crate::{
    mock::VmInstanceAttestMock,
    Attestation, CertChain, MeasurementLog, Nonce, VmInstanceAttester,
};

#[derive(Debug, Deserialize, Serialize)]
struct AttestData {
    nonce: Nonce,
    data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
enum Command {
    Attest(AttestData),
}

// This type is used by clients to send commands and get responses from
// an implementation of the VmInstanceAttest API over a socket
pub struct VmInstanceAttestSocket {
    _socket: UnixStream,
}

impl VmInstanceAttestSocket {
    pub fn new(socket: UnixStream) -> Self {
        Self { _socket: socket }
    }
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceAttestSocketError {
}

impl VmInstanceAttester for VmInstanceAttestSocket {
    type Error = VmInstanceAttestSocketError;

    // serialize parames into message structure representing the
    // VmInstanceAttester::attest function
    fn attest(
        &self,
        _nonce: &Nonce,
        _user_data: &[u8],
    ) -> Result<Vec<Attestation>, Self::Error> {
        todo!("VmInstanceAttestSocket::attest");
    }

    // serialize parames into message structure representing the
    // VmInstanceAttester::get_measurement_logs
    fn get_measurement_logs(&self) -> Result<Vec<MeasurementLog>, Self::Error> {
        todo!("VmInstanceAttestSocket::get_measurement_logs");
    }

    // serialize parames into message structure representing the
    // VmInstanceAttester::get_cert_chains
    fn get_cert_chains(&self) -> Result<Vec<CertChain>, Self::Error> {
        todo!("VmInstanceAttestSocket::get_cert_chains");
    }
}

/// This type acts as a socket server accepting encoded messages that
/// correspond to functions from the VmInstanceAttester.
pub struct VmInstanceAttestSocketServer {
    _mock: VmInstanceAttestMock,
    listener: UnixListener,
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceAttestSocketRunError {
    #[error("error deserializing Command from JSON")]
    CommandDeserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error deserializing data")]
    Serialize,
 }

impl VmInstanceAttestSocketServer {
    pub fn new(mock: VmInstanceAttestMock, listener: UnixListener) -> Self {
        Self { _mock: mock, listener }
    }

    // message handling loop
    pub fn run(&self) -> Result<(), VmInstanceAttestSocketRunError> {
        let mut msg = String::new();
        for client in self.listener.incoming() {
            // `incoming` yeilds iterator over a Result
            let mut client = client?;

            client.read_to_string(&mut msg)?;

            let command: Command = serde_json::from_str(&msg)?;
            match command {
                Command::Attest(_data) => {
                    todo!("VmInstanceAttestSocketServer::run handle Attest command");
                }
            }
        }

        Ok(())
     }
}
