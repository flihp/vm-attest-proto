use anyhow::{Context, Result, anyhow};
use clap::Parser;

use std::{os::unix::net::UnixStream, path::PathBuf};

use vm_attest_trait::{
    Nonce, VmInstanceAttester, socket::VmInstanceAttestSocket,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Path to socket file. If file already exists an error is returned
    file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.file.exists() {
        return Err(anyhow!("socket file missing"));
    }

    let stream = UnixStream::connect(&args.file).context("connec to socket")?;
    let attest = VmInstanceAttestSocket::new(stream);

    let nonce =
        Nonce::from_platform_rng().context("Nonce from paltform RNG")?;
    let data = vec![66, 77, 88, 99];
    let _attestation = attest.attest(&nonce, &data)?;

    Ok(())
}
