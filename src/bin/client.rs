use anyhow::{Context, Result, anyhow};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use log::debug;

use std::{os::unix::net::UnixStream, path::PathBuf};

use vm_attest_trait::{
    Nonce, VmInstanceAttester, socket::VmInstanceAttestSocket,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    // Path to socket file. If file already exists an error is returned
    file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    if !args.file.exists() {
        return Err(anyhow!("socket file missing"));
    }

    debug!("creating socket");
    let stream = UnixStream::connect(&args.file).context("connec to socket")?;
    let attest = VmInstanceAttestSocket::new(stream);

    let nonce =
        Nonce::from_platform_rng().context("Nonce from paltform RNG")?;
    debug!("generating nonce: {nonce:?}");
    let data = vec![66, 77, 88, 99];
    debug!("user_data: {data:?}");

    let attestations =
        attest.attest(&nonce, &data).context("get attestations")?;
    debug!("got attestations: {attestations:?}");

    let cert_chains = attest.get_cert_chains().context("get cert chains")?;
    debug!("got cert chains: {cert_chains:?}");

    Ok(())
}
