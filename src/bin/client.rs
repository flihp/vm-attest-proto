use anyhow::{Context, Result, anyhow};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use dice_verifier::{
    Attestation as OxAttestation, Log,
};

use log::{debug, info};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::net::UnixStream, path::PathBuf};
use x509_cert::{Certificate, der::Decode};

use vm_attest_trait::{
    Nonce, RotType, VmInstanceAttester, socket::VmInstanceAttestSocket,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    #[clap(long)]
    root_cert: Option<PathBuf>,

    #[clap(long, default_value_t = false)]
    self_signed: bool,

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

    let root_cert = match args.root_cert {
        Some(path) => {
            let root_cert = fs::read(&path)
                .with_context(|| format!("read file: {}", path.display()))?;
            Some(
                Certificate::load_pem_chain(&root_cert)
                    .context("failed to load certs from the provided file")?,
            )
        }
        None => {
            if !args.self_signed {
                return Err(anyhow!(
                    "No root cert, `--self-signed` must be explicit"
                ));
            } else {
                None
            }
        }
    };

    debug!("loaded root certs: {:?}", root_cert);

    debug!("creating socket");
    let stream = UnixStream::connect(&args.file).context("connec to socket")?;
    let attest = VmInstanceAttestSocket::new(stream);

    let nonce =
        Nonce::from_platform_rng().context("Nonce from paltform RNG")?;
    debug!("generating nonce: {nonce:?}");
    let data = vec![66, 77, 88, 99];
    debug!("user_data: {data:?}");

    let cert_chains = attest.get_cert_chains().context("get cert chains")?;
    debug!("got cert chains");

    for cert_chain in &cert_chains {
        match cert_chain.rot {
            RotType::OxidePlatform => {
                let mut cert_chain_pem = Vec::new();
                for cert in &cert_chain.certs {
                    cert_chain_pem.push(
                        Certificate::from_der(&cert)
                            .context("Certificate from DER")?,
                    );
                }
                let _verified_root = dice_verifier::verify_cert_chain(
                    &cert_chain_pem,
                    root_cert.as_deref(),
                )
                .context("verify cert chain")?;
                match root_cert {
                    Some(_) => {
                        // TODO: pull subject string from the cert
                        info!("cert chain verified against provided root");
                    }
                    None => info!("cert chain verified to self-signed root"),
                }
            }
            // this RoT doesn't have a cert chain
            RotType::OxideInstance => assert!(false),
        }
    }

    let logs = attest
        .get_measurement_logs()
        .context("get measurement logs")?;
    debug!("got measurement logs");

    let attestations =
        attest.attest(&nonce, &data).context("get attestations")?;
    debug!("got attestations");

    if attestations.len() != 1 {
        return Err(anyhow!("unexpected number of attestations returned"));
    }

    let attestation = &attestations[0];
    if attestation.rot != RotType::OxidePlatform {
        return Err(anyhow!(format!(
            "unexpected RotType in attestation: {:?}",
            attestation.rot
        )));
    }

    let (attestation, _): (OxAttestation, _) =
        hubpack::deserialize(&attestation.data)
            .context("deserialize attestation from Oxide platform RoT")?;

    // Reconstruct the 32 bytes passed from `VmInstanceAttestMock` down to
    // the RotType::OxidePlatform:
    //
    // The challenger passes OxideInstance RoT 32 byte nonce and a &[u8]
    // that we call `data`. It then combines them as:
    // `sha256(instance_log | nonce | data)`
    let mut data_digest = Sha256::new();

    // include the log from the OxideInstance RoT in the digest
    for log in &logs {
        match log.rot {
            RotType::OxideInstance => data_digest.update(&log.data),
            _ => continue,
        }
    }

    // update digest w/ data provided by the VM
    data_digest.update(&nonce);
    data_digest.update(&data);

    // smuggle this data into the `verify_attestation` function in the
    // `attest_data::Nonce` type
    let data_digest = data_digest.finalize();
    let data_digest = attest_data::Nonce {
        0: data_digest.into(),
    };

    // get the log from the Oxide platform RoT
    let oxlog = logs.iter().find_map(|log| {
        if log.rot == RotType::OxidePlatform {
            Some(log)
        } else {
            None
        }
    });

    // put log in the form expected by the `verify_attestation` function
    let (log, _): (Log, _) = if let Some(oxlog) = oxlog {
        hubpack::deserialize(&oxlog.data)
            .expect("deserialize hubpacked log")
    } else {
        return Err(anyhow!("No measurement log for RotType::OxidePlatform"));
    };

    // signer cert is the leaf
    let cert = Certificate::from_der(&cert_chains[0].certs[0])
        .expect("Certificate from DER");

    let result = dice_verifier::verify_attestation(
        &cert,
        &attestation,
        &log,
        &data_digest,
    );

    if !result.is_ok() {
        return Err(anyhow!("attestation verification failed"));
    } else {
        info!("attestation verified");
    }

    Ok(())
}
