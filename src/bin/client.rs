use anyhow::{anyhow, Context, Result};
use clap::Parser;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Path to socket file. If file already exists an error is returned
    file: PathBuf,

    // Message to send to server
    message: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.file.exists() {
        return Err(anyhow!("socket file missing"));
    }

    let mut stream = UnixStream::connect(&args.file).context("connec to socket")?;

    Ok(stream.write_all(args.message.as_bytes()).context("write message to socket")?)
}
