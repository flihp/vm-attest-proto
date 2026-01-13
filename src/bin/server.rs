use anyhow::{anyhow, Context, Result};
use clap::Parser;

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Path to socket file. If file already exists an error is returned.
    file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.file.exists() {
        return Err(anyhow!("socket file exists"));
    }

    let listener = UnixListener::bind(&args.file).context("failed to bind to socket")?;
    println!("Listening on socket {:?}", &args.file);

    // Iterate over clients, blocks if no client available
    let mut msg = String::new();
    for client in listener.incoming() {
        let mut client = client.context("listener incoming")?;
        client.read_to_string(&mut msg).context("read string from client")?;
        println!("Client said: {}", msg);
    }

    Ok(())
}
