// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use std::env;
use std::fs;
use std::path::{self, Path, PathBuf};

/// Execute one of the `pki-playground` commands to generate part of the PKI
/// used for testing.
fn pki_gen_cmd(command: &str, cfg: Option<&Path>) -> Result<()> {
    let mut cmd = std::process::Command::new("pki-playground");

    if let Some(cfg) = cfg {
        cmd.arg("--config");
        cmd.arg(cfg);
    }

    cmd.arg(command);
    let output = cmd
        .output()
        .context("executing command \"pki-playground\"")?;

    if !output.status.success() {
        let stdout = String::from_utf8(output.stdout)
            .context("String from pki-playground stdout")?;
        println!("stdout: {stdout}");
        let stderr = String::from_utf8(output.stderr)
            .context("String from pki-playground stderr")?;
        println!("stderr: {stderr}");

        return Err(anyhow!("cmd failed: {cmd:?}"));
    }

    Ok(())
}

/// Execute one of the `attest-mock` commands to generate mock input data used
/// for testing.
fn attest_gen_cmd(command: &str, input: &Path, output: &str) -> Result<()> {
    // attest-mock "input" "cmd" > "output"
    let mut cmd = std::process::Command::new("attest-mock");
    cmd.arg(input).arg(command);
    let cmd_output =
        cmd.output().context("executing command \"attest-mock\"")?;

    if cmd_output.status.success() {
        std::fs::write(output, cmd_output.stdout).context("write {output}")
    } else {
        let stderr = String::from_utf8(cmd_output.stderr)
            .context("String from attest-mock stderr")?;
        println!("stderr: {stderr}");

        Err(anyhow!("cmd failed: {cmd:?}"))
    }
}

fn main() -> Result<()> {
    let start_dir = env::current_dir().context("get current dir")?;
    let start_dir =
        path::absolute(start_dir).context("current_dir to absolute")?;

    let mut test_data_dir = start_dir.clone();
    test_data_dir.push("test-data");
    let test_data_dir = test_data_dir;

    let mut pki_cfg = test_data_dir.clone();
    pki_cfg.push("config.kdl");
    let pki_cfg = pki_cfg;
    if !fs::exists(&pki_cfg).with_context(|| {
        format!("required file doesn't exist: {}", pki_cfg.display())
    })? {
        return Err(anyhow!("missing PKI config file: {}", pki_cfg.display()));
    }

    let mut log_cfg = test_data_dir.clone();
    log_cfg.push("log.kdl");
    let log_cfg = log_cfg;
    if !fs::exists(&log_cfg).with_context(|| {
        format!("required file doesn't exist: {}", log_cfg.display())
    })? {
        return Err(anyhow!(
            "missing measurement log config file: {}",
            log_cfg.display()
        ));
    }

    let mut corim_cfg = test_data_dir.clone();
    corim_cfg.push("corim.kdl");
    let corim_cfg = corim_cfg;
    if !fs::exists(&corim_cfg).with_context(|| {
        format!("required file doesn't exist: {}", corim_cfg.display())
    })? {
        return Err(anyhow!(
            "missing reference integrity measurement config file: {}",
            corim_cfg.display()
        ));
    }

    let out_dir =
        PathBuf::from(env::var("OUT_DIR").context("Could not get OUT_DIR")?);

    env::set_current_dir(&out_dir)
        .with_context(|| format!("chdir to {}", out_dir.display()))?;

    // generate keys, certs, and cert chains / lists
    pki_gen_cmd("generate-key-pairs", Some(&pki_cfg))?;
    pki_gen_cmd("generate-certificates", Some(&pki_cfg))?;
    pki_gen_cmd("generate-certificate-lists", Some(&pki_cfg))?;

    // generate measurement log
    attest_gen_cmd("log", &log_cfg, "log.bin")?;

    // generate the corpus of reference measurements
    attest_gen_cmd("corim", &corim_cfg, "corim.cbor")?;

    std::env::set_current_dir(start_dir)
        .context("restore current dir to original")?;

    Ok(())
}
