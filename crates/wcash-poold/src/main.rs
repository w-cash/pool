//! Wcash pool service entry point.
//!
//! The public service is deliberately unavailable until the local mining
//! backend, durable share path, and miner edge pass the documented testnet
//! gates. This binary exposes a machine-readable readiness probe without
//! opening a network listener.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

const NOT_READY_EXIT_CODE: u8 = 78;

#[derive(Debug, Parser)]
#[command(
    name = "wcash-poold",
    version,
    about = "Wcash/Zcash merged-mining pool (pre-testnet foundation)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report whether this revision may serve miners.
    Readiness,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Readiness => {
            println!(
                "{{\"ready\":false,\"stage\":\"foundation\",\"reason\":\"public miner service is not implemented\"}}"
            );
            ExitCode::from(NOT_READY_EXIT_CODE)
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn exposes_readiness_but_no_serve_command() {
        assert!(matches!(
            Cli::try_parse_from(["wcash-poold", "readiness"]),
            Ok(Cli {
                command: Command::Readiness
            })
        ));
        assert!(Cli::try_parse_from(["wcash-poold", "serve"]).is_err());
    }
}
