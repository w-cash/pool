//! Wcash pool service entry point.
//!
//! The service starts fail-closed: every durable store, authoritative backend,
//! payout signer, and address authority must pass its Testnet fence before a
//! miner or portal listener is opened.

#![forbid(unsafe_code)]

mod bootstrap;
mod config;
mod edge;
mod payout;
mod service;
mod wec_wallet_transport;

use std::{path::PathBuf, process::ExitCode};

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
    /// Validate immutable policy and protected credential files without connecting.
    ConfigCheck {
        /// Absolute path to the protected Testnet policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply schema migrations and bind immutable zero-fee accounting policy.
    Migrate {
        /// Absolute path to the protected Testnet policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Prove database, replay, snapshot, nonce, and authentication bootstrap.
    Preflight {
        /// Absolute path to the protected Testnet policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the fail-closed Testnet pool until SIGINT or SIGTERM.
    Serve {
        /// Absolute path to the protected Testnet policy.
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::ConfigCheck { config } => {
            match config::RuntimeConfig::load(&config).and_then(|runtime| {
                let database = runtime.database_url()?;
                let token =
                    config::RuntimeConfig::portal_secret(&runtime.portal_token_pepper_file)?;
                let totp = config::RuntimeConfig::portal_secret(&runtime.portal_totp_key_file)?;
                if *token == *totp {
                    return Err(config::ConfigError::WeakCredential);
                }
                drop((database, token, totp));
                Ok(())
            }) {
                Ok(()) => {
                    println!("{{\"valid\":true,\"network\":\"testnet\"}}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("configuration rejected: {error}");
                    ExitCode::from(NOT_READY_EXIT_CODE)
                }
            }
        }
        Command::Migrate { config } => match config::RuntimeConfig::load(&config) {
            Ok(runtime) => match bootstrap::migrate(&runtime).await {
                Ok(()) => {
                    println!("{{\"migrated\":true,\"network\":\"testnet\",\"fees_bps\":0}}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("migration rejected: {error}");
                    ExitCode::from(NOT_READY_EXIT_CODE)
                }
            },
            Err(error) => {
                eprintln!("configuration rejected: {error}");
                ExitCode::from(NOT_READY_EXIT_CODE)
            }
        },
        Command::Preflight { config } => match config::RuntimeConfig::load(&config) {
            Ok(runtime) => match bootstrap::start(&runtime).await {
                Ok(started) => {
                    let bootstrap::MiningBootstrap {
                        store,
                        jobs,
                        shares,
                        authentication,
                        nonces,
                        nonce_claim,
                        timeline,
                    } = started;
                    let shutdown = shares.shutdown().await;
                    let release = store.release_nonce_namespace(&nonce_claim).await;
                    drop((store, jobs, authentication, nonces, timeline));
                    match (shutdown, release) {
                        (Ok(()), Ok(())) => {
                            println!("{{\"preflight\":true,\"network\":\"testnet\"}}");
                            ExitCode::SUCCESS
                        }
                        (Err(error), _) => {
                            eprintln!("preflight shutdown failed: {error}");
                            ExitCode::from(NOT_READY_EXIT_CODE)
                        }
                        (Ok(()), Err(error)) => {
                            eprintln!("preflight nonce release failed: {error}");
                            ExitCode::from(NOT_READY_EXIT_CODE)
                        }
                    }
                }
                Err(error) => {
                    eprintln!("preflight rejected: {error}");
                    ExitCode::from(NOT_READY_EXIT_CODE)
                }
            },
            Err(error) => {
                eprintln!("configuration rejected: {error}");
                ExitCode::from(NOT_READY_EXIT_CODE)
            }
        },
        Command::Serve { config } => match config::RuntimeConfig::load(&config) {
            Ok(runtime) => match service::run(runtime).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("service stopped: {error}");
                    ExitCode::from(NOT_READY_EXIT_CODE)
                }
            },
            Err(error) => {
                eprintln!("configuration rejected: {error}");
                ExitCode::from(NOT_READY_EXIT_CODE)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn exposes_explicit_testnet_service_commands() {
        assert!(matches!(
            Cli::try_parse_from(["wcash-poold", "serve", "--config", "/tmp/pool.toml"]),
            Ok(Cli {
                command: Command::Serve { .. }
            })
        ));
        assert!(Cli::try_parse_from(["wcash-poold", "serve"]).is_err());
        assert!(matches!(
            Cli::try_parse_from(["wcash-poold", "config-check", "--config", "/tmp/pool.toml"]),
            Ok(Cli {
                command: Command::ConfigCheck { .. }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["wcash-poold", "migrate", "--config", "/tmp/pool.toml"]),
            Ok(Cli {
                command: Command::Migrate { .. }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["wcash-poold", "preflight", "--config", "/tmp/pool.toml"]),
            Ok(Cli {
                command: Command::Preflight { .. }
            })
        ));
    }
}
