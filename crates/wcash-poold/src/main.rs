//! Wcash pool service entry point.
//!
//! The service starts fail-closed: every durable store, authoritative backend,
//! payout signer, and address authority must pass its Testnet fence before a
//! miner or portal listener is opened.

#![forbid(unsafe_code)]

mod bootstrap;
mod config;
mod edge;
mod live_payout;
mod miner_telemetry;
mod payout;
pub mod payout_runtime;
mod service;
pub mod settlement;
pub mod wcash_observation;
mod wec_wallet_transport;
mod zec_authority_check;

use std::{io::Read, path::PathBuf, process::ExitCode};

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
    /// Validate an Orchard-only Zcash Testnet collector address from standard input.
    #[command(hide = true)]
    ValidateZecTestnetOrchard,
    /// Validate immutable policy and protected credential files without connecting.
    ConfigCheck {
        /// Absolute path to the protected Testnet policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate only the isolated payout policy and its database credential.
    PayoutConfigCheck {
        /// Absolute path to the protected payout-worker policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Prove one finalized, empty Zcash Testnet collector before backend init.
    ZecAuthorityCheck {
        /// Absolute path to the standalone ZEC authority policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply schema migrations and bind immutable zero-fee accounting policy.
    Migrate {
        /// Absolute path to the protected Testnet policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Prove the complete non-listening Testnet service dependency graph.
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
    /// Run the isolated accounting projector with no public listener.
    Projector {
        /// Absolute path to the protected projector policy.
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the isolated key-bearing Testnet payout worker with no public listener.
    PayoutWorker {
        /// Absolute path to the protected payout-worker policy.
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::ValidateZecTestnetOrchard => {
            let mut encoded = String::new();
            let read_result = std::io::stdin().take(514).read_to_string(&mut encoded);
            let candidate = encoded.strip_suffix('\n');
            if read_result.is_err()
                || encoded.len() > 513
                || candidate.is_none()
                || candidate.is_some_and(|value| {
                    value
                        .chars()
                        .any(|character| matches!(character, '\r' | '\n'))
                })
            {
                eprintln!("collector address input is invalid");
                return ExitCode::from(NOT_READY_EXIT_CODE);
            }
            match wcash_pool_address::validate_zcash_testnet_orchard_only(
                candidate.unwrap_or_default(),
            ) {
                Ok(()) => {
                    println!("{{\"valid\":true,\"network\":\"testnet\",\"receiver\":\"orchard\"}}");
                    ExitCode::SUCCESS
                }
                Err(_) => {
                    eprintln!("collector address is not a valid Orchard-only Zcash Testnet UA");
                    ExitCode::from(NOT_READY_EXIT_CODE)
                }
            }
        }
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
        Command::PayoutConfigCheck { config } => {
            match config::RuntimeConfig::load(&config).and_then(|runtime| {
                if runtime.payout_mode != config::PayoutMode::Automatic
                    || runtime.automatic_payout.is_none()
                {
                    return Err(config::ConfigError::InvalidPolicy);
                }
                let database = runtime.database_url()?;
                drop(database);
                Ok(())
            }) {
                Ok(()) => {
                    println!("{{\"valid\":true,\"network\":\"testnet\",\"scope\":\"payout\"}}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("payout configuration rejected: {error}");
                    ExitCode::from(NOT_READY_EXIT_CODE)
                }
            }
        }
        Command::ZecAuthorityCheck { config } => {
            match zec_authority_check::ZecAuthorityConfig::load(&config) {
                Ok(runtime) => match zec_authority_check::check(&runtime).await {
                    Ok(summary) => match summary.to_json() {
                        Ok(summary) => {
                            println!("{summary}");
                            ExitCode::SUCCESS
                        }
                        Err(error) => {
                            eprintln!("ZEC authority rejected: {error}");
                            ExitCode::from(NOT_READY_EXIT_CODE)
                        }
                    },
                    Err(error) => {
                        eprintln!("ZEC authority rejected: {error}");
                        ExitCode::from(NOT_READY_EXIT_CODE)
                    }
                },
                Err(error) => {
                    eprintln!("ZEC authority rejected: {error}");
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
            Ok(runtime) => match service::preflight(&runtime).await {
                Ok(()) => {
                    println!("{{\"preflight\":true,\"network\":\"testnet\"}}");
                    ExitCode::SUCCESS
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
        Command::Projector { config } => match config::RuntimeConfig::load(&config) {
            Ok(runtime) => match service::run_projector(runtime).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("accounting projector stopped: {error}");
                    ExitCode::from(NOT_READY_EXIT_CODE)
                }
            },
            Err(error) => {
                eprintln!("projector configuration rejected: {error}");
                ExitCode::from(NOT_READY_EXIT_CODE)
            }
        },
        Command::PayoutWorker { config } => match config::RuntimeConfig::load(&config) {
            Ok(runtime) => match service::run_payout_worker(runtime).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("payout worker stopped: {error}");
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
            Cli::try_parse_from(["wcash-poold", "validate-zec-testnet-orchard"]),
            Ok(Cli {
                command: Command::ValidateZecTestnetOrchard
            })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "wcash-poold",
                "payout-config-check",
                "--config",
                "/tmp/payout.toml"
            ]),
            Ok(Cli {
                command: Command::PayoutConfigCheck { .. }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "wcash-poold",
                "payout-worker",
                "--config",
                "/tmp/payout.toml"
            ]),
            Ok(Cli {
                command: Command::PayoutWorker { .. }
            })
        ));
        assert!(Cli::try_parse_from(["wcash-poold", "payout-worker"]).is_err());
        assert!(matches!(
            Cli::try_parse_from([
                "wcash-poold",
                "projector",
                "--config",
                "/tmp/projector.toml"
            ]),
            Ok(Cli {
                command: Command::Projector { .. }
            })
        ));
        assert!(Cli::try_parse_from(["wcash-poold", "projector"]).is_err());
        assert!(matches!(
            Cli::try_parse_from(["wcash-poold", "serve", "--config", "/tmp/pool.toml"]),
            Ok(Cli {
                command: Command::Serve { .. }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "wcash-poold",
                "zec-authority-check",
                "--config",
                "/tmp/zec-authority.toml"
            ]),
            Ok(Cli {
                command: Command::ZecAuthorityCheck { .. }
            })
        ));
        assert!(Cli::try_parse_from(["wcash-poold", "zec-authority-check"]).is_err());
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
