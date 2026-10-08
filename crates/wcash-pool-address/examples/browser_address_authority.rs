//! Seedless production address authority bridge for the portal browser tests.
//! Build with `cargo build -p wcash-pool-address --example browser_address_authority`.
//! The only argument is an actual Wolf wallet executable; one JSON request is read
//! from stdin. This exercises the real codec without a node, wallet DB, or funds.

use std::{fs, io, os::unix::fs::MetadataExt, time::Duration};

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use wcash_pool_address::{TestnetAddressValidator, WcashCommandValidator};
use wcash_pool_portal::{AddressValidator, Asset, ChainNetwork};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    destination: String,
    enabled: bool,
    mainnet: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let program = fs::canonicalize(std::env::args().nth(1).ok_or("wallet path required")?)?;
    let digest = Sha256::digest(fs::read(&program)?).into();
    let command = WcashCommandValidator::new(
        &program,
        digest,
        fs::metadata(&program)?.uid(),
        Duration::from_secs(10),
    )?;
    let request: Request = serde_json::from_reader(io::stdin())?;
    let mut validator =
        TestnetAddressValidator::new(command).with_wcash_transparent_payouts(request.enabled);
    let network = if request.mainnet {
        validator = validator.with_mainnet_network();
        ChainNetwork::Mainnet
    } else {
        ChainNetwork::Testnet
    };
    let result = match validator.validate(Asset::Wec, network, &request.destination) {
        Ok(destination) => json!({
            "accepted": true,
            "receiver": destination.receiver_kind(),
            "canonical": destination.canonical_address(),
        }),
        Err(error) => json!({"accepted": false, "reason": format!("{error:?}")}),
    };
    println!("{result}");
    Ok(())
}
