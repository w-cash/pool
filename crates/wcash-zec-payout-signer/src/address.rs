//! Independent Zcash Testnet destination validation.

use wcash_pool_portal::ReceiverKind;
use zcash_address::{
    unified::{self, Container, Receiver},
    ConversionError, TryFromAddress, ZcashAddress,
};
use zcash_protocol::consensus::NetworkType;

use crate::ZecPayoutError;

pub(crate) enum Destination {
    Transparent { script_pubkey: Vec<u8> },
    Ironwood { receiver: [u8; 43] },
}

struct SupportedReceiver(Destination);

impl TryFromAddress for SupportedReceiver {
    type Error = ();

    fn try_from_unified(
        _network: NetworkType,
        address: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let receivers = address.items();
        let orchard = receivers.iter().find_map(|receiver| match receiver {
            Receiver::Orchard(receiver) => Some(*receiver),
            _ => None,
        });
        let has_unknown = receivers
            .iter()
            .any(|receiver| matches!(receiver, Receiver::Unknown { .. }));
        if let (Some(receiver), false) = (orchard, has_unknown) {
            Ok(Self(Destination::Ironwood { receiver }))
        } else {
            Err(ConversionError::User(()))
        }
    }

    fn try_from_transparent_p2pkh(
        _network: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let mut script_pubkey = Vec::with_capacity(25);
        script_pubkey.extend_from_slice(&[0x76, 0xa9, 0x14]);
        script_pubkey.extend_from_slice(&data);
        script_pubkey.extend_from_slice(&[0x88, 0xac]);
        Ok(Self(Destination::Transparent { script_pubkey }))
    }

    fn try_from_transparent_p2sh(
        _network: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let mut script_pubkey = Vec::with_capacity(23);
        script_pubkey.extend_from_slice(&[0xa9, 0x14]);
        script_pubkey.extend_from_slice(&data);
        script_pubkey.push(0x87);
        Ok(Self(Destination::Transparent { script_pubkey }))
    }
}

pub(crate) fn validate_destination(
    encoded: &str,
    expected_kind: ReceiverKind,
) -> Result<(), ZecPayoutError> {
    let parsed =
        ZcashAddress::try_from_encoded(encoded).map_err(|_| ZecPayoutError::InvalidRequest)?;
    if parsed.encode() != encoded {
        return Err(ZecPayoutError::InvalidRequest);
    }
    let SupportedReceiver(destination) = parsed
        .convert_if_network::<SupportedReceiver>(NetworkType::Test)
        .map_err(|_| ZecPayoutError::InvalidRequest)?;
    let actual_kind = match destination {
        Destination::Transparent { .. } => ReceiverKind::Transparent,
        Destination::Ironwood { .. } => ReceiverKind::Ironwood,
    };
    if actual_kind != expected_kind {
        return Err(ZecPayoutError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn decode_destination(encoded: &str) -> Result<Destination, ZecPayoutError> {
    let parsed =
        ZcashAddress::try_from_encoded(encoded).map_err(|_| ZecPayoutError::InvalidRequest)?;
    if parsed.encode() != encoded {
        return Err(ZecPayoutError::InvalidRequest);
    }
    parsed
        .convert_if_network::<SupportedReceiver>(NetworkType::Test)
        .map(|receiver| receiver.0)
        .map_err(|_| ZecPayoutError::InvalidRequest)
}
