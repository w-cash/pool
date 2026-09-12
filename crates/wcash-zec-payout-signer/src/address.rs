//! Independent Zcash Testnet destination validation.

use wcash_pool_portal::ReceiverKind;
use zcash_address::{
    unified::{self, Container, Receiver},
    ConversionError, TryFromAddress, ZcashAddress,
};
use zcash_protocol::consensus::NetworkType;

use crate::ZecPayoutError;

struct SupportedReceiver(ReceiverKind);

impl TryFromAddress for SupportedReceiver {
    type Error = ();

    fn try_from_unified(
        _network: NetworkType,
        address: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let receivers = address.items();
        let has_orchard = receivers
            .iter()
            .any(|receiver| matches!(receiver, Receiver::Orchard(_)));
        let has_unknown = receivers
            .iter()
            .any(|receiver| matches!(receiver, Receiver::Unknown { .. }));
        if has_orchard && !has_unknown {
            Ok(Self(ReceiverKind::Ironwood))
        } else {
            Err(ConversionError::User(()))
        }
    }

    fn try_from_transparent_p2pkh(
        _network: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self(ReceiverKind::Transparent))
    }

    fn try_from_transparent_p2sh(
        _network: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self(ReceiverKind::Transparent))
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
    let SupportedReceiver(actual_kind) = parsed
        .convert_if_network::<SupportedReceiver>(NetworkType::Test)
        .map_err(|_| ZecPayoutError::InvalidRequest)?;
    if actual_kind != expected_kind {
        return Err(ZecPayoutError::InvalidRequest);
    }
    Ok(())
}
