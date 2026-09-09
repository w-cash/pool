use std::fmt;

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use uuid::Uuid;

use crate::{error::invalid, ProtocolError};

/// Canonical, lowercase hexadecimal encoding of exactly `N` bytes.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FixedHex<const N: usize>([u8; N]);

/// A canonical 4-byte hexadecimal value.
pub type Hex4 = FixedHex<4>;
/// A canonical 24-byte hexadecimal value.
pub type Hex24 = FixedHex<24>;
/// A canonical 28-byte hexadecimal value.
pub type Hex28 = FixedHex<28>;
/// A canonical 32-byte hexadecimal value.
pub type Hex32 = FixedHex<32>;
/// The exact pre-nonce Zcash header input (108 bytes).
pub type Hex108 = FixedHex<108>;
/// A raw Equihash `(200, 9)` solution without its CompactSize prefix.
pub type Hex1344 = FixedHex<1344>;

/// A 256-bit target encoded least-significant byte first on the backend wire.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TargetLe(Hex32);

impl TargetLe {
    /// Creates a little-endian target from its exact wire bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(Hex32::new(bytes))
    }

    /// Returns the exact little-endian wire bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Returns true when this target encodes zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Removes the endian marker without changing byte order.
    pub fn into_hex(self) -> Hex32 {
        self.0
    }
}

impl fmt::Display for TargetLe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for TargetLe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TargetLe({})", self.0)
    }
}

impl From<Hex32> for TargetLe {
    fn from(value: Hex32) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for TargetLe {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

/// A 256-bit target encoded most-significant byte first on the ZIP-301 wire.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TargetBe(Hex32);

impl TargetBe {
    /// Creates a big-endian target from its exact wire bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(Hex32::new(bytes))
    }

    /// Returns the exact big-endian wire bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Returns true when this target encodes zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Removes the endian marker without changing byte order.
    pub fn into_hex(self) -> Hex32 {
        self.0
    }
}

impl fmt::Display for TargetBe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for TargetBe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TargetBe({})", self.0)
    }
}

impl From<Hex32> for TargetBe {
    fn from(value: Hex32) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for TargetBe {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

impl From<&TargetLe> for TargetBe {
    fn from(value: &TargetLe) -> Self {
        let mut bytes = *value.as_bytes();
        bytes.reverse();
        Self::new(bytes)
    }
}

impl From<TargetLe> for TargetBe {
    fn from(value: TargetLe) -> Self {
        Self::from(&value)
    }
}

impl From<&TargetBe> for TargetLe {
    fn from(value: &TargetBe) -> Self {
        let mut bytes = *value.as_bytes();
        bytes.reverse();
        Self::new(bytes)
    }
}

impl From<TargetBe> for TargetLe {
    fn from(value: TargetBe) -> Self {
        Self::from(&value)
    }
}

impl<const N: usize> FixedHex<N> {
    /// Wraps bytes that are already known to have the required length.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Returns the exact decoded bytes.
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Consumes this value and returns its exact decoded bytes.
    pub const fn into_bytes(self) -> [u8; N] {
        self.0
    }

    /// Returns true when every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Parses exactly `N` bytes from canonical lowercase hexadecimal.
    pub fn parse(encoded: &str) -> Result<Self, ProtocolError> {
        let expected = N
            .checked_mul(2)
            .ok_or_else(|| invalid("hexadecimal value", "encoded length overflowed"))?;
        if encoded.len() != expected {
            return Err(invalid(
                "hexadecimal value",
                format!("must contain exactly {expected} characters"),
            ));
        }
        if !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(
                "hexadecimal value",
                "must use canonical lowercase hexadecimal",
            ));
        }
        let mut bytes = [0; N];
        hex::decode_to_slice(encoded, &mut bytes)
            .map_err(|error| invalid("hexadecimal value", error.to_string()))?;
        Ok(Self(bytes))
    }
}

impl<const N: usize> From<[u8; N]> for FixedHex<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> fmt::Display for FixedHex<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl<const N: usize> fmt::Debug for FixedHex<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if N <= 32 {
            write!(formatter, "FixedHex<{N}>({self})")
        } else {
            write!(formatter, "FixedHex<{N}>([{N} bytes])")
        }
    }
}

impl<const N: usize> Serialize for FixedHex<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedHex<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedHexVisitor<const N: usize>;

        impl<const N: usize> Visitor<'_> for FixedHexVisitor<N> {
            type Value = FixedHex<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "exactly {} lowercase hexadecimal characters",
                    N * 2
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                FixedHex::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(FixedHexVisitor::<N>)
    }
}

/// A UUID encoded only in lowercase hyphenated form.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalUuid(Uuid);

impl CanonicalUuid {
    /// Creates a canonical wire UUID.
    pub const fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the parsed UUID.
    pub const fn get(self) -> Uuid {
        self.0
    }

    /// Returns true when this value is the nil UUID.
    pub const fn is_nil(self) -> bool {
        self.0.is_nil()
    }
}

impl Serialize for CanonicalUuid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.hyphenated().to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let uuid = Uuid::parse_str(&encoded).map_err(de::Error::custom)?;
        if uuid.hyphenated().to_string() != encoded {
            return Err(de::Error::custom(
                "UUID must use canonical lowercase hyphenated encoding",
            ));
        }
        Ok(Self(uuid))
    }
}
