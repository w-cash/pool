//! Explicitly endian-typed share targets.

use std::fmt;

use thiserror::Error;
use wcash_pool_protocol::{TargetBe, TargetLe};

/// A non-zero ZIP-301 target in canonical 256-bit big-endian form.
///
/// Larger numeric targets are easier. Backend targets use little-endian bytes,
/// so conversions at that boundary must reverse explicitly.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShareTarget([u8; 32]);

impl ShareTarget {
    /// The easiest representable non-zero target.
    pub const MAX: Self = Self([u8::MAX; 32]);

    /// Parses canonical big-endian bytes inside the core implementation.
    pub(crate) fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, ShareTargetError> {
        if bytes == [0; 32] {
            return Err(ShareTargetError::Zero);
        }
        Ok(Self(bytes))
    }

    /// Parses an explicitly typed ZIP-301 big-endian target.
    pub fn from_zip301(target: &TargetBe) -> Result<Self, ShareTargetError> {
        Self::from_be_bytes(*target.as_bytes())
    }

    /// Parses an explicitly typed backend little-endian target.
    pub fn from_backend(target: &TargetLe) -> Result<Self, ShareTargetError> {
        Self::from_zip301(&TargetBe::from(target))
    }

    /// Returns the canonical ZIP-301 big-endian target wrapper.
    pub fn to_zip301(self) -> TargetBe {
        TargetBe::new(self.0)
    }

    /// Returns the explicitly converted backend little-endian target wrapper.
    pub fn to_backend(self) -> TargetLe {
        TargetLe::from(self.to_zip301())
    }

    /// Returns the harder of two targets.
    pub fn harder(self, other: Self) -> Self {
        self.min(other)
    }

    /// Returns the easier of two targets.
    pub fn easier(self, other: Self) -> Self {
        self.max(other)
    }

    pub(crate) const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_nonzero_be_bytes(bytes: [u8; 32]) -> Self {
        debug_assert!(bytes != [0; 32]);
        Self(bytes)
    }
}

impl TryFrom<&TargetBe> for ShareTarget {
    type Error = ShareTargetError;

    fn try_from(value: &TargetBe) -> Result<Self, Self::Error> {
        Self::from_zip301(value)
    }
}

impl TryFrom<TargetBe> for ShareTarget {
    type Error = ShareTargetError;

    fn try_from(value: TargetBe) -> Result<Self, Self::Error> {
        Self::from_zip301(&value)
    }
}

impl TryFrom<&TargetLe> for ShareTarget {
    type Error = ShareTargetError;

    fn try_from(value: &TargetLe) -> Result<Self, Self::Error> {
        Self::from_backend(value)
    }
}

impl TryFrom<TargetLe> for ShareTarget {
    type Error = ShareTargetError;

    fn try_from(value: TargetLe) -> Result<Self, Self::Error> {
        Self::from_backend(&value)
    }
}

/// Numeric limits for miner share targets on one pair of network templates.
///
/// A share target must be at least as easy as both network targets so no valid
/// Wcash or Zcash winner can be discarded as a low-difficulty pool share. The
/// operator limit is the easiest accepted target and bounds validation load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetBounds {
    wcash_network: ShareTarget,
    zcash_network: ShareTarget,
    hardest_allowed: ShareTarget,
    easiest_allowed: ShareTarget,
}

impl TargetBounds {
    /// Creates limits from big-endian network and operator targets.
    pub fn new(
        wcash_network: ShareTarget,
        zcash_network: ShareTarget,
        operator_easiest: ShareTarget,
    ) -> Result<Self, TargetPolicyError> {
        let hardest_allowed = wcash_network.max(zcash_network);
        if operator_easiest < hardest_allowed {
            return Err(TargetPolicyError::OperatorLimitExcludesNetworkWinner {
                required: hardest_allowed,
                configured: operator_easiest,
            });
        }
        Ok(Self {
            wcash_network,
            zcash_network,
            hardest_allowed,
            easiest_allowed: operator_easiest,
        })
    }

    /// Returns the exact Wcash network target.
    pub const fn wcash_network(self) -> ShareTarget {
        self.wcash_network
    }

    /// Returns the exact Zcash network target.
    pub const fn zcash_network(self) -> ShareTarget {
        self.zcash_network
    }

    /// Returns the numerically smallest valid share target.
    pub const fn hardest_allowed(self) -> ShareTarget {
        self.hardest_allowed
    }

    /// Returns the operator's easiest accepted target.
    pub const fn easiest_allowed(self) -> ShareTarget {
        self.easiest_allowed
    }

    /// Clamps a target into this safe interval.
    pub fn clamp(self, target: ShareTarget) -> ShareTarget {
        target.clamp(self.hardest_allowed, self.easiest_allowed)
    }

    /// Checks whether a target is inside this safe interval.
    pub fn contains(self, target: ShareTarget) -> bool {
        (self.hardest_allowed..=self.easiest_allowed).contains(&target)
    }
}

/// A share target frozen into one miner-session job assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetBinding {
    revision: u64,
    target: ShareTarget,
    bounds: TargetBounds,
}

impl TargetBinding {
    /// Binds a policy revision and target to exact network limits.
    pub fn new(
        revision: u64,
        target: ShareTarget,
        bounds: TargetBounds,
    ) -> Result<Self, TargetPolicyError> {
        if !bounds.contains(target) {
            return Err(TargetPolicyError::OutsideBounds {
                target,
                hardest: bounds.hardest_allowed(),
                easiest: bounds.easiest_allowed(),
            });
        }
        Ok(Self {
            revision,
            target,
            bounds,
        })
    }

    /// Returns the vardiff revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the canonical big-endian share target.
    pub const fn target(self) -> ShareTarget {
        self.target
    }

    /// Returns the exact network and operator bounds used for this job.
    pub const fn bounds(self) -> TargetBounds {
        self.bounds
    }
}

impl fmt::Debug for ShareTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ShareTarget(0x")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// Invalid target encoding.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ShareTargetError {
    /// A zero target can never accept a share.
    #[error("share target must be non-zero")]
    Zero,
}

/// Invalid target-policy relationship.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TargetPolicyError {
    /// The operator ceiling is harder than at least one network target.
    #[error(
        "operator easiest target {configured:?} is harder than required network floor {required:?}"
    )]
    OperatorLimitExcludesNetworkWinner {
        /// Easiest of the two network targets, required as the numeric floor.
        required: ShareTarget,
        /// Invalid configured operator ceiling.
        configured: ShareTarget,
    },
    /// A bound job target is outside the permitted numeric interval.
    #[error("share target {target:?} is outside [{hardest:?}, {easiest:?}]")]
    OutsideBounds {
        /// Invalid share target.
        target: ShareTarget,
        /// Hardest permissible target.
        hardest: ShareTarget,
        /// Easiest permissible target.
        easiest: ShareTarget,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn target(last: u8) -> ShareTarget {
        let mut bytes = [0; 32];
        bytes[31] = last;
        ShareTarget::from_be_bytes(bytes).expect("fixture is non-zero")
    }

    #[test]
    fn numeric_order_matches_big_endian_order() {
        let mut high_limb = [0; 32];
        high_limb[0] = 1;
        let high_limb = ShareTarget::from_be_bytes(high_limb).expect("fixture is non-zero");
        assert!(high_limb > target(u8::MAX));
        assert_eq!(target(1).easier(target(2)), target(2));
        assert_eq!(target(1).harder(target(2)), target(1));
    }

    #[test]
    fn protocol_endian_types_are_explicit_and_round_trip_asymmetrically() {
        let mut big_endian = [0; 32];
        big_endian[0] = 1;
        big_endian[7] = 0x23;
        big_endian[19] = 0xa5;
        big_endian[31] = 2;
        let target =
            ShareTarget::from_zip301(&TargetBe::new(big_endian)).expect("fixture is non-zero");
        let backend = target.to_backend();
        assert_eq!(backend.as_bytes()[0], 2);
        assert_eq!(backend.as_bytes()[12], 0xa5);
        assert_eq!(backend.as_bytes()[24], 0x23);
        assert_eq!(backend.as_bytes()[31], 1);
        assert_eq!(ShareTarget::from_backend(&backend), Ok(target));
        assert_eq!(target.to_zip301().as_bytes(), &big_endian);
    }

    #[test]
    fn zero_is_rejected_in_both_endian_forms() {
        assert_eq!(
            ShareTarget::from_zip301(&TargetBe::new([0; 32])),
            Err(ShareTargetError::Zero)
        );
        assert_eq!(
            ShareTarget::from_backend(&TargetLe::new([0; 32])),
            Err(ShareTargetError::Zero)
        );
    }

    #[test]
    fn bounds_use_the_easier_network_target_as_the_numeric_floor() {
        let bounds = TargetBounds::new(target(2), target(4), target(8))
            .expect("operator ceiling includes both networks");
        assert_eq!(bounds.hardest_allowed(), target(4));
        assert_eq!(bounds.clamp(target(1)), target(4));
        assert_eq!(bounds.clamp(target(6)), target(6));
        assert_eq!(bounds.clamp(target(9)), target(8));
        assert!(!bounds.contains(target(3)));
        assert!(bounds.contains(target(4)));
    }

    #[test]
    fn bounds_reject_an_operator_limit_that_can_hide_winners() {
        assert_eq!(
            TargetBounds::new(target(2), target(4), target(3)),
            Err(TargetPolicyError::OperatorLimitExcludesNetworkWinner {
                required: target(4),
                configured: target(3),
            })
        );
    }

    #[test]
    fn binding_rejects_targets_outside_the_frozen_bounds() {
        let bounds = TargetBounds::new(target(2), target(4), target(8))
            .expect("operator ceiling includes both networks");
        assert!(TargetBinding::new(7, target(4), bounds).is_ok());
        assert!(matches!(
            TargetBinding::new(7, target(3), bounds),
            Err(TargetPolicyError::OutsideBounds { .. })
        ));
        assert!(matches!(
            TargetBinding::new(7, target(9), bounds),
            Err(TargetPolicyError::OutsideBounds { .. })
        ));
    }
}
