//! Deterministic integer PPLNS weighting and reward conservation.

use std::collections::{BTreeMap, HashSet};

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use thiserror::Error;
use uuid::Uuid;
use wcash_pool_protocol::{TargetLe, MAX_CHAIN_VALUE_ZAT};

/// Defensive launch ceiling for a configured pool fee (10%).
pub const MAX_POOL_FEE_BPS: u16 = 1_000;
const BASIS_POINTS: u64 = 10_000;

/// One unique accepted proof, ordered newest-first by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WeightedShare {
    /// Backend-authenticated share identity.
    pub share_id: [u8; 32],
    /// Stable pool account receiving this share's economic weight.
    pub account_id: Uuid,
    /// Expected hashes represented by the assigned target.
    pub work: BigUint,
}

/// Conserving allocation for one account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountAllocation {
    /// Credited account.
    pub account_id: Uuid,
    /// Work selected from the bounded PPLNS window.
    pub work: BigUint,
    /// Atomic units allocated after the disclosed fee.
    pub amount_zat: u64,
}

/// Complete allocation of one accepted block reward.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationPlan {
    /// Work actually present and selected, which can be smaller than the policy
    /// window while a new pool is bootstrapping.
    pub selected_work: BigUint,
    /// Exact disclosed pool fee in atomic units.
    pub pool_fee_zat: u64,
    /// Miner allocations in stable account-ID order.
    pub accounts: Vec<AccountAllocation>,
}

impl AllocationPlan {
    /// Returns the exact amount assigned to miners.
    pub fn miner_total_zat(&self) -> u64 {
        self.accounts.iter().map(|entry| entry.amount_zat).sum()
    }
}

/// Computes target-derived work as `floor(2^256 / (target + 1))`.
///
/// The backend target is explicitly little-endian. This function does not infer
/// consensus validity; it only gives variable-difficulty shares proportional
/// economic weight without using floating-point arithmetic.
pub fn target_work(target: &TargetLe) -> Result<BigUint, PplnsError> {
    let numeric_target = BigUint::from_bytes_le(target.as_bytes());
    if numeric_target.is_zero() {
        return Err(PplnsError::ZeroTarget);
    }
    Ok((BigUint::one() << 256usize) / (numeric_target + BigUint::one()))
}

/// Selects a newest-first work window and allocates every post-fee atomic unit.
///
/// If the oldest selected share crosses the exact window boundary, only its
/// required fractional work is used. Rewards use largest-remainder allocation;
/// ties are broken by canonical UUID bytes, making replays deterministic.
pub fn allocate_pplns(
    newest_first: &[WeightedShare],
    window_work: &BigUint,
    reward_zat: u64,
    fee_bps: u16,
) -> Result<AllocationPlan, PplnsError> {
    if window_work.is_zero() {
        return Err(PplnsError::ZeroWindow);
    }
    if reward_zat == 0 || reward_zat > MAX_CHAIN_VALUE_ZAT {
        return Err(PplnsError::InvalidReward(reward_zat));
    }
    if fee_bps > MAX_POOL_FEE_BPS {
        return Err(PplnsError::FeeTooHigh(fee_bps));
    }

    let mut remaining = window_work.clone();
    let mut by_account = BTreeMap::<Uuid, BigUint>::new();
    let mut seen = HashSet::with_capacity(newest_first.len());
    for share in newest_first {
        if share.account_id.is_nil() {
            return Err(PplnsError::NilAccount);
        }
        if share.share_id == [0; 32] {
            return Err(PplnsError::ZeroShareId);
        }
        if !seen.insert(share.share_id) {
            return Err(PplnsError::DuplicateShare);
        }
        if share.work.is_zero() {
            return Err(PplnsError::ZeroWork);
        }
        if remaining.is_zero() {
            break;
        }
        let selected = share.work.clone().min(remaining.clone());
        *by_account.entry(share.account_id).or_default() += &selected;
        remaining -= selected;
    }
    if by_account.is_empty() {
        return Err(PplnsError::NoEligibleWork);
    }

    let selected_work: BigUint = by_account.values().cloned().sum();
    let pool_fee_zat = reward_zat
        .checked_mul(u64::from(fee_bps))
        .ok_or(PplnsError::ArithmeticOverflow)?
        / BASIS_POINTS;
    let miner_reward_zat = reward_zat
        .checked_sub(pool_fee_zat)
        .ok_or(PplnsError::ArithmeticOverflow)?;
    let reward = BigUint::from(miner_reward_zat);

    let mut provisional = Vec::with_capacity(by_account.len());
    let mut floor_total = 0u64;
    for (account_id, work) in by_account {
        let numerator = &reward * &work;
        let quotient = &numerator / &selected_work;
        let remainder = numerator % &selected_work;
        let amount_zat = quotient.to_u64().ok_or(PplnsError::ArithmeticOverflow)?;
        floor_total = floor_total
            .checked_add(amount_zat)
            .ok_or(PplnsError::ArithmeticOverflow)?;
        provisional.push((account_id, work, amount_zat, remainder));
    }

    let leftover = miner_reward_zat
        .checked_sub(floor_total)
        .ok_or(PplnsError::ArithmeticOverflow)?;
    let mut remainder_order: Vec<usize> = (0..provisional.len()).collect();
    remainder_order.sort_by(|left, right| {
        provisional[*right]
            .3
            .cmp(&provisional[*left].3)
            .then_with(|| provisional[*left].0.cmp(&provisional[*right].0))
    });
    let leftover_usize = usize::try_from(leftover).map_err(|_| PplnsError::ArithmeticOverflow)?;
    if leftover_usize > remainder_order.len() {
        return Err(PplnsError::ArithmeticOverflow);
    }
    for index in remainder_order.into_iter().take(leftover_usize) {
        provisional[index].2 = provisional[index]
            .2
            .checked_add(1)
            .ok_or(PplnsError::ArithmeticOverflow)?;
    }

    let accounts = provisional
        .into_iter()
        .map(|(account_id, work, amount_zat, _)| AccountAllocation {
            account_id,
            work,
            amount_zat,
        })
        .collect::<Vec<_>>();
    let plan = AllocationPlan {
        selected_work,
        pool_fee_zat,
        accounts,
    };
    if plan.miner_total_zat().checked_add(plan.pool_fee_zat) != Some(reward_zat) {
        return Err(PplnsError::ConservationFailure);
    }
    Ok(plan)
}

/// Invalid PPLNS input or a failure to conserve the reward.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PplnsError {
    /// A share target encoded zero.
    #[error("share target must be nonzero")]
    ZeroTarget,
    /// The configured PPLNS work window was empty.
    #[error("PPLNS work window must be nonzero")]
    ZeroWindow,
    /// The block reward was zero or outside the chain-wide defensive bound.
    #[error("reward {0} is outside the allowed range")]
    InvalidReward(u64),
    /// The fee exceeded the launch safety ceiling.
    #[error("pool fee {0} basis points exceeds the launch ceiling")]
    FeeTooHigh(u16),
    /// No accepted proof was eligible for the winning window.
    #[error("no eligible work exists for this winner")]
    NoEligibleWork,
    /// A worker attribution used a nil account identifier.
    #[error("share attribution contains a nil account")]
    NilAccount,
    /// A share identifier was all zeroes.
    #[error("share identifier must be nonzero")]
    ZeroShareId,
    /// The candidate window contained the same share twice.
    #[error("PPLNS input contains a duplicate share")]
    DuplicateShare,
    /// A selected share represented no work.
    #[error("share work must be nonzero")]
    ZeroWork,
    /// An integer did not fit the bounded monetary representation.
    #[error("PPLNS arithmetic overflowed")]
    ArithmeticOverflow,
    /// An internal allocation failed the exact conservation check.
    #[error("PPLNS allocation did not conserve the reward")]
    ConservationFailure,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn share(id: u8, account: u128, work: u64) -> WeightedShare {
        WeightedShare {
            share_id: [id; 32],
            account_id: Uuid::from_u128(account),
            work: BigUint::from(work),
        }
    }

    #[test]
    fn work_uses_little_endian_target_and_exact_integer_formula() {
        let target = TargetLe::new([0xff; 32]);
        assert_eq!(target_work(&target), Ok(BigUint::one()));

        let mut half = [0xff; 32];
        half[31] = 0x7f;
        assert_eq!(target_work(&TargetLe::new(half)), Ok(BigUint::from(2u8)));
        assert_eq!(
            target_work(&TargetLe::new([0; 32])),
            Err(PplnsError::ZeroTarget)
        );
    }

    #[test]
    fn window_partially_selects_oldest_share_and_conserves_every_unit() {
        let plan = allocate_pplns(
            &[share(1, 1, 70), share(2, 2, 70), share(3, 3, 70)],
            &BigUint::from(100u8),
            1_001,
            100,
        )
        .expect("fixture is valid");
        assert_eq!(plan.selected_work, BigUint::from(100u8));
        assert_eq!(plan.pool_fee_zat, 10);
        assert_eq!(plan.miner_total_zat(), 991);
        assert_eq!(plan.accounts[0].work, BigUint::from(70u8));
        assert_eq!(plan.accounts[1].work, BigUint::from(30u8));
        assert!(plan
            .accounts
            .iter()
            .all(|entry| entry.account_id != Uuid::from_u128(3)));
    }

    #[test]
    fn largest_remainder_is_deterministic_under_ties() {
        let plan = allocate_pplns(
            &[share(1, 2, 1), share(2, 1, 1), share(3, 3, 1)],
            &BigUint::from(3u8),
            2,
            0,
        )
        .expect("fixture is valid");
        assert_eq!(plan.accounts[0].account_id, Uuid::from_u128(1));
        assert_eq!(plan.accounts[0].amount_zat, 1);
        assert_eq!(plan.accounts[1].amount_zat, 1);
        assert_eq!(plan.accounts[2].amount_zat, 0);
    }

    #[test]
    fn repeated_account_aggregates_before_rounding() {
        let plan = allocate_pplns(
            &[share(1, 1, 2), share(2, 2, 3), share(3, 1, 2)],
            &BigUint::from(7u8),
            700,
            0,
        )
        .expect("fixture is valid");
        assert_eq!(plan.accounts.len(), 2);
        assert_eq!(plan.accounts[0].amount_zat, 400);
        assert_eq!(plan.accounts[1].amount_zat, 300);
    }

    #[test]
    fn unsafe_or_ambiguous_inputs_fail_closed() {
        assert_eq!(
            allocate_pplns(&[], &BigUint::one(), 1, 0),
            Err(PplnsError::NoEligibleWork)
        );
        assert_eq!(
            allocate_pplns(&[share(1, 1, 1)], &BigUint::one(), 1, 1_001),
            Err(PplnsError::FeeTooHigh(1_001))
        );
        assert_eq!(
            allocate_pplns(&[share(1, 1, 1), share(1, 1, 1)], &BigUint::from(2u8), 1, 0,),
            Err(PplnsError::DuplicateShare)
        );
    }
}
