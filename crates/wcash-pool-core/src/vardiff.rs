//! Overflow-safe, integer-only variable share difficulty.

use thiserror::Error;

use crate::{ShareTarget, TargetBinding, TargetBounds, TargetPolicyError};

const BASIS_POINTS: u128 = 10_000;
const MINIMUM_SAMPLE_INTERVALS: u32 = 8;
const MINIMUM_SAMPLE_WINDOW_MS: u64 = 60_000;
const MINIMUM_HYSTERESIS_BPS: u16 = 2_500;
const MAXIMUM_ADJUSTMENT_FACTOR: u32 = 4;

/// Bounded variable-difficulty policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VardiffConfig {
    sample_intervals: u32,
    sample_window_ms: u64,
    hysteresis_bps: u16,
    maximum_adjustment_factor: u32,
    operator_easiest: ShareTarget,
}

impl VardiffConfig {
    /// Validates the timing, hysteresis, step, and load ceiling.
    pub fn new(
        target_interval_ms: u64,
        sample_intervals: u32,
        hysteresis_bps: u16,
        maximum_adjustment_factor: u32,
        operator_easiest: ShareTarget,
    ) -> Result<Self, VardiffError> {
        let sample_window_ms = target_interval_ms
            .checked_mul(u64::from(sample_intervals))
            .ok_or(VardiffError::IntervalOverflow)?;
        if sample_intervals < MINIMUM_SAMPLE_INTERVALS
            || sample_window_ms < MINIMUM_SAMPLE_WINDOW_MS
            || !(MINIMUM_HYSTERESIS_BPS..BASIS_POINTS as u16).contains(&hysteresis_bps)
            || !(1..=MAXIMUM_ADJUSTMENT_FACTOR).contains(&maximum_adjustment_factor)
        {
            return Err(VardiffError::InvalidConfig);
        }
        Ok(Self {
            sample_intervals,
            sample_window_ms,
            hysteresis_bps,
            maximum_adjustment_factor,
            operator_easiest,
        })
    }
}

/// Integer vardiff state bound to exact child and parent network targets.
#[derive(Clone, Debug)]
pub struct VardiffController {
    config: VardiffConfig,
    binding: TargetBinding,
    window_start_ms: Option<u64>,
    observed_intervals: u32,
    last_now_ms: Option<u64>,
}

impl VardiffController {
    /// Creates a controller, safely clamping the initial share target.
    pub fn new(
        config: VardiffConfig,
        wcash_network: ShareTarget,
        zcash_network: ShareTarget,
        initial: ShareTarget,
        initial_revision: u64,
    ) -> Result<Self, VardiffError> {
        let bounds = TargetBounds::new(wcash_network, zcash_network, config.operator_easiest)?;
        let binding = TargetBinding::new(initial_revision, bounds.clamp(initial), bounds)?;
        Ok(Self {
            config,
            binding,
            window_start_ms: None,
            observed_intervals: 0,
            last_now_ms: None,
        })
    }

    /// Returns the exact revision, target, and network bounds for the next job.
    pub const fn binding(&self) -> TargetBinding {
        self.binding
    }

    /// Rebinds the controller after either network template target changes.
    pub fn update_network_targets(
        &mut self,
        wcash_network: ShareTarget,
        zcash_network: ShareTarget,
    ) -> Result<TargetBinding, VardiffError> {
        let bounds = TargetBounds::new(wcash_network, zcash_network, self.config.operator_easiest)?;
        if bounds != self.binding.bounds() {
            let revision = self.next_revision()?;
            self.binding =
                TargetBinding::new(revision, bounds.clamp(self.binding.target()), bounds)?;
            self.reset_sample();
        }
        Ok(self.binding)
    }

    /// Observes one accepted share for the supplied exact job target binding.
    ///
    /// Stale bindings are ignored without altering the timing sample. The result
    /// can only be installed on a new per-session assignment and notification;
    /// existing announced assignments retain their immutable target binding.
    pub fn observe_share(
        &mut self,
        submitted_binding: TargetBinding,
        now_ms: u64,
    ) -> Result<VardiffUpdate, VardiffError> {
        if submitted_binding != self.binding {
            return Ok(VardiffUpdate::IgnoredStaleBinding);
        }
        if self.last_now_ms.is_some_and(|last| now_ms < last) {
            return Err(VardiffError::ClockMovedBackwards);
        }
        self.last_now_ms = Some(now_ms);

        let Some(window_start_ms) = self.window_start_ms else {
            self.window_start_ms = Some(now_ms);
            return Ok(VardiffUpdate::Sampling {
                observed_intervals: 0,
                required_intervals: self.config.sample_intervals,
            });
        };
        self.observed_intervals = self
            .observed_intervals
            .checked_add(1)
            .ok_or(VardiffError::SampleCounterOverflow)?;
        if self.observed_intervals < self.config.sample_intervals {
            return Ok(VardiffUpdate::Sampling {
                observed_intervals: self.observed_intervals,
                required_intervals: self.config.sample_intervals,
            });
        }

        let elapsed_ms = now_ms
            .checked_sub(window_start_ms)
            .ok_or(VardiffError::ClockMovedBackwards)?;
        let expected_ms = u128::from(self.config.sample_window_ms);
        let elapsed = u128::from(elapsed_ms);
        let delta = elapsed.abs_diff(expected_ms);
        let inside_hysteresis =
            delta * BASIS_POINTS <= expected_ms * u128::from(self.config.hysteresis_bps);
        if inside_hysteresis {
            self.reset_sample_at(now_ms);
            return Ok(VardiffUpdate::Unchanged(self.binding));
        }

        let previous = self.binding;
        let raw = scale_target(previous.target(), elapsed_ms, expected_ms);
        let hardest_step = divide_target(
            previous.target(),
            u64::from(self.config.maximum_adjustment_factor),
        );
        let easiest_step = multiply_target(
            previous.target(),
            u64::from(self.config.maximum_adjustment_factor),
        );
        let stepped = raw.clamp(hardest_step, easiest_step);
        let next_target = previous.bounds().clamp(stepped);
        if next_target == previous.target() {
            self.reset_sample_at(now_ms);
            return Ok(VardiffUpdate::Unchanged(previous));
        }
        let revision = self.next_revision()?;
        self.binding = TargetBinding::new(revision, next_target, previous.bounds())?;
        self.reset_sample_at(now_ms);
        Ok(VardiffUpdate::Changed {
            previous,
            current: self.binding,
        })
    }

    /// Advances the sampling clock even when no accepted share arrives.
    ///
    /// Call this once when a binding is advertised and periodically afterward.
    /// A worker that produces no shares past the upper hysteresis boundary is
    /// eased by the same integer scaling, per-adjustment clamp, target bounds,
    /// and immutable revision rules as an accepted-share sample. Calling more
    /// frequently cannot bypass the hysteresis window or adjustment clamp.
    pub fn tick(&mut self, now_ms: u64) -> Result<VardiffUpdate, VardiffError> {
        if self.last_now_ms.is_some_and(|last| now_ms < last) {
            return Err(VardiffError::ClockMovedBackwards);
        }
        self.last_now_ms = Some(now_ms);

        let Some(window_start_ms) = self.window_start_ms else {
            self.window_start_ms = Some(now_ms);
            return Ok(VardiffUpdate::Sampling {
                observed_intervals: self.observed_intervals,
                required_intervals: self.config.sample_intervals,
            });
        };
        let elapsed_ms = now_ms
            .checked_sub(window_start_ms)
            .ok_or(VardiffError::ClockMovedBackwards)?;
        let expected_ms = u128::from(self.config.sample_window_ms);
        let elapsed = u128::from(elapsed_ms);

        // A tick only supplies evidence that the worker is too slow. Do not
        // manufacture a harder target when the elapsed window is short.
        if elapsed <= expected_ms
            || (elapsed - expected_ms) * BASIS_POINTS
                <= expected_ms * u128::from(self.config.hysteresis_bps)
        {
            return Ok(VardiffUpdate::Sampling {
                observed_intervals: self.observed_intervals,
                required_intervals: self.config.sample_intervals,
            });
        }

        let previous = self.binding;
        let raw = scale_target(previous.target(), elapsed_ms, expected_ms);
        let easiest_step = multiply_target(
            previous.target(),
            u64::from(self.config.maximum_adjustment_factor),
        );
        let next_target = previous
            .bounds()
            .clamp(raw.clamp(previous.target(), easiest_step));
        if next_target == previous.target() {
            self.reset_sample_at(now_ms);
            return Ok(VardiffUpdate::Unchanged(previous));
        }
        let revision = self.next_revision()?;
        self.binding = TargetBinding::new(revision, next_target, previous.bounds())?;
        self.reset_sample_at(now_ms);
        Ok(VardiffUpdate::Changed {
            previous,
            current: self.binding,
        })
    }

    fn next_revision(&self) -> Result<u64, VardiffError> {
        self.binding
            .revision()
            .checked_add(1)
            .ok_or(VardiffError::RevisionOverflow)
    }

    fn reset_sample(&mut self) {
        self.window_start_ms = None;
        self.observed_intervals = 0;
    }

    fn reset_sample_at(&mut self, now_ms: u64) {
        self.window_start_ms = Some(now_ms);
        self.observed_intervals = 0;
    }
}

/// Result of one accepted-share timing observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VardiffUpdate {
    /// More accepted-share intervals are needed before retargeting.
    Sampling {
        /// Intervals collected in the current window.
        observed_intervals: u32,
        /// Configured intervals required for a decision.
        required_intervals: u32,
    },
    /// The submitted job carries an obsolete target revision.
    IgnoredStaleBinding,
    /// Hysteresis or target bounds kept the binding unchanged.
    Unchanged(TargetBinding),
    /// A new binding must be advertised on a newly issued job.
    Changed {
        /// Binding used by the measured sample.
        previous: TargetBinding,
        /// Newly calculated binding.
        current: TargetBinding,
    },
}

/// Variable-difficulty policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VardiffError {
    /// At least one timing, sample, hysteresis, or step value is invalid.
    #[error("vardiff configuration is invalid")]
    InvalidConfig,
    /// Target bounds or binding are unsafe.
    #[error(transparent)]
    TargetPolicy(#[from] TargetPolicyError),
    /// Monotonic observation time decreased.
    #[error("vardiff monotonic time moved backwards")]
    ClockMovedBackwards,
    /// Expected timing cannot be represented.
    #[error("vardiff timing interval overflowed")]
    IntervalOverflow,
    /// Observation counter cannot be represented.
    #[error("vardiff sample counter overflowed")]
    SampleCounterOverflow,
    /// A new immutable target revision cannot be represented.
    #[error("vardiff target revision is exhausted")]
    RevisionOverflow,
}

fn scale_target(target: ShareTarget, multiplier: u64, divisor: u128) -> ShareTarget {
    debug_assert!(divisor != 0);
    let product = multiply_limbs(to_little_limbs(target), multiplier);
    from_little_limbs(divide_320_by_128(product, divisor))
}

fn multiply_target(target: ShareTarget, multiplier: u64) -> ShareTarget {
    let product = multiply_limbs(to_little_limbs(target), multiplier);
    if product[4] != 0 {
        ShareTarget::MAX
    } else {
        from_little_limbs([product[0], product[1], product[2], product[3]])
    }
}

fn divide_target(target: ShareTarget, divisor: u64) -> ShareTarget {
    scale_target(target, 1, u128::from(divisor))
}

fn to_little_limbs(target: ShareTarget) -> [u64; 4] {
    let bytes = target.as_be_bytes();
    let mut limbs = [0; 4];
    for (index, chunk) in bytes.rchunks_exact(8).enumerate() {
        let mut limb = [0; 8];
        limb.copy_from_slice(chunk);
        limbs[index] = u64::from_be_bytes(limb);
    }
    limbs
}

fn from_little_limbs(limbs: [u64; 4]) -> ShareTarget {
    let mut bytes = [0; 32];
    for (index, limb) in limbs.into_iter().enumerate() {
        let start = 24 - index * 8;
        bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    if bytes == [0; 32] {
        bytes[31] = 1;
    }
    ShareTarget::from_nonzero_be_bytes(bytes)
}

fn multiply_limbs(limbs: [u64; 4], multiplier: u64) -> [u64; 5] {
    let mut result = [0; 5];
    let mut carry = 0u128;
    for (index, limb) in limbs.into_iter().enumerate() {
        let product = u128::from(limb) * u128::from(multiplier) + carry;
        result[index] = product as u64;
        carry = product >> 64;
    }
    result[4] = carry as u64;
    result
}

fn divide_320_by_128(numerator: [u64; 5], divisor: u128) -> [u64; 4] {
    let mut quotient = [0; 4];
    let mut remainder = 0u128;
    let mut overflow = false;
    for bit_index in (0..320).rev() {
        let input_bit = (numerator[bit_index / 64] >> (bit_index % 64)) & 1;
        let high = remainder >> 127 != 0;
        remainder = (remainder << 1) | u128::from(input_bit);
        if high || remainder >= divisor {
            remainder = remainder.wrapping_sub(divisor);
            if bit_index >= 256 {
                overflow = true;
            } else {
                quotient[bit_index / 64] |= 1u64 << (bit_index % 64);
            }
        }
    }
    if overflow {
        [u64::MAX; 4]
    } else {
        quotient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(value: u8) -> ShareTarget {
        let mut bytes = [0; 32];
        bytes[31] = value;
        ShareTarget::from_nonzero_be_bytes(bytes)
    }

    fn config(
        interval: u64,
        samples: u32,
        hysteresis: u16,
        factor: u32,
        easiest: u8,
    ) -> Result<VardiffConfig, VardiffError> {
        VardiffConfig::new(interval, samples, hysteresis, factor, small(easiest))
    }

    fn target_hex(hex: &str) -> Result<ShareTarget, std::num::ParseIntError> {
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
        }
        Ok(ShareTarget::from_nonzero_be_bytes(bytes))
    }

    fn sample_window(
        controller: &mut VardiffController,
        binding: TargetBinding,
        start_ms: u64,
        interval_ms: u64,
    ) -> Result<VardiffUpdate, VardiffError> {
        controller.observe_share(binding, start_ms)?;
        finish_window(controller, binding, start_ms, interval_ms)
    }

    fn finish_window(
        controller: &mut VardiffController,
        binding: TargetBinding,
        start_ms: u64,
        interval_ms: u64,
    ) -> Result<VardiffUpdate, VardiffError> {
        let mut result = VardiffUpdate::Sampling {
            observed_intervals: 0,
            required_intervals: 8,
        };
        for step in 1..=8 {
            result = controller.observe_share(binding, start_ms + interval_ms * step)?;
        }
        Ok(result)
    }

    #[test]
    fn full_width_scaling_is_exact_and_saturating() -> Result<(), std::num::ParseIntError> {
        assert_eq!(scale_target(small(100), 2, 1), small(200));
        let mut bytes = [0; 32];
        bytes[1] = 0x31;
        bytes[15] = 0xa7;
        bytes[31] = 0x55;
        let wide = ShareTarget::from_nonzero_be_bytes(bytes);
        assert_eq!(scale_target(wide, 7, 7), wide);
        assert_eq!(multiply_target(ShareTarget::MAX, 2), ShareTarget::MAX);
        assert_eq!(scale_target(small(1), 0, 1), small(1));
        let asymmetric =
            target_hex("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080")?;
        assert_eq!(
            multiply_target(asymmetric, 3),
            target_hex("0369d0369d0369cd00336699cd00336699cd00336699ccfd306090c0f1215180")?
        );
        assert_eq!(
            divide_target(asymmetric, 3),
            target_hex("00611722833944a50005b61116c72227d83338e94449fa550560101570202580")?
        );
        assert_eq!(
            scale_target(asymmetric, 17, 13),
            target_hex("017ce49b167e34aeb1517b7e1e484aeb1517b7e1e484aeb001652b67cb91ce31")?
        );
        Ok(())
    }

    #[test]
    fn faster_shares_harden_and_slower_shares_ease_by_integer_ratio() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 250)?,
            small(10),
            small(20),
            small(100),
            7,
        )?;
        let original = controller.binding();
        let VardiffUpdate::Changed { current, .. } =
            sample_window(&mut controller, original, 0, 3_750)?
        else {
            return Err(VardiffError::InvalidConfig);
        };
        assert_eq!(current.target(), small(50));
        let VardiffUpdate::Changed { current, .. } =
            finish_window(&mut controller, current, 30_000, 15_000)?
        else {
            return Err(VardiffError::InvalidConfig);
        };
        assert_eq!(current.target(), small(100));
        Ok(())
    }

    #[test]
    fn hysteresis_keeps_target_and_rotates_the_sample_window() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 250)?,
            small(10),
            small(20),
            small(100),
            1,
        )?;
        let binding = controller.binding();
        assert_eq!(
            sample_window(&mut controller, binding, 0, 8_625)?,
            VardiffUpdate::Unchanged(binding)
        );
        assert!(matches!(
            finish_window(&mut controller, binding, 69_000, 3_750)?,
            VardiffUpdate::Changed { .. }
        ));
        Ok(())
    }

    #[test]
    fn adjustment_and_network_operator_bounds_all_clamp() -> Result<(), VardiffError> {
        let mut hard = VardiffController::new(
            config(7_500, 8, 2_500, 2, 200)?,
            small(40),
            small(60),
            small(100),
            1,
        )?;
        let binding = hard.binding();
        let VardiffUpdate::Changed { current, .. } = sample_window(&mut hard, binding, 0, 1)?
        else {
            return Err(VardiffError::InvalidConfig);
        };
        assert_eq!(current.target(), small(60));

        let mut easy = VardiffController::new(
            config(7_500, 8, 2_500, 4, 150)?,
            small(40),
            small(60),
            small(100),
            1,
        )?;
        let binding = easy.binding();
        let VardiffUpdate::Changed { current, .. } = sample_window(&mut easy, binding, 0, 60_000)?
        else {
            return Err(VardiffError::InvalidConfig);
        };
        assert_eq!(current.target(), small(150));
        Ok(())
    }

    #[test]
    fn stale_binding_does_not_poison_timing_or_clock() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 250)?,
            small(10),
            small(20),
            small(100),
            5,
        )?;
        let binding = controller.binding();
        let stale = TargetBinding::new(4, binding.target(), binding.bounds())?;
        assert_eq!(
            controller.observe_share(stale, 1_000)?,
            VardiffUpdate::IgnoredStaleBinding
        );
        assert!(matches!(
            controller.observe_share(binding, 10)?,
            VardiffUpdate::Sampling { .. }
        ));
        assert_eq!(
            controller.observe_share(binding, 9),
            Err(VardiffError::ClockMovedBackwards)
        );
        Ok(())
    }

    #[test]
    fn inactivity_tick_eases_only_past_upper_hysteresis_boundary() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 250)?,
            small(10),
            small(20),
            small(100),
            11,
        )?;
        let original = controller.binding();
        assert_eq!(
            controller.tick(10_000)?,
            VardiffUpdate::Sampling {
                observed_intervals: 0,
                required_intervals: 8
            }
        );
        assert!(matches!(
            controller.tick(85_000)?,
            VardiffUpdate::Sampling { .. }
        ));
        assert_eq!(controller.binding(), original);

        let VardiffUpdate::Changed { previous, current } = controller.tick(85_001)? else {
            return Err(VardiffError::InvalidConfig);
        };
        assert_eq!(previous, original);
        assert_eq!(current.revision(), 12);
        assert_eq!(current.target(), small(125));
        Ok(())
    }

    #[test]
    fn inactivity_tick_is_step_clamped_and_cannot_rapidly_repeat() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 2, 250)?,
            small(10),
            small(20),
            small(100),
            1,
        )?;
        controller.tick(0)?;
        let VardiffUpdate::Changed { current, .. } = controller.tick(1_000_000)? else {
            return Err(VardiffError::InvalidConfig);
        };
        assert_eq!(current.target(), small(200));
        assert!(matches!(
            controller.tick(1_000_001)?,
            VardiffUpdate::Sampling { .. }
        ));
        assert_eq!(controller.binding(), current);
        Ok(())
    }

    #[test]
    fn inactivity_tick_clamps_at_easiest_bound_without_revision_churn() -> Result<(), VardiffError>
    {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 150)?,
            small(40),
            small(60),
            small(150),
            41,
        )?;
        let binding = controller.binding();
        controller.tick(0)?;
        assert_eq!(
            controller.tick(1_000_000)?,
            VardiffUpdate::Unchanged(binding)
        );
        assert_eq!(controller.binding(), binding);
        assert!(matches!(
            controller.tick(1_000_001)?,
            VardiffUpdate::Sampling { .. }
        ));
        Ok(())
    }

    #[test]
    fn inactivity_tick_is_overflow_safe_and_rejects_backward_clock() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, u8::MAX)?,
            small(1),
            small(2),
            small(3),
            0,
        )?;
        controller.tick(0)?;
        let VardiffUpdate::Changed { current, .. } = controller.tick(u64::MAX)? else {
            return Err(VardiffError::InvalidConfig);
        };
        assert_eq!(current.target(), small(12));
        assert_eq!(
            controller.tick(u64::MAX - 1),
            Err(VardiffError::ClockMovedBackwards)
        );
        Ok(())
    }

    #[test]
    fn inactivity_revision_overflow_fails_closed() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 250)?,
            small(10),
            small(20),
            small(100),
            u64::MAX,
        )?;
        controller.tick(0)?;
        assert_eq!(controller.tick(75_001), Err(VardiffError::RevisionOverflow));
        assert_eq!(controller.binding().target(), small(100));
        Ok(())
    }

    #[test]
    fn network_change_rebinds_and_never_excludes_either_winner() -> Result<(), VardiffError> {
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 250)?,
            small(10),
            small(20),
            small(100),
            9,
        )?;
        let changed = controller.update_network_targets(small(120), small(80))?;
        assert_eq!(changed.revision(), 10);
        assert_eq!(changed.target(), small(120));
        assert_eq!(changed.bounds().hardest_allowed(), small(120));
        assert_eq!(
            controller.update_network_targets(small(120), small(80))?,
            changed
        );
        Ok(())
    }

    #[test]
    fn invalid_configuration_and_revision_overflow_fail_closed() -> Result<(), VardiffError> {
        assert_eq!(
            VardiffConfig::new(0, 8, 2_500, 1, small(200)),
            Err(VardiffError::InvalidConfig)
        );
        assert_eq!(
            VardiffConfig::new(u64::MAX, 8, 2_500, 1, small(200)),
            Err(VardiffError::IntervalOverflow)
        );
        let mut controller = VardiffController::new(
            config(7_500, 8, 2_500, 4, 250)?,
            small(10),
            small(20),
            small(100),
            u64::MAX,
        )?;
        let binding = controller.binding();
        assert_eq!(
            sample_window(&mut controller, binding, 0, 3_750),
            Err(VardiffError::RevisionOverflow)
        );
        Ok(())
    }
}
