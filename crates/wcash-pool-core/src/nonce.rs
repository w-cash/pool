//! Collision-free ZIP-301 session nonce-prefix allocation.

use std::num::NonZeroU8;
use std::sync::Mutex;

use thiserror::Error;
use wcash_pool_protocol::{FixedHex, Hex4};

pub use wcash_pool_protocol::{NoncePrefix, NonceProfile};

const fn capacity(profile: NonceProfile) -> u64 {
    match profile {
        NonceProfile::FourByte => 1u64 << 24,
        NonceProfile::EightByte => 1u64 << 56,
    }
}

/// A nonce namespace from `1..=127` assigned by an external lease authority.
///
/// Construction only validates the namespace identifier. It does not acquire,
/// renew, or fence a distributed lease. Durable orchestration must ensure that
/// two live replicas never hold the same namespace and that a namespace is not
/// reused while mining jobs containing prefixes from its previous lease remain
/// acceptable. A restarted replica must restore the cursor for its exact lease.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NonceNamespaceLease(NonZeroU8);

impl NonceNamespaceLease {
    /// Wraps a namespace granted by durable orchestration.
    pub fn new(namespace: u8) -> Result<Self, NoncePrefixError> {
        let namespace = NonZeroU8::new(namespace).ok_or(NoncePrefixError::ZeroNamespace)?;
        if namespace.get() > 0x7f {
            return Err(NoncePrefixError::NamespaceOutOfRange(namespace.get()));
        }
        Ok(Self(namespace))
    }

    /// Returns the namespace encoded into every prefix under this lease.
    pub const fn namespace(self) -> u8 {
        self.0.get()
    }
}

const fn domain_byte(profile: NonceProfile, lease: NonceNamespaceLease) -> u8 {
    match profile {
        NonceProfile::FourByte => lease.namespace(),
        NonceProfile::EightByte => 0x80 | lease.namespace(),
    }
}

/// Durable next-allocation position for one nonce namespace.
///
/// An active/standby deployment must fence allocators and persist a cursor
/// before exposing any allocation covered by it. Restoring an older cursor can
/// reuse a prefix and is never safe against the same issued mining job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceCursor {
    profile: NonceProfile,
    lease: NonceNamespaceLease,
    next: u64,
}

impl NonceCursor {
    /// Validates a restored next-allocation counter.
    pub fn new(
        profile: NonceProfile,
        lease: NonceNamespaceLease,
        next: u64,
    ) -> Result<Self, NoncePrefixError> {
        if next > capacity(profile) {
            return Err(NoncePrefixError::InvalidCursor { profile, next });
        }
        Ok(Self {
            profile,
            lease,
            next,
        })
    }

    /// Returns the cursor profile.
    pub const fn profile(self) -> NonceProfile {
        self.profile
    }

    /// Returns the namespace lease whose allocation sequence this cursor tracks.
    pub const fn lease(self) -> NonceNamespaceLease {
        self.lease
    }

    /// Returns the counter that will be allocated next.
    pub const fn next(self) -> u64 {
        self.next
    }
}

/// Thread-safe monotonic allocator for one nonce namespace.
///
/// The first prefix byte uses its high bit as the profile discriminator and
/// its low seven bits for the leased namespace. The remaining three or seven
/// bytes are a little-endian counter. This keeps both profiles and all active
/// namespaces disjoint while retaining 24-bit and 56-bit allocation spaces.
/// The seven namespace bits permit at most 127 simultaneously fenced namespaces.
/// The bounded counter preserves an explicit exhausted state without wrapping.
#[derive(Debug)]
pub struct NoncePrefixAllocator {
    profile: NonceProfile,
    lease: NonceNamespaceLease,
    next: Mutex<u64>,
    end_exclusive: u64,
}

impl NoncePrefixAllocator {
    /// Starts the supplied externally leased namespace at counter zero.
    ///
    /// This allocator only serializes threads within this process. It does not
    /// provide distributed fencing. Production must durably reserve `lease`
    /// before construction and persist allocation progress before exposing a
    /// prefix to a miner.
    pub const fn new(profile: NonceProfile, lease: NonceNamespaceLease) -> Self {
        Self {
            profile,
            lease,
            next: Mutex::new(0),
            end_exclusive: capacity(profile),
        }
    }

    /// Restores a cursor after independently acquiring its namespace lease.
    ///
    /// The explicit equality check prevents accidentally restoring one
    /// namespace's counter under another namespace. The external lease
    /// authority remains responsible for exclusive ownership and fencing.
    pub fn restore(
        cursor: NonceCursor,
        lease: NonceNamespaceLease,
    ) -> Result<Self, NoncePrefixError> {
        if cursor.lease != lease {
            return Err(NoncePrefixError::LeaseMismatch {
                cursor_namespace: cursor.lease.namespace(),
                provided_namespace: lease.namespace(),
            });
        }
        Ok(Self {
            profile: cursor.profile,
            lease,
            next: Mutex::new(cursor.next),
            end_exclusive: capacity(cursor.profile),
        })
    }

    /// Restores only a transactionally reserved sub-range of one namespace.
    ///
    /// The durable authority must advance its global cursor to `end_exclusive`
    /// before constructing this allocator. A crash can then waste prefixes but
    /// can never cause another process to reissue them.
    pub fn restore_reserved(
        cursor: NonceCursor,
        lease: NonceNamespaceLease,
        end_exclusive: u64,
    ) -> Result<Self, NoncePrefixError> {
        if cursor.lease != lease {
            return Err(NoncePrefixError::LeaseMismatch {
                cursor_namespace: cursor.lease.namespace(),
                provided_namespace: lease.namespace(),
            });
        }
        if end_exclusive <= cursor.next || end_exclusive > capacity(cursor.profile) {
            return Err(NoncePrefixError::InvalidReservation {
                start: cursor.next,
                end_exclusive,
            });
        }
        Ok(Self {
            profile: cursor.profile,
            lease,
            next: Mutex::new(cursor.next),
            end_exclusive,
        })
    }

    /// Returns the profile allocated by this namespace.
    pub const fn profile(&self) -> NonceProfile {
        self.profile
    }

    /// Returns the externally assigned namespace lease.
    pub const fn lease(&self) -> NonceNamespaceLease {
        self.lease
    }

    /// Allocates the next unique prefix without wrapping.
    pub fn allocate(&self) -> Result<NoncePrefix, NoncePrefixError> {
        let mut next = self.next.lock().map_err(|_| NoncePrefixError::Poisoned)?;
        if *next >= self.end_exclusive {
            return Err(NoncePrefixError::Exhausted(self.profile));
        }
        let value = *next;
        *next += 1;
        Ok(match self.profile {
            NonceProfile::FourByte => {
                let counter = (value as u32).to_le_bytes();
                NoncePrefix::Four(Hex4::new([
                    domain_byte(self.profile, self.lease),
                    counter[0],
                    counter[1],
                    counter[2],
                ]))
            }
            NonceProfile::EightByte => {
                let counter = value.to_le_bytes();
                NoncePrefix::Eight(FixedHex::new([
                    domain_byte(self.profile, self.lease),
                    counter[0],
                    counter[1],
                    counter[2],
                    counter[3],
                    counter[4],
                    counter[5],
                    counter[6],
                ]))
            }
        })
    }

    /// Snapshots the next-allocation cursor while holding the allocator lock.
    pub fn next_cursor(&self) -> Result<NonceCursor, NoncePrefixError> {
        let next = *self.next.lock().map_err(|_| NoncePrefixError::Poisoned)?;
        NonceCursor::new(self.profile, self.lease, next)
    }

    #[cfg(test)]
    #[allow(clippy::expect_used)]
    fn with_next(profile: NonceProfile, lease: NonceNamespaceLease, next: u64) -> Self {
        Self::restore(
            NonceCursor::new(profile, lease, next).expect("test cursor must be valid"),
            lease,
        )
        .expect("test lease must match cursor")
    }
}

/// Nonce namespace allocation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NoncePrefixError {
    /// Namespace zero is reserved and cannot identify an active lease.
    #[error("nonce namespace zero is reserved")]
    ZeroNamespace,
    /// The profile discriminator reserves the high namespace bit.
    #[error("nonce namespace {0} is outside the supported range 1..=127")]
    NamespaceOutOfRange(u8),
    /// Every value in the negotiated prefix width has already been issued.
    #[error("all {0:?} nonce prefixes are exhausted")]
    Exhausted(NonceProfile),
    /// Another thread panicked while holding the allocator lock.
    #[error("nonce-prefix allocator lock is poisoned")]
    Poisoned,
    /// A restored cursor lies beyond its profile namespace.
    #[error("nonce cursor {next} is outside the {profile:?} namespace")]
    InvalidCursor {
        /// Cursor profile.
        profile: NonceProfile,
        /// Invalid next-allocation value.
        next: u64,
    },
    /// A durable cursor was presented under a different namespace lease.
    #[error(
        "nonce cursor namespace {cursor_namespace} does not match provided lease {provided_namespace}"
    )]
    LeaseMismatch {
        /// Namespace stored in the durable cursor.
        cursor_namespace: u8,
        /// Namespace supplied by the current durable lease authority.
        provided_namespace: u8,
    },
    /// A durable range was empty, inverted, or outside the nonce profile.
    #[error("nonce reservation [{start}, {end_exclusive}) is invalid")]
    InvalidReservation {
        /// First prefix reserved for this process.
        start: u64,
        /// Exclusive upper fence persisted before use.
        end_exclusive: u64,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use wcash_pool_protocol::{join_nonce, Hex24, Hex28, NonceSuffix};

    fn lease(namespace: u8) -> NonceNamespaceLease {
        NonceNamespaceLease::new(namespace).expect("test namespace must be nonzero")
    }

    fn prefix_bytes(prefix: &NoncePrefix) -> &[u8] {
        match prefix {
            NoncePrefix::Four(bytes) => bytes.as_bytes(),
            NoncePrefix::Eight(bytes) => bytes.as_bytes(),
        }
    }

    fn prefix_value(prefix: &NoncePrefix) -> u64 {
        match prefix {
            NoncePrefix::Four(bytes) => u64::from(u32::from_le_bytes([
                bytes.as_bytes()[1],
                bytes.as_bytes()[2],
                bytes.as_bytes()[3],
                0,
            ])),
            NoncePrefix::Eight(bytes) => u64::from_le_bytes([
                bytes.as_bytes()[1],
                bytes.as_bytes()[2],
                bytes.as_bytes()[3],
                bytes.as_bytes()[4],
                bytes.as_bytes()[5],
                bytes.as_bytes()[6],
                bytes.as_bytes()[7],
                0,
            ]),
        }
    }

    #[test]
    fn both_profiles_are_little_endian_and_monotonic() {
        for profile in [NonceProfile::FourByte, NonceProfile::EightByte] {
            let allocator = NoncePrefixAllocator::new(profile, lease(17));
            let zero = allocator.allocate().expect("namespace has capacity");
            let one = allocator.allocate().expect("namespace has capacity");
            assert_eq!(prefix_value(&zero), 0);
            assert_eq!(prefix_value(&one), 1);
            assert_eq!(prefix_bytes(&zero)[0], domain_byte(profile, lease(17)));
            assert_eq!(prefix_bytes(&one)[0] & 0x7f, 17);
            assert_eq!(prefix_bytes(&one)[1], 1);
            assert_eq!(prefix_bytes(&one).len(), profile.prefix_bytes());
        }
    }

    #[test]
    fn durable_subrange_exhausts_without_entering_the_next_range() {
        let lease = lease(23);
        let allocator = NoncePrefixAllocator::restore_reserved(
            NonceCursor::new(NonceProfile::FourByte, lease, 41).expect("cursor is in range"),
            lease,
            43,
        )
        .expect("reservation is valid");
        assert_eq!(
            prefix_value(&allocator.allocate().expect("41 is reserved")),
            41
        );
        assert_eq!(
            prefix_value(&allocator.allocate().expect("42 is reserved")),
            42
        );
        assert_eq!(
            allocator.allocate(),
            Err(NoncePrefixError::Exhausted(NonceProfile::FourByte))
        );
    }

    #[test]
    fn allocation_is_collision_free_across_threads() {
        let allocator = NoncePrefixAllocator::new(NonceProfile::EightByte, lease(1));
        let values = std::thread::scope(|scope| {
            let handles = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        (0..1_000)
                            .map(|_| {
                                let prefix = allocator.allocate().expect("namespace has capacity");
                                prefix_value(&prefix)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("allocator thread must not panic"))
                .collect::<Vec<_>>()
        });
        let unique = values.iter().copied().collect::<HashSet<_>>();
        assert_eq!(values.len(), 8_000);
        assert_eq!(unique.len(), values.len());
        assert_eq!(unique.iter().copied().min(), Some(0));
        assert_eq!(unique.iter().copied().max(), Some(7_999));
    }

    #[test]
    fn four_byte_boundary_never_wraps() {
        let last = capacity(NonceProfile::FourByte) - 1;
        let allocator = NoncePrefixAllocator::with_next(NonceProfile::FourByte, lease(1), last);
        assert_eq!(
            prefix_value(&allocator.allocate().expect("last prefix remains")),
            last
        );
        assert_eq!(
            allocator.allocate(),
            Err(NoncePrefixError::Exhausted(NonceProfile::FourByte))
        );
    }

    #[test]
    fn eight_byte_boundary_never_wraps() {
        let last = capacity(NonceProfile::EightByte) - 1;
        let allocator = NoncePrefixAllocator::with_next(NonceProfile::EightByte, lease(1), last);
        assert_eq!(
            prefix_value(&allocator.allocate().expect("last prefix remains")),
            last
        );
        assert_eq!(
            allocator.allocate(),
            Err(NoncePrefixError::Exhausted(NonceProfile::EightByte))
        );
    }

    #[test]
    fn profiles_are_disjoint_for_every_attacker_chosen_suffix() {
        let four = NoncePrefixAllocator::new(NonceProfile::FourByte, lease(1))
            .allocate()
            .expect("namespace has capacity");
        let eight = NoncePrefixAllocator::new(NonceProfile::EightByte, lease(1))
            .allocate()
            .expect("namespace has capacity");
        let four_nonce = join_nonce(&four, &NonceSuffix::TwentyEight(Hex28::new([0x08; 28])))
            .expect("matching protocol types reconstruct");
        let eight_nonce = join_nonce(&eight, &NonceSuffix::TwentyFour(Hex24::new([0x04; 24])))
            .expect("matching protocol types reconstruct");
        assert_eq!(four_nonce.as_bytes()[0], 0x01);
        assert_eq!(eight_nonce.as_bytes()[0], 0x81);
        assert_ne!(four_nonce, eight_nonce);
    }

    #[test]
    fn reconstruction_requires_an_exact_typed_suffix_profile() {
        let four = NoncePrefixAllocator::new(NonceProfile::FourByte, lease(1))
            .allocate()
            .expect("namespace has capacity");
        let suffix = NonceSuffix::TwentyEight(Hex28::new([0x5a; 28]));
        let nonce = join_nonce(&four, &suffix).expect("matching protocol types reconstruct");
        assert_eq!(&nonce.as_bytes()[..4], prefix_bytes(&four));
        assert_eq!(&nonce.as_bytes()[4..], &[0x5a; 28]);
        assert!(join_nonce(&four, &NonceSuffix::TwentyFour(Hex24::new([0; 24]))).is_err());
    }

    #[test]
    fn cursor_round_trip_continues_without_reuse() {
        let active_lease = lease(29);
        let allocator = NoncePrefixAllocator::new(NonceProfile::EightByte, active_lease);
        let first = allocator.allocate().expect("namespace has capacity");
        let cursor = allocator.next_cursor().expect("lock remains healthy");
        assert_eq!(cursor.profile(), NonceProfile::EightByte);
        assert_eq!(cursor.lease(), active_lease);
        assert_eq!(cursor.next(), 1);
        let restored = NoncePrefixAllocator::restore(cursor, active_lease)
            .expect("matching lease restores cursor");
        let second = restored.allocate().expect("namespace has capacity");
        assert_eq!(prefix_value(&first), 0);
        assert_eq!(prefix_value(&second), 1);
        assert_ne!(first, second);
    }

    #[test]
    fn cursor_may_represent_exact_exhaustion_but_not_beyond_it() {
        let capacity = capacity(NonceProfile::FourByte);
        let active_lease = lease(1);
        assert!(NonceCursor::new(NonceProfile::FourByte, active_lease, capacity).is_ok());
        assert_eq!(
            NonceCursor::new(NonceProfile::FourByte, active_lease, capacity + 1),
            Err(NoncePrefixError::InvalidCursor {
                profile: NonceProfile::FourByte,
                next: capacity + 1
            })
        );
    }

    #[test]
    fn zero_namespace_is_rejected_and_restore_requires_the_same_lease() {
        assert_eq!(
            NonceNamespaceLease::new(0),
            Err(NoncePrefixError::ZeroNamespace)
        );
        assert_eq!(
            NonceNamespaceLease::new(128),
            Err(NoncePrefixError::NamespaceOutOfRange(128))
        );
        assert_eq!(
            NonceNamespaceLease::new(u8::MAX),
            Err(NoncePrefixError::NamespaceOutOfRange(u8::MAX))
        );
        let cursor =
            NonceCursor::new(NonceProfile::FourByte, lease(7), 12).expect("cursor is in range");
        assert!(matches!(
            NoncePrefixAllocator::restore(cursor, lease(8)),
            Err(NoncePrefixError::LeaseMismatch {
                cursor_namespace: 7,
                provided_namespace: 8
            })
        ));
    }

    #[test]
    fn namespace_and_profile_domains_are_disjoint() {
        let mut nonces = HashSet::new();
        for profile in [NonceProfile::FourByte, NonceProfile::EightByte] {
            for namespace in [1, 2, 0x7f] {
                let allocator = NoncePrefixAllocator::new(profile, lease(namespace));
                for _ in 0..3 {
                    let prefix = allocator.allocate().expect("namespace has capacity");
                    let suffix = match profile {
                        NonceProfile::FourByte => NonceSuffix::TwentyEight(Hex28::new([0x08; 28])),
                        NonceProfile::EightByte => NonceSuffix::TwentyFour(Hex24::new([0x04; 24])),
                    };
                    let nonce =
                        join_nonce(&prefix, &suffix).expect("matching protocol types reconstruct");
                    assert!(nonces.insert(*nonce.as_bytes()));
                    assert_eq!(prefix_bytes(&prefix)[0] & 0x7f, namespace);
                    assert_eq!(
                        prefix_bytes(&prefix)[0] & 0x80,
                        if profile == NonceProfile::EightByte {
                            0x80
                        } else {
                            0
                        }
                    );
                }
            }
        }
        assert_eq!(nonces.len(), 18);
    }
}
