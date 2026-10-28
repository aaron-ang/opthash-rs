//! Load points and per-arm constructors for the `high_load` sweep.

use std::ops::RangeInclusive;

use opthash::ReserveFraction;

use crate::{BenchHasher, ElasticHashMap, FunnelHashMap, GroupProbeMap, HashbrownMap};

/// Slot counts: 2^16 stays cache-resident; 2^20 spills past one L3 cluster.
pub const HIGH_LOAD_SLOTS: [usize; 2] = [1 << 16, 1 << 20];
/// Reserve exponents `d`; a point fills `1 - 2^-d` of its slots.
pub const HIGH_LOAD_EXPONENTS: [u32; 4] = [3, 5, 7, 10];
/// Exponents start at hashbrown's 7/8 cap. Past `d = 10` the load label's one
/// decimal place stops telling points apart.
const EXPONENTS: RangeInclusive<u32> = 3..=10;
/// The smallest table whose tail holds an insert at every exponent.
const MIN_SLOTS: usize = 1 << (*EXPONENTS.end() + 1);

/// One `(slots, reserve)` point. Every arm holds `entries()` pairs.
#[derive(Clone, Copy, Debug)]
pub struct LoadPoint {
    slots: usize,
    reserve: ReserveFraction,
}

impl LoadPoint {
    pub fn new(slots: usize, exponent: u32) -> Self {
        assert!(
            slots.is_power_of_two() && slots >= MIN_SLOTS,
            "sweep slot counts are powers of two of at least {MIN_SLOTS}"
        );
        assert!(
            EXPONENTS.contains(&exponent),
            "sweep exponents run over {EXPONENTS:?}"
        );
        let reserve = ReserveFraction::from_exponent(exponent).expect("exponent is positive");
        Self { slots, reserve }
    }

    /// The insert budget of `slots` slots at `reserve`.
    pub const fn entries(self) -> usize {
        self.slots - self.reserved()
    }

    const fn reserved(self) -> usize {
        self.reserve.floor_reserved(self.slots)
    }

    /// The inserts that fill the last half of the reserve, so the free fraction
    /// falls from 1.5 to 1 times the reserve at every exponent.
    pub const fn tail(self) -> usize {
        self.reserved() / 2
    }

    /// `{workload}_{slots}_{load}`, for example `get_miss_64Ki_99_9`. Slot
    /// counts take binary prefixes, unlike the decimal entry counts elsewhere.
    pub fn group(self, workload: &str) -> String {
        let size = if self.slots >= 1 << 20 {
            format!("{}Mi", self.slots >> 20)
        } else {
            format!("{}Ki", self.slots >> 10)
        };
        let denominator = 1_usize << self.reserve.exponent();
        let tenths = (1000 * (denominator - 1) + denominator / 2) / denominator;
        format!("{workload}_{size}_{}_{}", tenths / 10, tenths % 10)
    }

    /// Elastic rounds to a power of two, so its budget is exactly `entries()`
    /// only when it lands on `slots`.
    pub fn elastic(self) -> ElasticHashMap<u64, u64> {
        let map: ElasticHashMap<u64, u64> = ElasticHashMap::with_capacity_and_reserve_and_hasher(
            self.entries(),
            self.reserve,
            BenchHasher::default(),
        );
        assert_eq!(map.capacity(), self.entries(), "elastic left its point");
        map
    }

    /// Funnel sizes exactly, so its slot count is near `slots`, not equal. Its
    /// budget may round up by a few slots; the check keeps that under an eighth
    /// of the reserve, so its free slots stay near the point's.
    pub fn funnel(self) -> FunnelHashMap<u64, u64> {
        let map: FunnelHashMap<u64, u64> = FunnelHashMap::with_capacity_and_reserve_and_hasher(
            self.entries(),
            self.reserve,
            BenchHasher::default(),
        );
        let spare = map.capacity().checked_sub(self.entries());
        assert!(
            spare.is_some_and(|spare| spare < self.reserved() / 8),
            "funnel left its point"
        );
        map
    }

    pub fn group_probe(self) -> GroupProbeMap {
        GroupProbeMap::with_slots(self.slots, self.entries())
    }

    /// hashbrown caps load at 7/8, so it has no table for a point above that.
    pub fn hashbrown(self) -> Option<HashbrownMap<u64, u64>> {
        if self.entries() > self.slots / 8 * 7 {
            return None;
        }
        let map: HashbrownMap<u64, u64> = crate::hashbrown_map_cap(self.entries());
        assert_eq!(map.capacity(), self.entries(), "hashbrown left its point");
        Some(map)
    }
}
