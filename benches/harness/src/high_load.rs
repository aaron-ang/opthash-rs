//! Load points and per-arm constructors for the `high_load` sweep.

use opthash::ReserveFraction;

use crate::{BenchHasher, ElasticHashMap, FunnelHashMap, GroupProbeMap, HashbrownMap};

/// Slot counts: 2^16 stays cache-resident; 2^20 spills past one L3 cluster.
pub const HIGH_LOAD_SLOTS: [usize; 2] = [1 << 16, 1 << 20];
/// Reserve exponents `d`; a point fills `1 - 2^-d` of its slots.
pub const HIGH_LOAD_EXPONENTS: [u32; 4] = [3, 5, 7, 10];
/// `tail_insert` times the last `entries >> TAIL_SHIFT` inserts.
const TAIL_SHIFT: u32 = 6;

/// One `(slots, reserve)` point. Every arm holds `entries()` pairs.
#[derive(Clone, Copy, Debug)]
pub struct LoadPoint {
    pub slots: usize,
    pub reserve: ReserveFraction,
}

impl LoadPoint {
    pub fn new(slots: usize, exponent: u32) -> Self {
        assert!(
            slots.is_power_of_two() && slots >= 1 << 10,
            "sweep slot counts are powers of two of at least 1K"
        );
        let reserve =
            ReserveFraction::from_exponent(exponent).expect("sweep exponents are positive");
        Self { slots, reserve }
    }

    /// The insert budget of `slots` slots at `reserve`.
    pub const fn entries(self) -> usize {
        self.slots - self.reserve.floor_reserved(self.slots)
    }

    pub const fn tail(self) -> usize {
        self.entries() >> TAIL_SHIFT
    }

    /// `{workload}_{size}_{load}`, for example `get_miss_64K_99_9`.
    pub fn group(self, workload: &str) -> String {
        let size = if self.slots >= 1 << 20 {
            format!("{}M", self.slots >> 20)
        } else {
            format!("{}K", self.slots >> 10)
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

    /// Funnel sizes exactly, so its slot count is near `slots`, not equal.
    pub fn funnel(self) -> FunnelHashMap<u64, u64> {
        let map: FunnelHashMap<u64, u64> = FunnelHashMap::with_capacity_and_reserve_and_hasher(
            self.entries(),
            self.reserve,
            BenchHasher::default(),
        );
        assert!(map.capacity() >= self.entries(), "funnel under its point");
        map
    }

    pub fn group_probe(self) -> GroupProbeMap {
        GroupProbeMap::with_slots(self.slots, self.entries())
    }

    /// hashbrown caps load at 7/8, so only a `d = 3` point fits its table.
    pub fn hashbrown(self) -> HashbrownMap<u64, u64> {
        let map: HashbrownMap<u64, u64> = crate::hashbrown_map_cap(self.entries());
        assert_eq!(
            map.capacity(),
            self.entries(),
            "hashbrown cannot hold this point's load"
        );
        map
    }
}
