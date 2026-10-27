//! Greedy group-probing control for the `high_load` sweep. It copies
//! hashbrown's `SwissTable` design (control-byte encoding, group width and
//! scans, hash split, triangular probing), so the two compare at 7/8 load, the
//! most hashbrown accepts. Above that, it is the only greedy arm.

use std::hash::BuildHasher;

use crate::BenchHasher;

/// Control byte of a never-filled slot, in hashbrown's encoding. Live slots
/// hold a 7-bit tag, so only empties have the high bit set.
const EMPTY: u8 = 0xFF;

/// SSE2 group scans. The safe fold compiles to the `pcmpeqb` + `pmovmskb` pair
/// hashbrown's SSE2 backend issues.
#[cfg(all(
    target_feature = "sse2",
    any(target_arch = "x86", target_arch = "x86_64"),
    not(miri)
))]
mod group {
    pub(super) const WIDTH: usize = 16;
    /// Mask bits per lane.
    pub(super) const STRIDE: u32 = 1;
    pub(super) type Mask = u16;

    #[inline]
    pub(super) fn match_tag(group: [u8; WIDTH], tag: u8) -> Mask {
        group.iter().enumerate().fold(0, |mask, (lane, &byte)| {
            mask | (Mask::from(byte == tag) << lane)
        })
    }

    #[inline]
    pub(super) fn match_empty(group: [u8; WIDTH]) -> Mask {
        match_tag(group, super::EMPTY)
    }
}

/// NEON group scans: `cmeq` + `fmov`, as hashbrown's NEON backend issues.
#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little",
    not(miri)
))]
mod group {
    use core::arch::aarch64::{vceq_u8, vcreate_u8, vdup_n_u8, vget_lane_u64, vreinterpret_u64_u8};

    pub(super) const WIDTH: usize = 8;
    /// Mask bits per lane; only each lane's high bit is kept.
    pub(super) const STRIDE: u32 = 8;
    pub(super) type Mask = u64;

    const LANE_MSB: u64 = 0x8080_8080_8080_8080;

    /// A matching lane compares to `0xFF`; keeping one bit of it lets `Lanes`
    /// clear the whole lane at once.
    #[inline]
    pub(super) fn match_tag(group: [u8; WIDTH], tag: u8) -> Mask {
        let group = u64::from_le_bytes(group);
        // SAFETY: this module compiles only when `neon` is enabled for the
        // whole build, so every intrinsic's target feature is present.
        let lanes = unsafe {
            vget_lane_u64::<0>(vreinterpret_u64_u8(vceq_u8(
                vcreate_u8(group),
                vdup_n_u8(tag),
            )))
        };
        lanes & LANE_MSB
    }

    #[inline]
    pub(super) fn match_empty(group: [u8; WIDTH]) -> Mask {
        match_tag(group, super::EMPTY)
    }
}

/// hashbrown's portable SWAR group scans, for targets with neither backend.
#[cfg(not(any(
    all(
        target_feature = "sse2",
        any(target_arch = "x86", target_arch = "x86_64"),
        not(miri)
    ),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little",
        not(miri)
    )
)))]
mod group {
    pub(super) const WIDTH: usize = 8;
    /// Mask bits per lane; only each lane's high bit is ever set.
    pub(super) const STRIDE: u32 = 8;
    pub(super) type Mask = u64;

    const LANE_LSB: u64 = 0x0101_0101_0101_0101;
    const LANE_MSB: u64 = 0x8080_8080_8080_8080;

    /// The borrow trick can also flag the lane above a true match; the key
    /// comparison rejects it.
    #[inline]
    pub(super) fn match_tag(group: [u8; WIDTH], tag: u8) -> Mask {
        let diff = u64::from_le_bytes(group) ^ (LANE_LSB * u64::from(tag));
        diff.wrapping_sub(LANE_LSB) & !diff & LANE_MSB
    }

    #[inline]
    pub(super) fn match_empty(group: [u8; WIDTH]) -> Mask {
        u64::from_le_bytes(group) & LANE_MSB
    }
}

/// Insert-and-lookup table over `(u64, u64)`. It never removes, so it needs no
/// tombstones, and a probe always ends at an empty slot because `max_len`
/// leaves at least one.
#[derive(Clone)]
pub struct GroupProbeMap {
    /// `slots + WIDTH` bytes. The tail mirrors the first `WIDTH`, so a group
    /// load from any start position stays in bounds without wrapping.
    ctrl: Box<[u8]>,
    entries: Box<[(u64, u64)]>,
    mask: usize,
    len: usize,
    max_len: usize,
    hasher: BenchHasher,
}

impl GroupProbeMap {
    /// Panics unless `slots` is a power of two of at least one group and
    /// `max_len < slots`.
    pub fn with_slots(slots: usize, max_len: usize) -> Self {
        assert!(
            slots.is_power_of_two() && slots >= group::WIDTH,
            "slots must be a power of two of at least {}",
            group::WIDTH
        );
        assert!(max_len < slots, "max_len must leave an empty slot");
        Self {
            ctrl: vec![EMPTY; slots + group::WIDTH].into_boxed_slice(),
            entries: vec![(0, 0); slots].into_boxed_slice(),
            mask: slots - 1,
            len: 0,
            max_len,
            hasher: BenchHasher::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The insert budget; fixed, because the table never grows.
    pub fn capacity(&self) -> usize {
        self.max_len
    }

    #[inline]
    pub fn get(&self, key: &u64) -> Option<&u64> {
        let mask = self.mask;
        // Reslicing to `mask + 1` entries lets the compiler drop the bounds
        // check on every tag match.
        let entries = &self.entries[..=mask];
        let (start, tag) = split_hash(self.hasher.hash_one(key), mask);
        let mut probe = Probe::new(start);
        loop {
            let group = load_group(&self.ctrl, probe.pos);
            for lane in Lanes(group::match_tag(group, tag)) {
                let (stored, value) = &entries[(probe.pos + lane) & mask];
                if stored == key {
                    return Some(value);
                }
            }
            if group::match_empty(group) != 0 {
                return None;
            }
            probe.advance(mask);
        }
    }

    /// Returns the replaced value, or `None` for a new key. Panics when a new
    /// key would exceed `max_len`.
    #[inline]
    pub fn insert(&mut self, key: u64, value: u64) -> Option<u64> {
        let mask = self.mask;
        let entries = &mut self.entries[..=mask];
        let (start, tag) = split_hash(self.hasher.hash_one(key), mask);
        let mut probe = Probe::new(start);
        loop {
            let group = load_group(&self.ctrl, probe.pos);
            for lane in Lanes(group::match_tag(group, tag)) {
                let slot = &mut entries[(probe.pos + lane) & mask];
                if slot.0 == key {
                    return Some(std::mem::replace(&mut slot.1, value));
                }
            }
            // No removals: a key absent before the first empty lane on its
            // probe sequence is absent from the table.
            if let Some(lane) = Lanes(group::match_empty(group)).next() {
                assert!(self.len < self.max_len, "GroupProbeMap is full");
                let index = (probe.pos + lane) & mask;
                self.ctrl[index] = tag;
                if index < group::WIDTH {
                    self.ctrl[mask + 1 + index] = tag;
                }
                entries[index] = (key, value);
                self.len += 1;
                return None;
            }
            probe.advance(mask);
        }
    }
}

#[inline]
fn load_group(ctrl: &[u8], pos: usize) -> [u8; group::WIDTH] {
    ctrl[pos..pos + group::WIDTH]
        .try_into()
        .expect("a group is WIDTH bytes")
}

/// The low bits pick the start slot; the top seven bits tag it.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn split_hash(hash: u64, mask: usize) -> (usize, u8) {
    (hash as usize & mask, (hash >> 57) as u8)
}

/// Triangular group probe: strides of 1, 2, 3, ... groups. Over a power-of-two
/// table it visits every group position before repeating.
struct Probe {
    pos: usize,
    stride: usize,
}

impl Probe {
    #[inline]
    fn new(pos: usize) -> Self {
        Self { pos, stride: 0 }
    }

    #[inline]
    fn advance(&mut self, mask: usize) {
        self.stride += group::WIDTH;
        self.pos = (self.pos + self.stride) & mask;
    }
}

/// Lane indices of the set bits in a group mask, lowest first.
struct Lanes(group::Mask);

impl Iterator for Lanes {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let lane = (self.0.trailing_zeros() / group::STRIDE) as usize;
        self.0 &= self.0 - 1;
        Some(lane)
    }
}
