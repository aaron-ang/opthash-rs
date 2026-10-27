//! Greedy group-probing control for the `high_load` sweep. It copies
//! hashbrown's `SwissTable` design (control-byte layout, group width, hash split,
//! triangular probing) so it can be calibrated against hashbrown at 7/8 load,
//! but drops hashbrown's 7/8 load cap and removal.

use std::hash::BuildHasher;

use crate::BenchHasher;

/// One group of SWAR lanes: 16 under SSE2, 8 elsewhere on 64-bit targets.
#[cfg(all(
    target_feature = "sse2",
    any(target_arch = "x86", target_arch = "x86_64")
))]
type Word = u128;
#[cfg(not(all(
    target_feature = "sse2",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
type Word = u64;

const GROUP: usize = size_of::<Word>();
/// Control byte of a never-filled slot. Live slots hold a 7-bit tag, so the
/// high bit alone marks empties.
const EMPTY: u8 = 0x80;
const LANE_LSB: Word = Word::MAX / 0xFF;
const LANE_MSB: Word = LANE_LSB << 7;

/// Insert-and-lookup table over `(u64, u64)`. It never removes, so it needs no
/// tombstones, and a probe always ends at an empty slot because `max_len`
/// leaves at least one.
#[derive(Clone)]
pub struct GroupProbeMap {
    /// `slots + GROUP` bytes. The tail mirrors the first `GROUP`, so a group
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
            slots.is_power_of_two() && slots >= GROUP,
            "slots must be a power of two of at least {GROUP}"
        );
        assert!(max_len < slots, "max_len must leave an empty slot");
        Self {
            ctrl: vec![EMPTY; slots + GROUP].into_boxed_slice(),
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
        let (start, tag) = split_hash(self.hasher.hash_one(key), self.mask);
        let mut probe = Probe::new(start);
        loop {
            let group = self.group(probe.pos);
            for lane in Lanes(match_tag(group, tag)) {
                let (stored, value) = &self.entries[(probe.pos + lane) & self.mask];
                if stored == key {
                    return Some(value);
                }
            }
            if match_empty(group) != 0 {
                return None;
            }
            probe.advance(self.mask);
        }
    }

    /// Returns the replaced value, or `None` for a new key. Panics when a new
    /// key would exceed `max_len`.
    #[inline]
    pub fn insert(&mut self, key: u64, value: u64) -> Option<u64> {
        let (start, tag) = split_hash(self.hasher.hash_one(key), self.mask);
        let mut probe = Probe::new(start);
        loop {
            let group = self.group(probe.pos);
            for lane in Lanes(match_tag(group, tag)) {
                let slot = &mut self.entries[(probe.pos + lane) & self.mask];
                if slot.0 == key {
                    return Some(std::mem::replace(&mut slot.1, value));
                }
            }
            // No removals: a key absent before the first empty lane on its
            // probe sequence is absent from the table.
            if let Some(lane) = Lanes(match_empty(group)).next() {
                assert!(self.len < self.max_len, "GroupProbeMap is full");
                let index = (probe.pos + lane) & self.mask;
                self.set_ctrl(index, tag);
                self.entries[index] = (key, value);
                self.len += 1;
                return None;
            }
            probe.advance(self.mask);
        }
    }

    #[inline]
    fn group(&self, pos: usize) -> Word {
        let bytes: [u8; GROUP] = self.ctrl[pos..pos + GROUP]
            .try_into()
            .expect("a group is GROUP bytes");
        Word::from_le_bytes(bytes)
    }

    #[inline]
    fn set_ctrl(&mut self, index: usize, tag: u8) {
        self.ctrl[index] = tag;
        if index < GROUP {
            self.ctrl[self.mask + 1 + index] = tag;
        }
    }
}

/// The low bits pick the start slot; the top seven bits tag it.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn split_hash(hash: u64, mask: usize) -> (usize, u8) {
    (hash as usize & mask, (hash >> 57) as u8)
}

/// High bit of every lane equal to `tag`. The borrow trick can also flag the
/// lane above a true match; the key comparison rejects it. Empty lanes never
/// match, because a tag has its high bit clear.
#[inline]
fn match_tag(group: Word, tag: u8) -> Word {
    let diff = group ^ (LANE_LSB * Word::from(tag));
    diff.wrapping_sub(LANE_LSB) & !diff & LANE_MSB
}

#[inline]
fn match_empty(group: Word) -> Word {
    group & LANE_MSB
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
        self.stride += GROUP;
        self.pos = (self.pos + self.stride) & mask;
    }
}

/// Lane indices of the set high bits in a SWAR mask, lowest first.
struct Lanes(Word);

impl Iterator for Lanes {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let lane = (self.0.trailing_zeros() / 8) as usize;
        self.0 &= self.0 - 1;
        Some(lane)
    }
}
