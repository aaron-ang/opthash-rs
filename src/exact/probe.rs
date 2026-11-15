//! Reproducible probe randomness and exact discrete formula primitives.

/// A domain in which one exact finite probe word is requested.
///
/// Keeping ordinary levels and each special-array choice distinct prevents an
/// implementation from reusing one counter stream for separate choices.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ProbeDomain {
    /// An ordinary Elastic level used by the dev-only scalar oracle.
    #[cfg(test)]
    ElasticOrdinary {
        /// The zero-based logical level index.
        level: u64,
    },
    /// An ordinary Funnel level.
    FunnelOrdinary {
        /// The zero-based logical level index.
        level: u64,
    },
    /// The primary choice in Funnel's special array.
    FunnelSpecialPrimary,
    /// Choice A when selecting a Funnel special-array fallback.
    FunnelSpecialFallbackChoiceA,
    /// Choice B when selecting a Funnel special-array fallback.
    FunnelSpecialFallbackChoiceB,
}

/// Supplies random words to dev-only scalar probe implementations.
///
/// Implementations must be stable functions of the complete input tuple. In the
/// theorem-level random-oracle ideal, words for distinct tuples are independent
/// and uniform, and `key_hash` is a collision-free identity over logical keys;
/// implementing this trait does not itself establish either property.
#[cfg(test)]
pub(crate) trait ProbeOracle {
    /// Returns one word for a fully domain-separated logical counter tuple.
    ///
    /// `rejection_index` starts at zero and advances only when an exact range
    /// reduction needs another word. Such retries do not advance
    /// `logical_probe_index` and therefore remain part of one logical probe.
    fn word(
        &self,
        key_hash: u64,
        domain: ProbeDomain,
        logical_probe_index: u64,
        rejection_index: u32,
    ) -> u64;
}

/// A seeded, copyable probe-word family for reproducible Elastic probing.
///
/// Every probe word of a key is a term of one double-hashing sequence: the
/// key's folded word plus a sequence index times an odd stride taken from
/// the same word ([`ElasticProbeSequence`]). A level reads the sequence at
/// its own run of indices ([`elastic_level_run`]). It is an engineering
/// random-oracle model only: its outputs are not evidence of statistical
/// independence, and the construction is not cryptographic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CounterPrf {
    seed: u64,
}

/// A library-only, domain-separated Funnel counter permutation.
///
/// The packed counter preserves the paper algorithm's distinct ordinary,
/// primary, and two fallback choices. The construction is deterministic and
/// does not establish the paper's random-oracle assumptions.
///
/// The first word of an ordinary level is the exception: it comes from
/// [`Self::ordinary_multiplier`], not from a counter. Retries in that level
/// and the special arrays draw counter words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FunnelPrf {
    /// The seed plus [`DOMAIN_KIND_LANE`], so preparing a probe is one add
    /// ahead of the fold.
    lane_seed: u64,
    /// [`KEY_FOLD`], held beside the seed so a probe loads the multiplier
    /// instead of building it from immediates.
    fold: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedElasticProbe {
    key: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedFastFunnelProbe {
    /// The key hash plus the oracle's lane seed; counter words derive their
    /// input lane from it.
    keyed: u64,
    key_out: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedFastFunnelDomainProbe {
    key_in: u64,
    key_out: u64,
    counter_base: u64,
}

// Declaration order is layout order, for the level records that embed it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedProbeRange {
    upper: usize,
    rejection_threshold: u64,
}

// Pinned to wyhash final 4.3's default secrets:
// https://github.com/wangyi-fudan/wyhash/blob/e4764a0b637d34d3421a7760affada9288b625a8/wyhash.h#L144-L145
pub(crate) const WYHASH_DEFAULT_SECRET: [u64; 4] = [
    0x2D35_8DCC_AA6C_78A5,
    0x8BB8_4B93_962E_ACC9,
    0x4B33_A62E_D433_D4A3,
    0x4D5A_2DA5_1DE1_AA47,
];

// Fixed separators from SplitMix64's increment and current upstream constants;
// they do not instantiate either generator.
const INITIAL_LANE: u64 = 0x9e37_79b9_7f4a_7c15;
const KEY_LANE: u64 = WYHASH_DEFAULT_SECRET[0];
const DOMAIN_KIND_LANE: u64 = WYHASH_DEFAULT_SECRET[1];
const ELASTIC_LEVEL_SHIFT: u32 = 16;
const ELASTIC_LOGICAL_SHIFT: u32 = 3;
const ELASTIC_REJECTION_MASK: u32 = (1 << ELASTIC_LOGICAL_SHIFT) - 1;
/// Odd multiplier that folds an Elastic signature into its probe origin.
pub(crate) const ELASTIC_FOLD_MULTIPLIER: u64 = WYHASH_DEFAULT_SECRET[2] | 1;
const ELASTIC_LEVEL_COUNT: usize = 1 << 5;
pub(crate) const ELASTIC_LEVEL_LIMIT: u64 = ELASTIC_LEVEL_COUNT as u64;
pub(crate) const ELASTIC_LOGICAL_LIMIT: u64 = 1 << 13;
/// Low bits of a sequence index, which hold its level.
const ELASTIC_RUN_LEVEL_BITS: u32 = ELASTIC_LEVEL_COUNT.trailing_zeros();
const ELASTIC_RUN_LEVEL_MASK: u32 = (1 << ELASTIC_RUN_LEVEL_BITS) - 1;
/// A first index stays in the lower half of `u32`.
const ELASTIC_RUN_FIRST_MASK: u32 = u32::MAX >> 1;
/// A step's odd factor is narrow enough that the last logical probe of a
/// run adds less than the other half.
const ELASTIC_RUN_UNIT_MASK: u32 =
    (1 << (u32::BITS - 1 - ELASTIC_LOGICAL_LIMIT.trailing_zeros() - ELASTIC_RUN_LEVEL_BITS)) - 1;
/// `(first index, step)` of each level's run of sequence indices; see
/// [`elastic_level_run`].
///
/// A first index carries its level in the low bits and a step is a multiple
/// of the level count, so the step never touches those bits: no two
/// `(level, probe)` pairs share an index. The remaining bits come from the
/// level's mixed word, which gives every level its own step and its own
/// offset along the sequence. Level zero starts at index zero, so its first
/// probe is the origin.
///
/// Both are narrow enough that a run never wraps `u32`, so a level's words
/// are themselves an arithmetic progression: consecutive probes differ by
/// the sequence's stride times the level's step.
#[allow(clippy::cast_possible_truncation)]
const ELASTIC_LEVEL_RUNS: [(u32, u32); ELASTIC_LEVEL_COUNT] = {
    let mut runs = [(0, 0); ELASTIC_LEVEL_COUNT];
    let mut level = 0;
    while level < runs.len() {
        let mixed = mix64(level as u64 ^ INITIAL_LANE);
        let first = if level == 0 {
            0
        } else {
            (mixed as u32 & ELASTIC_RUN_FIRST_MASK & !ELASTIC_RUN_LEVEL_MASK) | level as u32
        };
        let odd_units = ((mixed >> u32::BITS) as u32 & ELASTIC_RUN_UNIT_MASK) | 1;
        runs[level] = (first, odd_units << ELASTIC_RUN_LEVEL_BITS);
        level += 1;
    }
    runs
};
const _: () = assert!(
    ELASTIC_RUN_FIRST_MASK as u64
        + (ELASTIC_LOGICAL_LIMIT - 1) * ((ELASTIC_RUN_UNIT_MASK as u64) << ELASTIC_RUN_LEVEL_BITS)
        <= u32::MAX as u64
);
const ELASTIC_REJECTION_LIMIT: u32 = 1 << ELASTIC_LOGICAL_SHIFT;
/// Random words both backends spend per rejection-sampled probe before the
/// deterministic fallback.
pub(crate) const RANGE_WORD_CAP: u32 = 8;
const _: () = assert!(RANGE_WORD_CAP <= ELASTIC_REJECTION_LIMIT);
const FUNNEL_LEVEL_LIMIT: u64 = 1 << 46;
const FUNNEL_LOGICAL_LIMIT: u64 = 1 << 8;
const FUNNEL_REJECTION_LIMIT: u32 = 1 << 8;

impl CounterPrf {
    /// Creates a deterministic counter mixer with `seed`.
    #[must_use]
    pub(crate) const fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Keys the hash without a finaliser: the routing signature is the keyed
    /// hash itself, and the probe words fold it once per operation.
    #[inline]
    pub(crate) const fn prepare_elastic(self, key_hash: u64) -> PreparedElasticProbe {
        PreparedElasticProbe {
            key: key_hash ^ self.seed,
        }
    }
}

impl FunnelPrf {
    /// Creates the deterministic Funnel counter permutation for `seed`.
    #[must_use]
    pub(crate) const fn new(seed: u64) -> Self {
        Self {
            lane_seed: seed.wrapping_add(DOMAIN_KIND_LANE),
            fold: KEY_FOLD,
        }
    }

    /// The oracle for a seed `step` past this one.
    #[must_use]
    pub(crate) const fn reseeded(self, step: u64) -> Self {
        Self {
            lane_seed: self.lane_seed.wrapping_add(step),
            fold: self.fold,
        }
    }

    /// The key hash whose folded word is zero. Every level whose bucket
    /// count is not a power of two rejects that first word.
    #[cfg(test)]
    pub(crate) const fn zero_word_hash(self) -> u64 {
        self.lane_seed.wrapping_neg()
    }

    #[inline]
    pub(crate) fn prepare(self, key_hash: u64) -> PreparedFastFunnelProbe {
        let keyed = key_hash.wrapping_add(self.lane_seed);
        PreparedFastFunnelProbe {
            keyed,
            key_out: folded_multiply(keyed, self.fold),
        }
    }

    /// Odd multiplier that turns a key's folded word into its first random
    /// word in ordinary level `level`.
    pub(crate) const fn ordinary_multiplier(level: u64) -> Option<u64> {
        match Self::ordinary_counter_base(level) {
            Some(counter_base) => Some(mix64(counter_base ^ INITIAL_LANE) | 1),
            None => None,
        }
    }

    pub(crate) const fn ordinary_counter_base(level: u64) -> Option<u64> {
        try_pack_funnel_counter(ProbeDomain::FunnelOrdinary { level }, 0, 0)
    }
}

#[cfg(test)]
impl ProbeOracle for CounterPrf {
    fn word(
        &self,
        key_hash: u64,
        domain: ProbeDomain,
        logical_probe_index: u64,
        rejection_index: u32,
    ) -> u64 {
        let ProbeDomain::ElasticOrdinary { level } = domain else {
            panic!("Elastic counter permutation used with a different domain");
        };
        assert!(
            try_pack_elastic_counter(level, logical_probe_index, rejection_index).is_some(),
            "Elastic counter tuple exceeds its checked library encoding"
        );
        self.specified_word(key_hash, level, logical_probe_index, rejection_index)
    }
}

/// The Elastic word family written out from its definition in wide
/// arithmetic, sharing no step with [`PreparedElasticProbe`]'s production
/// words, which the tests hold against it.
#[cfg(test)]
impl CounterPrf {
    fn specified_word(
        self,
        key_hash: u64,
        level: u64,
        logical_probe_index: u64,
        rejection_index: u32,
    ) -> u64 {
        const WORD: u128 = 1 << u64::BITS;
        let multiplier = WYHASH_DEFAULT_SECRET[2] | 1;
        let signature = u128::from(key_hash ^ self.seed ^ multiplier);
        let product = signature * u128::from(multiplier);
        let origin = (((product % WORD) ^ (product / WORD)) * u128::from(multiplier)) % WORD;
        let half = 1_u128 << u32::BITS;
        let stride = (((origin % half) * half) + origin / half) | 1;
        let mut mixed = level ^ 0x9e37_79b9_7f4a_7c15;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^= mixed >> 31;
        let mixed = u128::from(mixed);
        let first_index = if level == 0 {
            0
        } else {
            (mixed % (half / 2)) / 32 * 32 + u128::from(level)
        };
        let step = ((mixed / half) % 8_192) / 2 * 64 + 32;
        let sequence_index = first_index + u128::from(logical_probe_index) * step;
        let first =
            u64::try_from((origin + sequence_index * stride) % WORD).expect("reduced to one word");
        if rejection_index == 0 {
            return first;
        }
        let mut mixed = first ^ u64::from(rejection_index);
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }
}

#[cfg(test)]
impl ProbeOracle for FunnelPrf {
    fn word(
        &self,
        key_hash: u64,
        domain: ProbeDomain,
        logical_probe_index: u64,
        rejection_index: u32,
    ) -> u64 {
        if let ProbeDomain::FunnelOrdinary { level } = domain
            && logical_probe_index == 0
            && rejection_index == 0
        {
            let multiplier = Self::ordinary_multiplier(level)
                .expect("Funnel level exceeds its checked library encoding");
            return self.prepare(key_hash).ordinary_first_word(multiplier);
        }
        let counter = try_pack_funnel_counter(domain, logical_probe_index, rejection_index)
            .expect("Funnel counter tuple exceeds its checked library encoding");
        self.prepare(key_hash).word_from_counter(counter)
    }
}

#[cfg(test)]
impl ProbeOracle for PreparedElasticProbe {
    fn word(
        &self,
        _key_hash: u64,
        domain: ProbeDomain,
        logical_probe_index: u64,
        rejection_index: u32,
    ) -> u64 {
        let ProbeDomain::ElasticOrdinary { level } = domain else {
            panic!("prepared Elastic probe used with a different domain");
        };
        let counter = try_pack_elastic_counter(level, logical_probe_index, rejection_index)
            .expect("Elastic counter tuple exceeds its checked library encoding");
        self.word_from_packed(counter)
    }
}

impl PreparedElasticProbe {
    #[inline]
    pub(crate) const fn routing_signature(self) -> u64 {
        self.key
    }

    /// The key's probe sequence, folding its signature with
    /// `fold_multiplier`, which must be [`ELASTIC_FOLD_MULTIPLIER`]. A table
    /// passes its stored copy so the fold reads the constant instead of
    /// building it.
    ///
    /// The origin and stride are the key's only probe state, so every level's
    /// probes lie on the one sequence `origin + index * stride`
    /// ([`ElasticProbeSequence`]).
    ///
    /// The signature is xored with the multiplier before the multiply. A
    /// zero factor folds to a zero origin and a stride of one, whose words
    /// all reduce to slot zero; the xor moves that factor from the zero
    /// signature, which an identity hasher gives the key zero, to the
    /// multiplier's own value.
    ///
    /// The fold is multiplied once more. Both halves of the product are
    /// close to linear in the signature, so signatures in arithmetic
    /// progression, such as keys that differ only in their high bits, would
    /// otherwise start on a lattice of level-zero slots; the second multiply
    /// carries every bit of the fold into the top of the origin.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    pub(crate) const fn sequence(self, fold_multiplier: u64) -> ElasticProbeSequence {
        debug_assert!(fold_multiplier == ELASTIC_FOLD_MULTIPLIER);
        let product = (self.key ^ fold_multiplier) as u128 * fold_multiplier as u128;
        let folded = (product as u64) ^ (product >> u64::BITS) as u64;
        let origin = folded.wrapping_mul(fold_multiplier);
        ElasticProbeSequence {
            origin,
            stride: origin.rotate_left(u32::BITS) | 1,
        }
    }

    /// Word `rejection_index` of the logical probe `counter` packs. Retries
    /// past the first word remix it with their index.
    #[allow(clippy::cast_lossless)]
    #[inline]
    const fn word_from_packed(self, counter: u32) -> u64 {
        let first = self
            .sequence(ELASTIC_FOLD_MULTIPLIER)
            .word(elastic_sequence_index(
                elastic_counter_level(counter),
                elastic_counter_logical(counter),
            ));
        let rejection_index = counter & ELASTIC_REJECTION_MASK;
        if rejection_index == 0 {
            first
        } else {
            mix64(first ^ rejection_index as u64)
        }
    }

    #[inline]
    const fn word_from_counter_base(self, counter_base: u32, rejection_index: u32) -> u64 {
        debug_assert!(counter_base & ELASTIC_REJECTION_MASK == 0);
        debug_assert!(rejection_index < ELASTIC_REJECTION_LIMIT);
        self.word_from_packed(counter_base | rejection_index)
    }
}

/// One key's Elastic probe words: the double-hashing sequence
/// `origin + index * stride`, which every level reads at its own run of
/// indices ([`elastic_level_run`]).
///
/// The origin and stride are all a key contributes, so its probe words are
/// related in two ways the paper's independent draws are not.
///
/// Within a level, consecutive probes differ by one word distance, the
/// stride times the level's step. A key for which a small multiple of that
/// distance is close to a whole number of turns of the level revisits slots
/// it has already probed, and so sees fewer distinct slots than independent
/// draws would.
///
/// Across levels, every level's words come from the same two values. Each
/// level multiplies the stride by its own step, so a key that revisits slots
/// in one level is not bound to in the next. The exception is a stride so
/// small that no step carries it out of one slot: an origin whose low half
/// is zero and whose high half is small stays in slot zero of every level
/// the stride cannot cross. The signature equal to the fold multiplier is
/// the one such key an identity hasher reaches directly; its origin is zero
/// and its stride one. Two keys with the same origin share every probe;
/// that takes a collision of the fold.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ElasticProbeSequence {
    /// Word at sequence index zero, the key's level-zero first probe: both
    /// halves of the signature's product with the fold multiplier, folded
    /// together and multiplied again.
    origin: u64,
    /// Odd distance between the words of consecutive indices. Its high half
    /// is the origin's low half, which the top bits that pick a level-zero
    /// slot do not reach.
    stride: u64,
}

impl ElasticProbeSequence {
    /// First random word of the probe at `sequence_index`
    /// ([`elastic_sequence_index`]).
    #[allow(clippy::cast_lossless)]
    #[inline]
    pub(crate) const fn word(self, sequence_index: u32) -> u64 {
        self.origin
            .wrapping_add((sequence_index as u64).wrapping_mul(self.stride))
    }

    /// First random word of `level`'s first logical probe, and the distance
    /// from each of the level's probes to its next.
    #[allow(clippy::cast_lossless)]
    #[inline]
    pub(crate) const fn level_words(self, level: usize) -> (u64, u64) {
        let (first, step) = elastic_level_run(level);
        (self.word(first), (step as u64).wrapping_mul(self.stride))
    }
}

impl PreparedFastFunnelProbe {
    #[cfg(test)]
    pub(crate) fn prepare_domain(
        self,
        domain: ProbeDomain,
    ) -> Option<PreparedFastFunnelDomainProbe> {
        let counter_base = try_pack_funnel_counter(domain, 0, 0)?;
        Some(self.prepare_counter_base(counter_base))
    }

    /// Input lane of the counter words: the key hash plus the seed and
    /// [`KEY_LANE`].
    #[inline]
    const fn key_in(self) -> u64 {
        self.keyed
            .wrapping_sub(DOMAIN_KIND_LANE)
            .wrapping_add(KEY_LANE)
    }

    /// Occupied control byte of the key, from the low bits of its folded
    /// word. A bucket draw reads the top of that word times an odd
    /// multiplier, which leaves these bits uniform among the keys sharing a
    /// bucket. The word follows the seed, so a reseed changes the byte.
    #[inline]
    pub(crate) const fn fingerprint(self) -> u8 {
        crate::raw::control::control_fingerprint_low(self.key_out)
    }

    #[inline]
    const fn ordinary_first_word(self, multiplier: u64) -> u64 {
        self.key_out.wrapping_mul(multiplier)
    }

    #[inline]
    pub(crate) const fn prepare_counter_base(
        self,
        counter_base: u64,
    ) -> PreparedFastFunnelDomainProbe {
        PreparedFastFunnelDomainProbe {
            key_in: self.key_in(),
            key_out: self.key_out,
            counter_base,
        }
    }
}

impl PreparedFastFunnelDomainProbe {
    #[inline]
    fn word_from_indices(self, logical_probe_index: u8, rejection_index: u8) -> u64 {
        let counter =
            self.counter_base | (u64::from(logical_probe_index) << 8) | u64::from(rejection_index);
        mix64(counter ^ self.key_in) ^ self.key_out
    }

    #[cfg(test)]
    fn word(self, logical_probe_index: u64, rejection_index: u32) -> u64 {
        assert!(
            logical_probe_index < FUNNEL_LOGICAL_LIMIT,
            "Funnel logical probe exceeds its checked counter encoding"
        );
        assert!(
            rejection_index < FUNNEL_REJECTION_LIMIT,
            "Funnel rejection retry exceeds its checked counter encoding"
        );
        self.word_from_indices(
            u8::try_from(logical_probe_index).expect("checked logical probe must fit"),
            u8::try_from(rejection_index).expect("checked rejection retry must fit"),
        )
    }
}

/// Packs one production Elastic request into a collision-free narrow counter.
///
/// Bits 16..=20 hold the level, bits 3..=15 the logical probe, and bits
/// 0..=2 the exact-reduction retry. Unsupported tuples fail instead of
/// truncating.
#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn try_pack_elastic_counter(
    level: u64,
    logical_probe_index: u64,
    rejection_index: u32,
) -> Option<u32> {
    if level >= ELASTIC_LEVEL_LIMIT
        || logical_probe_index >= ELASTIC_LOGICAL_LIMIT
        || rejection_index >= ELASTIC_REJECTION_LIMIT
    {
        return None;
    }
    Some(elastic_counter_base(level as u32, logical_probe_index) | rejection_index)
}

#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn elastic_counter_base(level: u32, logical_probe_index: u64) -> u32 {
    debug_assert!((level as u64) < ELASTIC_LEVEL_LIMIT);
    debug_assert!(logical_probe_index < ELASTIC_LOGICAL_LIMIT);
    (level << ELASTIC_LEVEL_SHIFT) | ((logical_probe_index as u32) << ELASTIC_LOGICAL_SHIFT)
}

/// Logical probe index a packed counter holds.
#[inline]
const fn elastic_counter_logical(counter: u32) -> u64 {
    ((counter & ((1 << ELASTIC_LEVEL_SHIFT) - 1)) >> ELASTIC_LOGICAL_SHIFT) as u64
}

/// `(first index, step)` of `level`'s run of sequence indices: logical probe
/// `j` of the level reads the key's sequence at `first + j * step`, which
/// stays inside `u32`.
#[inline]
pub(crate) const fn elastic_level_run(level: usize) -> (u32, u32) {
    ELASTIC_LEVEL_RUNS[level % ELASTIC_LEVEL_COUNT]
}

/// Position of logical probe `logical_probe_index` of `level` in a key's
/// probe sequence.
#[allow(clippy::cast_possible_truncation)]
#[inline]
pub(crate) const fn elastic_sequence_index(level: u32, logical_probe_index: u64) -> u32 {
    debug_assert!((level as u64) < ELASTIC_LEVEL_LIMIT);
    debug_assert!(logical_probe_index < ELASTIC_LOGICAL_LIMIT);
    let (first, step) = elastic_level_run(level as usize);
    first + logical_probe_index as u32 * step
}

/// `(level, logical probe)` of the probe at `sequence_index`.
pub(crate) const fn elastic_sequence_coordinates(sequence_index: u32) -> (u32, u64) {
    let level = sequence_index & ELASTIC_RUN_LEVEL_MASK;
    let (first, step) = elastic_level_run(level as usize);
    (level, ((sequence_index - first) / step) as u64)
}

#[inline]
pub(crate) const fn elastic_counter_level(counter: u32) -> u32 {
    (counter >> ELASTIC_LEVEL_SHIFT) & 0x1f
}

/// Packs one Funnel request into a collision-free library counter.
///
/// The encoding reserves two high bits for the four Funnel domains, 46 bits
/// for an ordinary level, and eight bits each for the logical probe and exact
/// range-reduction retry. Unsupported domains or out-of-range values fail
/// instead of truncating.
const fn try_pack_funnel_counter(
    domain: ProbeDomain,
    logical_probe_index: u64,
    rejection_index: u32,
) -> Option<u64> {
    if logical_probe_index >= FUNNEL_LOGICAL_LIMIT || rejection_index >= FUNNEL_REJECTION_LIMIT {
        return None;
    }
    let (tag, level) = match domain {
        ProbeDomain::FunnelOrdinary { level } if level < FUNNEL_LEVEL_LIMIT => (0_u64, level),
        ProbeDomain::FunnelSpecialPrimary => (1, 0),
        ProbeDomain::FunnelSpecialFallbackChoiceA => (2, 0),
        ProbeDomain::FunnelSpecialFallbackChoiceB => (3, 0),
        ProbeDomain::FunnelOrdinary { .. } => return None,
        #[cfg(test)]
        ProbeDomain::ElasticOrdinary { .. } => return None,
    };
    Some((tag << 62) | (level << 16) | (logical_probe_index << 8) | rejection_index as u64)
}

/// Counter bases of the three Funnel special-array domains: the domain tag
/// alone, since their level and starting indices are zero. Fixed by the
/// encoding, so the walks start from them without a fallible pack.
pub(crate) const FUNNEL_SPECIAL_PRIMARY_BASE: u64 =
    funnel_special_base(ProbeDomain::FunnelSpecialPrimary);
pub(crate) const FUNNEL_SPECIAL_FALLBACK_A_BASE: u64 =
    funnel_special_base(ProbeDomain::FunnelSpecialFallbackChoiceA);
pub(crate) const FUNNEL_SPECIAL_FALLBACK_B_BASE: u64 =
    funnel_special_base(ProbeDomain::FunnelSpecialFallbackChoiceB);

const fn funnel_special_base(domain: ProbeDomain) -> u64 {
    match try_pack_funnel_counter(domain, 0, 0) {
        Some(base) => base,
        None => panic!("Funnel special domains fit their counter encoding"),
    }
}

impl PreparedProbeRange {
    pub(crate) const fn empty() -> Self {
        Self {
            upper: 0,
            rejection_threshold: 0,
        }
    }

    /// A range with no index, which rejects every word.
    pub(crate) const fn rejecting() -> Self {
        Self {
            upper: 0,
            rejection_threshold: u64::MAX,
        }
    }

    pub(crate) fn new(upper: usize) -> Result<Self, RangeReductionError> {
        if upper == 0 {
            return Err(RangeReductionError::ZeroUpperBound);
        }
        let upper_word = upper as u64;
        Ok(Self {
            upper,
            rejection_threshold: upper_word.wrapping_neg() % upper_word,
        })
    }
}

/// One exact range-reduction result and its random-word cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProbeIndex {
    /// The sampled index in `[0, upper)`.
    pub index: usize,
    /// The number of oracle words consumed by this one logical probe.
    pub random_word_count: u32,
}

/// A failure to reduce oracle words to an exact bounded index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RangeReductionError {
    /// The requested range `[0, upper)` was empty.
    ZeroUpperBound,
    /// Every permitted oracle word fell in the exact algorithm's rejection
    /// interval.
    RejectionLimitExceeded {
        /// The number of rejected words consumed before returning.
        random_word_count: u32,
    },
}

/// Samples an unbiased index in `[0, upper)` with multiply-high and rejection.
///
/// For a uniform 64-bit word, the high half of `word * upper` supplies the
/// candidate. Rejecting low halves below `2^64 mod upper` removes the short
/// residue classes, leaving exactly the same number of accepted source words
/// for every output index. A low half equal to the threshold is accepted.
/// Consequently, exact unbiasedness remains conditional on the oracle
/// supplying uniform words for distinct retry tuples.
///
/// `max_random_words` explicitly bounds adversarial rejection. Passing zero is
/// permitted and immediately returns
/// [`RangeReductionError::RejectionLimitExceeded`] for a non-empty range.
/// Retry words increment only `rejection_index`; they do not create additional
/// logical probes.
///
/// Callers must surface a rejection-limit error, not recover by modulo
/// reduction, by resetting the retry counter, or by treating the failure as a
/// new logical probe.
///
/// # Errors
///
/// Returns [`RangeReductionError::ZeroUpperBound`] when `upper == 0`, or
/// [`RangeReductionError::RejectionLimitExceeded`] after consuming the allowed
/// number of words without accepting one.
#[cfg(test)]
pub(crate) fn unbiased_probe_index<O: ProbeOracle + ?Sized>(
    oracle: &O,
    key_hash: u64,
    domain: ProbeDomain,
    logical_probe_index: u64,
    upper: usize,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    reduce_probe_words(upper, max_random_words, |rejection_index| {
        oracle.word(key_hash, domain, logical_probe_index, rejection_index)
    })
}

#[allow(clippy::cast_possible_truncation)]
#[inline]
pub(crate) fn unbiased_prepared_elastic_probe_index(
    probe: PreparedElasticProbe,
    counter_base: u32,
    upper: usize,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    if max_random_words > ELASTIC_REJECTION_LIMIT {
        return Err(RangeReductionError::RejectionLimitExceeded {
            random_word_count: 0,
        });
    }
    if upper.is_power_of_two() {
        if max_random_words == 0 {
            return Err(RangeReductionError::RejectionLimitExceeded {
                random_word_count: 0,
            });
        }
        let word = probe.word_from_counter_base(counter_base, 0);
        let index = if upper == 1 {
            0
        } else {
            let index_bits = upper.trailing_zeros();
            (word >> (u64::BITS - index_bits)) as usize
        };
        return Ok(ProbeIndex {
            index,
            random_word_count: 1,
        });
    }
    reduce_prepared_elastic_non_power(probe, counter_base, upper, max_random_words)
}

/// Shift that reduces a random word to an index in `[0, upper)` by keeping
/// its top bits, or `None` when `upper` needs the general reduction. For a
/// power of two the multiply-high reduction never rejects a word and its high
/// half is exactly those top bits.
pub(crate) const fn elastic_index_shift(upper: usize) -> Option<u32> {
    if upper.is_power_of_two() && upper > 1 {
        Some(u64::BITS - upper.trailing_zeros())
    } else {
        None
    }
}

/// The index [`unbiased_prepared_elastic_probe_index`] yields from `word`,
/// a probe's first random word, for a level whose [`elastic_index_shift`] is
/// `index_shift`.
#[allow(clippy::cast_possible_truncation)]
#[inline]
pub(crate) const fn shifted_elastic_index(word: u64, index_shift: u32) -> usize {
    debug_assert!(index_shift < u64::BITS);
    (word >> index_shift) as usize
}

#[allow(clippy::cast_possible_truncation)]
#[inline]
pub(crate) fn unbiased_prepared_funnel_probe_index_in_range(
    probe: &PreparedFastFunnelDomainProbe,
    logical_probe_index: u8,
    range: PreparedProbeRange,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    if max_random_words == 0 {
        return Err(RangeReductionError::RejectionLimitExceeded {
            random_word_count: 0,
        });
    }
    let Ok(last_rejection_index) = u8::try_from(max_random_words - 1) else {
        return Err(RangeReductionError::RejectionLimitExceeded {
            random_word_count: 0,
        });
    };

    let upper_word = range.upper as u64;
    let product =
        u128::from(probe.word_from_indices(logical_probe_index, 0)) * u128::from(upper_word);
    if product as u64 >= range.rejection_threshold {
        return Ok(ProbeIndex {
            index: (product >> u64::BITS) as usize,
            random_word_count: 1,
        });
    }
    reduce_prepared_funnel_retries(probe, logical_probe_index, range, last_rejection_index)
}

/// The bucket an ordinary level's first random word selects, and whether that
/// word is accepted. The bucket is below the range's upper bound either way;
/// a rejected word needs [`ordinary_funnel_retry_index`].
///
/// The first word of an ordinary level is the folded key times that level's
/// multiplier, not a counter word: `key_out` already folds every bit of the
/// key, and a distinct odd multiplier per level decorrelates the levels with
/// one multiply.
#[allow(clippy::cast_possible_truncation)]
#[inline]
pub(crate) fn ordinary_funnel_first_draw(
    probe: PreparedFastFunnelProbe,
    multiplier: u64,
    range: PreparedProbeRange,
) -> (usize, bool) {
    let product =
        u128::from(probe.ordinary_first_word(multiplier)) * u128::from(range.upper as u64);
    (
        (product >> u64::BITS) as usize,
        product as u64 >= range.rejection_threshold,
    )
}

/// [`ordinary_funnel_first_draw`]'s bucket when its word is accepted.
#[inline]
pub(crate) fn ordinary_funnel_first_index(
    probe: PreparedFastFunnelProbe,
    multiplier: u64,
    range: PreparedProbeRange,
) -> Option<usize> {
    let (bucket, accepted) = ordinary_funnel_first_draw(probe, multiplier, range);
    accepted.then_some(bucket)
}

/// [`ordinary_funnel_first_draw`]'s bucket when the range's upper bound alone
/// shows the word accepted: the rejection threshold is below that bound, so a
/// low product above the bound is at or above the threshold. `None` leaves
/// the word to the exact test, and is the answer for every word of a range
/// with no index.
#[allow(clippy::cast_possible_truncation)]
#[inline]
pub(crate) fn ordinary_funnel_first_certain_index(
    probe: PreparedFastFunnelProbe,
    multiplier: u64,
    range: PreparedProbeRange,
) -> Option<usize> {
    let upper = range.upper as u64;
    let product = u128::from(probe.ordinary_first_word(multiplier)) * u128::from(upper);
    (product as u64 > upper).then_some((product >> u64::BITS) as usize)
}

/// Counter words one to [`RANGE_WORD_CAP`] of ordinary level `level`, for a
/// probe whose first word was rejected. `None` is a range failure.
#[cold]
#[inline(never)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn ordinary_funnel_retry_index(
    probe: PreparedFastFunnelProbe,
    level: usize,
    range: PreparedProbeRange,
) -> Option<usize> {
    let counter_base = FunnelPrf::ordinary_counter_base(level as u64)?;
    reduce_prepared_funnel_retries(
        &probe.prepare_counter_base(counter_base),
        0,
        range,
        (RANGE_WORD_CAP - 1) as u8,
    )
    .ok()
    .map(|probe| probe.index)
}

#[cold]
#[inline(never)]
#[allow(clippy::cast_possible_truncation)]
fn reduce_prepared_funnel_retries(
    probe: &PreparedFastFunnelDomainProbe,
    logical_probe_index: u8,
    range: PreparedProbeRange,
    last_rejection_index: u8,
) -> Result<ProbeIndex, RangeReductionError> {
    let upper_word = range.upper as u64;
    for rejection_index in 1..=last_rejection_index {
        let product = u128::from(probe.word_from_indices(logical_probe_index, rejection_index))
            * u128::from(upper_word);
        if product as u64 >= range.rejection_threshold {
            return Ok(ProbeIndex {
                index: (product >> u64::BITS) as usize,
                random_word_count: u32::from(rejection_index) + 1,
            });
        }
    }
    Err(RangeReductionError::RejectionLimitExceeded {
        random_word_count: u32::from(last_rejection_index) + 1,
    })
}

#[cold]
#[inline(never)]
fn reduce_prepared_elastic_non_power(
    probe: PreparedElasticProbe,
    counter_base: u32,
    upper: usize,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    reduce_probe_words(upper, max_random_words, |rejection_index| {
        probe.word_from_counter_base(counter_base, rejection_index)
    })
}

// The low-half cast deliberately selects the low 64 bits. The high-half value
// is strictly below `upper`, which originated as a `usize`, so it is also
// representable on 32-bit targets.
#[allow(clippy::cast_possible_truncation)]
#[inline]
fn reduce_probe_words(
    upper: usize,
    max_random_words: u32,
    mut word: impl FnMut(u32) -> u64,
) -> Result<ProbeIndex, RangeReductionError> {
    if upper == 0 {
        return Err(RangeReductionError::ZeroUpperBound);
    }

    let upper_word = upper as u64;
    let rejection_threshold = upper_word.wrapping_neg() % upper_word;
    for rejection_index in 0..max_random_words {
        let product = u128::from(word(rejection_index)) * u128::from(upper_word);
        let low = product as u64;
        if low >= rejection_threshold {
            return Ok(ProbeIndex {
                index: (product >> u64::BITS) as usize,
                random_word_count: rejection_index + 1,
            });
        }
    }

    Err(RangeReductionError::RejectionLimitExceeded {
        random_word_count: max_random_words,
    })
}

/// A coordinate rejected by [`elastic_phi`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhiCoordinate {
    /// The first, `i`, coordinate.
    I,
    /// The second, `j`, coordinate.
    J,
}

/// A failure to construct the checked paper-style injection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhiError {
    /// A coordinate was zero even though coordinates are positive and
    /// one-based.
    ZeroCoordinate {
        /// The coordinate whose value was zero.
        coordinate: PhiCoordinate,
    },
    /// The self-delimiting bit string does not fit in `u128`.
    Overflow,
}

/// Encodes positive one-based coordinates with a paper-style injection.
///
/// From most to least significant, the encoding contains, for each bit of
/// `j`, a marker bit `1` followed by that bit; it then contains a delimiter bit
/// `0` and the ordinary binary representation of `i`. The marker positions
/// make the boundary independently decodable, so the construction is
/// injective.
///
/// If `L(x)` is the positive binary length of `x`, the encoding has
/// `2*L(j) + 1 + L(i)` bits. Since `2^L(x) <= 2*x`, every represented result
/// satisfies `phi(i, j) < 16*i*j^2` (and therefore the weaker non-strict
/// bound `phi(i, j) <= 16*i*j^2`).
///
/// # Errors
///
/// Returns [`PhiError::ZeroCoordinate`] for a zero coordinate and
/// [`PhiError::Overflow`] when the complete encoding cannot fit in `u128`.
pub(crate) const fn elastic_phi(i: u128, j: u128) -> Result<u128, PhiError> {
    if i == 0 {
        return Err(PhiError::ZeroCoordinate {
            coordinate: PhiCoordinate::I,
        });
    }
    if j == 0 {
        return Err(PhiError::ZeroCoordinate {
            coordinate: PhiCoordinate::J,
        });
    }

    let mut encoded = 0;
    let mut bit_index = u128::BITS - j.leading_zeros();
    while bit_index > 0 {
        bit_index -= 1;
        encoded = match append_bit(encoded, 1) {
            Some(value) => value,
            None => return Err(PhiError::Overflow),
        };
        encoded = match append_bit(encoded, (j >> bit_index) & 1) {
            Some(value) => value,
            None => return Err(PhiError::Overflow),
        };
    }
    encoded = match append_bit(encoded, 0) {
        Some(value) => value,
        None => return Err(PhiError::Overflow),
    };

    bit_index = u128::BITS - i.leading_zeros();
    while bit_index > 0 {
        bit_index -= 1;
        encoded = match append_bit(encoded, (i >> bit_index) & 1) {
            Some(value) => value,
            None => return Err(PhiError::Overflow),
        };
    }
    Ok(encoded)
}

#[inline]
fn spread_low_16(mut value: u32) -> u32 {
    value = (value | value << 8) & 0x00ff_00ff;
    value = (value | value << 4) & 0x0f0f_0f0f;
    value = (value | value << 2) & 0x3333_3333;
    (value | value << 1) & 0x5555_5555
}

/// Constant-time encoder for Elastic's reachable production coordinates.
#[inline]
pub(crate) fn elastic_phi_bounded(i: u32, j: u64) -> Option<u64> {
    if i == 0 || j == 0 {
        return None;
    }
    let j = u16::try_from(j).ok()?;
    let j_bits = u16::BITS - j.leading_zeros();
    let i_bits = u32::BITS - i.leading_zeros();
    let pair_bits = j_bits.checked_mul(2)?;
    let encoded_bits = pair_bits.checked_add(1)?.checked_add(i_bits)?;
    if encoded_bits > u64::BITS {
        return None;
    }
    let pair_mask = (1_u64 << pair_bits).wrapping_sub(1);
    let data = u64::from(spread_low_16(u32::from(j)));
    let markers = 0xaaaa_aaaa_u64 & pair_mask;
    let pairs = data | markers;
    pairs
        .checked_shl(i_bits.checked_add(1)?)
        .map(|prefix| prefix | u64::from(i))
}

/// Inverts the exact self-delimiting image produced by [`elastic_phi`].
///
/// Values outside that image return `None`. A syntactically decoded candidate
/// is accepted only when re-encoding it produces `encoded` exactly; this also
/// rejects truncated marker pairs, a missing delimiter, zero coordinates, and
/// leading-zero suffixes.
#[must_use]
#[cfg(test)]
pub(crate) fn elastic_phi_inverse(encoded: u128) -> Option<(u128, u128)> {
    if encoded == 0 {
        return None;
    }

    let mut remaining_bits = u128::BITS - encoded.leading_zeros();
    let mut j = 0_u128;
    loop {
        if remaining_bits == 0 {
            return None;
        }
        remaining_bits -= 1;
        let marker = (encoded >> remaining_bits) & 1;
        if marker == 0 {
            break;
        }
        if remaining_bits == 0 {
            return None;
        }
        remaining_bits -= 1;
        let bit = (encoded >> remaining_bits) & 1;
        j = j.checked_mul(2)?.checked_add(bit)?;
    }

    if remaining_bits == 0 {
        return None;
    }
    let suffix_mask = 1_u128
        .checked_shl(remaining_bits)
        .and_then(|limit| limit.checked_sub(1))?;
    let i = encoded & suffix_mask;
    if elastic_phi(i, j).ok()? == encoded {
        Some((i, j))
    } else {
        None
    }
}

/// A failure to compute the exact discrete Elastic probe budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ElasticProbeBudgetError {
    /// `free_slots` was outside the required interval
    /// `0 < free_slots <= level_slots`.
    InvalidFreeSlots {
        /// The rejected free-slot count.
        free_slots: usize,
        /// The level size against which the count was validated.
        level_slots: usize,
    },
    /// The caller supplied `c == 0`.
    ZeroConstant,
    /// A checked intermediate or final result was not representable as
    /// `usize`.
    Overflow,
}

/// Computes the conservative dyadic Elastic probe-budget convention.
///
/// Let `k = ceil(log2(level_slots / free_slots))`, computed without floating
/// point. Returns `c * min(k^2, reserve_exponent)`. The ceiling is taken before
/// squaring, so this is not the exact ceiling of the paper's real-valued
/// formula. The paper leaves finite rounding, logarithm base, and the
/// sufficiently-large constant unspecified; this fixes only the dyadic
/// rounding convention, and callers supply `c` explicitly.
///
/// More precisely, let `L = log2(level_slots / free_slots)`. The dyadic term is
/// always conservative because
/// `min(L^2, reserve_exponent) <= min(ceil(L)^2, reserve_exponent)`. On an actual Elastic
/// state satisfying `L >= 2`, `ceil(L) <= 3*L/2`, so the capped dyadic term is
/// between `1` and `9/4` times the capped real term. There is no global
/// constant-factor relation over every valid free-slot count: as positive `L`
/// approaches zero, `ceil(L)^2 / L^2` is unbounded.
///
/// The result counts logical slot probes, not random words, SIMD groups, or
/// control-byte scans.
///
/// # Errors
///
/// Returns [`ElasticProbeBudgetError::InvalidFreeSlots`] unless
/// `0 < free_slots <= level_slots`,
/// [`ElasticProbeBudgetError::ZeroConstant`] when `c == 0`, and
/// [`ElasticProbeBudgetError::Overflow`] when checked arithmetic cannot
/// represent the exact result.
pub(crate) const fn elastic_dyadic_probe_budget(
    free_slots: usize,
    level_slots: usize,
    reserve_exponent: u32,
    c: usize,
) -> Result<usize, ElasticProbeBudgetError> {
    if free_slots == 0 || free_slots > level_slots {
        return Err(ElasticProbeBudgetError::InvalidFreeSlots {
            free_slots,
            level_slots,
        });
    }
    if c == 0 {
        return Err(ElasticProbeBudgetError::ZeroConstant);
    }

    let quotient = level_slots / free_slots;
    let ratio_ceiling = if level_slots.is_multiple_of(free_slots) {
        quotient
    } else {
        let Some(rounded) = quotient.checked_add(1) else {
            return Err(ElasticProbeBudgetError::Overflow);
        };
        rounded
    };
    let log_ceiling = (usize::BITS - (ratio_ceiling - 1).leading_zeros()) as usize;
    let Some(log_squared) = log_ceiling.checked_mul(log_ceiling) else {
        return Err(ElasticProbeBudgetError::Overflow);
    };
    let capped = if log_squared < reserve_exponent as usize {
        log_squared
    } else {
        reserve_exponent as usize
    };
    let Some(budget) = c.checked_mul(capped) else {
        return Err(ElasticProbeBudgetError::Overflow);
    };
    Ok(budget)
}

/// Multiplier of the per-key fold in [`FunnelPrf::prepare`].
const KEY_FOLD: u64 = 0xbf58_476d_1ce4_e5b9;

const fn mix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Both halves of the 128-bit product combined by XOR, so every bit of
/// `value` reaches the high bits the range reduction reads.
#[allow(clippy::cast_possible_truncation)]
#[inline]
const fn folded_multiply(value: u64, multiplier: u64) -> u64 {
    let product = value as u128 * multiplier as u128;
    (product as u64) ^ ((product >> u64::BITS) as u64)
}

const fn append_bit(prefix: u128, bit: u128) -> Option<u128> {
    match prefix.checked_mul(2) {
        Some(value) => value.checked_add(bit),
        None => None,
    }
}

#[cfg(test)]
impl PreparedFastFunnelProbe {
    #[inline]
    fn word_from_counter(self, counter: u64) -> u64 {
        mix64(counter ^ self.key_in()) ^ self.key_out
    }
}

#[cfg(test)]
impl PreparedProbeRange {
    pub(crate) const fn upper(self) -> usize {
        self.upper
    }
}

#[cfg(test)]
mod tests;
