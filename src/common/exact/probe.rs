//! Reproducible probe randomness and exact discrete formula primitives.
#![allow(
    clippy::cast_possible_truncation,
    clippy::inline_always,
    clippy::similar_names,
    clippy::trivially_copy_pass_by_ref
)]

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
/// Implementations must be stable functions of the complete input tuple:
/// repeated evaluation of the same tuple must return the same word. In the
/// theorem-level random-oracle ideal, words attached to *distinct* tuples are
/// independently and uniformly distributed; repeated evaluation of one tuple
/// observes the same random variable rather than drawing a fresh word. An
/// implementation may intentionally model weaker assumptions, but must report
/// them; implementing this trait does not itself establish independence or
/// uniformity.
///
/// For the theorem-level ideal, a finite instantiation must use `key_hash` as a
/// collision-free identity over its logical keys. If it instead
/// permits identity collisions, the collisions and resulting weaker
/// randomness model must be reported with the experiment.
#[cfg(test)]
pub(crate) trait ProbeOracle {
    /// Returns one word for a fully domain-separated logical counter tuple.
    ///
    /// Repeating this method with all four arguments unchanged must return the
    /// same word. Two logical experiment keys must not share `key_hash` unless
    /// that collision and the consequent shared counter stream are reported.
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

/// A seeded, copyable counter mixer for reproducible exact probing.
///
/// The construction domain-separates every tuple component before applying a
/// 64-bit avalanche mixer. It is an engineering random-oracle/PRF model only:
/// its outputs are not evidence of statistical independence, and the
/// construction is not claimed to be a universal hash family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CounterPrf {
    seed: u64,
}

/// A production-only, domain-separated Funnel counter permutation.
///
/// The packed counter preserves the paper algorithm's distinct ordinary,
/// primary, and two fallback choices. The construction is deterministic and
/// does not establish the paper's random-oracle assumptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FunnelPrf {
    seed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedElasticProbe {
    domain_state: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedElasticLevelProbe {
    level_state: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedFastFunnelProbe {
    key_in: u64,
    key_out: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedFastFunnelDomainProbe {
    key_in: u64,
    key_out: u64,
    counter_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedProbeRange {
    upper: usize,
    rejection_threshold: u64,
}

const INITIAL_LANE: u64 = 0x9e37_79b9_7f4a_7c15;
const KEY_LANE: u64 = 0xa076_1d64_78bd_642f;
const DOMAIN_KIND_LANE: u64 = 0xe703_7ed1_a0b4_28db;
const DOMAIN_LEVEL_LANE: u64 = 0x8ebc_6af0_9c88_c6e3;
const PROBE_LANE: u64 = 0x5899_65cc_7537_4cc3;
const REJECTION_LANE: u64 = 0x1d8e_4e27_c47d_124f;
const FUNNEL_LEVEL_LIMIT: u64 = 1 << 46;
const FUNNEL_LOGICAL_LIMIT: u64 = 1 << 8;
const FUNNEL_REJECTION_LIMIT: u32 = 1 << 8;

impl CounterPrf {
    /// Creates a deterministic counter mixer with `seed`.
    #[must_use]
    pub(crate) const fn new(seed: u64) -> Self {
        Self { seed }
    }

    pub(crate) fn prepare_elastic(&self, key_hash: u64) -> PreparedElasticProbe {
        let state = mix64(self.seed.wrapping_add(INITIAL_LANE));
        let state = absorb_counter_lane(state, key_hash, KEY_LANE);
        let domain_state = absorb_counter_lane(state, 1, DOMAIN_KIND_LANE);
        PreparedElasticProbe { domain_state }
    }
}

impl FunnelPrf {
    /// Creates the deterministic Funnel counter permutation for `seed`.
    #[must_use]
    pub(crate) const fn new(seed: u64) -> Self {
        Self { seed }
    }

    #[inline]
    pub(crate) fn prepare(&self, key_hash: u64) -> PreparedFastFunnelProbe {
        let keyed = key_hash.wrapping_add(self.seed);
        PreparedFastFunnelProbe {
            key_in: mix64(keyed.wrapping_add(KEY_LANE)),
            key_out: mix64(keyed.wrapping_add(DOMAIN_KIND_LANE)),
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
        let (domain_kind, level) = match domain {
            ProbeDomain::ElasticOrdinary { level } => (1, level),
            ProbeDomain::FunnelOrdinary { level } => (2, level),
            ProbeDomain::FunnelSpecialPrimary => (3, 0),
            ProbeDomain::FunnelSpecialFallbackChoiceA => (4, 0),
            ProbeDomain::FunnelSpecialFallbackChoiceB => (5, 0),
        };

        let mut state = mix64(self.seed.wrapping_add(INITIAL_LANE));
        state = absorb_counter_lane(state, key_hash, KEY_LANE);
        state = absorb_counter_lane(state, domain_kind, DOMAIN_KIND_LANE);
        state = absorb_counter_lane(state, level, DOMAIN_LEVEL_LANE);
        state = absorb_counter_lane(state, logical_probe_index, PROBE_LANE);
        absorb_counter_lane(state, u64::from(rejection_index), REJECTION_LANE)
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
        let counter = try_pack_funnel_counter(domain, logical_probe_index, rejection_index)
            .expect("Funnel counter tuple exceeds its checked production encoding");
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
        self.prepare_level_lane(Self::level_lane(level))
            .word_from_probe_lane(
                Self::logical_probe_lane(logical_probe_index),
                rejection_index,
            )
    }
}

impl PreparedElasticProbe {
    pub(crate) const fn level_lane(level: u64) -> u64 {
        mix64(level.wrapping_add(DOMAIN_LEVEL_LANE))
    }

    pub(crate) const fn logical_probe_lane(logical_probe_index: u64) -> u64 {
        mix64(logical_probe_index.wrapping_add(PROBE_LANE))
    }

    #[inline]
    pub(crate) fn prepare_level_lane(&self, level_lane: u64) -> PreparedElasticLevelProbe {
        PreparedElasticLevelProbe {
            level_state: mix64(self.domain_state.wrapping_add(level_lane)),
        }
    }
}

impl PreparedElasticLevelProbe {
    #[inline(always)]
    fn word_from_probe_lane(&self, logical_probe_lane: u64, rejection_index: u32) -> u64 {
        let state = mix64(self.level_state.wrapping_add(logical_probe_lane));
        let rejection_lane = if rejection_index == 0 {
            mix64(REJECTION_LANE)
        } else {
            mix64(u64::from(rejection_index).wrapping_add(REJECTION_LANE))
        };
        mix64(state.wrapping_add(rejection_lane))
    }
}

impl PreparedFastFunnelProbe {
    #[inline(always)]
    #[cfg(test)]
    fn word_from_counter(self, counter: u64) -> u64 {
        mix64(counter ^ self.key_in) ^ self.key_out
    }

    #[inline]
    pub(crate) fn prepare_domain(
        self,
        domain: ProbeDomain,
    ) -> Option<PreparedFastFunnelDomainProbe> {
        let counter_base = try_pack_funnel_counter(domain, 0, 0)?;
        Some(self.prepare_counter_base(counter_base))
    }

    #[inline(always)]
    pub(crate) const fn prepare_counter_base(
        self,
        counter_base: u64,
    ) -> PreparedFastFunnelDomainProbe {
        PreparedFastFunnelDomainProbe {
            key_in: self.key_in,
            key_out: self.key_out,
            counter_base,
        }
    }
}

impl PreparedFastFunnelDomainProbe {
    #[inline(always)]
    fn word(self, logical_probe_index: u64, rejection_index: u32) -> u64 {
        assert!(
            logical_probe_index < FUNNEL_LOGICAL_LIMIT,
            "Funnel logical probe exceeds its checked counter encoding"
        );
        assert!(
            rejection_index < FUNNEL_REJECTION_LIMIT,
            "Funnel rejection retry exceeds its checked counter encoding"
        );
        let counter = self.counter_base | (logical_probe_index << 8) | u64::from(rejection_index);
        mix64(counter ^ self.key_in) ^ self.key_out
    }
}

/// Packs one Funnel request into a collision-free production counter.
///
/// The encoding reserves two high bits for the four Funnel domains, 46 bits
/// for an ordinary level, and eight bits each for the logical probe and exact
/// range-reduction retry. Unsupported domains or out-of-range values fail
/// instead of truncating.
pub(crate) const fn try_pack_funnel_counter(
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

impl PreparedProbeRange {
    pub(crate) const fn empty() -> Self {
        Self {
            upper: 0,
            rejection_threshold: 0,
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

    #[inline(always)]
    #[cfg(test)]
    pub(crate) const fn upper(self) -> usize {
        self.upper
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
/// Callers must surface a rejection-limit error and include its
/// `random_word_count` in failure metrics. They must not recover by modulo
/// reduction, by resetting the retry counter, or by treating the failure as a
/// new logical probe.
///
/// # Errors
///
/// Returns [`RangeReductionError::ZeroUpperBound`] when `upper == 0`, or
/// [`RangeReductionError::RejectionLimitExceeded`] after consuming the allowed
/// number of words without accepting one.
// The low-half cast deliberately selects the low 64 bits. The high-half value
// is strictly below `upper`, which originated as a `usize`, so it is also
// representable on 32-bit targets.
#[allow(clippy::cast_possible_truncation)]
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

#[inline(always)]
pub(crate) fn unbiased_prepared_elastic_probe_index(
    probe: &PreparedElasticLevelProbe,
    logical_probe_lane: u64,
    upper: usize,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    if upper.is_power_of_two() {
        if max_random_words == 0 {
            return Err(RangeReductionError::RejectionLimitExceeded {
                random_word_count: 0,
            });
        }
        let word = probe.word_from_probe_lane(logical_probe_lane, 0);
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
    reduce_prepared_elastic_non_power(probe, logical_probe_lane, upper, max_random_words)
}

#[inline(always)]
pub(crate) fn unbiased_prepared_funnel_probe_index_in_range(
    probe: &PreparedFastFunnelDomainProbe,
    logical_probe_index: u64,
    range: PreparedProbeRange,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    if max_random_words == 0 {
        return Err(RangeReductionError::RejectionLimitExceeded {
            random_word_count: 0,
        });
    }

    let upper_word = range.upper as u64;
    let product = u128::from(probe.word(logical_probe_index, 0)) * u128::from(upper_word);
    if product as u64 >= range.rejection_threshold {
        return Ok(ProbeIndex {
            index: (product >> u64::BITS) as usize,
            random_word_count: 1,
        });
    }
    reduce_prepared_funnel_retries(probe, logical_probe_index, range, max_random_words)
}

#[cold]
#[inline(never)]
fn reduce_prepared_funnel_retries(
    probe: &PreparedFastFunnelDomainProbe,
    logical_probe_index: u64,
    range: PreparedProbeRange,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    let upper_word = range.upper as u64;
    for rejection_index in 1..max_random_words {
        let product =
            u128::from(probe.word(logical_probe_index, rejection_index)) * u128::from(upper_word);
        if product as u64 >= range.rejection_threshold {
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

#[cold]
#[inline(never)]
fn reduce_prepared_elastic_non_power(
    probe: &PreparedElasticLevelProbe,
    logical_probe_lane: u64,
    upper: usize,
    max_random_words: u32,
) -> Result<ProbeIndex, RangeReductionError> {
    reduce_probe_words(upper, max_random_words, |rejection_index| {
        probe.word_from_probe_lane(logical_probe_lane, rejection_index)
    })
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
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
pub(crate) fn elastic_phi(i: u128, j: u128) -> Result<u128, PhiError> {
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
        encoded = append_bit(encoded, 1).ok_or(PhiError::Overflow)?;
        encoded = append_bit(encoded, (j >> bit_index) & 1).ok_or(PhiError::Overflow)?;
    }
    encoded = append_bit(encoded, 0).ok_or(PhiError::Overflow)?;

    bit_index = u128::BITS - i.leading_zeros();
    while bit_index > 0 {
        bit_index -= 1;
        encoded = append_bit(encoded, (i >> bit_index) & 1).ok_or(PhiError::Overflow)?;
    }
    Ok(encoded)
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
/// point. This function returns `c * min(k^2, delta_log2)`. In particular, the
/// ceiling is taken before squaring. Thus `k^2` is generally not
/// `ceil(log2(level_slots / free_slots)^2)`, and this API does not claim to be
/// the exact ceiling of the paper's real-valued formula. The paper leaves its
/// finite rounding, logarithm base, and sufficiently-large constant
/// unspecified; this function fixes the dyadic rounding convention only, and
/// requires callers to supply `c` without a hidden default.
///
/// More precisely, let `L = log2(level_slots / free_slots)`. The dyadic term is
/// always conservative because
/// `min(L^2, delta_log2) <= min(ceil(L)^2, delta_log2)`. On an actual Elastic
/// state satisfying `L >= 2`, `ceil(L) <= 3*L/2`, so the capped dyadic term is
/// between `1` and `9/4` times the capped real term. There is no global
/// constant-factor relation over every valid free-slot count: as positive `L`
/// approaches zero, `ceil(L)^2 / L^2` is unbounded.
///
/// A fidelity report using this helper must record at least these fields:
/// `probe_budget_convention = "dyadic-ceil-before-square"`,
/// `probe_budget_c = c`, and
/// `probe_budget_unit = "logical-slot-probes"`. The returned value counts
/// individual logical slot probes, not random words, SIMD groups, or control
/// byte scans.
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
    delta_log2: u32,
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
    let capped = if log_squared < delta_log2 as usize {
        log_squared
    } else {
        delta_log2 as usize
    };
    let Some(budget) = c.checked_mul(capped) else {
        return Err(ElasticProbeBudgetError::Overflow);
    };
    Ok(budget)
}

const fn mix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

const fn absorb_counter_lane(state: u64, value: u64, lane: u64) -> u64 {
    mix64(state.wrapping_add(mix64(value.wrapping_add(lane))))
}

fn append_bit(prefix: u128, bit: u128) -> Option<u128> {
    prefix
        .checked_mul(2)
        .and_then(|value| value.checked_add(bit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_elastic_probe_is_bit_identical_to_the_full_counter_prf() {
        let oracle = CounterPrf::new(0x1234_5678_9abc_def0);
        for key in [0, 1, u64::MAX, 0xd1b5_4a32_d192_ed03] {
            let prepared = oracle.prepare_elastic(key);
            for level in [0, 1, 17, u64::from(u32::MAX)] {
                let domain = ProbeDomain::ElasticOrdinary { level };
                for logical_probe in [0, 1, 383, u64::MAX] {
                    for rejection in [0, 1, 7, u32::MAX] {
                        assert_eq!(
                            prepared.word(0, domain, logical_probe, rejection),
                            oracle.word(key, domain, logical_probe, rejection)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn prepared_power_of_two_reduction_is_bit_identical_to_generic_reduction() {
        let oracle = CounterPrf::new(0x1234_5678_9abc_def0);
        for key in [0, 1, u64::MAX, 0xd1b5_4a32_d192_ed03] {
            let prepared = oracle.prepare_elastic(key);
            for level in [0, 1, 17, 63] {
                let domain = ProbeDomain::ElasticOrdinary { level };
                let level_lane = PreparedElasticProbe::level_lane(level);
                let prepared_level = prepared.prepare_level_lane(level_lane);
                for logical_probe in [0, 1, 383, 4_095] {
                    let probe_lane = PreparedElasticProbe::logical_probe_lane(logical_probe);
                    for upper in [1, 2, 4, 16, 1 << 20] {
                        assert_eq!(
                            unbiased_prepared_elastic_probe_index(
                                &prepared_level,
                                probe_lane,
                                upper,
                                8,
                            ),
                            unbiased_probe_index(&oracle, key, domain, logical_probe, upper, 8,)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn fast_funnel_counter_pack_is_injective_and_checked() {
        let mut counters = alloc::collections::BTreeSet::new();
        for domain in [
            ProbeDomain::FunnelOrdinary { level: 0 },
            ProbeDomain::FunnelOrdinary { level: 262 },
            ProbeDomain::FunnelSpecialPrimary,
            ProbeDomain::FunnelSpecialFallbackChoiceA,
            ProbeDomain::FunnelSpecialFallbackChoiceB,
        ] {
            for logical in 0..8 {
                for retry in 0..8 {
                    let counter = try_pack_funnel_counter(domain, logical, retry).unwrap();
                    assert!(counters.insert(counter));
                }
            }
        }
        assert!(
            try_pack_funnel_counter(ProbeDomain::FunnelOrdinary { level: 1 << 46 }, 0, 0,)
                .is_none()
        );
        assert!(try_pack_funnel_counter(ProbeDomain::FunnelSpecialPrimary, 256, 0).is_none());
        assert!(try_pack_funnel_counter(ProbeDomain::FunnelSpecialPrimary, 0, 256).is_none());
        assert!(try_pack_funnel_counter(ProbeDomain::ElasticOrdinary { level: 0 }, 0, 0).is_none());
    }

    #[test]
    fn fast_funnel_prepared_words_and_reductions_match_the_generic_oracle() {
        let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
        for key in [0, 1, u64::MAX, 0xd1b5_4a32_d192_ed03] {
            let prepared = oracle.prepare(key);
            for domain in [
                ProbeDomain::FunnelOrdinary { level: 0 },
                ProbeDomain::FunnelOrdinary { level: 17 },
                ProbeDomain::FunnelSpecialPrimary,
                ProbeDomain::FunnelSpecialFallbackChoiceA,
                ProbeDomain::FunnelSpecialFallbackChoiceB,
            ] {
                let prepared_domain = prepared.prepare_domain(domain).unwrap();
                for logical in [0, 1, 7, 255] {
                    for retry in [0, 1, 7, 255] {
                        assert_eq!(
                            prepared_domain.word(logical, retry),
                            oracle.word(key, domain, logical, retry)
                        );
                    }
                    for upper in [1, 2, 3, 16, 191, 1_237, 1 << 20] {
                        let range = PreparedProbeRange::new(upper).unwrap();
                        assert_eq!(
                            unbiased_prepared_funnel_probe_index_in_range(
                                &prepared_domain,
                                logical,
                                range,
                                8,
                            ),
                            unbiased_probe_index(&oracle, key, domain, logical, upper, 8)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn fast_funnel_counter_permutation_has_fixed_golden_vectors() {
        let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
        let cases = [
            (
                0,
                ProbeDomain::FunnelOrdinary { level: 0 },
                0,
                0,
                0x0000_0000_0000_0000,
                0x584f_bd8c_cfbf_e67c,
            ),
            (
                1,
                ProbeDomain::FunnelOrdinary {
                    level: (1 << 46) - 1,
                },
                255,
                255,
                0x3fff_ffff_ffff_ffff,
                0x25aa_bb0a_07b2_074f,
            ),
            (
                u64::MAX,
                ProbeDomain::FunnelSpecialPrimary,
                255,
                255,
                0x4000_0000_0000_ffff,
                0x6b27_15b8_99c2_d843,
            ),
            (
                0xd1b5_4a32_d192_ed03,
                ProbeDomain::FunnelSpecialFallbackChoiceA,
                7,
                1,
                0x8000_0000_0000_0701,
                0xcbcd_0c5b_e9c2_0453,
            ),
            (
                0x0123_4567_89ab_cdef,
                ProbeDomain::FunnelSpecialFallbackChoiceB,
                0,
                0,
                0xc000_0000_0000_0000,
                0xf0ef_9ef3_0ac2_58f3,
            ),
        ];
        for (key, domain, logical, retry, counter, word) in cases {
            assert_eq!(
                try_pack_funnel_counter(domain, logical, retry),
                Some(counter)
            );
            assert_eq!(oracle.word(key, domain, logical, retry), word);
            assert_eq!(
                oracle
                    .prepare(key)
                    .prepare_domain(domain)
                    .unwrap()
                    .word(logical, retry),
                word
            );
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn fast_funnel_retries_and_exhaustion_use_distinct_checked_counters() {
        let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
        let range = PreparedProbeRange::new((1_usize << 63) + 1).unwrap();
        let accepts = |word: u64| {
            let product = u128::from(word) * u128::from(range.upper as u64);
            product as u64 >= range.rejection_threshold
        };
        let mut reject_then_accept = None;
        let mut three_rejections = None;
        for key in 0..1_024 {
            let prepared = oracle
                .prepare(key)
                .prepare_domain(ProbeDomain::FunnelSpecialPrimary)
                .unwrap();
            let accepted = [0, 1, 2].map(|retry| accepts(prepared.word(9, retry)));
            if !accepted[0] && accepted[1] && reject_then_accept.is_none() {
                reject_then_accept = Some(prepared);
            }
            if accepted == [false; 3] && three_rejections.is_none() {
                three_rejections = Some(prepared);
            }
        }

        let retry = reject_then_accept.expect("fixed seed must exercise one exact retry");
        assert_eq!(
            unbiased_prepared_funnel_probe_index_in_range(&retry, 9, range, 1),
            Err(RangeReductionError::RejectionLimitExceeded {
                random_word_count: 1
            })
        );
        assert_eq!(
            unbiased_prepared_funnel_probe_index_in_range(&retry, 9, range, 2)
                .unwrap()
                .random_word_count,
            2
        );

        let exhausted = three_rejections.expect("fixed seed must exercise bounded exhaustion");
        assert_eq!(
            unbiased_prepared_funnel_probe_index_in_range(&exhausted, 9, range, 3),
            Err(RangeReductionError::RejectionLimitExceeded {
                random_word_count: 3
            })
        );
    }

    #[test]
    fn fast_funnel_fixed_seed_distribution_smoke() {
        const SAMPLES: u64 = 1 << 18;
        let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
        let mut one_counts = [0_u64; u64::BITS as usize];
        let mut avalanche_bits = 0_u64;
        let mut cross_level_equal_bits = 0_u64;
        let mut fallback_same_bucket = 0_u64;
        let fallback_range = PreparedProbeRange::new(257).unwrap();
        let mut fallback_a_counts = alloc::vec![0_u32; fallback_range.upper()];
        let mut fallback_b_counts = alloc::vec![0_u32; fallback_range.upper()];

        for key in 0..SAMPLES {
            let ordinary = oracle.word(key, ProbeDomain::FunnelOrdinary { level: 7 }, 0, 0);
            for bit in 0..u64::BITS {
                one_counts[bit as usize] += (ordinary >> bit) & 1;
            }
            let flipped_key = key ^ (1_u64 << (key % u64::from(u64::BITS)));
            avalanche_bits += u64::from(
                (ordinary
                    ^ oracle.word(flipped_key, ProbeDomain::FunnelOrdinary { level: 7 }, 0, 0))
                .count_ones(),
            );
            cross_level_equal_bits += u64::from(
                (!(ordinary ^ oracle.word(key, ProbeDomain::FunnelOrdinary { level: 8 }, 0, 0)))
                    .count_ones(),
            );

            let prepared = oracle.prepare(key);
            let a = unbiased_prepared_funnel_probe_index_in_range(
                &prepared
                    .prepare_domain(ProbeDomain::FunnelSpecialFallbackChoiceA)
                    .unwrap(),
                0,
                fallback_range,
                8,
            )
            .unwrap()
            .index;
            let b = unbiased_prepared_funnel_probe_index_in_range(
                &prepared
                    .prepare_domain(ProbeDomain::FunnelSpecialFallbackChoiceB)
                    .unwrap(),
                0,
                fallback_range,
                8,
            )
            .unwrap()
            .index;
            fallback_a_counts[a] += 1;
            fallback_b_counts[b] += 1;
            fallback_same_bucket += u64::from(a == b);
        }

        for count in one_counts {
            assert!((SAMPLES * 48 / 100..=SAMPLES * 52 / 100).contains(&count));
        }
        assert!((SAMPLES * 30..=SAMPLES * 34).contains(&avalanche_bits));
        assert!((SAMPLES * 30..=SAMPLES * 34).contains(&cross_level_equal_bits));

        let expected_bucket_count = SAMPLES / fallback_range.upper() as u64;
        let bucket_min = expected_bucket_count * 3 / 4;
        let bucket_max = expected_bucket_count * 5 / 4;
        assert!((bucket_min..=bucket_max).contains(&fallback_same_bucket));
        for count in fallback_a_counts.into_iter().chain(fallback_b_counts) {
            assert!((bucket_min..=bucket_max).contains(&u64::from(count)));
        }
    }

    #[test]
    fn fast_funnel_awkward_ranges_have_no_large_fixed_seed_skew() {
        const EXPECTED_PER_BUCKET: usize = 512;
        let oracle = FunnelPrf::new(0x1234_5678_9abc_def0);
        for upper in [3, 191, 1_237] {
            let range = PreparedProbeRange::new(upper).unwrap();
            let mut counts = alloc::vec![0_u32; upper];
            for key in 0..(upper * EXPECTED_PER_BUCKET) as u64 {
                let prepared = oracle
                    .prepare(key)
                    .prepare_domain(ProbeDomain::FunnelSpecialPrimary)
                    .unwrap();
                let sample =
                    unbiased_prepared_funnel_probe_index_in_range(&prepared, 3, range, 8).unwrap();
                counts[sample.index] += 1;
            }
            for count in counts {
                assert!(
                    (EXPECTED_PER_BUCKET - 128..=EXPECTED_PER_BUCKET + 128)
                        .contains(&(count as usize)),
                    "upper={upper} count={count}"
                );
            }
        }
    }
}
