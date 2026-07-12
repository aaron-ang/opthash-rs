//! Exact finite geometry and configuration shared by the library and scalar tests.

use core::iter::FusedIterator;

/// Exact fixed-size inputs shared by library placement and scalar tests.
///
/// `delta` is represented as `1 / 2^reserve_exponent`; no floating-point value is
/// constructed or sanitized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PaperConfig {
    n: usize,
    reserve_exponent: u32,
}

impl PaperConfig {
    /// Validates exact experiment inputs.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::NTooSmall`] when `n < 2` and
    /// [`ConfigError::ExponentZero`] when `reserve_exponent == 0`.
    pub(crate) const fn new(n: usize, reserve_exponent: u32) -> Result<Self, ConfigError> {
        if n < 2 {
            return Err(ConfigError::NTooSmall { n });
        }
        if reserve_exponent == 0 {
            return Err(ConfigError::ExponentZero);
        }
        Ok(Self {
            n,
            reserve_exponent,
        })
    }

    /// Returns the paper array size `n`.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn n(&self) -> usize {
        self.n
    }

    /// Returns the exponent in the exact representation `delta = 1 / 2^d`.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn reserve_exponent(&self) -> u32 {
        self.reserve_exponent
    }

    /// Returns `floor(delta * n)` using exact integer arithmetic.
    #[must_use]
    pub(crate) const fn floor_delta_n(&self) -> usize {
        floor_div_pow2(self.n, self.reserve_exponent)
    }

    /// Returns the paper experiment's exact insertion count.
    #[must_use]
    pub(crate) const fn target_insertions(&self) -> usize {
        self.n - self.floor_delta_n()
    }

    /// Reports the Elastic theorem's unquantified asymptotic precondition.
    ///
    /// The exact inverse-power-of-two representation is accepted, but the
    /// paper's `delta > O(1/n)` precondition does not specify a concrete
    /// constant, so this method deliberately does not claim applicability.
    #[must_use]
    #[cfg(test)]
    #[allow(clippy::unused_self)]
    pub(crate) const fn elastic_domain_status(&self) -> TheoremDomainStatus {
        TheoremDomainStatus::UnquantifiedAsymptoticPrecondition
    }

    /// Checks Funnel's concrete `delta <= 1/8` restriction and reports the
    /// remaining unquantified asymptotic precondition.
    ///
    /// # Errors
    ///
    /// Returns [`FunnelDomainError::ExponentBelowMinimum`] when
    /// `reserve_exponent < 3`.
    pub(crate) const fn funnel_domain_status(
        &self,
    ) -> Result<TheoremDomainStatus, FunnelDomainError> {
        if self.reserve_exponent < 3 {
            return Err(FunnelDomainError::ExponentBelowMinimum {
                reserve_exponent: self.reserve_exponent,
                minimum: 3,
            });
        }
        Ok(TheoremDomainStatus::UnquantifiedAsymptoticPrecondition)
    }

    /// Creates a pure logical Funnel geometry plan.
    ///
    /// # Errors
    ///
    /// Returns [`FunnelPlanError`] when the concrete Funnel domain is not met,
    /// a derived parameter overflows, the paper's special-array interval has
    /// no compatible length, or the ordinary levels have no positive exact
    /// partition.
    pub(crate) fn funnel_plan(&self) -> Result<FunnelPlan, FunnelPlanError> {
        self.funnel_domain_status()
            .map_err(FunnelPlanError::Domain)?;

        let reserve_exponent = u128::from(self.reserve_exponent);
        let alpha = reserve_exponent
            .checked_mul(4)
            .and_then(|value| value.checked_add(10))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(FunnelPlanError::DerivedParameterOverflow {
                parameter: FunnelPlanParameter::Alpha,
                reserve_exponent: self.reserve_exponent,
            })?;
        let beta = reserve_exponent
            .checked_mul(2)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(FunnelPlanError::DerivedParameterOverflow {
                parameter: FunnelPlanParameter::Beta,
                reserve_exponent: self.reserve_exponent,
            })?;

        let bound_exponent = u64::from(self.reserve_exponent);
        let lower = ceil_div_pow2(self.n, bound_exponent + 1);
        let upper = floor_three_div_pow2(self.n, bound_exponent + 2);
        let loglog_ceiling = base_two_loglog_ceiling(self.n);
        let fallback_bucket_width = 2 * loglog_ceiling;
        let no_compatible_layout = FunnelPlanError::NoCompatibleSpecialLayout {
            lower,
            upper,
            beta,
            loglog_ceiling,
            fallback_bucket_width,
        };
        let (special_len, first_bucket_count) = largest_compatible_special_layout(
            self.n,
            lower,
            upper,
            alpha,
            beta,
            fallback_bucket_width,
        )
        .ok_or(no_compatible_layout)?;

        Ok(FunnelPlan {
            config: *self,
            alpha,
            beta,
            loglog_ceiling,
            fallback_bucket_width,
            special_len,
            first_bucket_count,
        })
    }

    /// Creates a pure logical Elastic geometry and batch plan.
    #[must_use]
    pub(crate) const fn elastic_plan(&self) -> ElasticPlan {
        ElasticPlan { config: *self }
    }
}

/// Invalid exact paper-configuration input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigError {
    /// The paper array has fewer than two slots.
    NTooSmall {
        /// The rejected array size.
        n: usize,
    },
    /// `delta = 1 / 2^d` was given the invalid exponent `d = 0`.
    ExponentZero,
}

/// A concrete Funnel-domain restriction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FunnelDomainError {
    /// Funnel requires `delta <= 1/8`, or equivalently `reserve_exponent >= 3`.
    ExponentBelowMinimum {
        /// The rejected exponent.
        reserve_exponent: u32,
        /// The smallest accepted exponent.
        minimum: u32,
    },
}

/// A derived Funnel geometry parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FunnelPlanParameter {
    /// The ordinary-level count `alpha = 4 * reserve_exponent + 10`.
    Alpha,
    /// The ordinary bucket length `beta = 2 * reserve_exponent`.
    Beta,
}

/// A failure to construct the paper's exact logical Funnel geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FunnelPlanError {
    /// Funnel's concrete `delta <= 1/8` restriction failed.
    Domain(FunnelDomainError),
    /// A derived parameter cannot be represented exactly.
    DerivedParameterOverflow {
        /// The parameter whose checked derivation failed.
        parameter: FunnelPlanParameter,
        /// The input exponent used by the failed derivation.
        reserve_exponent: u32,
    },
    /// No special length supports the complete finite logical layout.
    ///
    /// This reports a finite tiling incompatibility, not a rejection of the
    /// paper's asymptotic theorem domain. A compatible length must leave a
    /// beta-divisible feasible ordinary partition and at least one complete
    /// fallback bucket.
    NoCompatibleSpecialLayout {
        /// `ceil(delta * n / 2)`.
        lower: usize,
        /// `floor(3 * delta * n / 4)`.
        upper: usize,
        /// The required ordinary-bucket length.
        beta: usize,
        /// `max(1, ceil(log2(ceil(log2(n)))))`.
        loglog_ceiling: usize,
        /// The exact fallback bucket width `2 * loglog_ceiling`.
        fallback_bucket_width: usize,
    },
}

/// The status of an algorithm's asymptotic theorem preconditions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TheoremDomainStatus {
    /// The paper uses big-O notation without a concrete constant to check.
    UnquantifiedAsymptoticPrecondition,
}

/// A pure logical Elastic geometry and insertion-batch plan.
///
/// No table storage is allocated. Level lengths and batch quotas are exposed
/// as exact-size iterators derived from the validated configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ElasticPlan {
    config: PaperConfig,
}

/// A pure logical Funnel geometry plan.
/// No table or region storage is allocated. The ordinary bucket counts are
/// produced by an exact-size iterator. Among valid sequences, construction
/// chooses a first count nearest the real-valued estimate
/// `total_buckets / 4`, preferring the smaller count on an exact tie. Later
/// counts use the largest valid value that still permits the residual bucket
/// sum, making the remaining tie-break lexicographically largest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FunnelPlan {
    config: PaperConfig,
    alpha: usize,
    beta: usize,
    loglog_ceiling: usize,
    fallback_bucket_width: usize,
    special_len: usize,
    first_bucket_count: usize,
}

impl FunnelPlan {
    /// Returns the validated inputs used by this plan.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn config(&self) -> PaperConfig {
        self.config
    }

    /// Returns the ordinary-level count `alpha = 4 * reserve_exponent + 10`.
    #[must_use]
    pub(crate) const fn alpha(&self) -> usize {
        self.alpha
    }

    /// Returns the logical slots per ordinary bucket,
    /// `beta = 2 * reserve_exponent`.
    #[must_use]
    pub(crate) const fn beta(&self) -> usize {
        self.beta
    }

    /// Returns the exact base-two finite value
    /// `max(1, ceil(log2(ceil(log2(n)))))`.
    #[must_use]
    pub(crate) const fn loglog_ceiling(&self) -> usize {
        self.loglog_ceiling
    }

    /// Returns the special fallback's exact bucket width,
    /// `2 * loglog_ceiling`.
    #[must_use]
    pub(crate) const fn fallback_bucket_width(&self) -> usize {
        self.fallback_bucket_width
    }

    /// Returns the logical length of special array `A_(alpha + 1)`.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn special_len(&self) -> usize {
        self.special_len
    }

    /// Returns `B = ceil(special_len / 2)`, the special primary length.
    #[must_use]
    pub(crate) const fn special_primary_len(&self) -> usize {
        self.special_len / 2 + self.special_len % 2
    }

    /// Returns `C = floor(special_len / 2)`, the special fallback length.
    #[must_use]
    pub(crate) const fn special_fallback_len(&self) -> usize {
        self.special_len / 2
    }

    /// Returns the positive number of complete equal-width fallback buckets.
    #[must_use]
    pub(crate) const fn fallback_bucket_count(&self) -> usize {
        self.special_fallback_len() / self.fallback_bucket_width
    }

    /// Iterates over exact positive bucket counts for ordinary levels
    /// `A_1, ..., A_alpha`.
    ///
    /// Counts are monotone non-increasing, sum to the available ordinary
    /// buckets, and every adjacent pair satisfies
    /// `|4 * next - 3 * current| <= 4`, the exact integer form of
    /// `next = 3 * current / 4 +/- 1` over the reals.
    #[must_use]
    pub(crate) fn ordinary_bucket_counts(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        FunnelBucketCounts {
            next_count: Some(self.first_bucket_count),
            remaining_sum: (self.config.n - self.special_len) / self.beta,
            remaining_levels: self.alpha,
        }
    }

    /// Iterates over each ordinary level's exact logical slot length.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn ordinary_level_lengths(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        let beta = self.beta;
        self.ordinary_bucket_counts().map(move |count| count * beta)
    }
}

impl ElasticPlan {
    /// Returns the paper's exact `ceil(log2(n))` number of non-empty levels.
    #[must_use]
    pub(crate) const fn level_count(&self) -> usize {
        (usize::BITS - (self.config.n - 1).leading_zeros()) as usize
    }

    /// Iterates over logical level lengths in paper order.
    ///
    /// The deterministic construction repeatedly gives the next level
    /// `ceil(remaining / 2)` slots and gives the final level all residual
    /// slots. Thus the lengths sum to `n`, are non-empty, and each next length
    /// is within one of half the preceding length in the real-valued sense.
    #[must_use]
    pub(crate) fn level_lengths(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        LevelLengths {
            remaining_slots: self.config.n,
            remaining_levels: self.level_count(),
        }
    }

    /// Iterates over the exact Elastic batch quotas from paper §4, capped in
    /// order at [`PaperConfig::target_insertions`].
    ///
    /// `B_0` is `ceil(3|A_1|/4)`. Each later quota is:
    ///
    /// ```text
    /// |A_i| - floor(delta|A_i|/2) - ceil(3|A_i|/4) + ceil(3|A_(i+1)|/4)
    /// ```
    ///
    /// Trailing quotas are zero once the insertion target is reached.
    #[must_use]
    pub(crate) fn batch_quotas(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        BatchQuotas {
            levels: LevelLengths {
                remaining_slots: self.config.n,
                remaining_levels: self.level_count(),
            },
            previous_level: None,
            remaining_insertions: self.config.target_insertions(),
            reserve_exponent: self.config.reserve_exponent,
        }
    }
}

#[derive(Clone)]
struct FunnelBucketCounts {
    next_count: Option<usize>,
    remaining_sum: usize,
    remaining_levels: usize,
}

impl Iterator for FunnelBucketCounts {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let count = self.next_count.take()?;
        let remaining_sum = self.remaining_sum.checked_sub(count)?;
        let remaining_levels = self.remaining_levels.checked_sub(1)?;

        self.next_count = if remaining_levels == 0 {
            None
        } else {
            select_largest_feasible_next(count, remaining_sum, remaining_levels)
        };
        self.remaining_sum = remaining_sum;
        self.remaining_levels = remaining_levels;
        Some(count)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_levels, Some(self.remaining_levels))
    }
}

impl ExactSizeIterator for FunnelBucketCounts {}
impl FusedIterator for FunnelBucketCounts {}

#[derive(Clone)]
struct LevelLengths {
    remaining_slots: usize,
    remaining_levels: usize,
}

impl Iterator for LevelLengths {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_levels == 0 {
            return None;
        }

        let length = if self.remaining_levels == 1 {
            self.remaining_slots
        } else {
            self.remaining_slots / 2 + self.remaining_slots % 2
        };
        self.remaining_slots -= length;
        self.remaining_levels -= 1;
        Some(length)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_levels, Some(self.remaining_levels))
    }
}

impl ExactSizeIterator for LevelLengths {}
impl FusedIterator for LevelLengths {}

#[derive(Clone)]
struct BatchQuotas {
    levels: LevelLengths,
    previous_level: Option<usize>,
    remaining_insertions: usize,
    reserve_exponent: u32,
}

impl Iterator for BatchQuotas {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let level = self.levels.next()?;
        let raw_quota = if let Some(previous) = self.previous_level {
            previous
                - floor_div_pow2(previous, self.reserve_exponent.saturating_add(1))
                - ceil_three_quarters(previous)
                + ceil_three_quarters(level)
        } else {
            ceil_three_quarters(level)
        };
        self.previous_level = Some(level);

        let quota = raw_quota.min(self.remaining_insertions);
        self.remaining_insertions -= quota;
        Some(quota)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.levels.size_hint()
    }
}

impl ExactSizeIterator for BatchQuotas {}
impl FusedIterator for BatchQuotas {}

fn largest_compatible_special_layout(
    n: usize,
    lower: usize,
    upper: usize,
    alpha: usize,
    beta: usize,
    fallback_bucket_width: usize,
) -> Option<(usize, usize)> {
    // Positive bucket counts make `alpha` the minimum reachable total. The
    // adjacent 3/4 +/- 1 path intervals are contiguous and overlap as the
    // first count increases (exhaustively guarded by the reference tests), so
    // every total at least `alpha` has a feasible ordinary partition.
    let minimum_main_len = alpha.checked_mul(beta)?;
    if minimum_main_len > n {
        return None;
    }
    let minimum_special_len = lower.max(fallback_bucket_width.checked_mul(2)?);
    let maximum_special_len = upper.min(n - minimum_main_len);
    if minimum_special_len > maximum_special_len {
        return None;
    }

    let minimum_main_candidate = n - maximum_special_len;
    let maximum_main_candidate = n - minimum_special_len;
    let minimum_main_multiple =
        minimum_main_candidate / beta + usize::from(!minimum_main_candidate.is_multiple_of(beta));
    if minimum_main_multiple > maximum_main_candidate / beta {
        return None;
    }
    let mut main_len = minimum_main_multiple.checked_mul(beta)?;

    let fallback_period = fallback_bucket_width.checked_mul(2)?;
    // beta is even. Advancing the main length by beta decreases
    // C=floor((n-main)/2) by beta/2. C divisibility by q therefore repeats
    // after q/gcd(beta/2,q) = 2q/gcd(beta,2q) steps, which is exactly this
    // bounded residue-cycle length (at most 12 steps on a 64-bit target).
    let residue_cycle_len = fallback_period / greatest_common_divisor(beta, fallback_period);
    for _ in 0..residue_cycle_len {
        if main_len > maximum_main_candidate {
            break;
        }
        let special_len = n - main_len;
        let fallback_len = special_len / 2;
        if fallback_len >= fallback_bucket_width
            && fallback_len.is_multiple_of(fallback_bucket_width)
        {
            let total_buckets = main_len / beta;
            let first_bucket_count = nearest_feasible_first_count(total_buckets, alpha)?;
            return Some((special_len, first_bucket_count));
        }
        let Some(next_main_len) = main_len.checked_add(beta) else {
            break;
        };
        main_len = next_main_len;
    }
    None
}

const fn greatest_common_divisor(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn nearest_feasible_first_count(total_buckets: usize, level_count: usize) -> Option<usize> {
    let maximum_first = total_buckets.checked_sub(level_count.checked_sub(1)?)?;

    let mut lower_left = 1;
    let mut lower_right = maximum_first;
    if !maximum_path_sum_at_least(maximum_first, level_count, total_buckets) {
        return None;
    }
    while lower_left < lower_right {
        let middle = lower_left + (lower_right - lower_left) / 2;
        if maximum_path_sum_at_least(middle, level_count, total_buckets) {
            lower_right = middle;
        } else {
            lower_left = middle + 1;
        }
    }
    let first_lower = lower_left;

    let mut upper_left = 1;
    let mut upper_right = maximum_first;
    if !minimum_path_sum_at_most(upper_left, level_count, total_buckets) {
        return None;
    }
    while upper_left < upper_right {
        let middle = upper_left + (upper_right - upper_left) / 2 + 1;
        if minimum_path_sum_at_most(middle, level_count, total_buckets) {
            upper_left = middle;
        } else {
            upper_right = middle - 1;
        }
    }
    let first_upper = upper_left;
    if first_lower > first_upper {
        return None;
    }

    let quotient = total_buckets / 4;
    let nearest_estimate = if total_buckets % 4 <= 2 {
        quotient
    } else {
        quotient + 1
    };
    let first = nearest_estimate.clamp(first_lower, first_upper);
    let mut counts = FunnelBucketCounts {
        next_count: Some(first),
        remaining_sum: total_buckets,
        remaining_levels: level_count,
    };
    for _ in 0..level_count {
        counts.next()?;
    }
    if counts.next().is_none() && counts.remaining_sum == 0 {
        Some(first)
    } else {
        None
    }
}

fn select_largest_feasible_next(
    current: usize,
    remaining_sum: usize,
    remaining_levels: usize,
) -> Option<usize> {
    let minimum = minimum_next_bucket_count(current);
    let maximum = maximum_next_bucket_count(current);
    (minimum..=maximum).rev().find(|&candidate| {
        minimum_path_sum_at_most(candidate, remaining_levels, remaining_sum)
            && maximum_path_sum_at_least(candidate, remaining_levels, remaining_sum)
    })
}

fn minimum_path_sum_at_most(mut current: usize, mut level_count: usize, target: usize) -> bool {
    let mut sum = 0_usize;
    while level_count > 0 {
        let Some(next_sum) = sum.checked_add(current) else {
            return false;
        };
        if next_sum > target {
            return false;
        }
        sum = next_sum;
        current = minimum_next_bucket_count(current);
        level_count -= 1;
    }
    true
}

fn maximum_path_sum_at_least(mut current: usize, mut level_count: usize, target: usize) -> bool {
    let mut sum = 0_usize;
    while level_count > 0 {
        let Some(next_sum) = sum.checked_add(current) else {
            return true;
        };
        sum = next_sum;
        if sum >= target {
            return true;
        }
        current = maximum_next_bucket_count(current);
        level_count -= 1;
    }
    false
}

const fn minimum_next_bucket_count(current: usize) -> usize {
    let minimum = ceil_three_quarters(current) - 1;
    if minimum == 0 { 1 } else { minimum }
}

const fn maximum_next_bucket_count(current: usize) -> usize {
    let remainder = if current.is_multiple_of(4) { 0 } else { 1 };
    let ceil_quarter = current / 4 + remainder;
    let maximum = current - ceil_quarter + 1;
    if maximum > current { current } else { maximum }
}

// Both casts are guarded by `exponent < u128::BITS`.
#[allow(clippy::cast_possible_truncation)]
const fn ceil_div_pow2(value: usize, exponent: u64) -> usize {
    if value == 0 {
        0
    } else if exponent >= u128::BITS as u64 {
        1
    } else {
        let value = value as u128;
        let denominator = 1_u128 << exponent as u32;
        let remainder = if value.is_multiple_of(denominator) {
            0
        } else {
            1
        };
        (value / denominator + remainder) as usize
    }
}

#[allow(clippy::cast_possible_truncation)]
const fn floor_three_div_pow2(value: usize, exponent: u64) -> usize {
    if exponent >= u128::BITS as u64 {
        0
    } else {
        ((value as u128 * 3) >> exponent as u32) as usize
    }
}

pub(crate) const fn floor_div_pow2(value: usize, exponent: u32) -> usize {
    if exponent >= usize::BITS {
        0
    } else {
        value >> exponent
    }
}

const fn base_two_loglog_ceiling(n: usize) -> usize {
    let loglog_ceiling = ceil_log2(ceil_log2(n));
    if loglog_ceiling == 0 {
        1
    } else {
        loglog_ceiling
    }
}

const fn ceil_log2(value: usize) -> usize {
    if value <= 1 {
        0
    } else {
        (usize::BITS - (value - 1).leading_zeros()) as usize
    }
}

pub(crate) const fn ceil_three_quarters(value: usize) -> usize {
    value - value / 4
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigError, FunnelDomainError, FunnelPlanError, FunnelPlanParameter, PaperConfig,
        TheoremDomainStatus,
    };

    #[test]
    fn rejects_invalid_configuration_inputs() {
        assert_eq!(PaperConfig::new(1, 3), Err(ConfigError::NTooSmall { n: 1 }));
        assert_eq!(PaperConfig::new(2, 0), Err(ConfigError::ExponentZero));
    }

    #[test]
    fn computes_exact_reserved_slots_and_insertion_target() {
        let config = PaperConfig::new(32_768, 3).unwrap();

        assert_eq!(config.n(), 32_768);
        assert_eq!(config.reserve_exponent(), 3);
        assert_eq!(config.floor_delta_n(), 4_096);
        assert_eq!(config.target_insertions(), 28_672);
    }

    #[test]
    fn exponents_at_least_as_wide_as_usize_reserve_no_slots() {
        for reserve_exponent in [usize::BITS, usize::BITS.saturating_add(1), u32::MAX] {
            let config = PaperConfig::new(32_768, reserve_exponent).unwrap();

            assert_eq!(config.floor_delta_n(), 0);
            assert_eq!(config.target_insertions(), 32_768);
        }
    }

    #[test]
    fn algorithm_domain_checks_do_not_claim_a_theorem_applies() {
        let below_funnel_domain = PaperConfig::new(32_768, 2).unwrap();
        assert_eq!(
            below_funnel_domain.elastic_domain_status(),
            TheoremDomainStatus::UnquantifiedAsymptoticPrecondition
        );
        assert_eq!(
            below_funnel_domain.funnel_domain_status(),
            Err(FunnelDomainError::ExponentBelowMinimum {
                reserve_exponent: 2,
                minimum: 3,
            })
        );

        let accepted_by_funnel = PaperConfig::new(32_768, 3).unwrap();
        assert_eq!(
            accepted_by_funnel.funnel_domain_status(),
            Ok(TheoremDomainStatus::UnquantifiedAsymptoticPrecondition)
        );
    }

    #[test]
    fn elastic_level_geometry_obeys_paper_invariants() {
        for n in 2..=4_096 {
            let plan = PaperConfig::new(n, 3).unwrap().elastic_plan();
            let lengths: Vec<_> = plan.level_lengths().collect();
            let expected_level_count = (usize::BITS - (n - 1).leading_zeros()) as usize;

            assert_eq!(lengths.len(), expected_level_count, "n={n}");
            assert!(lengths.iter().all(|&length| length > 0), "n={n}");
            assert_eq!(lengths.iter().sum::<usize>(), n, "n={n}");
            for adjacent in lengths.windows(2) {
                assert!(
                    adjacent[1].saturating_mul(2).abs_diff(adjacent[0]) <= 2,
                    "n={n}, current={}, next={}",
                    adjacent[0],
                    adjacent[1]
                );
            }
        }
    }

    #[test]
    fn elastic_batches_use_exact_formula_and_cap_at_target() {
        const RESERVE_EXPONENT_VALUES: [u32; 4] = [3, 4, 6, 8];
        const NON_POWER_OF_TWO_N_VALUES: [usize; 10] = [3, 5, 6, 7, 10, 17, 31, 33, 1_001, 4_095];

        for reserve_exponent in RESERVE_EXPONENT_VALUES {
            for n in NON_POWER_OF_TWO_N_VALUES {
                let config = PaperConfig::new(n, reserve_exponent).unwrap();
                let plan = config.elastic_plan();
                let levels: Vec<_> = plan.level_lengths().collect();
                let actual: Vec<_> = plan.batch_quotas().collect();
                let mut raw = Vec::with_capacity(levels.len());
                raw.push(ceil_three_quarters(levels[0]));
                for adjacent in levels.windows(2) {
                    let current = adjacent[0];
                    let next = adjacent[1];
                    raw.push(
                        current
                            - floor_div_pow2(current, reserve_exponent.saturating_add(1))
                            - ceil_three_quarters(current)
                            + ceil_three_quarters(next),
                    );
                }

                let mut remaining = config.target_insertions();
                let expected: Vec<_> = raw
                    .into_iter()
                    .map(|quota| {
                        let capped = quota.min(remaining);
                        remaining -= capped;
                        capped
                    })
                    .collect();

                assert_eq!(
                    actual, expected,
                    "n={n}, reserve_exponent={reserve_exponent}"
                );
                assert_eq!(
                    actual.iter().sum::<usize>(),
                    config.target_insertions(),
                    "n={n}, reserve_exponent={reserve_exponent}"
                );
            }
        }
    }

    #[test]
    fn funnel_canonical_plan_uses_exact_paper_geometry() {
        let config = PaperConfig::new(32_768, 3).unwrap();
        let plan = config.funnel_plan().unwrap();
        let counts: Vec<_> = plan.ordinary_bucket_counts().collect();
        let lengths: Vec<_> = plan.ordinary_level_lengths().collect();

        assert_eq!(plan.config(), config);
        assert_eq!(plan.alpha(), 22);
        assert_eq!(plan.beta(), 6);
        assert_eq!(plan.loglog_ceiling(), 4);
        assert_eq!(plan.fallback_bucket_width(), 8);
        assert_eq!(plan.special_len(), 3_056);
        assert_eq!(plan.special_primary_len(), 1_528);
        assert_eq!(plan.special_fallback_len(), 1_528);
        assert_eq!(plan.fallback_bucket_count(), 191);
        assert_eq!(config.target_insertions(), 28_672);
        assert_eq!(counts.len(), 22);
        assert_eq!(counts[0], 1_238);
        assert_eq!(
            counts,
            [
                1_238, 929, 697, 523, 393, 295, 222, 167, 126, 95, 72, 55, 41, 30, 22, 16, 12, 8,
                5, 3, 2, 1,
            ]
        );
        assert_eq!(counts.iter().sum::<usize>(), (32_768 - 3_056) / 6);
        assert_eq!(lengths.iter().sum::<usize>() + plan.special_len(), 32_768);
    }

    #[test]
    fn funnel_geometry_obeys_exact_formulas_across_a_grid() {
        const RESERVE_EXPONENT_VALUES: [u32; 4] = [3, 4, 6, 8];
        const N_VALUES: [usize; 4] = [32_768, 65_537, 100_000, 131_072];

        for reserve_exponent in RESERVE_EXPONENT_VALUES {
            for n in N_VALUES {
                assert_funnel_invariants(n, reserve_exponent);
            }
        }
    }

    #[test]
    fn funnel_special_length_is_the_largest_compatible_choice() {
        for (n, reserve_exponent) in [(32_768, 3), (50_000, 4), (131_072, 8)] {
            let plan = PaperConfig::new(n, reserve_exponent)
                .unwrap()
                .funnel_plan()
                .unwrap();
            let (_, upper) = independent_special_bounds(n, reserve_exponent);
            let alpha = usize::try_from(4_u128 * u128::from(reserve_exponent) + 10).unwrap();

            assert!((plan.special_len() + 1..=upper).all(|candidate| {
                !independent_special_is_compatible(
                    n,
                    candidate,
                    plan.beta(),
                    plan.fallback_bucket_width(),
                    alpha,
                )
            }));
        }
    }

    #[test]
    fn funnel_rejects_a_finite_special_array_that_cannot_be_tiled() {
        assert_eq!(
            PaperConfig::new(50_003, 4).unwrap().funnel_plan(),
            Err(FunnelPlanError::NoCompatibleSpecialLayout {
                lower: 1_563,
                upper: 2_343,
                beta: 8,
                loglog_ceiling: 4,
                fallback_bucket_width: 8,
            })
        );
    }

    #[test]
    fn funnel_plan_rejects_delta_above_the_concrete_domain() {
        let config = PaperConfig::new(32_768, 2).unwrap();

        assert_eq!(
            config.funnel_plan(),
            Err(FunnelPlanError::Domain(
                FunnelDomainError::ExponentBelowMinimum {
                    reserve_exponent: 2,
                    minimum: 3,
                }
            ))
        );
    }

    #[test]
    fn funnel_plan_reports_small_and_infeasible_geometry() {
        assert_eq!(
            PaperConfig::new(2, 3).unwrap().funnel_plan(),
            Err(FunnelPlanError::NoCompatibleSpecialLayout {
                lower: 1,
                upper: 0,
                beta: 6,
                loglog_ceiling: 1,
                fallback_bucket_width: 2,
            })
        );
        assert_eq!(
            PaperConfig::new(128, 3).unwrap().funnel_plan(),
            Err(FunnelPlanError::NoCompatibleSpecialLayout {
                lower: 8,
                upper: 12,
                beta: 6,
                loglog_ceiling: 3,
                fallback_bucket_width: 6,
            })
        );
    }

    #[test]
    fn funnel_plan_handles_extreme_inputs_without_overflow() {
        let extreme_exponent = PaperConfig::new(usize::MAX, u32::MAX)
            .unwrap()
            .funnel_plan();
        if usize::BITS >= 64 {
            assert_eq!(
                extreme_exponent,
                Err(FunnelPlanError::NoCompatibleSpecialLayout {
                    lower: 1,
                    upper: 0,
                    beta: usize::try_from(2_u128 * u128::from(u32::MAX)).unwrap(),
                    loglog_ceiling: 6,
                    fallback_bucket_width: 12,
                })
            );
        } else {
            assert_eq!(
                extreme_exponent,
                Err(FunnelPlanError::DerivedParameterOverflow {
                    parameter: FunnelPlanParameter::Alpha,
                    reserve_exponent: u32::MAX,
                })
            );
        }

        let plan = PaperConfig::new(usize::MAX - 2, 3)
            .unwrap()
            .funnel_plan()
            .unwrap();
        let ordinary_slots: u128 = plan
            .ordinary_level_lengths()
            .map(|length| length as u128)
            .sum();
        assert_eq!(
            ordinary_slots + plan.special_len() as u128,
            (usize::MAX - 2) as u128
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn funnel_plan_rejects_zero_bucket_fallback_even_when_zero_is_divisible() {
        assert_eq!(
            PaperConfig::new(12_297_829_382_473_034_485, 63)
                .unwrap()
                .funnel_plan(),
            Err(FunnelPlanError::NoCompatibleSpecialLayout {
                lower: 1,
                upper: 1,
                beta: 126,
                loglog_ceiling: 6,
                fallback_bucket_width: 12,
            })
        );
    }

    #[test]
    fn funnel_loglog_ceiling_changes_at_exact_base_two_boundaries() {
        let mut k = 0_u32;
        loop {
            let exponent = 1_u32 << k;
            if exponent >= usize::BITS {
                break;
            }
            let boundary = 1_usize << exponent;

            assert_result_loglog(boundary, usize::try_from(k).unwrap().max(1));
            assert_result_loglog(boundary + 1, usize::try_from(k + 1).unwrap().max(1));
            k += 1;
        }
    }

    #[test]
    fn funnel_special_selector_matches_an_exhaustive_small_reference() {
        const MAX_TOTAL_BUCKETS: usize = 400;

        for reserve_exponent in 3..=6 {
            let alpha = 4 * reserve_exponent as usize + 10;
            let beta = 2 * reserve_exponent as usize;
            let reachable = independent_reachable_totals(alpha, MAX_TOTAL_BUCKETS);

            for n in 2..=2_000 {
                let expected = brute_force_special_len(n, reserve_exponent, beta, &reachable);
                match (
                    PaperConfig::new(n, reserve_exponent).unwrap().funnel_plan(),
                    expected,
                ) {
                    (Ok(plan), Some(special_len)) => {
                        assert_eq!(
                            plan.special_len(),
                            special_len,
                            "n={n}, d={reserve_exponent}"
                        );
                    }
                    (Err(FunnelPlanError::NoCompatibleSpecialLayout { .. }), None) => {}
                    (actual, expected) => {
                        panic!(
                            "n={n}, d={reserve_exponent}, actual={actual:?}, expected={expected:?}"
                        )
                    }
                }
            }
        }
    }

    #[test]
    fn funnel_ordinary_iterators_preserve_exact_size_and_fused_contracts() {
        let plan = PaperConfig::new(32_768, 3).unwrap().funnel_plan().unwrap();
        let mut counts = plan.ordinary_bucket_counts();
        let mut lengths = plan.ordinary_level_lengths();

        for remaining in (1..=plan.alpha()).rev() {
            assert_eq!(counts.len(), remaining);
            assert_eq!(lengths.len(), remaining);
            assert_eq!(
                lengths.next(),
                counts.next().map(|count| count * plan.beta())
            );
        }
        assert_eq!(counts.len(), 0);
        assert_eq!(lengths.len(), 0);
        assert_eq!(counts.next(), None);
        assert_eq!(counts.next(), None);
        assert_eq!(lengths.next(), None);
        assert_eq!(lengths.next(), None);
    }

    #[test]
    fn funnel_reachable_path_sums_are_contiguous_in_a_small_reference_model() {
        for first in 1_usize..=64 {
            let mut states = std::collections::BTreeSet::from([(first, first)]);
            for level_count in 1..=24 {
                let sums: std::collections::BTreeSet<_> =
                    states.iter().map(|&(_, sum)| sum).collect();
                let minimum = *sums.first().unwrap();
                let maximum = *sums.last().unwrap();
                assert_eq!(
                    sums.len(),
                    maximum - minimum + 1,
                    "first={first}, level_count={level_count}"
                );

                let mut next_states = std::collections::BTreeSet::new();
                for &(current, sum) in &states {
                    for next in 1..=current {
                        if (4_u128 * next as u128).abs_diff(3_u128 * current as u128) <= 4 {
                            next_states.insert((next, sum + next));
                        }
                    }
                }
                states = next_states;
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn assert_funnel_invariants(n: usize, reserve_exponent: u32) {
        let config = PaperConfig::new(n, reserve_exponent).unwrap();
        let plan = config.funnel_plan().unwrap();
        let counts: Vec<_> = plan.ordinary_bucket_counts().collect();
        let lengths: Vec<_> = plan.ordinary_level_lengths().collect();
        let (lower, upper) = independent_special_bounds(n, reserve_exponent);
        let expected_alpha = usize::try_from(4_u128 * u128::from(reserve_exponent) + 10).unwrap();
        let expected_beta = usize::try_from(2_u128 * u128::from(reserve_exponent)).unwrap();
        let expected_loglog_ceiling = independent_loglog_ceiling(n);
        let expected_fallback_width = 2 * expected_loglog_ceiling;
        let expected_target = n - n / usize::try_from(1_u128 << reserve_exponent).unwrap();

        assert_eq!(
            plan.config(),
            config,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            plan.alpha(),
            expected_alpha,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            plan.beta(),
            expected_beta,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            plan.loglog_ceiling(),
            expected_loglog_ceiling,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            plan.fallback_bucket_width(),
            expected_fallback_width,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            config.target_insertions(),
            expected_target,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert!(
            (lower..=upper).contains(&plan.special_len()),
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            (n - plan.special_len()) % expected_beta,
            0,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            counts.len(),
            expected_alpha,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert!(
            counts.iter().all(|&count| count > 0),
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            counts.iter().sum::<usize>(),
            (n - plan.special_len()) / expected_beta,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            lengths,
            counts
                .iter()
                .map(|&count| count * expected_beta)
                .collect::<Vec<_>>(),
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            lengths.iter().sum::<usize>() + plan.special_len(),
            n,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        for adjacent in counts.windows(2) {
            let current = adjacent[0] as u128;
            let next = adjacent[1] as u128;
            assert!(
                next <= current,
                "n={n}, reserve_exponent={reserve_exponent}"
            );
            assert!(
                (4_u128 * next).abs_diff(3_u128 * current) <= 4,
                "n={n}, reserve_exponent={reserve_exponent}, current={current}, next={next}"
            );
        }
        assert_eq!(
            plan.special_primary_len() + plan.special_fallback_len(),
            plan.special_len(),
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert!(
            plan.special_primary_len() >= plan.special_fallback_len(),
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert!(
            plan.special_primary_len()
                .abs_diff(plan.special_fallback_len())
                <= 1,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert!(
            plan.special_fallback_len() >= expected_fallback_width,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            plan.special_fallback_len() % expected_fallback_width,
            0,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert_eq!(
            plan.fallback_bucket_count() * expected_fallback_width,
            plan.special_fallback_len(),
            "n={n}, reserve_exponent={reserve_exponent}"
        );
        assert!(
            plan.fallback_bucket_count() > 0,
            "n={n}, reserve_exponent={reserve_exponent}"
        );
    }

    fn assert_result_loglog(n: usize, expected: usize) {
        match PaperConfig::new(n, 3).unwrap().funnel_plan() {
            Ok(plan) => {
                assert_eq!(plan.loglog_ceiling(), expected, "n={n}");
                assert_eq!(plan.fallback_bucket_width(), 2 * expected, "n={n}");
            }
            Err(FunnelPlanError::NoCompatibleSpecialLayout {
                loglog_ceiling,
                fallback_bucket_width,
                ..
            }) => {
                assert_eq!(loglog_ceiling, expected, "n={n}");
                assert_eq!(fallback_bucket_width, 2 * expected, "n={n}");
            }
            Err(error) => panic!("n={n}, unexpected error={error:?}"),
        }
    }

    fn brute_force_special_len(
        n: usize,
        reserve_exponent: u32,
        beta: usize,
        reachable_totals: &std::collections::BTreeSet<usize>,
    ) -> Option<usize> {
        let (lower, upper) = independent_special_bounds(n, reserve_exponent);
        if lower > upper {
            return None;
        }
        let fallback_width = 2 * independent_loglog_ceiling(n);

        (lower..=upper).rev().find(|&special_len| {
            let main_len = n - special_len;
            let fallback_len = special_len / 2;
            main_len.is_multiple_of(beta)
                && fallback_len >= fallback_width
                && fallback_len.is_multiple_of(fallback_width)
                && reachable_totals.contains(&(main_len / beta))
        })
    }

    fn independent_special_is_compatible(
        n: usize,
        special_len: usize,
        beta: usize,
        fallback_width: usize,
        alpha: usize,
    ) -> bool {
        let main_len = n - special_len;
        let fallback_len = special_len / 2;
        main_len.is_multiple_of(beta)
            && fallback_len >= fallback_width
            && fallback_len.is_multiple_of(fallback_width)
            && main_len / beta >= alpha
    }

    fn independent_reachable_totals(
        level_count: usize,
        maximum_total: usize,
    ) -> std::collections::BTreeSet<usize> {
        let mut states: std::collections::BTreeSet<_> =
            (1..=maximum_total).map(|first| (first, first)).collect();
        for _ in 1..level_count {
            let mut next_states = std::collections::BTreeSet::new();
            for &(current, sum) in &states {
                for next in 1..=current {
                    if (4_u128 * next as u128).abs_diff(3_u128 * current as u128) <= 4
                        && sum + next <= maximum_total
                    {
                        next_states.insert((next, sum + next));
                    }
                }
            }
            states = next_states;
        }
        states.into_iter().map(|(_, sum)| sum).collect()
    }

    fn independent_loglog_ceiling(n: usize) -> usize {
        independent_ceil_log2(independent_ceil_log2(n)).max(1)
    }

    fn independent_ceil_log2(value: usize) -> usize {
        let mut exponent = 0;
        let mut power = 1_u128;
        while power < value as u128 {
            power *= 2;
            exponent += 1;
        }
        exponent
    }

    fn independent_special_bounds(n: usize, reserve_exponent: u32) -> (usize, usize) {
        let lower_denominator = 1_u128 << (reserve_exponent + 1);
        let upper_denominator = 1_u128 << (reserve_exponent + 2);
        let n = n as u128;
        let lower = n / lower_denominator + u128::from(!n.is_multiple_of(lower_denominator));
        let upper = (3 * n) / upper_denominator;
        (
            usize::try_from(lower).unwrap(),
            usize::try_from(upper).unwrap(),
        )
    }

    fn ceil_three_quarters(value: usize) -> usize {
        usize::try_from(((value as u128) * 3).div_ceil(4)).unwrap()
    }

    fn floor_div_pow2(value: usize, exponent: u32) -> usize {
        if exponent >= usize::BITS {
            0
        } else {
            value >> exponent
        }
    }
}
