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
    /// Validates exact geometry inputs.
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

    /// Returns `floor(delta * n)` using exact integer arithmetic.
    #[must_use]
    pub(crate) const fn floor_delta_n(&self) -> usize {
        floor_div_pow2(self.n, self.reserve_exponent as u64)
    }

    /// Returns the exact insertion budget, `n - floor(delta * n)`.
    #[must_use]
    pub(crate) const fn max_insertions(&self) -> usize {
        self.n - self.floor_delta_n()
    }

    /// Creates a pure logical Funnel geometry plan.
    ///
    /// # Errors
    ///
    /// Returns [`FunnelPlanError`] when the concrete Funnel domain
    /// (`delta <= 1/8`, or equivalently `reserve_exponent >= 3`) is not met, a
    /// derived parameter overflows, the paper's special-array interval has no
    /// compatible length, or the ordinary levels have no positive exact
    /// partition. The paper's remaining preconditions are asymptotic and carry
    /// no concrete constant to check.
    pub(crate) fn funnel_plan(&self) -> Result<FunnelPlan, FunnelPlanError> {
        if self.reserve_exponent < 3 {
            return Err(FunnelPlanError::ExponentBelowMinimum {
                reserve_exponent: self.reserve_exponent,
                minimum: 3,
            });
        }

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
    /// Funnel requires `delta <= 1/8`, or equivalently `reserve_exponent >= 3`.
    ExponentBelowMinimum {
        /// The rejected exponent.
        reserve_exponent: u32,
        /// The smallest accepted exponent.
        minimum: u32,
    },
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
    pub(crate) fn ordinary_bucket_counts(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        FunnelBucketCounts {
            next_count: Some(self.first_bucket_count),
            remaining_sum: (self.config.n - self.special_len) / self.beta,
            remaining_levels: self.alpha,
        }
    }
}

impl ElasticPlan {
    /// Returns the paper's exact `ceil(log2(n))` number of non-empty levels.
    #[must_use]
    pub(crate) const fn level_count(&self) -> usize {
        ceil_log2(self.config.n)
    }

    /// Iterates over logical level lengths in paper order.
    ///
    /// The deterministic construction repeatedly gives the next level
    /// `ceil(remaining / 2)` slots and gives the final level all residual
    /// slots. Thus the lengths sum to `n`, are non-empty, and each next length
    /// is within one of half the preceding length in the real-valued sense.
    pub(crate) fn level_lengths(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        LevelLengths {
            remaining_slots: self.config.n,
            remaining_levels: self.level_count(),
        }
    }

    /// Iterates over the exact Elastic batch quotas from paper §4, capped in
    /// order at [`PaperConfig::max_insertions`].
    ///
    /// `B_0` is `ceil(3|A_1|/4)`. Each later quota is:
    ///
    /// ```text
    /// |A_i| - floor(delta|A_i|/2) - ceil(3|A_i|/4) + ceil(3|A_(i+1)|/4)
    /// ```
    ///
    /// Trailing quotas are zero once the insertion target is reached.
    pub(crate) fn batch_quotas(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        BatchQuotas {
            levels: LevelLengths {
                remaining_slots: self.config.n,
                remaining_levels: self.level_count(),
            },
            previous_level: None,
            remaining_insertions: self.config.max_insertions(),
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
                - floor_div_pow2(previous, u64::from(self.reserve_exponent) + 1)
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

/// Returns the smallest `n >= from` whose special-array ceiling
/// `floor(3n / 2^(d+2))` can hold two fallback buckets, a necessary condition
/// for [`PaperConfig::funnel_plan`]. The bucket width grows with `n`, so the
/// bound is iterated to its least fixed point. `None` on overflow.
pub(crate) fn funnel_minimum_slots(reserve_exponent: u32, from: usize) -> Option<usize> {
    let mut n = from;
    loop {
        let minimum_special_len = 4 * base_two_loglog_ceiling(n) as u128;
        let required = minimum_special_len
            .checked_mul(1_u128.checked_shl(reserve_exponent.checked_add(2)?)?)?
            .div_ceil(3);
        let required = usize::try_from(required).ok()?;
        if required <= n {
            return Some(n);
        }
        n = required;
    }
}

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

/// Returns `floor(value / 2^exponent)`; the wide exponent lets callers pass
/// `d + 1` without an overflow check.
pub(crate) const fn floor_div_pow2(value: usize, exponent: u64) -> usize {
    if exponent >= usize::BITS as u64 {
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

const fn ceil_three_quarters(value: usize) -> usize {
    value - value / 4
}

#[cfg(test)]
impl PaperConfig {
    pub(crate) const fn n(&self) -> usize {
        self.n
    }

    pub(crate) const fn reserve_exponent(&self) -> u32 {
        self.reserve_exponent
    }
}

#[cfg(test)]
impl FunnelPlan {
    pub(crate) const fn config(&self) -> PaperConfig {
        self.config
    }

    pub(crate) const fn special_len(&self) -> usize {
        self.special_len
    }

    pub(crate) fn ordinary_level_lengths(&self) -> impl ExactSizeIterator<Item = usize> + Clone {
        let beta = self.beta;
        self.ordinary_bucket_counts().map(move |count| count * beta)
    }
}

#[cfg(test)]
mod tests;
