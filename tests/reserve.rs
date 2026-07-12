use opthash::{
    ElasticHashMap, FunnelHashMap, ReserveFraction, ReserveFractionError, TryBuildError,
};

#[test]
fn default_is_exactly_one_eighth() {
    let reserve = ReserveFraction::DEFAULT;

    assert_eq!(reserve.exponent(), 3);
    assert_eq!(reserve.as_f64(), Some(0.125));
    assert_eq!(reserve.floor_reserved(17), 2);
    assert_eq!(reserve.floor_half_reserved(17), 1);
}

#[test]
fn exponent_constructor_rejects_zero_and_handles_unrepresentable_floats() {
    assert_eq!(
        ReserveFraction::from_exponent(0),
        Err(ReserveFractionError::ExponentZero)
    );

    let reserve = ReserveFraction::from_exponent(u32::MAX).unwrap();
    assert_eq!(reserve.exponent(), u32::MAX);
    assert_eq!(reserve.as_f64(), None);
    assert_eq!(reserve.floor_reserved(usize::MAX), 0);
    assert_eq!(reserve.floor_half_reserved(usize::MAX), 0);
}

#[test]
fn float_constructor_accepts_exact_inverse_powers_of_two() {
    for (value, exponent) in [
        (0.5, 1),
        (0.125, 3),
        (f64::MIN_POSITIVE, 1_022),
        (f64::from_bits(1_u64 << 51), 1_023),
        (f64::from_bits(1), 1_074),
    ] {
        let reserve = ReserveFraction::try_from(value).unwrap();
        assert_eq!(reserve.exponent(), exponent);
        assert_eq!(reserve.as_f64(), Some(value));
    }
}

#[test]
fn float_constructor_rejects_values_outside_the_open_unit_interval() {
    for (value, expected) in [
        (f64::NAN, ReserveFractionError::NonFinite),
        (f64::INFINITY, ReserveFractionError::NonFinite),
        (f64::NEG_INFINITY, ReserveFractionError::NonFinite),
        (0.0, ReserveFractionError::NonPositive),
        (-0.0, ReserveFractionError::NonPositive),
        (-0.5, ReserveFractionError::NonPositive),
        (1.0, ReserveFractionError::NotBelowOne),
        (2.0, ReserveFractionError::NotBelowOne),
    ] {
        assert_eq!(ReserveFraction::try_from(value), Err(expected));
    }
}

#[test]
fn float_constructor_rejects_non_inverse_powers_of_two() {
    for value in [0.75, 0.375, 0.1, f64::from_bits(3)] {
        assert_eq!(
            ReserveFraction::try_from(value),
            Err(ReserveFractionError::NotInversePowerOfTwo)
        );
    }
}

#[test]
fn integer_reserve_rounding_is_exact_at_word_boundaries() {
    let one_half = ReserveFraction::from_exponent(1).unwrap();
    assert_eq!(one_half.floor_reserved(usize::MAX), usize::MAX >> 1);
    assert_eq!(one_half.floor_half_reserved(usize::MAX), usize::MAX >> 2);

    let last_nonzero = ReserveFraction::from_exponent(usize::BITS - 1).unwrap();
    assert_eq!(last_nonzero.floor_reserved(usize::MAX), 1);
    assert_eq!(last_nonzero.floor_half_reserved(usize::MAX), 0);
}

#[test]
fn maps_report_the_configured_reserve() {
    let default_elastic = ElasticHashMap::<u64, u64>::with_capacity(64);
    let default_funnel = FunnelHashMap::<u64, u64>::with_capacity(64);
    assert_eq!(default_elastic.reserve_fraction(), ReserveFraction::DEFAULT);
    assert_eq!(default_funnel.reserve_fraction(), ReserveFraction::DEFAULT);

    let reserve = ReserveFraction::from_exponent(4).unwrap();
    let elastic = ElasticHashMap::<u64, u64>::with_capacity_and_reserve(64, reserve);
    let funnel = FunnelHashMap::<u64, u64>::with_capacity_and_reserve(64, reserve);
    assert_eq!(elastic.reserve_fraction(), reserve);
    assert_eq!(funnel.reserve_fraction(), reserve);
}

#[test]
fn fallible_float_compatibility_constructor_rejects_non_dyadic_input() {
    let result = ElasticHashMap::<u64, u64>::try_with_capacity_and_reserve_fraction(64, 0.1);

    assert!(matches!(
        result,
        Err(TryBuildError::InvalidReserveFraction(
            ReserveFractionError::NotInversePowerOfTwo
        ))
    ));
}

#[test]
fn funnel_fallible_constructor_rejects_reserve_above_one_eighth() {
    let reserve = ReserveFraction::from_exponent(2).unwrap();
    let result = FunnelHashMap::<u64, u64>::try_with_capacity_and_reserve(64, reserve);

    assert!(matches!(
        result,
        Err(TryBuildError::FunnelExponentBelowMinimum {
            reserve_exponent: 2,
            minimum: 3
        })
    ));
}

#[test]
fn infallible_float_compatibility_constructor_no_longer_clamps() {
    let result = std::panic::catch_unwind(|| {
        FunnelHashMap::<u64, u64>::with_capacity_and_reserve_fraction(64, 0.5)
    });

    assert!(result.is_err());
}
