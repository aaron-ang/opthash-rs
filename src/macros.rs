//! Crate-internal macros.

/// Declare one backend's public type-alias surface.
///
/// Each backend only *names* its instantiations of the generic
/// [`map::HashMap`](crate::map::HashMap) / [`set::HashSet`](crate::set::HashSet)
/// shells; the generic-argument threading lives here once. Pass `doc`, alias
/// name, and the unprefixed shell type per entry. Categories are the distinct
/// generic shapes: `*_no_lifetime` (owned/consuming, `<K, V, S, A>`), `*_ref`
/// (borrowing, carries `'a`), and `map_extract_if` (threads its `F` after the
/// table type).
macro_rules! declare_backend_aliases {
    (
        table = $Table:ident,
        // map, no lifetime: `<K, V, S, A>` -> `map::Target<K, V, Table<K, V, S, A>>`
        map_no_lifetime { $($mp_doc:literal $mp_alias:ident => $mp_target:ident),* $(,)? },
        // map, borrowing (`'a`): `map::Target<'a, K, V, Table<K, V, S, A>>`
        map_ref { $($mr_doc:literal $mr_alias:ident => $mr_target:ident),* $(,)? },
        // map `ExtractIf`: `<'a, K, V, F, S, A>` -> `map::ExtractIf<'a, K, V, Table<..>, F>`
        map_extract_if { $mx_doc:literal $mx_alias:ident },
        // set, no lifetime: `<T, S, A>` -> `set::Target<T, Table<T, (), S, A>>`
        set_no_lifetime { $($sp_doc:literal $sp_alias:ident => $sp_target:ident),* $(,)? },
        // set, borrowing (`'a`): `set::Target<'a, T, Table<T, (), S, A>>`
        set_ref { $($sr_doc:literal $sr_alias:ident => $sr_target:ident),* $(,)? },
    ) => {
        $(
            #[doc = $mp_doc]
            pub type $mp_alias<
                K,
                V,
                S = $crate::common::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::map::$mp_target<K, V, $Table<K, V, S, A>>;
        )*
        $(
            #[doc = $mr_doc]
            pub type $mr_alias<
                'a,
                K,
                V,
                S = $crate::common::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::map::$mr_target<'a, K, V, $Table<K, V, S, A>>;
        )*
        #[doc = $mx_doc]
        pub type $mx_alias<
            'a,
            K,
            V,
            F,
            S = $crate::common::DefaultHashBuilder,
            A = allocator_api2::alloc::Global,
        > = $crate::map::ExtractIf<'a, K, V, $Table<K, V, S, A>, F>;
        $(
            #[doc = $sp_doc]
            pub type $sp_alias<
                T,
                S = $crate::common::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::set::$sp_target<T, $Table<T, (), S, A>>;
        )*
        $(
            #[doc = $sr_doc]
            pub type $sr_alias<
                'a,
                T,
                S = $crate::common::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::set::$sr_target<'a, T, $Table<T, (), S, A>>;
        )*
    };
}

pub(crate) use declare_backend_aliases;
