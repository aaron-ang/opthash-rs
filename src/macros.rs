//! Crate-internal macros.

/// Declare one backend's public type-alias surface.
///
/// Each backend only *names* its instantiations of the generic
/// [`map::HashMap`](crate::map::HashMap) / [`set::HashSet`](crate::set::HashSet)
/// shells; the generic-argument threading lives here once. Each entry is its
/// doc attributes, alias name, and the unprefixed shell type. Categories are the distinct
/// generic shapes: `*_no_lifetime` (owned/consuming, `<K, V, S, A>`), `*_ref`
/// (borrowing, carries `'a`), and `map_extract_if` (threads its `F` after the
/// table type).
macro_rules! declare_backend_aliases {
    (
        table = $Table:ident,
        // map, no lifetime: `<K, V, S, A>` -> `map::Target<K, V, Table<K, V, S, A>>`
        map_no_lifetime { $($(#[$mp_meta:meta])* $mp_alias:ident => $mp_target:ident),* $(,)? },
        // map, borrowing (`'a`): `map::Target<'a, K, V, Table<K, V, S, A>>`
        map_ref { $($(#[$mr_meta:meta])* $mr_alias:ident => $mr_target:ident),* $(,)? },
        // map `ExtractIf`: `<'a, K, V, F, S, A>` -> `map::ExtractIf<'a, K, V, Table<..>, F>`
        map_extract_if { $(#[$mx_meta:meta])* $mx_alias:ident },
        // set, no lifetime: `<T, S, A>` -> `set::Target<T, Table<T, (), S, A>>`
        set_no_lifetime { $($(#[$sp_meta:meta])* $sp_alias:ident => $sp_target:ident),* $(,)? },
        // set, borrowing (`'a`): `set::Target<'a, T, Table<T, (), S, A>>`
        set_ref { $($(#[$sr_meta:meta])* $sr_alias:ident => $sr_target:ident),* $(,)? },
    ) => {
        $(
            $(#[$mp_meta])*
            pub type $mp_alias<
                K,
                V,
                S = $crate::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::map::$mp_target<K, V, $Table<K, V, S, A>>;
        )*
        $(
            $(#[$mr_meta])*
            pub type $mr_alias<
                'a,
                K,
                V,
                S = $crate::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::map::$mr_target<'a, K, V, $Table<K, V, S, A>>;
        )*
        $(#[$mx_meta])*
        pub type $mx_alias<
            'a,
            K,
            V,
            F,
            S = $crate::DefaultHashBuilder,
            A = allocator_api2::alloc::Global,
        > = $crate::map::ExtractIf<'a, K, V, $Table<K, V, S, A>, F>;
        $(
            $(#[$sp_meta])*
            pub type $sp_alias<
                T,
                S = $crate::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::set::$sp_target<T, $Table<T, (), S, A>>;
        )*
        $(
            $(#[$sr_meta])*
            pub type $sr_alias<
                'a,
                T,
                S = $crate::DefaultHashBuilder,
                A = allocator_api2::alloc::Global,
            > = $crate::set::$sr_target<'a, T, $Table<T, (), S, A>>;
        )*
    };
}

pub(crate) use declare_backend_aliases;
