//! The lookup schedule: one route per `(level, probe)` pair a lookup may
//! visit, in query-position order.

use alloc::vec::Vec;

use super::{GENERAL_REDUCTION, Level};
use crate::error::TryReserveError;
use crate::exact::probe;
use crate::raw::control::CTRL_EMPTY;

/// One lookup probe, carrying what the walk reads from its level so a step
/// touches the route alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct PhiRoute {
    /// The distance of the level's bit of a closed-level set below the top
    /// bit in the low byte, the index shift in the next and the sequence
    /// index in the high half, so one load brings all three. Both byte
    /// fields are below the word width: used as a shift amount, the word
    /// itself moves the level's bit to the top, and the top bit down to the
    /// level's.
    packed: u64,
    control: *const u8,
}

const _: () = assert!(size_of::<PhiRoute>() <= 16);

const INDEX_SHIFT_BIT: u32 = u8::BITS;
const SEQUENCE_INDEX_BIT: u32 = u32::BITS;

const fn pack(level: u8, index_shift: u8, sequence_index: u32) -> u64 {
    assert!(level <= SENTINEL_LEVEL && (index_shift as u32) < u64::BITS);
    (TOP_LEVEL_BIT - level_bit(level)) as u64
        | (index_shift as u64) << INDEX_SHIFT_BIT
        | (sequence_index as u64) << SEQUENCE_INDEX_BIT
}

impl PhiRoute {
    /// The route of `level`'s logical probe `logical_probe_index`. A level
    /// that needs the general range reduction has no shift, so its route
    /// probes the sentinel's control bytes instead: a walk reads `EMPTY`
    /// there and matches nothing.
    fn new<T>(level: usize, region: &Level<T>, logical_probe_index: u64) -> Self {
        let (index_shift, control) = if region.index_shift() == GENERAL_REDUCTION {
            (SENTINEL_LEVEL, SENTINEL.control)
        } else {
            (
                u8::try_from(region.index_shift()).expect("Elastic index shift fits u8"),
                region.ctrl_ptr.cast_const(),
            )
        };
        Self {
            packed: pack(
                u8::try_from(level).expect("Elastic level count fits u8"),
                index_shift,
                probe::elastic_sequence_index(
                    u32::try_from(level).expect("Elastic level count fits u32"),
                    logical_probe_index,
                ),
            ),
            control,
        }
    }

    /// The direct route: level zero's first probe, or the sentinel's control
    /// bytes for a table without levels. No walk steps onto it, so its word
    /// is its index shift alone, ready to shift by.
    fn direct<T>(levels: &[Level<T>]) -> Self {
        let Some(region) = levels.first() else {
            return Self {
                packed: u64::from(SENTINEL_LEVEL),
                control: SENTINEL.control,
            };
        };
        let route = Self::new(0, region, 0);
        Self {
            packed: u64::from(route.index_shift()),
            control: route.control,
        }
    }

    /// The route at `route`. Where the target has a load as wide as the
    /// route, the packed word comes out of one such load and the pointer is
    /// read as a pointer beside it: the two reads fold into the wide one, and
    /// a walk that skips the route keeps no second pointer to it.
    ///
    /// # Safety
    ///
    /// `route` addresses a route of a [`ProbeSchedule`].
    #[inline]
    pub(super) unsafe fn load(route: *const Self) -> Self {
        #[cfg(all(target_pointer_width = "64", target_endian = "little"))]
        {
            const _: () = assert!(
                size_of::<PhiRoute>() == size_of::<u128>()
                    && core::mem::offset_of!(PhiRoute, packed) == 0
            );
            // SAFETY: the route is sixteen initialized bytes, by the
            // caller's contract and the layout asserted above.
            let both = unsafe { route.cast::<u128>().read_unaligned() };
            #[allow(clippy::cast_possible_truncation)]
            Self {
                packed: both as u64,
                // SAFETY: the caller's contract.
                control: unsafe { (*route).control },
            }
        }
        #[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
        // SAFETY: the caller's contract.
        unsafe {
            *route
        }
    }

    /// [`Self::index_shift`] of the direct route.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn direct_index_shift(&self) -> u32 {
        self.packed as u32
    }

    /// Level the route probes; [`SENTINEL_LEVEL`] for the sentinel.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn level(&self) -> u8 {
        (TOP_LEVEL_BIT - (self.packed as u8 & TOP_LEVEL_BIT)).wrapping_sub(1) & TOP_LEVEL_BIT
    }

    /// Whether `closed_levels` holds the route's level.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn is_closed(&self, closed_levels: u64) -> bool {
        closed_levels.wrapping_shl(self.packed as u32) >> TOP_LEVEL_BIT != 0
    }

    /// `closed_levels` with the route's level.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn close(&self, closed_levels: u64) -> u64 {
        closed_levels | (1_u64 << TOP_LEVEL_BIT).wrapping_shr(self.packed as u32)
    }

    /// Shift that reduces a probe word to a slot of the route's level.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn index_shift(&self) -> u32 {
        u32::from((self.packed >> INDEX_SHIFT_BIT) as u8)
    }

    /// The route's [`probe::elastic_sequence_index`].
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn sequence_index(&self) -> u32 {
        (self.packed >> SEQUENCE_INDEX_BIT) as u32
    }

    /// Control bytes of the route's level.
    #[inline]
    pub(super) fn control(&self) -> *const u8 {
        self.control
    }

    /// `(level, logical probe)` the route stands for.
    pub(super) fn coordinates(&self) -> (u32, u64) {
        probe::elastic_sequence_coordinates(self.sequence_index())
    }

    /// Packed retry-zero counter of the route, for the general reduction.
    #[inline]
    pub(super) fn counter_base(&self) -> u32 {
        let (level, logical) = self.coordinates();
        probe::elastic_counter_base(level, logical)
    }
}

/// Control bytes the sentinel route probes: its shift leaves one index bit.
static SENTINEL_CONTROL: [u8; 2] = [CTRL_EMPTY; 2];

/// Level of the sentinel route, above every real level.
pub(super) const SENTINEL_LEVEL: u8 = 63;
const _: () = assert!(SENTINEL_LEVEL as u32 == u64::BITS - 1);

/// Top bit position of a lookup's closed-level set.
const TOP_LEVEL_BIT: u8 = 63;

/// The sentinel's bit of a closed-level set, the lowest: a stored route
/// summary keeps it clear, so a walk always stops at the sentinel.
pub(super) const SENTINEL_BIT: u64 = 1;

/// Bit position of `level` in a closed-level set: one above the level for a
/// real level, the lowest for the sentinel.
const fn level_bit(level: u8) -> u8 {
    level.wrapping_add(1) & TOP_LEVEL_BIT
}

const SENTINEL: PhiRoute = PhiRoute {
    packed: pack(SENTINEL_LEVEL, SENTINEL_LEVEL, 0),
    control: SENTINEL_CONTROL.as_ptr(),
};

/// Storage reserved for a [`ProbeSchedule`], taken before the levels it
/// will address exist.
pub(super) struct ProbeScheduleRoom {
    routes: Vec<PhiRoute>,
}

impl ProbeScheduleRoom {
    /// Room for `route_capacity` routes.
    pub(super) fn try_with_capacity(route_capacity: usize) -> Result<Self, TryReserveError> {
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(route_capacity + FIXED_ROUTES)
            .map_err(|_| TryReserveError::AllocError)?;
        Ok(Self { routes })
    }

    /// The empty schedule of `levels`.
    pub(super) fn schedule<T>(self, levels: &[Level<T>]) -> ProbeSchedule {
        let mut routes = self.routes;
        routes.push(PhiRoute::direct(levels));
        routes.push(SENTINEL);
        ProbeSchedule {
            routes,
            entry_origin: entry_origin(levels),
        }
    }
}

/// Routes a schedule holds besides the ones pushed: the direct route and the
/// sentinel.
const FIXED_ROUTES: usize = 2;

/// The direct route, then the lookup routes in query-position order, closed
/// by a sentinel route so a walk needs no end test: the sentinel's level is
/// open in every walk and its probe reads an `EMPTY` control byte, which is
/// where a walk stops.
///
/// Every route addresses a level of the slice its schedule was built for:
/// [`ProbeScheduleRoom::schedule`], [`Self::clone_onto`] and [`Self::push`]
/// each take that slice, and a route holds only what [`PhiRoute::new`]
/// derives from one of its levels.
pub(super) struct ProbeSchedule {
    /// The direct route, the pushed routes, then the sentinel. No method
    /// leaves the first or the last off, so a walk from [`Self::direct`]
    /// always reaches the sentinel.
    routes: Vec<PhiRoute>,
    /// See [`entry_origin`].
    entry_origin: *mut u8,
}

/// Where the entry of a control byte at address zero would lie. The arena
/// lays the levels' control bytes out back to back and their entries in the
/// same order, so an entry's address is this plus its control byte's address
/// times the entry size.
fn entry_origin<T>(levels: &[Level<T>]) -> *mut u8 {
    let origin_of = |region: &Level<T>| {
        region
            .data_ptr
            .cast::<u8>()
            .wrapping_sub(region.ctrl_ptr.addr().wrapping_mul(size_of::<T>()))
    };
    let origin = levels.first().map_or(core::ptr::null_mut(), origin_of);
    debug_assert!(levels.iter().all(|region| origin_of(region) == origin));
    origin
}

impl ProbeSchedule {
    /// Byte offset from the entry origin of the entry beside control byte
    /// `slot` of the control bytes at `control`.
    #[inline]
    pub(super) fn entry_offset<T>(control: *const u8, slot: usize) -> usize {
        control
            .addr()
            .wrapping_add(slot)
            .wrapping_mul(size_of::<T>())
    }

    /// The entry at [`Self::entry_offset`] `offset`.
    ///
    /// # Safety
    ///
    /// The offset is that of a control byte of the levels this schedule was
    /// built for, and `T` is their entry type.
    #[inline]
    pub(super) unsafe fn entry_at<T>(&self, offset: usize) -> *mut T {
        self.entry_origin.wrapping_add(offset).cast()
    }

    /// A copy of `self` with room for `route_capacity` routes, each route
    /// addressing its level in `levels`.
    pub(super) fn clone_onto<T>(&self, route_capacity: usize, levels: &[Level<T>]) -> Self {
        let mut routes = Vec::with_capacity(route_capacity + FIXED_ROUTES);
        routes.push(PhiRoute::direct(levels));
        routes.extend(self.routes().iter().map(|route| {
            let (level, logical_probe_index) = route.coordinates();
            let level = level as usize;
            PhiRoute::new(level, &levels[level], logical_probe_index)
        }));
        routes.push(SENTINEL);
        Self {
            routes,
            entry_origin: entry_origin(levels),
        }
    }

    /// The pushed routes, in query-position order.
    #[inline]
    pub(super) fn routes(&self) -> &[PhiRoute] {
        &self.routes[1..self.routes.len() - 1]
    }

    /// The direct route, which every lookup probes first. Every route from
    /// it up to and including the sentinel, whose level is
    /// [`SENTINEL_LEVEL`], may be read.
    #[inline]
    pub(super) fn direct(&self) -> *const PhiRoute {
        self.routes.as_ptr()
    }

    /// Drops the pushed routes.
    pub(super) fn clear(&mut self) {
        self.routes.truncate(1);
        self.routes.push(SENTINEL);
    }

    /// Appends the route of logical probe `logical_probe_index` of level
    /// `level` of `levels`, the slice this schedule was built for or a
    /// prefix of it. The caller appends routes in query-position order.
    pub(super) fn push<T>(&mut self, levels: &[Level<T>], level: usize, logical_probe_index: u64) {
        let sentinel = self.routes.len() - 1;
        self.routes[sentinel] = PhiRoute::new(level, &levels[level], logical_probe_index);
        self.routes.push(SENTINEL);
    }

    /// Whether every route is the one its level in `levels` gives.
    #[cfg(test)]
    pub(super) fn addresses<T>(&self, levels: &[Level<T>]) -> bool {
        self.routes[0] == PhiRoute::direct(levels)
            && self.entry_origin == entry_origin(levels)
            && self.routes().iter().all(|route| {
                let (level, logical_probe_index) = route.coordinates();
                let level = level as usize;
                *route == PhiRoute::new(level, &levels[level], logical_probe_index)
            })
    }

    #[cfg(test)]
    pub(super) fn route_capacity(&self) -> usize {
        self.routes.capacity() - FIXED_ROUTES
    }

    #[cfg(test)]
    pub(super) fn ends_with_sentinel(&self) -> bool {
        self.routes.last() == Some(&SENTINEL)
    }
}
