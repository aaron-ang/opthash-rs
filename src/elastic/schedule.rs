//! The lookup schedule: one route per `(level, probe)` pair a lookup may
//! visit, in query-position order.

use alloc::vec::Vec;

use super::{GENERAL_REDUCTION, Level};
use crate::error::TryReserveError;
use crate::exact::probe;
use crate::raw::control::CTRL_EMPTY;

/// One lookup probe, carrying what the walk reads from its level so a step
/// touches the route alone.
///
/// `repr(C)` keeps the two words a step tests and multiplies adjacent, and
/// the two a probe reduces and reads through adjacent, so each pair comes in
/// one load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct PhiRoute {
    /// The level's bit of a closed-level set, alone, so a step tests it
    /// against the set and closes the level with it as they are.
    level_bit: u64,
    /// [`probe::elastic_sequence_index`] of the probe, as wide as the
    /// multiply that takes it.
    sequence_index: u64,
    /// The index shift in the low byte and the level in the next. The shift
    /// is below the word width, so the word itself is the shift amount.
    reduction: u64,
    control: *const u8,
}

const LEVEL_BIT: u32 = u8::BITS;

const fn reduction(level: u8, index_shift: u8) -> u64 {
    assert!(level <= SENTINEL_LEVEL && (index_shift as u32) < u64::BITS);
    index_shift as u64 | (level as u64) << LEVEL_BIT
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
        let level = u8::try_from(level).expect("Elastic level count fits u8");
        Self {
            level_bit: 1 << level_bit(level),
            sequence_index: u64::from(probe::elastic_sequence_index(
                u32::from(level),
                logical_probe_index,
            )),
            reduction: reduction(level, index_shift),
            control,
        }
    }

    /// The direct route: level zero's first probe, or the sentinel's control
    /// bytes for a table without levels. No walk steps onto it.
    fn direct<T>(levels: &[Level<T>]) -> Self {
        let Some(region) = levels.first() else {
            return SENTINEL;
        };
        Self::new(0, region, 0)
    }

    /// Steps `route` to the route after it and reads the two words a walk's
    /// step takes there: the level's bit and the sequence index. On `AArch64`
    /// the step and both reads are one pre-indexed pair load; the compiler
    /// left to itself reads the second word apart, in the probe that uses
    /// it, and carries the route's address twice.
    ///
    /// # Safety
    ///
    /// `route` addresses a route of a [`ProbeSchedule`] ahead of its
    /// sentinel.
    #[inline]
    pub(super) unsafe fn step(route: &mut *const Self) -> RouteStep {
        #[cfg(all(target_arch = "aarch64", not(miri)))]
        {
            const _: () = assert!(size_of::<PhiRoute>() == 32);
            let level_bit: u64;
            let sequence_index: u64;
            // SAFETY: the caller's contract: the next route holds both
            // words, which the load only reads.
            unsafe {
                core::arch::asm!(
                    "ldp {level_bit}, {sequence_index}, [{route}, #32]!",
                    route = inout(reg) *route,
                    level_bit = lateout(reg) level_bit,
                    sequence_index = lateout(reg) sequence_index,
                    options(pure, readonly, nostack, preserves_flags),
                );
            }
            RouteStep {
                level_bit,
                sequence_index,
            }
        }
        #[cfg(not(all(target_arch = "aarch64", not(miri))))]
        {
            // SAFETY: the caller's contract.
            *route = unsafe { route.add(1) };
            // SAFETY: as above.
            unsafe { (**route).as_step() }
        }
    }

    /// What [`Self::step`] reads of this route.
    #[cfg(any(test, not(all(target_arch = "aarch64", not(miri)))))]
    pub(super) fn as_step(&self) -> RouteStep {
        RouteStep {
            level_bit: self.level_bit,
            sequence_index: self.sequence_index,
        }
    }

    /// The two words a walk's probe reads at `route`: the index shift, as
    /// [`Self::index_shift`] gives it, and the level's control bytes.
    ///
    /// # Safety
    ///
    /// `route` addresses a route of a [`ProbeSchedule`].
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) unsafe fn reach(route: *const Self) -> (u32, *const u8) {
        // SAFETY: the caller's contract.
        let reduction = unsafe { &raw const (*route).reduction };
        // SAFETY: the reduction and the control pointer are the route's last
        // two words.
        let (reduction, control) = unsafe { read_pair(reduction) };
        // SAFETY: the caller's contract.
        let control = unsafe { (*route).control }.with_addr(control as usize);
        (reduction as u32, control)
    }

    /// Level the route probes; [`SENTINEL_LEVEL`] for the sentinel.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn level(&self) -> u8 {
        (self.reduction >> LEVEL_BIT) as u8
    }

    /// Shift that reduces a probe word to a slot of the route's level. Only
    /// its low six bits are the shift: a caller shifts by it with a wrapping
    /// shift, which reads no others.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn index_shift(&self) -> u32 {
        self.reduction as u32
    }

    /// The route's [`probe::elastic_sequence_index`].
    #[cfg(test)]
    pub(super) fn sequence_index(&self) -> u64 {
        self.sequence_index
    }

    /// Control bytes of the route's level.
    #[inline]
    pub(super) fn control(&self) -> *const u8 {
        self.control
    }

    /// `(level, logical probe)` the route stands for.
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn coordinates(&self) -> (u32, u64) {
        probe::elastic_sequence_coordinates(self.sequence_index as u32)
    }

    /// Packed retry-zero counter of the route, for the general reduction.
    #[inline]
    pub(super) fn counter_base(&self) -> u32 {
        let (level, logical) = self.coordinates();
        probe::elastic_counter_base(level, logical)
    }
}

const _: () = assert!(
    size_of::<PhiRoute>() == 4 * size_of::<u64>()
        && core::mem::offset_of!(PhiRoute, level_bit) == 0
        && core::mem::offset_of!(PhiRoute, sequence_index) == size_of::<u64>()
        && core::mem::offset_of!(PhiRoute, control)
            == core::mem::offset_of!(PhiRoute, reduction) + size_of::<u64>()
);

/// Two adjacent words at `words`, read together where the target is
/// little-endian and so splits one wide load into them in order.
///
/// # Safety
///
/// `words` addresses two initialized words.
#[inline]
#[allow(clippy::cast_possible_truncation)]
unsafe fn read_pair(words: *const u64) -> (u64, u64) {
    #[cfg(target_endian = "little")]
    {
        // SAFETY: the caller's contract.
        let both = unsafe { words.cast::<u128>().read_unaligned() };
        (both as u64, (both >> u64::BITS) as u64)
    }
    #[cfg(not(target_endian = "little"))]
    // SAFETY: the caller's contract.
    unsafe {
        (words.read(), words.add(1).read())
    }
}

/// What a walk's step reads of a route.
#[derive(Clone, Copy)]
pub(super) struct RouteStep {
    level_bit: u64,
    sequence_index: u64,
}

impl RouteStep {
    /// Whether `closed_levels` holds the route's level.
    #[inline]
    pub(super) fn is_closed(self, closed_levels: u64) -> bool {
        closed_levels & self.level_bit != 0
    }

    /// `closed_levels` with the route's level.
    #[inline]
    pub(super) fn close(self, closed_levels: u64) -> u64 {
        closed_levels | self.level_bit
    }

    /// The route's [`probe::elastic_sequence_index`].
    #[inline]
    pub(super) fn sequence_index(self) -> u64 {
        self.sequence_index
    }
}

/// Control bytes the sentinel route probes: its shift leaves one index bit.
static SENTINEL_CONTROL: [u8; 2] = [CTRL_EMPTY; 2];

/// Level of the sentinel route, above every real level.
pub(super) const SENTINEL_LEVEL: u8 = 63;
const _: () = assert!(SENTINEL_LEVEL as u32 == u64::BITS - 1);

/// The sentinel's bit of a closed-level set, the lowest: a stored route
/// summary keeps it clear, so a walk always stops at the sentinel.
pub(super) const SENTINEL_BIT: u64 = 1;

/// Bit position of `level` in a closed-level set: one above the level for a
/// real level, the lowest for the sentinel.
const fn level_bit(level: u8) -> u8 {
    level.wrapping_add(1) & SENTINEL_LEVEL
}

const SENTINEL: PhiRoute = PhiRoute {
    level_bit: SENTINEL_BIT,
    sequence_index: 0,
    reduction: reduction(SENTINEL_LEVEL, SENTINEL_LEVEL),
    control: SENTINEL_CONTROL.as_ptr(),
};
const _: () = assert!(SENTINEL_BIT == 1 << level_bit(SENTINEL_LEVEL));

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
        ProbeSchedule::assemble(routes, entry_origin(levels))
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
///
/// `repr(C)` keeps the two addresses a lookup starts from adjacent, so one
/// load brings both.
#[repr(C)]
pub(super) struct ProbeSchedule {
    /// `routes.as_ptr()`. The routes never move: [`Self::clear`] only
    /// shortens them, and [`Self::push`] writes into room they already
    /// hold or panics.
    direct: *const PhiRoute,
    /// See [`entry_origin`].
    entry_origin: *mut u8,
    /// The direct route, the pushed routes, then the sentinel. No method
    /// leaves the first or the last off, so a walk from [`Self::direct`]
    /// always reaches the sentinel.
    routes: Vec<PhiRoute>,
}

/// Where the entry of a control byte at address zero would lie. The arena
/// lays the levels' control bytes and their entries out in the same order
/// and leaves the same number of slots between two levels in both, so an
/// entry's address is this plus its control byte's address times the entry
/// size.
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

const _: () = assert!(
    core::mem::offset_of!(ProbeSchedule, entry_origin)
        == core::mem::offset_of!(ProbeSchedule, direct) + size_of::<*const PhiRoute>()
);

impl ProbeSchedule {
    fn assemble(routes: Vec<PhiRoute>, entry_origin: *mut u8) -> Self {
        Self {
            direct: routes.as_ptr(),
            entry_origin,
            routes,
        }
    }

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
        Self::assemble(routes, entry_origin(levels))
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
        debug_assert_eq!(self.direct, self.routes.as_ptr());
        self.direct
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
        // Growing would move the routes away from `direct`.
        assert!(
            self.routes.len() < self.routes.capacity(),
            "probe schedule outgrew its room"
        );
        self.routes[sentinel] = PhiRoute::new(level, &levels[level], logical_probe_index);
        self.routes.push(SENTINEL);
    }

    /// Whether every route is the one its level in `levels` gives.
    #[cfg(test)]
    pub(super) fn addresses<T>(&self, levels: &[Level<T>]) -> bool {
        self.direct == self.routes.as_ptr()
            && self.routes[0] == PhiRoute::direct(levels)
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
