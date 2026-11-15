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
    level: u8,
    index_shift: u8,
    sequence_index: u32,
    control: *const u8,
}

const _: () = assert!(size_of::<PhiRoute>() <= 16);

impl PhiRoute {
    /// The route of `level`'s logical probe `logical_probe_index`. A level
    /// that needs the general range reduction has no shift, so its route
    /// probes the sentinel's control bytes instead: a walk reads `EMPTY`
    /// there and matches nothing.
    fn new<T>(level: usize, region: &Level<T>, logical_probe_index: u64) -> Self {
        let (index_shift, control) = if region.index_shift() == GENERAL_REDUCTION {
            (SENTINEL.index_shift, SENTINEL.control)
        } else {
            (
                u8::try_from(region.index_shift()).expect("Elastic index shift fits u8"),
                region.ctrl_ptr.cast_const(),
            )
        };
        Self {
            level: u8::try_from(level).expect("Elastic level count fits u8"),
            index_shift,
            sequence_index: probe::elastic_sequence_index(
                u32::try_from(level).expect("Elastic level count fits u32"),
                logical_probe_index,
            ),
            control,
        }
    }

    /// The direct route: level zero's first probe, or the sentinel for a
    /// table without levels.
    fn direct<T>(levels: &[Level<T>]) -> Self {
        levels
            .first()
            .map_or(SENTINEL, |region| Self::new(0, region, 0))
    }

    /// Level the route probes; [`SENTINEL_LEVEL`] for the sentinel.
    #[inline]
    pub(super) fn level(&self) -> u8 {
        self.level
    }

    /// Shift that reduces a probe word to a slot of the route's level.
    #[inline]
    pub(super) fn index_shift(&self) -> u32 {
        u32::from(self.index_shift)
    }

    /// The route's [`probe::elastic_sequence_index`].
    #[inline]
    pub(super) fn sequence_index(&self) -> u32 {
        self.sequence_index
    }

    /// Control bytes of the route's level.
    #[inline]
    pub(super) fn control(&self) -> *const u8 {
        self.control
    }

    /// `(level, logical probe)` the route stands for.
    pub(super) fn coordinates(&self) -> (u32, u64) {
        probe::elastic_sequence_coordinates(self.sequence_index)
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

/// Level of the sentinel route, above every real level: the top bit of a
/// lookup's open-level set.
pub(super) const SENTINEL_LEVEL: u8 = 63;
const _: () = assert!(SENTINEL_LEVEL as u32 == u64::BITS - 1);

const SENTINEL: PhiRoute = PhiRoute {
    level: SENTINEL_LEVEL,
    index_shift: SENTINEL_LEVEL,
    sequence_index: 0,
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
        ProbeSchedule { routes }
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
}

impl ProbeSchedule {
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
        Self { routes }
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
