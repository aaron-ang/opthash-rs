//! The lookup schedule: one route per `(level, probe)` pair a lookup may
//! visit, in query-position order.

use alloc::vec::Vec;

use super::Level;
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

    /// Paper query position of the route.
    fn phi(&self) -> u128 {
        let (level, logical) = self.coordinates();
        probe::elastic_phi(u128::from(level) + 1, u128::from(logical) + 1)
            .expect("a scheduled route has a query position")
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

/// Lookup routes in query-position order, closed by a sentinel route so a
/// walk needs no end test: the sentinel's level is open in every walk and
/// its probe reads an `EMPTY` control byte, which is where a walk stops.
pub(super) struct ProbeSchedule {
    /// The routes, then the sentinel. No method leaves the sentinel off, so
    /// a walk from [`Self::first`] always reaches it.
    routes: Vec<PhiRoute>,
}

impl ProbeSchedule {
    /// An empty schedule with room for `route_capacity` routes.
    pub(super) fn try_with_capacity(route_capacity: usize) -> Result<Self, TryReserveError> {
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(route_capacity + 1)
            .map_err(|_| TryReserveError::AllocError)?;
        routes.push(SENTINEL);
        Ok(Self { routes })
    }

    /// A copy of `self` with room for `route_capacity` routes, each route
    /// addressing the control bytes `control_of` gives its level.
    pub(super) fn clone_onto(
        &self,
        route_capacity: usize,
        control_of: impl Fn(usize) -> *const u8,
    ) -> Self {
        let mut routes = Vec::with_capacity(route_capacity + 1);
        routes.extend(self.routes().iter().map(|route| PhiRoute {
            control: control_of(route.level as usize),
            ..*route
        }));
        routes.push(SENTINEL);
        Self { routes }
    }

    #[inline]
    pub(super) fn routes(&self) -> &[PhiRoute] {
        &self.routes[..self.routes.len() - 1]
    }

    /// First route of a walk. Every route from it up to and including the
    /// sentinel, whose level is [`SENTINEL_LEVEL`], may be read.
    #[inline]
    pub(super) fn first(&self) -> *const PhiRoute {
        self.routes.as_ptr()
    }

    pub(super) fn clear(&mut self) {
        self.routes.clear();
        self.routes.push(SENTINEL);
    }

    /// Appends the route of `level`'s logical probe `logical_probe_index`.
    /// The schedule is out of order until [`Self::sort_from`] runs over the
    /// appended routes.
    pub(super) fn push<T>(&mut self, level: usize, region: &Level<T>, logical_probe_index: u64) {
        let route = PhiRoute {
            level: u8::try_from(level).expect("Elastic level count fits u8"),
            index_shift: u8::try_from(region.index_shift).expect("Elastic index shift fits u8"),
            sequence_index: probe::elastic_sequence_index(
                u32::try_from(level).expect("Elastic level count fits u32"),
                logical_probe_index,
            ),
            control: region.ctrl_ptr,
        };
        let sentinel = self.routes.len() - 1;
        self.routes[sentinel] = route;
        self.routes.push(SENTINEL);
    }

    /// Orders the routes from index `start` on by query position.
    pub(super) fn sort_from(&mut self, start: usize) {
        let sentinel = self.routes.len() - 1;
        self.routes[start..sentinel].sort_unstable_by_key(PhiRoute::phi);
    }

    #[cfg(test)]
    pub(super) fn route_capacity(&self) -> usize {
        self.routes.capacity() - 1
    }

    #[cfg(test)]
    pub(super) fn ends_with_sentinel(&self) -> bool {
        self.routes.last() == Some(&SENTINEL)
    }
}
