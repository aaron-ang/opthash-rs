//! The lookup schedule: one route per `(level, probe)` pair a lookup may
//! visit, in query-position order, and each level's routes again as a run of
//! their own for a lookup that has one level left to visit.

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ptr;

use super::{
    GENERAL_REDUCTION, Level, MAX_LEVELS, NO_LEVELS_OCCUPIED, PROBE_SCHEDULE_CAPACITY, SummaryBin,
    summary_level,
};
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
    /// step takes there: the level's bit and the sequence index. On 64-bit
    /// `AArch64` the step and both reads are one pre-indexed pair load.
    ///
    /// # Safety
    ///
    /// `route` addresses a route of a [`ProbeSchedule`] ahead of the
    /// sentinel that closes its list.
    #[inline]
    pub(super) unsafe fn step(route: &mut *const Self) -> RouteStep {
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64", not(miri)))]
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
        #[cfg(not(all(target_arch = "aarch64", target_pointer_width = "64", not(miri))))]
        {
            // SAFETY: the caller's contract.
            *route = unsafe { route.add(1) };
            // SAFETY: as above.
            unsafe { (**route).as_step() }
        }
    }

    /// What [`Self::step`] reads of this route.
    #[cfg(any(
        test,
        not(all(target_arch = "aarch64", target_pointer_width = "64", not(miri)))
    ))]
    pub(super) fn as_step(&self) -> RouteStep {
        RouteStep {
            level_bit: self.level_bit,
            sequence_index: self.sequence_index,
        }
    }

    /// The two words a walk's probe reads at `route`: the index shift, as
    /// [`Self::index_shift`] gives it, and the level's control bytes. Where
    /// a pointer is as wide as the reduction and the target is little-endian,
    /// so that one wide load splits into the two in order, it reads them
    /// together.
    ///
    /// # Safety
    ///
    /// `route` addresses a route of a [`ProbeSchedule`].
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) unsafe fn reach(route: *const Self) -> (u32, *const u8) {
        #[cfg(all(target_pointer_width = "64", target_endian = "little"))]
        {
            const _: () = assert!(
                size_of::<*const u8>() == size_of::<u64>()
                    && core::mem::offset_of!(PhiRoute, control)
                        == core::mem::offset_of!(PhiRoute, reduction) + size_of::<u64>()
                    && size_of::<PhiRoute>()
                        == core::mem::offset_of!(PhiRoute, control) + size_of::<u64>()
            );
            // SAFETY: the caller's contract; the reduction and the control
            // pointer are the route's last two words, with no padding
            // between or after them.
            let both = unsafe {
                (&raw const (*route).reduction)
                    .cast::<u128>()
                    .read_unaligned()
            };
            // SAFETY: the caller's contract.
            let control = unsafe { (*route).control }.with_addr((both >> u64::BITS) as usize);
            (both as u32, control)
        }
        #[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
        // SAFETY: the caller's contract.
        unsafe {
            ((*route).reduction as u32, (*route).control)
        }
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
    #[cfg(test)]
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
    core::mem::offset_of!(PhiRoute, level_bit) == 0
        && core::mem::offset_of!(PhiRoute, sequence_index) == size_of::<u64>()
);

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

/// A stored route summary as a walk's closed-level set: bit zero, the
/// sentinel's, is clear, and bit `i + 1` is set for a level `i` the summary
/// rules out. The summary keeps the levels it rules out set and its last bit
/// is its sign, so sign extension alone gives every deeper level its own bit
/// and leaves the sentinel open.
#[inline]
pub(super) const fn closed_levels(summary: SummaryBin) -> u64 {
    (summary.cast_signed() as i64).cast_unsigned()
}

/// Storage reserved for a [`ProbeSchedule`], taken before the levels it
/// will address exist.
pub(super) struct ProbeScheduleRoom {
    slots: Vec<MaybeUninit<PhiRoute>>,
    book: Vec<ScheduleBook>,
    levels: usize,
}

impl ProbeScheduleRoom {
    /// Room for the full schedule of `levels` levels.
    pub(super) fn try_for_levels(levels: usize) -> Result<Self, TryReserveError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(slot_count(levels))
            .map_err(|_| TryReserveError::AllocError)?;
        let mut book = Vec::new();
        book.try_reserve_exact(1)
            .map_err(|_| TryReserveError::AllocError)?;
        Ok(Self {
            slots,
            book,
            levels,
        })
    }

    fn for_levels(levels: usize) -> Self {
        Self {
            slots: Vec::with_capacity(slot_count(levels)),
            book: Vec::with_capacity(1),
            levels,
        }
    }

    /// The empty schedule of `levels`, the levels the room was taken for.
    pub(super) fn schedule<T>(self, levels: &[Level<T>]) -> ProbeSchedule {
        assert_eq!(levels.len(), self.levels);
        let Self {
            mut slots,
            mut book,
            levels: level_count,
        } = self;
        let direct = PhiRoute::direct(levels);
        slots.resize_with(slot_count(level_count), MaybeUninit::uninit);
        slots[0].write(direct);
        book.push(ScheduleBook {
            starts: [slots.as_ptr().cast(); WALK_STARTS],
            run_len: [0; MAX_LEVELS],
            pushed: 0,
            levels: level_count,
            whole_runs: level_count,
            starts_name_runs: false,
        });
        let mut schedule = ProbeSchedule {
            direct_reduction: direct.reduction,
            direct_control: direct.control(),
            entry_origin: entry_origin(levels),
            // SAFETY: the table holds `WALK_STARTS` entries.
            starts: unsafe { book.as_ptr().cast::<*const PhiRoute>().add(WALK_STARTS / 2) },
            slots,
            book,
        };
        schedule.clear();
        schedule
    }
}

/// Entries of a schedule's table of walk starts: one per summary value.
const WALK_STARTS: usize = 1 << SummaryBin::BITS;

/// What a schedule keeps besides its slots, which only building it reads
/// past the walk starts.
#[repr(C)]
struct ScheduleBook {
    /// For each summary value, the slot a walk under it steps on from, with
    /// the summaries that are negative as signed bytes first. The slots
    /// never move, so an entry changes only when a run stops being whole or
    /// becomes whole again.
    starts: [*const PhiRoute; WALK_STARTS],
    /// Routes each level's run holds while it is whole.
    run_len: [u16; MAX_LEVELS],
    pushed: usize,
    levels: usize,
    /// [`whole_runs`] of `pushed`.
    whole_runs: usize,
    /// Whether `starts` holds the slots the summaries name. Until the first
    /// route is pushed every entry is the direct route instead, which the
    /// sentinel follows as it does the lead of each run.
    starts_name_runs: bool,
}

const _: () = assert!(core::mem::offset_of!(ScheduleBook, starts) == 0);

/// Routes a schedule holds in query-position order besides the ones pushed:
/// the direct route and the sentinel.
const FIXED_ROUTES: usize = 2;

/// Slots of the schedule of `levels` levels: room for the direct route and
/// every route in query-position order with the sentinel that closes them,
/// and one more slot per level and one over, so that the room also holds a
/// sentinel after each level's run and a last slot no route is written to.
const fn slot_count(levels: usize) -> usize {
    PROBE_SCHEDULE_CAPACITY[levels] + FIXED_ROUTES + levels + 1
}

/// The slot ahead of `level`'s run in the schedule of `levels` levels. The
/// runs lie at the end of the room, the first level's last: a run fills the
/// slots after its lead up to the lead of the level before it, or up to the
/// last slot, and that slot is the sentinel of a run that is full.
const fn run_lead(levels: usize, level: usize) -> usize {
    slot_count(levels) - 1 - (PROBE_SCHEDULE_CAPACITY[level + 1] + level + 1)
}

/// Routes `level`'s run has slots for: the level's share of the schedule.
const fn run_capacity(level: usize) -> usize {
    PROBE_SCHEDULE_CAPACITY[level + 1] - PROBE_SCHEDULE_CAPACITY[level]
}

/// Levels whose runs stay whole in the schedule of `levels` levels once it
/// holds `pushed` routes, of the first `whole` that were. The runs share
/// the room of the routes in query-position order, which grow from its
/// front and reach the deepest level's slots first. A run is whole while
/// those routes and their sentinel end at its lead or before it.
const fn whole_runs(levels: usize, pushed: usize, mut whole: usize) -> usize {
    while whole > 0 && run_lead(levels, whole - 1) < pushed + 1 {
        whole -= 1;
    }
    whole
}

/// The summary that leaves `level` alone open in a table of `levels`
/// levels, if one does: a level past the summary's width shares its bit
/// with every other such level.
const fn lone_level_summary(levels: usize, level: usize) -> Option<SummaryBin> {
    let bit = summary_level(level);
    let shared = bit != level || (summary_level(level + 1) == bit && levels > level + 1);
    if shared {
        None
    } else {
        #[allow(clippy::cast_possible_truncation)]
        Some(NO_LEVELS_OCCUPIED & !(1 << level_bit(bit as u8)))
    }
}

/// The direct route, then the lookup routes in query-position order, closed
/// by a sentinel route so a walk needs no end test: the sentinel's level is
/// open in every walk and its probe reads an `EMPTY` control byte, which is
/// where a walk stops. Each level's routes are held again in probe order as
/// a run closed by its own sentinel, while the room has slots for it.
///
/// Every route addresses a level of the slice its schedule was built for:
/// [`ProbeScheduleRoom::schedule`], [`Self::clone_onto`] and [`Self::push`]
/// each take that slice, and a route holds only what [`PhiRoute::new`]
/// derives from one of its levels.
///
/// `repr(C)` keeps the words a direct probe reads adjacent and ahead of the
/// address only a walk needs, so a lookup the direct probe answers never
/// loads a route.
#[repr(C)]
pub(super) struct ProbeSchedule {
    /// The direct route's [`PhiRoute::index_shift`] word and control bytes,
    /// held beside the entry origin. [`ProbeScheduleRoom::schedule`] alone
    /// writes them, from the route it puts first.
    direct_reduction: u64,
    direct_control: *const u8,
    /// See [`entry_origin`].
    entry_origin: *mut u8,
    /// The entry of the book's walk starts for summary zero.
    starts: *const *const PhiRoute,
    /// Every slot of the schedule. The slots never move and their count
    /// never changes: [`Self::push`] and [`Self::clear`] only write them.
    ///
    /// These hold a route or the sentinel, and no others are read: the
    /// direct route; the pushed routes after it and the sentinel after
    /// them; after the lead ([`run_lead`]) of each whole run, the routes
    /// its level pushed and the sentinel after them; and the last slot,
    /// a sentinel.
    slots: Vec<MaybeUninit<PhiRoute>>,
    /// One book, at an address that never changes.
    book: Vec<ScheduleBook>,
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
    core::mem::offset_of!(ProbeSchedule, direct_reduction) == 0
        && core::mem::offset_of!(ProbeSchedule, entry_origin)
            == core::mem::offset_of!(ProbeSchedule, direct_control) + size_of::<*const u8>()
);

impl ProbeSchedule {
    /// [`PhiRoute::index_shift`] and [`PhiRoute::control`] of the direct
    /// route, without reading the route, and the origin [`Self::entry_at`]
    /// adds to. Where two pointers fill one wide load and the target is
    /// little-endian, that load brings the control bytes and the origin, so
    /// a caller that needs the origin on every path does not load it once
    /// per path.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn direct_reach(&self) -> (u32, *const u8, *mut u8) {
        #[cfg(all(target_pointer_width = "64", target_endian = "little"))]
        {
            // SAFETY: `repr(C)` puts the origin right after the control
            // pointer, asserted above, so the read covers exactly those two
            // initialized fields. The pointer comes from `self` whole, so it
            // may read both.
            let both = unsafe {
                core::ptr::from_ref(self)
                    .cast::<u8>()
                    .add(core::mem::offset_of!(Self, direct_control))
                    .cast::<u128>()
                    .read_unaligned()
            };
            (
                self.direct_reduction as u32,
                self.direct_control.with_addr(both as usize),
                self.entry_origin.with_addr((both >> u64::BITS) as usize),
            )
        }
        #[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
        (
            self.direct_reduction as u32,
            self.direct_control,
            self.entry_origin,
        )
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

    /// The entry at [`Self::entry_offset`] `offset` from `entry_origin`, the
    /// origin [`Self::direct_reach`] gives. It is an entry of the levels the
    /// schedule was built for when the offset is that of one of their
    /// control bytes and `T` is their entry type.
    #[inline]
    pub(super) fn entry_at<T>(entry_origin: *mut u8, offset: usize) -> *mut T {
        entry_origin.wrapping_add(offset).cast()
    }

    /// A copy of `self` for `levels`, each route addressing its level
    /// there.
    pub(super) fn clone_onto<T>(&self, levels: &[Level<T>]) -> Self {
        let mut copy = ProbeScheduleRoom::for_levels(levels.len()).schedule(levels);
        for route in self.routes() {
            let (level, logical_probe_index) = route.coordinates();
            copy.push(levels, level as usize, logical_probe_index);
        }
        copy
    }

    /// The pushed routes, in query-position order.
    #[inline]
    pub(super) fn routes(&self) -> &[PhiRoute] {
        let pushed = &self.slots[1..=self.book[0].pushed];
        // SAFETY: the slots of the pushed routes hold routes, and a slot
        // that holds a route is laid out as one.
        unsafe { &*(ptr::from_ref(pushed) as *const [PhiRoute]) }
    }

    /// The route a walk under `summary` steps on from. Every route after it
    /// up to and including a sentinel, whose level is [`SENTINEL_LEVEL`],
    /// may be read. Between the two lie, in query-position order, the pushed
    /// routes of every level `summary` leaves open, and none but pushed
    /// routes.
    #[inline]
    pub(super) fn walk_start(&self, summary: SummaryBin) -> *const PhiRoute {
        // SAFETY: `starts` has an entry at every signed byte's distance.
        unsafe { *self.starts.offset(isize::from(summary.cast_signed())) }
    }

    /// Points every walk start at a slot the walk may step on from: for
    /// the summary that leaves one level open, the lead of that level's run
    /// while it is whole; for the one that leaves none, the slot ahead of
    /// the last, a sentinel; for the others, the direct route. Either way
    /// the walk probes what it would from the direct route, where every
    /// route of a level the summary closes is a step it skips.
    fn fill_starts(&mut self) {
        let first = self.slots.as_ptr().cast::<PhiRoute>();
        let slots = self.slots.len();
        let book = &mut self.book[0];
        let entry = |summary: SummaryBin| (WALK_STARTS / 2 + usize::from(summary)) % WALK_STARTS;
        book.starts = [first; WALK_STARTS];
        // SAFETY: a schedule has the direct route's slot and two more.
        book.starts[entry(NO_LEVELS_OCCUPIED)] = unsafe { first.add(slots - 2) };
        for level in 0..book.whole_runs {
            if let Some(summary) = lone_level_summary(book.levels, level) {
                // SAFETY: a run's lead is a slot of the schedule.
                book.starts[entry(summary)] = unsafe { first.add(run_lead(book.levels, level)) };
            }
        }
        book.starts_name_runs = true;
    }

    /// Drops the pushed routes.
    pub(super) fn clear(&mut self) {
        let book = &mut self.book[0];
        // Every run is whole again, and empty: a sentinel follows its lead.
        // So does one follow the direct route, and one is the last slot.
        self.slots[1].write(SENTINEL);
        for level in 0..book.levels {
            self.slots[run_lead(book.levels, level) + 1].write(SENTINEL);
        }
        self.slots
            .last_mut()
            .expect("a schedule has slots")
            .write(SENTINEL);
        book.run_len = [0; MAX_LEVELS];
        book.pushed = 0;
        if book.whole_runs != book.levels {
            book.whole_runs = book.levels;
            self.fill_starts();
        }
    }

    /// Appends the route of logical probe `logical_probe_index` of level
    /// `level` of `levels`, the slice this schedule was built for or a
    /// prefix of it. The caller appends routes in query-position order,
    /// which is each level's probe order.
    pub(super) fn push<T>(&mut self, levels: &[Level<T>], level: usize, logical_probe_index: u64) {
        let book = &mut self.book[0];
        assert!(
            book.pushed < PROBE_SCHEDULE_CAPACITY[book.levels],
            "probe schedule outgrew its room"
        );
        let route = PhiRoute::new(level, &levels[level], logical_probe_index);
        let whole_runs = whole_runs(book.levels, book.pushed + 1, book.whole_runs);
        let run_len = usize::from(book.run_len[level]);
        if level < whole_runs {
            assert!(
                run_len < run_capacity(level),
                "probe schedule outgrew its room"
            );
            // Level zero's first probe is the direct route, which no run
            // holds. A run with a gap would not be its level's routes.
            assert!(
                usize::try_from(logical_probe_index)
                    .is_ok_and(|probe| probe == run_len + usize::from(level == 0)),
                "probe schedule pushed out of order"
            );
        }
        if whole_runs != book.whole_runs || !book.starts_name_runs {
            // No walk may start at a run the routes are about to overwrite.
            book.whole_runs = whole_runs;
            self.fill_starts();
        }
        let book = &mut self.book[0];
        book.pushed += 1;
        self.slots[book.pushed].write(route);
        self.slots[book.pushed + 1].write(SENTINEL);
        if level < whole_runs {
            let run = run_lead(book.levels, level) + 1 + run_len;
            self.slots[run].write(route);
            // The lead of the run after this one, or the last slot, when
            // the run is full.
            self.slots[run + 1].write(SENTINEL);
            book.run_len[level] += 1;
        }
    }

    /// The direct route, which a walk under a summary that names no run
    /// steps on from.
    #[cfg(test)]
    pub(super) fn direct(&self) -> *const PhiRoute {
        self.slots.as_ptr().cast()
    }

    /// The routes a walk under `summary` steps over before its sentinel.
    #[cfg(test)]
    pub(super) fn walk_routes(&self, summary: SummaryBin) -> Vec<PhiRoute> {
        let mut route = self.walk_start(summary);
        let mut routes = Vec::new();
        loop {
            // SAFETY: a sentinel follows every walk start, and the walk
            // stops at it.
            route = unsafe { route.add(1) };
            // SAFETY: as above.
            let held = unsafe { *route };
            if held == SENTINEL {
                return routes;
            }
            routes.push(held);
        }
    }

    /// Starts every walk at the direct route, as a schedule without runs
    /// would, until its routes are dropped.
    #[cfg(test)]
    pub(super) fn start_walks_at_the_direct_route(&mut self) {
        let direct = self.direct();
        let book = &mut self.book[0];
        book.whole_runs = 0;
        book.starts_name_runs = true;
        book.starts = [direct; WALK_STARTS];
    }

    /// Whether every route is the one its level in `levels` gives, every
    /// whole run holds its level's pushed routes in order, and every walk
    /// start is the direct route, the lead of a whole run, or the slot
    /// ahead of the last.
    #[cfg(test)]
    pub(super) fn addresses<T>(&self, levels: &[Level<T>]) -> bool {
        let book = &self.book[0];
        let pushed_of = |level: usize| {
            self.routes()
                .iter()
                .filter(move |route| usize::from(route.level()) == level)
        };
        // SAFETY: only called on slots the schedule's invariant initializes.
        let slot = |slot: usize| unsafe { self.slots[slot].assume_init() };
        book.levels == levels.len()
            && self.slots.len() == slot_count(book.levels)
            && slot(0) == PhiRoute::direct(levels)
            && self.direct_reach() == (slot(0).index_shift(), slot(0).control(), self.entry_origin)
            && self.entry_origin == entry_origin(levels)
            && self.routes().iter().all(|route| {
                let (level, logical_probe_index) = route.coordinates();
                let level = level as usize;
                *route == PhiRoute::new(level, &levels[level], logical_probe_index)
            })
            && self.ends_with_sentinel()
            && slot(self.slots.len() - 1) == SENTINEL
            && book.whole_runs == whole_runs(book.levels, book.pushed, book.levels)
            && (0..book.whole_runs).all(|level| {
                let first = run_lead(book.levels, level) + 1;
                let len = usize::from(book.run_len[level]);
                len == pushed_of(level).count()
                    && (first..first + len)
                        .zip(pushed_of(level))
                        .all(|(run, pushed)| slot(run) == *pushed)
                    && slot(first + len) == SENTINEL
            })
            && (SummaryBin::MIN..=SummaryBin::MAX).all(|summary| {
                let start = self.walk_start(summary);
                start == self.direct()
                    || book.starts_name_runs
                        && (start == self.slots[self.slots.len() - 2].as_ptr()
                            || (0..book.whole_runs).any(|level| {
                                start == self.slots[run_lead(book.levels, level)].as_ptr()
                            }))
            })
            && (book.starts_name_runs || book.pushed == 0)
    }

    /// Levels whose runs a walk may start at.
    #[cfg(test)]
    pub(super) fn whole_runs(&self) -> usize {
        self.book[0].whole_runs
    }

    #[cfg(test)]
    pub(super) fn route_capacity(&self) -> usize {
        PROBE_SCHEDULE_CAPACITY[self.book[0].levels]
    }

    #[cfg(test)]
    pub(super) fn ends_with_sentinel(&self) -> bool {
        // SAFETY: a sentinel follows the pushed routes.
        unsafe { self.slots[self.book[0].pushed + 1].assume_init() == SENTINEL }
    }
}
