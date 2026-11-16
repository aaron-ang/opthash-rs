//! The lookup schedule: one route per `(level, probe)` pair a lookup may
//! visit, in query-position order, and each level's routes again as a run of
//! their own for a lookup that has one level left to visit, and the routes
//! of the first few levels again as a run per set of them for a lookup that
//! has that set left.

use alloc::vec::Vec;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::{self, NonNull};

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
///
/// Its alignment leaves the low bits of a route's address clear, which a
/// [`WalkStart`] marks a run's lead in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C, align(32))]
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

/// Where a walk steps on from: the slot ahead of routes of several levels
/// in query-position order, which is the direct route or the lead of a
/// group's run, or the lead of one level's run, for a walk that has that
/// level alone to visit or no level at all.
///
/// It is the address of the word the walk's step reads in the route after:
/// a route's first word, or, for the lead of a level's run, its sequence
/// index, which no route's own address is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct WalkStart(*const u8);

/// Offset in a route of the one word a walk of a run steps on.
const RUN_STEP_WORD: usize = core::mem::offset_of!(PhiRoute, sequence_index);
const _: () = assert!(RUN_STEP_WORD.is_power_of_two() && RUN_STEP_WORD < align_of::<PhiRoute>());

impl WalkStart {
    fn at_list(ahead: *const PhiRoute) -> Self {
        Self(ahead.cast())
    }

    fn at_run(lead: *const PhiRoute) -> Self {
        Self(lead.cast::<u8>().wrapping_add(RUN_STEP_WORD))
    }

    /// The start as the lead of a level's run, or as the slot ahead of
    /// routes of several levels.
    #[inline]
    pub(super) fn run(self) -> Result<RunWalk, *const PhiRoute> {
        if self.0.addr() & RUN_STEP_WORD == 0 {
            Err(self.0.cast())
        } else {
            Ok(RunWalk(self.0.cast()))
        }
    }
}

/// A walk of one run: the sequence index of the route it is at, which starts
/// as the run's lead.
#[derive(Clone, Copy)]
pub(super) struct RunWalk(*const u64);

impl RunWalk {
    /// Steps to the route after and reads its sequence index, the one word
    /// a step takes where no other level is left to skip. On 64-bit
    /// `AArch64` the step and the read are one pre-indexed load.
    ///
    /// # Safety
    ///
    /// The walk is ahead of the sentinel that closes its run.
    #[inline]
    pub(super) unsafe fn step(&mut self) -> u64 {
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64", not(miri)))]
        {
            const _: () = assert!(size_of::<PhiRoute>() == 32);
            let sequence_index: u64;
            // SAFETY: the caller's contract: the next route holds the word,
            // which the load only reads.
            unsafe {
                core::arch::asm!(
                    "ldr {sequence_index}, [{at}, #32]!",
                    at = inout(reg) self.0,
                    sequence_index = lateout(reg) sequence_index,
                    options(pure, readonly, nostack, preserves_flags),
                );
            }
            sequence_index
        }
        #[cfg(not(all(target_arch = "aarch64", target_pointer_width = "64", not(miri))))]
        {
            // SAFETY: the caller's contract.
            self.0 = unsafe { self.0.byte_add(size_of::<PhiRoute>()) };
            // SAFETY: as above.
            unsafe { *self.0 }
        }
    }

    /// The route the walk is at, once it has stepped.
    #[inline]
    pub(super) fn route(self) -> *const PhiRoute {
        self.0.wrapping_byte_sub(RUN_STEP_WORD).cast()
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
            starts: [WalkStart::at_list(slots.as_ptr().cast()); WALK_STARTS],
            run_len: [0; MAX_LEVELS],
            group_next: [0; GROUPS],
            group_end: GROUP_RUNS[level_count].map(GroupRun::end),
            pushed: 0,
            reach: 0,
            levels: level_count,
            whole_runs: named_levels(level_count),
            open_groups: 0,
            grouped_pushed: 0,
            grouped_held: 0,
            whole_groups: 0,
            allocated: book.capacity(),
            #[cfg(test)]
            group_appends: 0,
        });
        let mut schedule = ProbeSchedule {
            direct_reduction: direct.reduction,
            direct_control: direct.control(),
            direct_entries: levels
                .first()
                .map_or(ptr::null_mut(), |level| level.data_ptr.cast()),
            entry_origin: entry_origin(levels),
            book: OwnedBook::new(book),
            slots,
        };
        schedule.clear();
        schedule.fill_starts();
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
    starts: [WalkStart; WALK_STARTS],
    /// Routes each level's run holds while it is whole.
    run_len: [u16; MAX_LEVELS],
    /// The slot each group's run takes its next route in while it is whole.
    group_next: [u16; GROUPS],
    /// [`GroupRun::end`] of each group, which a push reads.
    group_end: [u16; GROUPS],
    pushed: usize,
    /// The routes the schedule holds once a push has work besides writing
    /// its route: the lead of the whole run the pushed routes reach first,
    /// or one route more than the schedule has room for.
    reach: usize,
    levels: usize,
    /// [`whole_runs`] of `pushed`.
    whole_runs: usize,
    /// [`GROUPED_LEVELS`] while a group's run is whole, and no level
    /// otherwise: the levels whose routes a push also gives to groups.
    open_groups: usize,
    /// Routes of the grouped levels among the pushed ones, counted while a
    /// group's run is whole.
    grouped_pushed: u16,
    /// Routes of the grouped levels the whole groups' runs were given, in
    /// the order they were pushed. It runs ahead of `grouped_pushed` while
    /// routes dropped by [`ProbeSchedule::rewind`] are pushed again.
    grouped_held: u16,
    /// The groups whose runs are whole, a bit each: those of
    /// [`FITTED_GROUPS`] that the pushed routes and their sentinel end at
    /// the lead of or before it, and that had a slot for every route their
    /// levels pushed.
    whole_groups: u8,
    /// Books the allocation has room for, which freeing it takes.
    allocated: usize,
    /// Routes written to groups' runs since the schedule was made.
    #[cfg(test)]
    group_appends: usize,
}

const _: () = assert!(core::mem::offset_of!(ScheduleBook, starts) == 0);

/// Routes a schedule holds in query-position order besides the ones pushed:
/// the direct route and the sentinel.
const FIXED_ROUTES: usize = 2;

/// Slots of the schedule of `levels` levels: room for the direct route and
/// every route in query-position order with the sentinel that closes them,
/// and one more slot per level and one over. The runs share that room: a
/// level's share holds its run where it has one ([`named_levels`]), the
/// groups' runs lie in the other levels' shares ([`group_run`]), and the
/// last slot is one no route is written to.
const fn slot_count(levels: usize) -> usize {
    PROBE_SCHEDULE_CAPACITY[levels] + FIXED_ROUTES + levels + 1
}

/// The slot ahead of `level`'s share of the schedule of `levels` levels,
/// which holds the level's run where it has one. The shares lie at the end
/// of the room, the first level's last: a run fills the slots after its
/// lead up to the lead of the level before it, or up to the last slot, and
/// that slot is the sentinel of a run that is full.
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

/// Levels of a table of `levels` levels that a summary can leave open
/// alone: the first ones, each with a summary bit of its own. Only these
/// have runs.
const fn named_levels(levels: usize) -> usize {
    let mut named = 0;
    while named < levels && lone_level_summary(levels, named).is_some() {
        named += 1;
    }
    named
}

/// Levels whose routes the schedule also holds together: one run per set of
/// two or more of them, a group, for the summary that leaves that set open.
pub(super) const GROUPED_LEVELS: usize = 3;
const GROUPS: usize = (1 << GROUPED_LEVELS) - 1 - GROUPED_LEVELS;

/// Each group's levels, bit `i` for level `i`, in the order the groups'
/// runs lie in the room. The pushed routes reach the first one first.
const GROUP_LEVELS: [u8; GROUPS] = [0b111, 0b110, 0b101, 0b011];

const _: () = {
    let mut group = 0;
    while group < GROUPS {
        let levels = GROUP_LEVELS[group];
        assert!(levels.count_ones() >= 2 && levels >> GROUPED_LEVELS == 0);
        let mut other = 0;
        while other < group {
            assert!(GROUP_LEVELS[other] != levels);
            other += 1;
        }
        group += 1;
    }
    assert!(GROUPED_LEVELS <= named_levels(MAX_LEVELS) && GROUPS <= u8::BITS as usize);
    assert!(GROUP_LEVELS[0].count_ones() as usize == GROUPED_LEVELS);
};

/// The groups each grouped level is in, a bit each.
const LEVEL_GROUPS: [u8; GROUPED_LEVELS] = {
    let mut groups = [0; GROUPED_LEVELS];
    let mut group = 0;
    while group < GROUPS {
        let mut level = 0;
        while level < GROUPED_LEVELS {
            groups[level] |= (GROUP_LEVELS[group] >> level & 1) << group;
            level += 1;
        }
        group += 1;
    }
    groups
};

/// Whether `level` is one of `group`'s.
const fn in_group(group: usize, level: usize) -> bool {
    level < GROUPED_LEVELS && GROUP_LEVELS[group] >> level & 1 != 0
}

/// Routes the levels of `group` push in a full schedule.
const fn group_routes(group: usize) -> usize {
    let mut routes = 0;
    let mut level = 0;
    while level < GROUPED_LEVELS {
        if in_group(group, level) {
            routes += run_capacity(level);
        }
        level += 1;
    }
    routes
}

/// A group's run: the slot ahead of it and the routes it has slots for,
/// none where the schedule has no room for the group.
#[derive(Clone, Copy)]
struct GroupRun {
    lead: u16,
    capacity: u16,
}

impl GroupRun {
    const fn lead(self) -> usize {
        self.lead as usize
    }

    /// The slot after the run's last: the sentinel of a run that is full,
    /// and the lead of the run that follows.
    const fn end(self) -> u16 {
        self.lead + 1 + self.capacity
    }
}

/// `group`'s run in the schedule of `levels` levels. The groups' runs lie
/// where the runs of the levels past [`named_levels`] would, which no walk
/// starts at, the last group's against the lead of the last named level.
/// That room is shared out in proportion to the routes a full schedule
/// holds: the routes in query-position order get their share at its front,
/// and each group the same fraction of its levels' full runs. A table whose
/// levels are all named has no such room and no groups.
const fn group_run(levels: usize, group: usize) -> GroupRun {
    let named = named_levels(levels);
    if named == levels || named < GROUPED_LEVELS {
        return GroupRun {
            lead: 0,
            capacity: 0,
        };
    }
    let end = run_lead(levels, named - 1);
    let room = end - run_lead(levels, levels - 1) - GROUPS;
    let mut every = PROBE_SCHEDULE_CAPACITY[levels];
    let mut other = 0;
    while other < GROUPS {
        every += group_routes(other);
        other += 1;
    }
    let mut lead = end;
    let mut other = GROUPS;
    loop {
        other -= 1;
        let capacity = group_routes(other) * room / every;
        lead -= capacity + 1;
        if other == group {
            assert!(lead + 1 + capacity <= u16::MAX as usize);
            #[allow(clippy::cast_possible_truncation)]
            return GroupRun {
                lead: lead as u16,
                capacity: capacity as u16,
            };
        }
    }
}

/// [`group_run`] of every group, by the schedule's level count.
const GROUP_RUNS: [[GroupRun; GROUPS]; MAX_LEVELS + 1] = {
    let mut runs = [[GroupRun {
        lead: 0,
        capacity: 0,
    }; GROUPS]; MAX_LEVELS + 1];
    let mut levels = 0;
    while levels <= MAX_LEVELS {
        let mut group = 0;
        while group < GROUPS {
            runs[levels][group] = group_run(levels, group);
            group += 1;
        }
        levels += 1;
    }
    runs
};

/// The groups whose runs have a slot for a route, a bit each, by the
/// schedule's level count.
const FITTED_GROUPS: [u8; MAX_LEVELS + 1] = {
    let mut fitted = [0; MAX_LEVELS + 1];
    let mut levels = 0;
    while levels <= MAX_LEVELS {
        let mut group = 0;
        while group < GROUPS {
            if GROUP_RUNS[levels][group].capacity != 0 {
                fitted[levels] |= 1 << group;
            }
            group += 1;
        }
        levels += 1;
    }
    fitted
};

/// The summary that leaves `group`'s levels open and no other.
const fn group_summary(group: usize) -> SummaryBin {
    let mut summary = NO_LEVELS_OCCUPIED;
    let mut level = 0;
    while level < GROUPED_LEVELS {
        if in_group(group, level) {
            #[allow(clippy::cast_possible_truncation)]
            {
                summary &= !(1 << level_bit(level as u8));
            }
        }
        level += 1;
    }
    summary
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
/// where a walk stops. Each named level's routes are held again in probe
/// order as a run closed by its own sentinel, and each group's in
/// query-position order likewise, while the room has slots for it.
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
    /// held beside its level's entries. [`ProbeScheduleRoom::schedule`]
    /// alone writes them, from the route it puts first.
    direct_reduction: u64,
    direct_control: *const u8,
    /// The entries of level zero, or null for a table without levels.
    direct_entries: *mut u8,
    /// See [`entry_origin`].
    entry_origin: *mut u8,
    book: OwnedBook,
    /// Every slot of the schedule. The slots never move and their count
    /// never changes: [`Self::push`] and [`Self::clear`] only write them.
    ///
    /// These hold a route or the sentinel, and no others are read: the
    /// direct route; the pushed routes after it and the sentinel after
    /// them; after the lead ([`run_lead`]) of each whole run, the routes
    /// its level pushed and the sentinel after them; after the lead
    /// ([`group_run`]) of each whole group's run, the routes its levels
    /// pushed and the sentinel after them; and the last slot, a sentinel.
    slots: Vec<MaybeUninit<PhiRoute>>,
}

/// A [`ScheduleBook`] owned through the address of its walk start for
/// summary zero, so a walk indexes the starts by the signed summary from
/// the one word the schedule holds.
struct OwnedBook {
    zero_start: NonNull<WalkStart>,
}

impl OwnedBook {
    /// Owns `book`, which holds one book and its own capacity in it.
    fn new(book: Vec<ScheduleBook>) -> Self {
        assert!(book.len() == 1 && book[0].allocated == book.capacity());
        let starts = ManuallyDrop::new(book).as_mut_ptr().cast::<WalkStart>();
        // SAFETY: the book begins with its `WALK_STARTS` starts, so the
        // entry is in the allocation, which is not at address zero.
        let zero_start = unsafe { NonNull::new_unchecked(starts.add(WALK_STARTS / 2)) };
        Self { zero_start }
    }

    /// The book, with the provenance of the vector it came in.
    fn as_ptr(&self) -> *mut ScheduleBook {
        // SAFETY: `new` stepped this far into the book.
        unsafe { self.zero_start.as_ptr().sub(WALK_STARTS / 2).cast() }
    }
}

impl core::ops::Deref for OwnedBook {
    type Target = ScheduleBook;

    fn deref(&self) -> &ScheduleBook {
        // SAFETY: the book is live until `drop`, and only `self` reaches it.
        unsafe { &*self.as_ptr() }
    }
}

impl core::ops::DerefMut for OwnedBook {
    fn deref_mut(&mut self) -> &mut ScheduleBook {
        // SAFETY: as in `deref`, and `&mut self` borrows the book alone.
        unsafe { &mut *self.as_ptr() }
    }
}

impl Drop for OwnedBook {
    fn drop(&mut self) {
        let allocated = self.allocated;
        // SAFETY: `new` took the book out of a vector of this length and
        // capacity, and nothing else frees it.
        drop(unsafe { Vec::from_raw_parts(self.as_ptr(), 1, allocated) });
    }
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
        && core::mem::offset_of!(ProbeSchedule, direct_entries)
            == core::mem::offset_of!(ProbeSchedule, direct_control) + size_of::<*const u8>()
        && core::mem::offset_of!(ProbeSchedule, book)
            == core::mem::offset_of!(ProbeSchedule, entry_origin) + size_of::<*const u8>()
        && size_of::<OwnedBook>() == size_of::<*const u8>()
);

impl ProbeSchedule {
    /// [`PhiRoute::index_shift`] and [`PhiRoute::control`] of the direct
    /// route, without reading the route, and the entries of its level.
    /// Where two pointers fill one wide load and the target is
    /// little-endian, that load brings both pointers.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn direct_reach(&self) -> (u32, *const u8, *mut u8) {
        #[cfg(all(target_pointer_width = "64", target_endian = "little"))]
        {
            // SAFETY: `repr(C)` puts the entries right after the control
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
                self.direct_entries.with_addr((both >> u64::BITS) as usize),
            )
        }
        #[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
        (
            self.direct_reduction as u32,
            self.direct_control,
            self.direct_entries,
        )
    }

    /// What a walk past the direct route reads of the schedule: the entry
    /// origin [`Self::entry_at`] adds to, and where a walk under `summary`
    /// steps on from, as [`Self::walk_start`] gives it. Where two pointers
    /// fill one wide load and the target is little-endian, that load brings
    /// the origin and the address of the walk starts.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn walk_reach(&self, summary: SummaryBin) -> (*mut u8, WalkStart) {
        #[cfg(all(target_pointer_width = "64", target_endian = "little"))]
        let (entry_origin, zero_start) = {
            // SAFETY: `repr(C)` puts the book, one pointer, right after the
            // origin, asserted above, so the read covers exactly those two
            // initialized fields. The pointer comes from `self` whole, so it
            // may read both.
            let both = unsafe {
                core::ptr::from_ref(self)
                    .cast::<u8>()
                    .add(core::mem::offset_of!(Self, entry_origin))
                    .cast::<u128>()
                    .read_unaligned()
            };
            (
                self.entry_origin.with_addr(both as usize),
                self.book
                    .zero_start
                    .as_ptr()
                    .with_addr((both >> u64::BITS) as usize),
            )
        };
        #[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
        let (entry_origin, zero_start) = (self.entry_origin, self.book.zero_start.as_ptr());
        // SAFETY: `starts` has an entry at every signed byte's distance.
        let start = unsafe { *zero_start.offset(isize::from(summary.cast_signed())) };
        (entry_origin, start)
    }

    /// The entry beside control byte `slot` of the control bytes at
    /// `control`, by `entry_origin`, the origin [`Self::walk_reach`] gives:
    /// the level's entries first, then the slot's among them. It is an
    /// entry of the levels the schedule was built for when `control` is the
    /// control bytes of one of them, `slot` one of its slots and `T` their
    /// entry type.
    #[inline]
    pub(super) fn entry_at<T>(entry_origin: *mut u8, control: *const u8, slot: usize) -> *mut T {
        entry_origin
            .wrapping_add(control.addr().wrapping_mul(size_of::<T>()))
            .cast::<T>()
            .wrapping_add(slot)
    }

    /// A copy of `self`, which holds routes of the first `scheduled` levels,
    /// for `levels`: each route addresses its level there.
    pub(super) fn clone_onto<T>(&self, levels: &[Level<T>], scheduled: usize) -> Self {
        let mut copy = ProbeScheduleRoom::for_levels(levels.len()).schedule(levels);
        copy.rewind(0, scheduled);
        for route in self.routes() {
            let (level, logical_probe_index) = route.coordinates();
            copy.push(levels, level as usize, logical_probe_index);
        }
        copy
    }

    /// The pushed routes, in query-position order.
    #[inline]
    pub(super) fn routes(&self) -> &[PhiRoute] {
        let pushed = &self.slots[1..=self.book.pushed];
        // SAFETY: the slots of the pushed routes hold routes, and a slot
        // that holds a route is laid out as one.
        unsafe { &*(ptr::from_ref(pushed) as *const [PhiRoute]) }
    }

    /// Where a walk under `summary` steps on from. Every route after it up
    /// to and including a sentinel, whose level is [`SENTINEL_LEVEL`], may
    /// be read. Between the two lie, in query-position order, the pushed
    /// routes of every level `summary` leaves open, and none but pushed
    /// routes; after the lead of a level's run, no other route at all.
    #[cfg(test)]
    pub(super) fn walk_start(&self, summary: SummaryBin) -> WalkStart {
        self.walk_reach(summary).1
    }

    #[cfg(test)]
    pub(super) fn entry_origin(&self) -> *mut u8 {
        self.entry_origin
    }

    /// Points every walk start at a slot the walk may step on from: for
    /// the summary that leaves one level open, the lead of that level's run
    /// while it is whole; for the one that leaves a group's levels open,
    /// the lead of that group's run while it is whole; for the one that
    /// leaves none, the slot ahead of the last, a sentinel; for the others,
    /// the direct route. Either way the walk probes what it would from the
    /// direct route, where every route of a level the summary closes is a
    /// step it skips.
    fn fill_starts(&mut self) {
        let first = self.slots.as_ptr().cast::<PhiRoute>();
        let slots = self.slots.len();
        let book = &mut *self.book;
        let entry = |summary: SummaryBin| (WALK_STARTS / 2 + usize::from(summary)) % WALK_STARTS;
        book.starts = [WalkStart::at_list(first); WALK_STARTS];
        // SAFETY: a schedule has the direct route's slot and two more.
        book.starts[entry(NO_LEVELS_OCCUPIED)] = WalkStart::at_run(unsafe { first.add(slots - 2) });
        for level in 0..book.whole_runs {
            if let Some(summary) = lone_level_summary(book.levels, level) {
                // SAFETY: a run's lead is a slot of the schedule.
                let lead = unsafe { first.add(run_lead(book.levels, level)) };
                book.starts[entry(summary)] = WalkStart::at_run(lead);
            }
        }
        for (group, run) in GROUP_RUNS[book.levels].iter().enumerate() {
            if book.whole_groups >> group & 1 != 0 {
                // SAFETY: a fitted group's lead is a slot of the schedule.
                let lead = unsafe { first.add(run.lead()) };
                book.starts[entry(group_summary(group))] = WalkStart::at_list(lead);
            }
        }
    }

    /// Drops the pushed routes.
    pub(super) fn clear(&mut self) {
        self.rewind(0, 0);
    }

    /// Drops the pushed routes ahead of pushing those of the first `after`
    /// levels, where the first `before` levels were pushed: the routes of
    /// the levels in both are pushed again, in the same order and every
    /// one of them. A group's run holds no route of another level, so where
    /// every grouped level is in both the groups' runs keep their routes
    /// and are not written again. The groups have runs from the first push
    /// on once every grouped level is pushed, and none before: a walk of a
    /// group's levels has no route to skip until then.
    pub(super) fn rewind(&mut self, before: usize, after: usize) {
        let book = &mut *self.book;
        // Every level's run is whole again, and empty: a sentinel follows
        // its lead. So does one follow the direct route, and one is the
        // last slot.
        let runs = named_levels(book.levels);
        self.slots[1].write(SENTINEL);
        for level in 0..runs {
            self.slots[run_lead(book.levels, level) + 1].write(SENTINEL);
        }
        self.slots
            .last_mut()
            .expect("a schedule has slots")
            .write(SENTINEL);
        book.run_len = [0; MAX_LEVELS];
        book.pushed = 0;
        book.grouped_pushed = 0;
        let mut groups = book.whole_groups;
        if before.min(after) < GROUPED_LEVELS {
            groups = if after < GROUPED_LEVELS {
                0
            } else {
                FITTED_GROUPS[book.levels]
            };
            book.grouped_held = 0;
            for (group, run) in GROUP_RUNS[book.levels].iter().enumerate() {
                if groups >> group & 1 != 0 {
                    book.group_next[group] = run.lead + 1;
                    self.slots[run.lead() + 1].write(SENTINEL);
                }
            }
        }
        self.set_whole(runs, groups);
    }

    /// Makes the first `runs` levels' runs and the runs of `groups` the
    /// ones a walk may start at. Nothing walks the schedule while it is
    /// borrowed to change, so the starts may follow the writes that end a
    /// run.
    fn set_whole(&mut self, runs: usize, groups: u8) {
        let book = &mut *self.book;
        // The groups' runs lie ahead of the levels', the first group's
        // first, and a deeper level's ahead of a shallower one's.
        let lead = if groups != 0 {
            GROUP_RUNS[book.levels][groups.trailing_zeros() as usize].lead()
        } else if runs != 0 {
            run_lead(book.levels, runs - 1)
        } else {
            usize::MAX
        };
        book.reach = lead.min(PROBE_SCHEDULE_CAPACITY[book.levels] + 1);
        book.open_groups = if groups == 0 { 0 } else { GROUPED_LEVELS };
        if (book.whole_runs, book.whole_groups) != (runs, groups) {
            book.whole_runs = runs;
            book.whole_groups = groups;
            self.fill_starts();
        }
    }

    /// Appends the route of logical probe `logical_probe_index` of level
    /// `level` of `levels`, the slice this schedule was built for or a
    /// prefix of it. The caller appends routes in query-position order,
    /// which is each level's probe order.
    pub(super) fn push<T>(&mut self, levels: &[Level<T>], level: usize, logical_probe_index: u64) {
        if self.book.pushed + 1 >= self.book.reach {
            // No walk may start at a run the routes are about to overwrite.
            self.leave_reached_runs();
        }
        let route = PhiRoute::new(level, &levels[level], logical_probe_index);
        let book = &mut *self.book;
        let in_run = level < book.whole_runs;
        let run_len = usize::from(book.run_len[level]);
        if in_run {
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
        book.pushed += 1;
        self.slots[book.pushed].write(route);
        self.slots[book.pushed + 1].write(SENTINEL);
        if in_run {
            let run = run_lead(book.levels, level) + 1 + run_len;
            self.slots[run].write(route);
            // The lead of the run after this one, or the last slot, when
            // the run is full.
            self.slots[run + 1].write(SENTINEL);
            book.run_len[level] += 1;
        }
        if level < book.open_groups {
            book.grouped_pushed += 1;
            if book.grouped_pushed > book.grouped_held {
                book.grouped_held = book.grouped_pushed;
                self.append_to_groups(route, level);
            } else {
                // The first group has every grouped level, so its run holds
                // the routes in the order `grouped_pushed` counts them.
                debug_assert!(
                    book.whole_groups & 1 == 0 || {
                        let held =
                            GROUP_RUNS[book.levels][0].lead() + usize::from(book.grouped_pushed);
                        // SAFETY: a whole run holds a route in each slot up to
                        // its next, which the routes it was given reach.
                        unsafe { self.slots[held].assume_init() == route }
                    }
                );
            }
        }
    }

    /// Stops walks from starting at the runs the routes and their sentinel
    /// reach with one more pushed, which they do in the runs' order.
    #[cold]
    fn leave_reached_runs(&mut self) {
        let book = &*self.book;
        assert!(
            book.pushed < PROBE_SCHEDULE_CAPACITY[book.levels],
            "probe schedule outgrew its room"
        );
        let pushed = book.pushed + 1;
        let mut groups = book.whole_groups;
        while groups != 0 {
            let first = groups.trailing_zeros() as usize;
            if GROUP_RUNS[book.levels][first].lead() > pushed {
                break;
            }
            groups &= groups - 1;
        }
        let runs = whole_runs(book.levels, pushed, book.whole_runs);
        self.set_whole(runs, groups);
    }

    /// Appends `route`, of grouped level `level`, to the run of each whole
    /// group the level is in, or stops walks from starting at a run that
    /// has no slot for it.
    fn append_to_groups(&mut self, route: PhiRoute, level: usize) {
        let book = &mut *self.book;
        let mut whole = book.whole_groups;
        let groups = whole & LEVEL_GROUPS[level];
        for group in 0..GROUPS {
            if groups >> group & 1 == 0 {
                continue;
            }
            let slot = book.group_next[group];
            if slot == book.group_end[group] {
                whole &= !(1 << group);
                continue;
            }
            self.slots[usize::from(slot)].write(route);
            // The lead of the group after this one, or of the last named
            // level, when the run is full.
            self.slots[usize::from(slot) + 1].write(SENTINEL);
            book.group_next[group] = slot + 1;
            #[cfg(test)]
            {
                book.group_appends += 1;
            }
        }
        if whole != book.whole_groups {
            let runs = book.whole_runs;
            self.set_whole(runs, whole);
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
        let mut route = match self.walk_start(summary).run() {
            Ok(run) => run.route(),
            Err(direct) => direct,
        };
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
        let book = &mut *self.book;
        book.whole_runs = 0;
        book.whole_groups = 0;
        book.open_groups = 0;
        book.reach = PROBE_SCHEDULE_CAPACITY[book.levels] + 1;
        book.starts = [WalkStart::at_list(direct); WALK_STARTS];
    }

    /// Whether every route is the one its level in `levels` gives, every
    /// whole run holds its level's pushed routes in order and every whole
    /// group's run its levels', and every walk start is the one its
    /// summary has: the lead of the whole run of the one level or group it
    /// leaves open, the slot ahead of the last where it leaves none open,
    /// and the direct route otherwise.
    #[cfg(test)]
    pub(super) fn addresses<T>(&self, levels: &[Level<T>]) -> bool {
        let book = &*self.book;
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
            && self.direct_reach().0 == slot(0).index_shift()
            && self.direct_reach().1 == slot(0).control()
            && self.direct_reach().2
                == levels
                    .first()
                    .map_or(ptr::null_mut(), |level| level.data_ptr.cast())
            && self.entry_origin == entry_origin(levels)
            && self.walk_reach(0).0 == self.entry_origin
            && self.routes().iter().all(|route| {
                let (level, logical_probe_index) = route.coordinates();
                let level = level as usize;
                *route == PhiRoute::new(level, &levels[level], logical_probe_index)
            })
            && self.ends_with_sentinel()
            && slot(self.slots.len() - 1) == SENTINEL
            && book.whole_runs == whole_runs(book.levels, book.pushed, named_levels(book.levels))
            && book.whole_groups & !FITTED_GROUPS[book.levels] == 0
            && (0..GROUPS)
                .filter(|group| book.whole_groups >> group & 1 != 0)
                .all(|group| {
                    let run = GROUP_RUNS[book.levels][group];
                    let (lead, capacity) = (run.lead(), usize::from(run.capacity));
                    let len = usize::from(book.group_next[group]) - lead - 1;
                    let pushed = || {
                        self.routes()
                            .iter()
                            .filter(move |route| in_group(group, usize::from(route.level())))
                    };
                    book.pushed < lead
                        && len <= capacity
                        && len == pushed().count()
                        && (lead + 1..)
                            .zip(pushed())
                            .all(|(run, pushed)| slot(run) == *pushed)
                        && slot(lead + 1 + len) == SENTINEL
                })
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
                let slot = |slot: usize| self.slots[slot].as_ptr().cast::<PhiRoute>();
                let group = (0..GROUPS).find(|&group| {
                    book.whole_groups >> group & 1 != 0 && summary == group_summary(group)
                });
                let level = (0..book.whole_runs)
                    .find(|&level| lone_level_summary(book.levels, level) == Some(summary));
                let start = if let Some(group) = group {
                    WalkStart::at_list(slot(GROUP_RUNS[book.levels][group].lead()))
                } else if let Some(level) = level {
                    WalkStart::at_run(slot(run_lead(book.levels, level)))
                } else if summary == NO_LEVELS_OCCUPIED {
                    WalkStart::at_run(slot(self.slots.len() - 2))
                } else {
                    WalkStart::at_list(self.direct())
                };
                self.walk_start(summary) == start
            })
    }

    /// Levels whose runs a walk may start at.
    #[cfg(test)]
    pub(super) fn whole_runs(&self) -> usize {
        self.book.whole_runs
    }

    /// Levels that have runs.
    #[cfg(test)]
    pub(super) fn named_levels(&self) -> usize {
        named_levels(self.book.levels)
    }

    #[cfg(test)]
    pub(super) fn group_appends(&self) -> usize {
        self.book.group_appends
    }

    /// Groups whose runs a walk may start at, of how many the schedule has
    /// room for.
    #[cfg(test)]
    pub(super) fn whole_groups(&self) -> (u32, u32) {
        (
            self.book.whole_groups.count_ones(),
            FITTED_GROUPS[self.book.levels].count_ones(),
        )
    }

    #[cfg(test)]
    pub(super) fn route_capacity(&self) -> usize {
        PROBE_SCHEDULE_CAPACITY[self.book.levels]
    }

    #[cfg(test)]
    pub(super) fn ends_with_sentinel(&self) -> bool {
        // SAFETY: a sentinel follows the pushed routes.
        unsafe { self.slots[self.book.pushed + 1].assume_init() == SENTINEL }
    }
}
