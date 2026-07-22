mod harness;

use std::fs::File;
use std::hint::black_box;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

include!("../tests/fixtures/cache_gate_layout_adversary.rs");

#[derive(Clone, Copy)]
enum Operation {
    ElasticInsert,
    ElasticGet,
    FunnelInsert,
    FunnelGet,
}

struct Arguments {
    operation: Operation,
    iterations: usize,
    ready_fd: RawFd,
    go_fd: RawFd,
}

struct Gate {
    ready: File,
    go: BufReader<File>,
}

fn parse_arguments() -> Result<Arguments, String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 8 {
        return Err(
            "expected exactly --operation VALUE --iterations N --ready-fd FD --go-fd FD".into(),
        );
    }
    let mut operation = None;
    let mut iterations = None;
    let mut ready_fd = None;
    let mut go_fd = None;
    for pair in arguments.chunks_exact(2) {
        match pair[0].as_str() {
            "--operation" if operation.is_none() => {
                operation = Some(match pair[1].as_str() {
                    "elastic-insert" => Operation::ElasticInsert,
                    "elastic-get" => Operation::ElasticGet,
                    "funnel-insert" => Operation::FunnelInsert,
                    "funnel-get" => Operation::FunnelGet,
                    value => return Err(format!("unsupported operation: {value}")),
                });
            }
            "--iterations" if iterations.is_none() => {
                let value = pair[1]
                    .parse::<usize>()
                    .map_err(|_| "--iterations must be a positive integer")?;
                if value == 0 {
                    return Err("--iterations must be a positive integer".into());
                }
                iterations = Some(value);
            }
            "--ready-fd" if ready_fd.is_none() => {
                ready_fd = Some(parse_fd(&pair[1], "--ready-fd")?);
            }
            "--go-fd" if go_fd.is_none() => {
                go_fd = Some(parse_fd(&pair[1], "--go-fd")?);
            }
            option => return Err(format!("duplicate or unsupported option: {option}")),
        }
    }
    let operation = operation.ok_or("missing --operation")?;
    let iterations = iterations.ok_or("missing --iterations")?;
    let ready_fd = ready_fd.ok_or("missing --ready-fd")?;
    let go_fd = go_fd.ok_or("missing --go-fd")?;
    harness::validate_cache_gate_profile_fds(ready_fd, go_fd).map_err(str::to_owned)?;
    harness::validate_cache_gate_profile_iterations(
        matches!(
            operation,
            Operation::ElasticInsert | Operation::FunnelInsert
        ),
        iterations,
    )?;
    Ok(Arguments {
        operation,
        iterations,
        ready_fd,
        go_fd,
    })
}

fn parse_fd(value: &str, option: &str) -> Result<RawFd, String> {
    value
        .parse::<RawFd>()
        .ok()
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| format!("{option} must be a nonnegative file descriptor"))
}

fn ready_then_wait(ready_fd: RawFd, go_fd: RawFd) -> Result<Gate, Box<dyn std::error::Error>> {
    harness::validate_cache_gate_profile_fds(ready_fd, go_fd)?;
    // SAFETY: validated descriptors are distinct and launcher transfers both
    // owned descriptors to this short-lived process exactly once.
    let ready_owned = unsafe { OwnedFd::from_raw_fd(ready_fd) };
    // SAFETY: same ownership contract, after the distinctness check above.
    let go_owned = unsafe { OwnedFd::from_raw_fd(go_fd) };
    let mut ready = File::from(ready_owned);
    let go = File::from(go_owned);
    ready.write_all(harness::cache_gate_profile_ready_message(std::process::id()).as_bytes())?;
    ready.flush()?;
    let mut command = String::new();
    let mut go = BufReader::new(go);
    go.read_line(&mut command)?;
    if command.trim_end() != "GO" {
        return Err(format!("expected GO, received {command:?}").into());
    }
    Ok(Gate { ready, go })
}

impl Gate {
    fn done_then_wait_for_stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.ready.write_all(b"DONE\n")?;
        self.ready.flush()?;
        let mut command = String::new();
        self.go.read_line(&mut command)?;
        if command.trim_end() != "STOP" {
            return Err(format!("expected STOP, received {command:?}").into());
        }
        Ok(())
    }
}

// SAFETY: Linux cache-gate links this function through the checked RX-only
// target-specific augmentation and validates the final ELF.
#[cfg_attr(
    target_os = "linux",
    unsafe(link_section = ".text.opthash.cache_gate.profile.elastic.insert")
)]
#[inline(never)]
fn elastic_profile_insert_kernel(
    maps: &mut [harness::ElasticHashMap<u64, u64>],
    pairs: &[(u64, u64)],
) {
    for map in maps {
        for &(key, value) in pairs {
            black_box(map.insert(black_box(key), black_box(value)));
        }
    }
}

// SAFETY: Linux cache-gate links this function through the checked RX-only
// target-specific augmentation and validates the final ELF.
#[cfg_attr(
    target_os = "linux",
    unsafe(link_section = ".text.opthash.cache_gate.profile.elastic.get")
)]
#[inline(never)]
fn elastic_profile_get_kernel(
    map: &harness::ElasticHashMap<u64, u64>,
    keys: &[u64],
    iterations: usize,
) -> u64 {
    let mut checksum = 0_u64;
    for key in keys.iter().cycle().take(iterations) {
        checksum ^= black_box(map.get(black_box(key)).copied().unwrap());
    }
    checksum
}

// SAFETY: Linux cache-gate links this function through the checked RX-only
// target-specific augmentation and validates the final ELF.
#[cfg_attr(
    target_os = "linux",
    unsafe(link_section = ".text.opthash.cache_gate.profile.funnel.insert")
)]
#[inline(never)]
fn funnel_profile_insert_kernel(
    maps: &mut [harness::FunnelHashMap<u64, u64>],
    pairs: &[(u64, u64)],
) {
    for map in maps {
        for &(key, value) in pairs {
            black_box(map.insert(black_box(key), black_box(value)));
        }
    }
}

fn empty_elastic_maps(
    iterations: usize,
    pairs: &[(u64, u64)],
) -> Vec<harness::ElasticHashMap<u64, u64>> {
    (0..iterations)
        .map(|_| {
            let mut map = harness::elastic_cache_gate_map();
            harness::validate_cache_gate_fill(&mut map, pairs);
            map.clear();
            map
        })
        .collect()
}

fn empty_funnel_maps(
    iterations: usize,
    pairs: &[(u64, u64)],
) -> Vec<harness::FunnelHashMap<u64, u64>> {
    (0..iterations)
        .map(|_| {
            let mut map = harness::funnel_cache_gate_map();
            harness::validate_funnel_cache_gate_fill(&mut map, pairs);
            map.clear();
            map
        })
        .collect()
}

// SAFETY: Linux cache-gate links this function through the checked RX-only
// target-specific augmentation and validates the final ELF.
#[cfg_attr(
    target_os = "linux",
    unsafe(link_section = ".text.opthash.cache_gate.profile.funnel.get")
)]
#[inline(never)]
fn funnel_profile_get_kernel(
    map: &harness::FunnelHashMap<u64, u64>,
    keys: &[u64],
    iterations: usize,
) -> u64 {
    let mut checksum = 0_u64;
    for key in keys.iter().cycle().take(iterations) {
        checksum ^= black_box(map.get(black_box(key)).copied().unwrap());
    }
    checksum
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    exercise_cache_gate_layout_adversary();
    let arguments = parse_arguments().map_err(|error| format!("error: {error}"))?;
    let pairs = harness::cache_gate_pairs();
    match arguments.operation {
        Operation::ElasticInsert => {
            let expected = arguments
                .iterations
                .checked_mul(pairs.len())
                .ok_or("operation count overflow")?;
            let mut maps = empty_elastic_maps(arguments.iterations, &pairs);
            let gate = ready_then_wait(arguments.ready_fd, arguments.go_fd)?;
            elastic_profile_insert_kernel(&mut maps, &pairs);
            gate.done_then_wait_for_stop()?;
            assert_eq!(maps.len() * pairs.len(), expected);
            for map in &maps {
                assert_eq!(map.len(), pairs.len());
            }
        }
        Operation::ElasticGet => {
            let mut map = harness::elastic_cache_gate_map();
            harness::validate_cache_gate_fill(&mut map, &pairs);
            let keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
            let gate = ready_then_wait(arguments.ready_fd, arguments.go_fd)?;
            let checksum = black_box(elastic_profile_get_kernel(
                &map,
                &keys,
                arguments.iterations,
            ));
            gate.done_then_wait_for_stop()?;
            black_box(checksum);
        }
        Operation::FunnelInsert => {
            let expected = arguments
                .iterations
                .checked_mul(pairs.len())
                .ok_or("operation count overflow")?;
            let mut maps = empty_funnel_maps(arguments.iterations, &pairs);
            let gate = ready_then_wait(arguments.ready_fd, arguments.go_fd)?;
            funnel_profile_insert_kernel(&mut maps, &pairs);
            gate.done_then_wait_for_stop()?;
            assert_eq!(maps.len() * pairs.len(), expected);
            for map in &maps {
                assert_eq!(map.len(), pairs.len());
            }
        }
        Operation::FunnelGet => {
            let mut map = harness::funnel_cache_gate_map();
            harness::validate_funnel_cache_gate_fill(&mut map, &pairs);
            let keys = pairs.iter().map(|pair| pair.0).collect::<Vec<_>>();
            let gate = ready_then_wait(arguments.ready_fd, arguments.go_fd)?;
            let checksum = black_box(funnel_profile_get_kernel(&map, &keys, arguments.iterations));
            gate.done_then_wait_for_stop()?;
            black_box(checksum);
        }
    }
    Ok(())
}
