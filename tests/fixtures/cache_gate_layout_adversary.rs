#[cfg(cache_gate_layout_adversary)]
// SAFETY: Proof-only generic emission is linked into an ordinary executable
// text section and structural validation proves it stays outside reservations.
#[unsafe(link_section = ".text.opthash.cache_gate.layout_adversary")]
#[inline(never)]
fn cache_gate_layout_adversary_private<T: Copy>(value: T) -> usize {
    std::hint::black_box(std::mem::size_of_val(std::hint::black_box(&value)))
}

#[cfg(cache_gate_layout_adversary)]
fn exercise_cache_gate_layout_adversary() {
    std::hint::black_box(cache_gate_layout_adversary_private([0xA5_u64; 17]));
}

#[cfg(not(cache_gate_layout_adversary))]
fn exercise_cache_gate_layout_adversary() {}
