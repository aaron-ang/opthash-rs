SECTIONS
{
  .opthash.cache_gate.funnel.insert ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_funnel_insert_reservation_start = .; KEEP(*(.text.opthash.cache_gate.funnel.insert)) __opthash_cache_gate_funnel_insert_body_end = .; ASSERT((__opthash_cache_gate_funnel_insert_body_end - __opthash_cache_gate_funnel_insert_reservation_start) <= CONSTANT(MAXPAGESIZE), "funnel insert cache-gate reservation overflow"); . = __opthash_cache_gate_funnel_insert_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_funnel_insert_reservation_end = .; }
  .opthash.cache_gate.funnel.get ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_funnel_get_reservation_start = .; KEEP(*(.text.opthash.cache_gate.funnel.get)) __opthash_cache_gate_funnel_get_body_end = .; ASSERT((__opthash_cache_gate_funnel_get_body_end - __opthash_cache_gate_funnel_get_reservation_start) <= CONSTANT(MAXPAGESIZE), "funnel get cache-gate reservation overflow"); . = __opthash_cache_gate_funnel_get_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_funnel_get_reservation_end = .; }
}
INSERT BEFORE .text;
