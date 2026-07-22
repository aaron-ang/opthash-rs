SECTIONS
{
  .opthash.cache_gate.elastic.insert ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_elastic_insert_reservation_start = .; KEEP(*(.text.opthash.cache_gate.elastic.insert)) __opthash_cache_gate_elastic_insert_body_end = .; ASSERT((__opthash_cache_gate_elastic_insert_body_end - __opthash_cache_gate_elastic_insert_reservation_start) <= CONSTANT(MAXPAGESIZE), "elastic insert cache-gate reservation overflow"); . = __opthash_cache_gate_elastic_insert_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_elastic_insert_reservation_end = .; }
  .opthash.cache_gate.elastic.get ALIGN(CONSTANT(MAXPAGESIZE)) :
  { __opthash_cache_gate_elastic_get_reservation_start = .; KEEP(*(.text.opthash.cache_gate.elastic.get)) __opthash_cache_gate_elastic_get_body_end = .; ASSERT((__opthash_cache_gate_elastic_get_body_end - __opthash_cache_gate_elastic_get_reservation_start) <= CONSTANT(MAXPAGESIZE), "elastic get cache-gate reservation overflow"); . = __opthash_cache_gate_elastic_get_reservation_start + CONSTANT(MAXPAGESIZE); __opthash_cache_gate_elastic_get_reservation_end = .; }
}
INSERT BEFORE .text;
