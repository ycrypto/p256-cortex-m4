#include <stdint.h>
/**
 * Checks that the argument, as little-endian integer, is a reduced non-zero element of the scalar field.
 *
 * In other words, that it is in the range `1..=n-1`, where `n = 2^256 - 2^224 + 2^192 - 0x4319055258e8617b0c46353d039cdaaf`.
 *
 */
bool P256_check_range_n(const uint32_t a[8]);
/**
 * Checks that the argument, as little-endian integer, is a reduced element of the base field.
 *
 * In other words, that it is in the range `0..=p-1`, where `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
 */
bool P256_check_range_p(const uint32_t a[8]);
