#ifndef JETEX_TABLE_FRAGMENT_H
#define JETEX_TABLE_FRAGMENT_H
#include <stdint.h>

#include "utility/cc.h"

/* "JetX" in LE. */
#define FRAGMENT_HEADER_MAGIC 0x5874654AU

struct fragment_header {
	uint32_t magic;
	uint32_t version;
	uint64_t pattern;
	uint8_t n_bits;
	uint8_t key_size; /* in uint64_t. */
	uint16_t item_size; /* in uint64_t. */
	uint16_t max_displacement;
	uint16_t padding0;
	uint64_t table_size; /* of the data table, including header. */
	uint64_t min;
	uint64_t max;
	uint64_t multiplier;
	uint64_t padding1;
	uint8_t signature[64];
};

struct fragment {
	const struct fragment_header *data;
	uint64_t n_bytes;
	uint64_t min;
	uint64_t range;
	uint64_t multiplier;
	uint32_t item_size; /* in uint64_t. */
	uint32_t max_displacement;
	unsigned int key_size; /* in uint64_t */
	int fd;
	int64_t data_offset;
} __attribute__((__aligned__(64)));

static inline const void *
fragment_header_data(const struct fragment_header *header)
{

	return (header + 1);
}

JT_CC_PUBLIC int
jetex_table_fragment_validate(int fd);

int
fragment_validate(int fd, uint64_t *OUT_pattern, uint8_t *OUT_nbits);

struct fragment
fragment_map(int fd);

void
fragment_unmap(const struct fragment *fragment);

const void *
fragment_lookup(const struct fragment *restrict fragment,
    size_t *restrict OUT_item_size,
    const uint64_t key[static 8]);
#endif /* !JETEX_TABLE_FRAGMENT_H */
