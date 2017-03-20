#ifndef JETEX_TABLE_H
#define JETEX_TABLE_H
#include <stdint.h>
#include <stddef.h>

#include "fragment.h"

struct jetex_table {
	union {
		uint64_t uuid[2];
		uint8_t uuid_bytes[16];
	};
	uint32_t min_fragment;
	uint32_t n_fragment;
	uint8_t fragment_shift;
	uint8_t padding[7];
};

static inline struct fragment *
jetex_table_fragment(const struct jetex_table *table, size_t index)
{
	struct fragment *fragments = (void *)(table + 1);

	return &fragments[index];
}

JT_CC_PUBLIC struct jetex_table *
jetex_table_create(const uint8_t uuid[static 16],
    const int *restrict fds, uint64_t *restrict refcounts, size_t n_fd);

JT_CC_PUBLIC void
jetex_table_destroy(struct jetex_table *table);

const void *
table_lookup(const struct jetex_table *restrict table,
    size_t *restrict OUT_item_size,
    const uint64_t key[static 8]);
#endif /* !JETEX_TABLE_H */
