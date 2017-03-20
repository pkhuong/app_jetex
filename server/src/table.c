#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "include/jetex_server.h"
#include "utility/cc.h"
#include "table.h"
#include "fragment.h"

struct table_scan_result {
	uint64_t max_pattern;
	uint64_t min_pattern;
	uint32_t n_bits;
	uint32_t fail;
};

static struct table_scan_result
table_scan(const int *fds, size_t n_fd)
{
	struct table_scan_result ret = {
		.max_pattern = 0,
		.min_pattern = UINT64_MAX,
		.n_bits = 0,
		.fail = 0
	};

	for (size_t i = 0; i < n_fd; i++) {
		uint64_t pattern;
		uint8_t cur_n_bits;

		if (fragment_validate(fds[i], &pattern, &cur_n_bits) != 0 ||
		    cur_n_bits >= 32) {
			return (struct table_scan_result) { .fail = 1 };
		}

		if (pattern < ret.min_pattern) {
			ret.min_pattern = pattern;
		}

		/* find the (inclusive) top end of the range. */
		if (cur_n_bits == 0) {
			pattern = UINT64_MAX;
		} else {
			pattern |= (1UL << (64 - cur_n_bits)) - 1;
		}

		if (pattern > ret.max_pattern) {
			ret.max_pattern = pattern;
		}

		if (cur_n_bits > ret.n_bits) {
			ret.n_bits = cur_n_bits;
		}
	}

	return ret;
}

static inline uint64_t
extract(uint64_t pattern, uint8_t n_bits)
{

	return pattern >> (64 - n_bits);
}

struct jetex_table *
jetex_table_create(const uint8_t uuid[static 16],
    const int *restrict fds, uint64_t *restrict refcounts, size_t n)
{
	struct jetex_table *ret = NULL;
	struct fragment *fragments = NULL; /* [n]. */
	size_t *slot_index = NULL; /* slot -> fd/refcount/fragment index. */
	uint64_t max_pattern = 0;
	uint64_t min_pattern = UINT64_MAX;
	size_t n_fragment;
	uint8_t n_bits = 0;

	if (n == 0) {
		return NULL;
	}

	{
		struct table_scan_result scan_result;

		scan_result = table_scan(fds, n);
		if (scan_result.fail != 0) {
			goto fail;
		}

		max_pattern = scan_result.max_pattern;
		min_pattern = scan_result.min_pattern;
		n_bits = (uint8_t)scan_result.n_bits;
	}

	n_fragment = 1 + extract(max_pattern - min_pattern, n_bits);
	if (n_fragment > (SIZE_MAX - sizeof(*ret)) / sizeof(struct fragment)) {
		goto fail;
	}

	ret = calloc(1,
	    sizeof(*ret) + sizeof(struct fragment) * n_fragment);
	fragments = calloc(n, sizeof(fragments[0]));
	slot_index = calloc(n_fragment, sizeof(slot_index[0]));

	for (size_t i = 0; i < n; i++) {
		fragments[i] = fragment_map(fds[i]);
		refcounts[i] = 0;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ret->uuid_bytes); i++) {
		ret->uuid_bytes[i] = uuid[i];
	}

	ret->min_fragment = (uint32_t)extract(min_pattern, n_bits);
	ret->n_fragment = (uint32_t)n_fragment;
	ret->fragment_shift = (uint8_t)(64 - n_bits);

	for (size_t i = 0; i < n; i++) {
		struct fragment *cur = &fragments[i];
		uint64_t lo, hi;

		lo = cur->data->pattern;
		hi = lo | ((1ULL << (64 - cur->data->n_bits)) - 1);

		lo >>= ret->fragment_shift;
		hi >>= ret->fragment_shift;
		lo -= ret->min_fragment;
		hi -= ret->min_fragment;

		for (uint64_t j = lo; j <= hi; j++) {
			struct fragment *dst = jetex_table_fragment(ret, j);

			assert(j <= n_fragment);
			if (dst->data != NULL) {
				assert(slot_index[j] < n);
				assert(refcounts[slot_index[j]] > 0);
				refcounts[slot_index[j]]--;
			}

			*dst = *cur;
			assert(refcounts[i] < UINT64_MAX);
			refcounts[i]++;
			slot_index[j] = i;
		}
	}

	for (size_t i = 0; i < n; i++) {
		if (refcounts[i] == 0) {
			fragment_unmap(&fragments[i]);
		}
	}

	free(fragments);
	free(slot_index);
	return ret;

fail:
	free(ret);
	free(fragments);
	free(slot_index);
	return NULL;
}

static int
cmp_fragment(const void *vx, const void *vy)
{
	const struct fragment *x = vx;
	const struct fragment *y = vy;

	if ((uintptr_t)x->data != (uintptr_t)y->data) {
		return ((uintptr_t)x->data < (uintptr_t)y->data) ? -1 : 1;
	}

	return 0;
}

void
jetex_table_destroy(struct jetex_table *table)
{
	const struct fragment_header *last_data = NULL;

	if (table == NULL) {
		return;
	}

	qsort(jetex_table_fragment(table, 0), table->n_fragment,
	    sizeof(struct fragment), cmp_fragment);
	for (size_t i = 0; i < table->n_fragment; i++) {
		struct fragment *fragment = jetex_table_fragment(table, i);

		if (fragment->data != NULL && fragment->data != last_data) {
			fragment_unmap(fragment);
		}

		last_data = fragment->data;
		*fragment = (struct fragment) { .data = NULL };
	}

	*table = (struct jetex_table) { .uuid = { 0, 0 } };
	free(table);
	return;
}

const void *
table_lookup(const struct jetex_table *restrict table,
    size_t *restrict OUT_item_size,
    const uint64_t key[static 8])
{
	uint64_t key0 = key[0];
	uint64_t idx;

	*OUT_item_size = 0;
	idx = (table->fragment_shift >= 64) ? 0 : key0 >> table->fragment_shift;
	if (idx < table->min_fragment) {
		return NULL;
	}

	idx -= table->min_fragment;
	if (idx >= table->n_fragment) {
		return NULL;
	}

	return fragment_lookup(jetex_table_fragment(table, idx),
	    OUT_item_size, key);
}
