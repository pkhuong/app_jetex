#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "include/jetex_server.h"
#include "fragment.h"
#include "utility/cc.h"

static inline uint64_t
scale(uint64_t delta, uint64_t multiplier)
{
	unsigned __int128 offset = multiplier;

	offset *= delta;
	return (uint64_t)(offset >> 64);
}

static int
validate_header(const struct fragment_header *header, int fd)
{

	if (header->magic != FRAGMENT_HEADER_MAGIC) {
		return -1;
	}

	if (header->version != 0) {
		return -1;
	}

	if (header->n_bits == 0) {
		if (header->pattern != 0) {
			return -1;
		}
	} else {
		uint64_t mask;

		if (header->n_bits >= 64) {
			return -1;
		}

		mask = ~(uint64_t)0;
		mask <<= 64 - header->n_bits;
		/* Low 64 - n_bits bits must all be 0. */
		if (header->pattern != (header->pattern & mask)) {
			return -1;
		}
	}

	if (header->key_size != 1 &&
	    header->key_size != 2 &&
	    header->key_size != 4 &&
	    header->key_size != 8) {
		return -1;
	}

	if (header->item_size < header->key_size) {
		return -1;
	}

	if (header->max < header->min) {
		return -1;
	}

	{
		uint64_t range = header->max - header->min;
		uint64_t guess = scale(range, header->multiplier);
		uint64_t max_index;
		uint64_t max_offset;

		if (UINT64_MAX - guess < header->max_displacement) {
			return -1;
		}

		max_index = guess + header->max_displacement;
		if (max_index > UINT64_MAX / (sizeof(uint64_t) * header->item_size)) {
			return -1;
		}

		max_offset = max_index * sizeof(uint64_t) * header->item_size;
		if (max_offset > UINT64_MAX - sizeof(*header)) {
			return -1;
		}

		if (max_offset + sizeof(*header) > header->table_size) {
			return -1;
		}
	}

	{
		struct stat buf;
		int r;

		r = fstat(fd, &buf);
		if (r < 0 || header->table_size < (uint64_t)buf.st_size) {
			return -1;
		}
	}

	return 0;
}

int
fragment_validate(int fd, uint64_t *OUT_pattern, uint8_t *OUT_nbits)
{
	struct fragment_header header;
	ssize_t r;

	*OUT_pattern = 0;
	*OUT_nbits = 0;
	for (size_t i = 0; i < 10; i++) {
		r = pread(fd, &header, sizeof(header), 0);

		if (r == -1 && errno == EINTR) {
			continue;
		}

		if (r < 0 || (size_t)r < sizeof(header)) {
			return -1;
		}
	}

	if (r < 0) {
		return (int)r;
	}

	r = validate_header(&header, fd);
	if (r != 0) {
		return (int)r;
	}

	/* XXX: Check signature. */
	*OUT_pattern = header.pattern;
	*OUT_nbits = header.n_bits;
	return 0;
}

int
jetex_table_fragment_validate(int fd)
{
	uint64_t pattern;
	uint8_t n_bits;

	(void)pattern;
	(void)n_bits;
	return fragment_validate(fd, &pattern, &n_bits);
}

struct fragment
fragment_map(int fd)
{
	struct fragment_header header;
	struct fragment_header *map;
	ssize_t r;

	r = pread(fd, &header, sizeof(header), 0);
	assert(r == sizeof(header) && "Short header read.");
	assert(validate_header(&header, fd) == 0 &&
	    "fragment header failed validation.");

	map = mmap(NULL, header.table_size,
	    PROT_READ, MAP_SHARED, fd, 0);
	assert((void *)map != MAP_FAILED && "mmap of fragment failed.");

	return (struct fragment) {
		.data = map,
		.n_bytes = header.table_size - sizeof(header),
		.min = header.min,
		.range = header.max - header.min,
		.multiplier = header.multiplier,
		.max_displacement = header.max_displacement,
		.fd = fd,
		.data_offset = (int64_t)header.table_size
	};
}

void
fragment_unmap(const struct fragment *fragment)
{
	int r;

	if (fragment->data == NULL) {
		return;
	}

	r = munmap((void *)fragment->data, fragment->data->table_size);
	assert(r == 0 && "munmap failed");
	return;
}

static const void *
lookup8(const struct fragment *restrict fragment,
    const uint64_t key[static 8],
    uint64_t key0, uint64_t guess)
{
	const uint64_t *data = fragment_header_data(fragment->data);
	size_t item_size = fragment->item_size;
	size_t max_displacement = fragment->max_displacement;

	(void)key;
	if (JT_CC_UNLIKELY(key0 == fragment->min + fragment->range)) {
		return &data[guess * item_size + max_displacement];
	}

	for (size_t i = 0, offset = guess * item_size;
	     i <= max_displacement;
	     i++, offset += item_size) {
		uint64_t current = data[offset];

		if (current == key0) {
			return &data[offset];
		}

		if (current > key0) {
			return NULL;
		}
	}

	return NULL;
}

static const void *
lookup16(const struct fragment *restrict fragment,
    const uint64_t key[static 8],
    uint64_t key0, uint64_t guess)
{
	const uint64_t *data = fragment_header_data(fragment->data);
	uint64_t key1 = key[1];
	size_t item_size = fragment->item_size;
	size_t max_displacement = fragment->max_displacement;

	(void)key;
	if (JT_CC_UNLIKELY(key0 == fragment->min + fragment->range)) {
		if (key1 == UINT64_MAX) {
			return &data[guess * item_size + max_displacement];
		}
	}

	for (size_t i = 0, offset = guess * item_size;
	     i <= max_displacement;
	     i++, offset += item_size) {
		uint64_t c0 = data[offset];
		uint64_t c1 = data[offset + 1];

		if (((c0 ^ key0) | (c1 & key1)) == 0) {
			return &data[offset];
		}

		if (c0 > key0) {
			return NULL;
		}
	}

	return NULL;
}

static const void *
lookup32(const struct fragment *restrict fragment,
    const uint64_t key[static 8],
    uint64_t key0, uint64_t guess)
{
	const uint64_t *data = fragment_header_data(fragment->data);
	uint64_t key1 = key[1];
	size_t item_size = fragment->item_size;
	size_t max_displacement = fragment->max_displacement;

	(void)key;
	if (JT_CC_UNLIKELY(key0 == fragment->min + fragment->range)) {
		if (key1 == UINT64_MAX &&
		    key[2] == UINT64_MAX &&
		    key[3] == UINT64_MAX) {
			return &data[guess * item_size + max_displacement];
		}
	}

	for (size_t i = 0, offset = guess * item_size;
	     i <= max_displacement;
	     i++, offset += item_size) {
		uint64_t c0 = data[offset];
		uint64_t c1 = data[offset + 1];

		if (((c0 ^ key0) | (c1 & key1)) == 0) {
			if (key[2] == data[offset + 2] &&
			    key[3] == data[offset + 3]) {
				return &data[offset];
			}
		}

		if (c0 > key0) {
			return NULL;
		}
	}

	return NULL;
}

static const void *
lookup64(const struct fragment *restrict fragment,
    const uint64_t key[static 8],
    uint64_t key0, uint64_t guess)
{
	const uint64_t *data = fragment_header_data(fragment->data);
	uint64_t key1 = key[1];
	size_t item_size = fragment->item_size;
	size_t max_displacement = fragment->max_displacement;

	(void)key;
	if (JT_CC_UNLIKELY(key0 == fragment->min + fragment->range)) {
		if (key1 == UINT64_MAX &&
		    key[2] == UINT64_MAX &&
		    key[3] == UINT64_MAX &&
		    key[4] == UINT64_MAX &&
		    key[5] == UINT64_MAX &&
		    key[6] == UINT64_MAX &&
		    key[7] == UINT64_MAX) {
			return &data[guess * item_size + max_displacement];
		}
	}

	for (size_t i = 0, offset = guess * item_size;
	     i <= max_displacement;
	     i++, offset += item_size) {
		uint64_t c0 = data[offset];
		uint64_t c1 = data[offset + 1];

		if (((c0 ^ key0) | (c1 & key1)) == 0) {
			if (key[2] == data[offset + 2] &&
			    key[3] == data[offset + 3] &&
			    key[4] == data[offset + 4] &&
			    key[5] == data[offset + 5] &&
			    key[6] == data[offset + 6] &&
			    key[7] == data[offset + 7]) {
				return &data[offset];
			}
		}

		if (c0 > key0) {
			return NULL;
		}
	}

	return NULL;
}

const void *
fragment_lookup(const struct fragment *restrict fragment,
    size_t *restrict OUT_item_size,
    const uint64_t key[static 8])
{
	uint64_t key0 = key[0];
	uint64_t delta = key0 - fragment->min;
	uint64_t guess;

	*OUT_item_size = 0;
	if (JT_CC_UNLIKELY(fragment->data == NULL ||
	    delta > fragment->range)) {
		return NULL;
	}

	guess = scale(delta, fragment->multiplier);
	*OUT_item_size = fragment->item_size;
	switch (fragment->key_size) {
	case 1:
		return lookup8(fragment, key, key0, guess);
	case 2:
		return lookup16(fragment, key, key0, guess);
	case 4:
		return lookup32(fragment, key, key0, guess);
	case 8:
		return lookup64(fragment, key, key0, guess);
	default:
		*OUT_item_size = 0;
		return NULL;
	}

	return NULL;
}
