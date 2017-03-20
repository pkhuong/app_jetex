#include <stddef.h>
#include <string.h>

#include "packet.h"

#define ADV(N)						\
	({						\
		__typeof__(bytes) adv_dst = bytes;	\
		size_t produced_bytes = (N);		\
							\
		if (produced_bytes > remaining) {	\
			goto fail;			\
		}					\
							\
		bytes += produced_bytes;		\
		remaining -= produced_bytes;		\
		adv_dst;				\
	})

#define OUT(SRC) do {						\
		if (remaining < sizeof(SRC)) {			\
			goto fail;				\
		}						\
								\
		memcpy(ADV(sizeof(SRC)), &(SRC), sizeof(SRC));	\
	} while (0)

#define IN(DST) do {						\
		if (remaining < sizeof(DST)) {			\
			goto fail;				\
		}						\
								\
		memcpy(&(DST), ADV(sizeof(DST)), sizeof(DST));	\
	} while (0)

ssize_t
jetex_packet_lookup_encode(struct jetex_header_lookup *restrict dst,
    const void *restrict correlation, size_t correlation_len,
    const struct sockaddr *restrict addr, socklen_t addr_len,
    uint8_t table[static 16], const void *restrict key, size_t key_len)
{
	char *restrict bytes;
	size_t remaining;

	*dst = (struct jetex_header_lookup) { .header.len = 0 };
	dst->header.type = 0;
	bytes = &dst->data[0];
	remaining = sizeof(dst->data);

	if (addr == NULL && addr_len != 0) {
		return -1;
	}

	if (correlation_len > 128 || correlation_len > remaining) {
		return -1;
	}

	if (correlation_len == 0) {
		ADV(sizeof(uint64_t));
		dst->header.extra = 0;
	} else {
		size_t u64sz = sizeof(uint64_t);
		size_t count = (correlation_len + u64sz - 1) / u64sz;

		memcpy(ADV(count * u64sz), correlation, correlation_len);
		dst->header.extra = (uint8_t)(count - 1);
	}

	if (addr != NULL) {
		switch (addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in in;

			_Static_assert(sizeof(in.sin_addr) == 4,
			    "ipv4 address must be exactly 4 bytes.");
			_Static_assert(sizeof(in.sin_port) == 2,
			    "ipv4 port must be exactly 2 bytes.");

			if (addr_len < sizeof(in)) {
				goto fail;
			}

			memcpy(&in, addr, sizeof(in));
			OUT(in.sin_addr);
			OUT(in.sin_port);
			dst->header.extra |= 1U << 4;
			break;
		}

		case AF_INET6: {
			struct sockaddr_in6 in;

			_Static_assert(sizeof(in.sin6_addr) == 16,
			    "ipv6 address must be exactly 16 bytes.");
			_Static_assert(sizeof(in.sin6_port) == 2,
			    "ipv6 port must be exactly 2 bytes.");

			if (addr_len < sizeof(in)) {
				goto fail;
			}

			memcpy(&in, addr, sizeof(in));
			OUT(in.sin6_addr);
			OUT(in.sin6_port);
			dst->header.extra |= 2U << 4;
			break;
		}

		default:
			goto fail;
		}
	}

	if (remaining < 16) {
		goto fail;
	}

	memcpy(ADV(16), &table[0], 16);

	/* key length must be a power of two in [8, 64]. */
	if (key_len < 8 ||
	    key_len > 64 ||
	    (key_len & (key_len - 1)) != 0) {
		return -1;
	}

	if (remaining < key_len) {
		goto fail;
	}

	memcpy(ADV(key_len), key, key_len);
	dst->header.len = (uint16_t)(sizeof(dst->header) + (size_t)(bytes - &dst->data[0]));
	return dst->header.len;

fail:
	*dst = (struct jetex_header_lookup) { .header.len = 0 };
	return -1;
}

int
jetex_packet_lookup_decode(struct jetex_lookup *restrict dst,
    const void *restrict packet, size_t packet_len,
    const struct sockaddr *restrict src, socklen_t srclen)
{
	struct jetex_header header;
	const char *bytes;
	size_t remaining;

	*dst = (struct jetex_lookup) { .base_data = NULL };
	bytes = packet;
	remaining = packet_len;

	IN(header);
	if (packet_len > sizeof(struct jetex_header_lookup)) {
		return -1;
	}

	if (header.type != 0) {
		return -1;
	}

	if (header.len != packet_len) {
		return -1;
	}

	dst->correlation_key_offset = (uint32_t)(bytes - (char *)packet);
	dst->correlation_key_length = 8 * (1 + (header.extra % 16U));
	ADV(dst->correlation_key_length);
	
	dst->base_data = packet;
	switch (header.extra >> 4) {
	case 0:
		/* Implicit dst. */
		if (srclen > sizeof(dst->dst)) {
			goto fail;
		}

		memcpy(&dst->dst, src, srclen);
		dst->dstlen = srclen;
		break;

	case 1: {
		/* ipv4 */
		struct sockaddr_in in = { .sin_family = AF_INET };

		_Static_assert(sizeof(in.sin_addr) == 4,
		    "ipv4 address must be exactly 4 bytes.");
		_Static_assert(sizeof(in.sin_port) == 2,
		    "ipv4 port must be exactly 2 bytes.");
		IN(in.sin_addr);
		IN(in.sin_port);
		memcpy(&dst->dst, &in, sizeof(in));
		dst->dstlen = sizeof(in);
		break;
	}

	case 2: {
		/* ipv6 */
		struct sockaddr_in6 in = { .sin6_family = AF_INET6 };

		_Static_assert(sizeof(in.sin6_addr) == 16,
		    "ipv6 address must be exactly 16 bytes.");
		_Static_assert(sizeof(in.sin6_port) == 2,
		    "ipv4 port must be exactly 2 bytes.");
		IN(in.sin6_addr);
		IN(in.sin6_port);
		memcpy(&dst->dst, &in, sizeof(in));
		dst->dstlen = sizeof(in);
		break;
	}

	default:
		goto fail;
	}

	IN(dst->table_uuid);
	if (remaining >= sizeof(dst->key)) {
		memcpy(&dst->key[0], bytes, sizeof(dst->key));
	} else {
		memcpy(&dst->key[0], bytes, remaining);
	}
	
	return 0;

fail:
	*dst = (struct jetex_lookup) { .base_data = NULL };
	return -1;
}

static ssize_t
jetex_response_header_encode(struct jetex_response_header *restrict dst,
    uint8_t type,
    const void *restrict correlation, size_t correlation_len,
    const uint8_t table[static 16], const void *restrict key, size_t key_len)
{
	char *restrict bytes;
	size_t remaining;

	*dst = (struct jetex_response_header) { .header.len = 0 };
	bytes = &dst->data[0];
	remaining = sizeof(dst->data);

	dst->header.type = type;
	if (correlation_len > 128 || correlation_len > remaining) {
		goto fail;
	}

	if (correlation_len == 0) {
		ADV(sizeof(uint64_t));
		dst->header.extra = 0;
	} else {
		size_t u64sz = sizeof(uint64_t);
		size_t count = (correlation_len + u64sz - 1) / u64sz;

		memcpy(ADV(count * u64sz), correlation, correlation_len);
		dst->header.extra = (uint8_t)(count - 1);
	}

	memcpy(ADV(16), &table[0], 16);
	switch (key_len) {
	case 8:
		dst->header.extra |= 0;
		break;
	case 16:
		dst->header.extra |= 1U << 4;
		break;
	case 32:
		dst->header.extra |= 2U << 4;
		break;		
	case 64:
		dst->header.extra |= 3U << 4;
		break;		
	default:
		goto fail;
	}

	memcpy(ADV(key_len), key, key_len);
	dst->header.len = (uint16_t)(sizeof(dst->header) + (size_t)(bytes - &dst->data[0]));
	return dst->header.len;

fail:
	*dst = (struct jetex_response_header) { .header.len = 0 };
	return -1;
}

ssize_t
jetex_packet_missing_encode(struct jetex_header_missing *restrict dst,
    const void *restrict correlation, size_t correlation_len,
    const uint8_t table[static 16], const void *restrict key, size_t key_len)
{

	return jetex_response_header_encode(&dst->header, 3,
	    correlation, correlation_len,
	    table, key, key_len);
}

ssize_t
jetex_packet_found_encode(struct jetex_header_found *restrict dst,
    const void *restrict correlation, size_t correlation_len,
    const uint8_t table[static 16], const void *restrict key, size_t key_len,
    size_t value_len)
{
	ssize_t r;

	r = jetex_response_header_encode(&dst->header, 1,
	    correlation, correlation_len,
	    table, key, key_len);

	if (r < 0) {
		return r;
	}

	if (dst->header.header.len + value_len >= (1UL << 15)) {
		*dst = (struct jetex_header_found) { .header.header.len = 0 };
		return -1;
	}

	dst->header.header.len = (uint16_t)(dst->header.header.len + value_len);
	return r;
}
