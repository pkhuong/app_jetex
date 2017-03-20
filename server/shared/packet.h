#ifndef JETEX_PACKET_H
#define JETEX_PACKET_H
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>

struct jetex_header {
	/* LE, at most 32767 */
	uint16_t len;
	/* low bit is 0 for lookup, 1 for value. */
	/* high bit should be 0. */
	uint8_t type;
	uint8_t extra;
	/* low 8 bits are TTL.  High 24 (LE) are deadline, in millis
	 * since epoch.  Use modular comparison to check for
	 * expiration; worst case is we send a response for an expired
	 * request.
	 */
	uint32_t expiry;
} __attribute__((__packed__));

struct jetex_response_header {
	/*
	 * type is odd.
	 * extra is split in 2x 4 bit values.
	 * Low 4 bits is the correlation key size - 1, in uint64_t;
	 *  i.e., 0 = 8 bytes, and 15 = 128 bytes.
	 * High 4 bits is the key size:
	 *  0: 8 bytes;
	 *  1: 16 bytes;
	 *  2: 32 bytes;
	 *  3: 64 bytes.
	 */
	struct jetex_header header;
	/* correlation key. */
	/* table UUID (16 bytes). */
	/* key. */
	char data[128 + 16 + 64];
	/* any data follows. */
}  __attribute__((__packed__));

struct jetex_header_lookup {
	/*
	 * type is 0.
	 * extra is split in 2x 4 bit values.
	 * Low 4 bits is the correlation key size - 1, in uint64_t;
	 *  i.e., 0 = 8 bytes, and 15 = 128 bytes.
	 * High 4 bits is the destination type:
	 *  0: use the requesting host:port pair (0 bytes);
	 *  1: ipv4, 32 bit host IP + 16 bit port (6 bytes);
	 *  2: ipv6, 128 bit host + 16 bit port (18 bytes).
	 */
	struct jetex_header header;
	/* correlation key. */
	/* destination section: 0, 6, or 18 bytes */
	/* table UUID (16 bytes). */
	/* key (remainder). Size should be 8, 16, 32, or 64 bytes. */
	char data[128 + 18 + 16 + 64];
} __attribute__((__packed__));

struct jetex_header_found {
	/* type is 1. */
	struct jetex_response_header header;
	/* value follows; */
} __attribute__((__packed__));

struct jetex_header_missing {
	/* type is 3. */
	struct jetex_response_header header;
} __attribute__((__packed__));

struct jetex_lookup {
	const void *base_data; /* pointer to the bytes we're decoding. */
	struct sockaddr_storage dst;
	size_t dstlen;
	uint32_t correlation_key_offset; /* from base_data. */
	uint32_t correlation_key_length;
	uint8_t table_uuid[16];
	uint64_t key[8];
} __attribute__((__packed__));

static inline void
jetex_packet_set_ttl(struct jetex_header *header, uint8_t ttl)
{

	header->expiry = (header->expiry & ~0xFFU) | (uint32_t)ttl;
	return;
}

/* return false iff ttl reached 0. 0 = no TTL. */
static inline bool
jetex_packet_dec_ttl(struct jetex_header *header)
{

	if ((header->expiry & 0xFFU) == 0) {
		return true;
	}

	return (--header->expiry) != 0;
}

static inline void
jetex_packet_set_deadline(struct jetex_header *restrict header,
    const struct timeval *restrict tv)
{
	uint32_t limit = (uint32_t)(tv->tv_sec * 1000 + tv->tv_usec / 1000) << 8;

	/* 0 = no limit. */
	limit = (limit == 0) ? 0x100U : limit;
	header->expiry = limit | (header->expiry & 0xFFU);
	return;
}

static inline bool
jetex_packet_expired(const struct jetex_header *restrict header,
    const struct timeval *restrict tv)
{
	uint32_t now = (uint32_t)(tv->tv_sec * 1000 + tv->tv_usec / 1000) << 8;
	uint32_t limit = header->expiry | 0xFFU;

	return (limit != 0xFFU && ((int32_t)(limit - now) < 0));
}

ssize_t
jetex_packet_lookup_encode(struct jetex_header_lookup *restrict dst,
    const void *restrict correlation, size_t correlation_len,
    const struct sockaddr *restrict addr, socklen_t addr_len,
    uint8_t table[static 16], const void *restrict key, size_t key_len);

int
jetex_packet_lookup_decode(struct jetex_lookup *restrict dst,
    const void *restrict packet, size_t packet_len,
    const struct sockaddr *restrict src, socklen_t srclen);

ssize_t
jetex_packet_missing_encode(struct jetex_header_missing *restrict dst,
    const void *restrict correlation, size_t correlation_len,
    const uint8_t table[static 16], const void *restrict key, size_t key_len);

ssize_t
jetex_packet_found_encode(struct jetex_header_found *restrict dst,
    const void *restrict correlation, size_t correlation_len,
    const uint8_t table[static 16], const void *restrict key, size_t key_len,
    size_t value_len);
#endif /* !JETEX_PACKET_H */
