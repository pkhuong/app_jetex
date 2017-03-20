#ifndef JETEX_SERVER_H
#define JETEX_SERVER_H
#include <stdint.h>
#include <stddef.h>

struct jetex_namespace;
struct jetex_table;

struct jetex_namespace *
jetex_namespace_create(const struct jetex_table **tables, size_t n_table);

void
jetex_namespace_destroy(struct jetex_namespace *ns, int recursive);

/* 0 -> ok. */
int
jetex_table_fragment_validate(int fd);

struct jetex_table *
jetex_table_create(const uint8_t uuid[static 16],
    const int *restrict fds, uint64_t *restrict refcounts, size_t n_fd);

void
jetex_table_destroy(struct jetex_table *table);

void
jetex_serve(const struct jetex_namespace *ns,
    double deadline, /* seconds since epoch. */
    const int *fds, size_t n_fd);
#endif /* !JETEX_SERVER_H */
