#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "include/jetex_server.h"
#include "namespace.h"
#include "table.h"

static int
cmp_jetex_table_ptr(const void *vx, const void *vy)
{
	const struct jetex_table *const *px = vx;
	const struct jetex_table *const *py = vy;
	const struct jetex_table *x = *px;
	const struct jetex_table *y = *py;

	if (x->uuid[0] != y->uuid[0]) {
		return (x->uuid[0] < y->uuid[0]) ? -1 : 1;
	}

	if (x->uuid[1] != y->uuid[1]) {
		return (x->uuid[1] < y->uuid[1]) ? -1 : 1;
	}

	return 0;
}

struct jetex_namespace *
jetex_namespace_create(const struct jetex_table **tables, size_t n)
{
	struct jetex_namespace *ret;

	ret = calloc(1, sizeof(*ret) + n * sizeof(tables[0]));
	ret->ntable = n;
	for (size_t i = 0; i < n; i++) {
		ret->tables[i] = tables[i];
	}

	qsort(ret->tables, n, sizeof(ret->tables[0]), cmp_jetex_table_ptr);
	return ret;
}

void
jetex_namespace_destroy(struct jetex_namespace *ns, int recursive)
{

	if (ns == NULL) {
		return;
	}

	for (size_t i = 0; i < ns->ntable; i++) {
		if (recursive != 0) {
			const struct jetex_table *table = ns->tables[i];

			jetex_table_destroy((struct jetex_table *)table);
		}

		ns->tables[i] = NULL;
	}

	ns->ntable = 0;
	free(ns);
	return;
}
