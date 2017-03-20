#ifndef JETEX_NAMESPACE_H
#define JETEX_NAMESPACE_H
#include <stddef.h>

#include "utility/cc.h"

struct jetex_table;

struct jetex_namespace {
	size_t ntable;
	const struct jetex_table *tables[];
};

JT_CC_PUBLIC struct jetex_namespace *
jetex_namespace_create(const struct jetex_table **tables, size_t nt);

JT_CC_PUBLIC void
jetex_namespace_destroy(struct jetex_namespace *ns, int recursive);
#endif /* !JETEX_NAMESPACE_H */
