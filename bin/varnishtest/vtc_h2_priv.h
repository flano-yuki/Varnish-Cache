#include "vqueue.h"

#define ITER_DONE(iter) (iter->buf == iter->end ? HdrDone : HdrMore)

struct dynhdr {
	struct hdrng header;
	VTAILQ_ENTRY(dynhdr)      list;
};

VTAILQ_HEAD(dynamic_table,dynhdr);

struct HdrIter {
	struct stm_ctx *ctx;
	char *orig;
	char *buf;
	char *end;
};

const struct txt *
tbl_get_key(struct stm_ctx *ctx, uint32_t index);

const struct txt *
tbl_get_value(struct stm_ctx *ctx, uint32_t index);
void
push_header (struct stm_ctx *ctx, const struct hdrng *h);
