#include "vqueue.h"

#define ITER_DONE(iter) (iter->buf == iter->end ? HdrDone : HdrMore)

struct dynhdr {
	struct hdrng header;
	VTAILQ_ENTRY(dynhdr)      list;
};

VTAILQ_HEAD(dynamic_table,dynhdr);

struct stm_ctx {
	struct hdrng *sttbl;
	struct dynamic_table      dyntbl;
	int maxsize;
	int size;
};

struct HdrIter {
	struct stm_ctx *ctx;
	char *orig;
	char *buf;
	char *end;
};

struct txt *
tbl_get_name(struct HdrIter *iter, uint64_t index);

struct txt *
tbl_get_value(struct HdrIter *iter, uint64_t index);
void
push_header (struct stm_ctx *ctx, const struct hdrng *h);
