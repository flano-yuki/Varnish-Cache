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

enum HdrRet
num_decode(uint64_t *result, struct HdrIter *iter, uint8_t prefix);

enum HdrRet
num_encode(struct HdrIter *iter, uint8_t prefix, uint64_t num);

struct txt *
tbl_get_name(struct HdrIter *iter, uint64_t index);

struct txt *
tbl_get_value(struct HdrIter *iter, uint64_t index);

void push_header (struct stm_ctx *ctx, const struct hdrng *h);

uint8_t                                                                                                                                                                                                            
num_simulate(uint8_t prefix, uint64_t num);

enum HdrRet
str_encode(struct HdrIter *iter, struct txt *t);
enum HdrRet
str_decode(struct HdrIter *iter, struct txt *t);
