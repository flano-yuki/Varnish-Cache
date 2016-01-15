#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <vas.h>

#include "hpack.h"
#include "vtc_h2_priv.h"

/* TODO: fix that crazy workaround */
#define STAT_HDRS(i, k, v) \
	char key_ ## i[] = k; \
	char value_ ## i[] = v;
#include "vtc_h2_stattbl.h"
#undef STAT_HDRS

struct hdrng sttbl[] = {
	{{NULL, 0}, {NULL, 0}, HdrIdx, 0},
#define STAT_HDRS(j, k, v) \
{ \
	.key = { \
		.ptr = key_ ## j, \
		.size = sizeof(k) - 1 \
	}, \
	.value = { \
		.ptr = value_ ## j, \
		.size = sizeof(v) - 1 \
	}, \
	.t = HdrIdx, \
	.i = j, \
},
#include "vtc_h2_stattbl.h"
#undef STAT_HDRS
};

struct stm_ctx {
	const struct hdrng *sttbl;
	struct dynamic_table      dyntbl;
	int maxsize;
	int size;
};


struct HdrIter *newHdrIter(struct stm_ctx *ctx, char *buf, int size) {
	struct HdrIter *iter = malloc(sizeof(*iter));
	assert(iter);
	assert(ctx);
	assert(buf);
	assert(size);
	iter->ctx = ctx;
	iter->orig = buf;
	iter->buf = buf;
	iter->end = buf + size;
	return (iter);
}

void destroyHdrIter(struct HdrIter *iter) {
	free(iter);
}

static void
pop_header(struct stm_ctx *ctx) {
	assert(!VTAILQ_EMPTY(&ctx->dyntbl));
	struct dynhdr *h = VTAILQ_LAST(&ctx->dyntbl, dynamic_table);
	VTAILQ_REMOVE(&ctx->dyntbl, h, list);
	ctx->size -= h->header.key.size + h->header.value.size + 32;
	free(h->header.key.ptr);
	free(h->header.value.ptr);
	free(h);
}

void
push_header (struct stm_ctx *ctx, const struct hdrng *oh) {
	const struct hdrng *ih;
	assert(ctx->size <= ctx->maxsize);
	assert(oh);
	if (!ctx->maxsize)
		return;
	int size = oh->value.size + 32;
	if (oh->key.ptr)
		size += oh->key.size;
	else {
		AN(oh->i);
		ih = getHeader(ctx, oh->i);
		AN(ih);
		size += ih->key.size;
	}

	struct dynhdr *h = malloc(sizeof(*h));

	while (!VTAILQ_EMPTY(&ctx->dyntbl) && ctx->maxsize - ctx->size < size)
		pop_header(ctx);
	if (ctx->maxsize - ctx->size >= size) {

		if (oh->key.ptr) {
			h->header.key.size = oh->key.size;
			h->header.key.ptr = malloc(oh->key.size + 1);
			AN(h->header.key.ptr);
			memcpy(h->header.key.ptr, oh->key.ptr, oh->key.size + 1);
		} else {
			AN(oh->i);
			ih = getHeader(ctx, oh->i);
			AN(ih);

			h->header.key.size = ih->key.size;
			h->header.key.ptr = malloc(ih->key.size + 1);
			AN(h->header.key.ptr);
			memcpy(h->header.key.ptr, ih->key.ptr, ih->key.size + 1);
		}


		h->header.value.size = oh->value.size;
		h->header.value.ptr = malloc(oh->value.size + 1);
		AN(h->header.value.ptr);
		memcpy(h->header.value.ptr, oh->value.ptr, oh->value.size + 1);

		VTAILQ_INSERT_HEAD(&ctx->dyntbl, h, list);
		ctx->size += size;
	}

}

enum HdrRet
resizeTable(struct stm_ctx *ctx, uint64_t num) {
	ctx->maxsize = num;
	while (!VTAILQ_EMPTY(&ctx->dyntbl) && ctx->maxsize < ctx->size)
		pop_header(ctx);
	return (HdrDone);
}

const struct txt *
tbl_get_name(struct stm_ctx *ctx, uint64_t index) {
	struct dynhdr *dh;
	assert(ctx);
	if (index > 61 + ctx->size)
		return (NULL);
	else if (index <= 61)
		return (&ctx->sttbl[index].key);

	index -= 62;
	VTAILQ_FOREACH(dh, &ctx->dyntbl, list)
		if (!index--)
			break;
	if (index && dh)
		return (&dh->header.key);
	else
		return (NULL);
}

const struct txt *
tbl_get_value(struct stm_ctx *ctx, uint64_t index) {
	struct dynhdr *dh;
	assert(ctx);
	if (index > 61 + ctx->size)
		return (NULL);
	else if (index <= 61)
		return (&ctx->sttbl[index].value);

	index -= 62;
	VTAILQ_FOREACH(dh, &ctx->dyntbl, list)
		if (!index--)
			break;
	if (index && dh)
		return (&dh->header.value);
	else
		return (NULL);

}

const struct hdrng *
getHeader(struct stm_ctx *ctx, uint32_t index) {
	uint32_t oi = index;
	struct dynhdr *dh;
	assert(ctx);
	if (index > 61 + ctx->size)
		return (NULL);
	else if (index <= 61)
		return (&ctx->sttbl[index]);

	index -= 62;
	VTAILQ_FOREACH(dh, &ctx->dyntbl, list)
		if (!index--)
			break;
	if (index && dh) {
		dh->header.i = oi;
		return (&dh->header);
	} else
		return (NULL);
}

uint32_t
getTblSize(struct stm_ctx *ctx) {
	return ctx->size;
}

void
dump_dyn_tbl(struct stm_ctx *ctx) {
	int i = 0;
	printf("DUMPING %d/%d\n", ctx->size, ctx->maxsize);
	struct dynhdr *dh;
	VTAILQ_FOREACH(dh, &ctx->dyntbl, list) {
		printf(" (%d) %s: %s\n", i++, dh->header.key.ptr, dh->header.value.ptr);
	}
	printf("DONE\n");
}

struct stm_ctx *initStmCtx(int maxsize) {
	struct stm_ctx *ctx = calloc(1, sizeof(*ctx));
	assert(ctx);
	ctx->sttbl = sttbl;
	ctx->maxsize = maxsize;
	ctx->size = 0;
	return (ctx);
}

void destroyStmCtx(struct stm_ctx *ctx) {

	while(!VTAILQ_EMPTY(&ctx->dyntbl))
		pop_header(ctx);
	free(ctx);
}
