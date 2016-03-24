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

struct hpk_hdr sttbl[] = {
	{{NULL, 0}, {NULL, 0}, hpk_idx, 0},
#define STAT_HDRS(j, k, v) \
{ \
	.key = { \
		.ptr = key_ ## j, \
		.len = sizeof(k) - 1 \
	}, \
	.value = { \
		.ptr = value_ ## j, \
		.len = sizeof(v) - 1 \
	}, \
	.t = hpk_idx, \
	.i = j, \
},
#include "vtc_h2_stattbl.h"
#undef STAT_HDRS
};

struct hpk_ctx {
	const struct hpk_hdr *sttbl;
	struct dynamic_table      dyntbl;
	uint32_t maxsize;
	uint32_t size;
};


struct hpk_iter *HPK_NewIter(struct hpk_ctx *ctx, char *buf, int size) {
	struct hpk_iter *iter = malloc(sizeof(*iter));
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

void HPK_FreeIter(struct hpk_iter *iter) {
	free(iter);
}

static void
pop_header(struct hpk_ctx *ctx) {
	assert(!VTAILQ_EMPTY(&ctx->dyntbl));
	struct dynhdr *h = VTAILQ_LAST(&ctx->dyntbl, dynamic_table);
	VTAILQ_REMOVE(&ctx->dyntbl, h, list);
	ctx->size -= h->header.key.len + h->header.value.len + 32;
	free(h->header.key.ptr);
	free(h->header.value.ptr);
	free(h);
}

void
push_header (struct hpk_ctx *ctx, const struct hpk_hdr *oh) {
	const struct hpk_hdr *ih;
	struct dynhdr *h;
	uint32_t len;

	assert(ctx->size <= ctx->maxsize);
	AN(oh);

	if (!ctx->maxsize)
		return;
	len = oh->value.len + 32;
	if (oh->key.ptr)
		len += oh->key.len;
	else {
		AN(oh->i);
		ih = HPK_GetHdr(ctx, oh->i);
		AN(ih);
		len += ih->key.len;
	}

	h = malloc(sizeof(*h));
	AN(h);
	h->header.t = hpk_idx;

	while (!VTAILQ_EMPTY(&ctx->dyntbl) && ctx->maxsize - ctx->size < len)
		pop_header(ctx);
	if (ctx->maxsize - ctx->size >= len) {

		if (oh->key.ptr) {
			h->header.key.len = oh->key.len;
			h->header.key.ptr = malloc(oh->key.len + 1);
			AN(h->header.key.ptr);
			memcpy(h->header.key.ptr, oh->key.ptr, oh->key.len + 1);
		} else {
			AN(oh->i);
			ih = HPK_GetHdr(ctx, oh->i);
			AN(ih);

			h->header.key.len = ih->key.len;
			h->header.key.ptr = malloc(ih->key.len + 1);
			AN(h->header.key.ptr);
			memcpy(h->header.key.ptr, ih->key.ptr, ih->key.len + 1);
		}

		h->header.value.len = oh->value.len;
		h->header.value.ptr = malloc(oh->value.len + 1);
		AN(h->header.value.ptr);
		memcpy(h->header.value.ptr, oh->value.ptr, oh->value.len + 1);

		VTAILQ_INSERT_HEAD(&ctx->dyntbl, h, list);
		ctx->size += len;
	}

}

enum hpk_result
HPK_ResizeTbl(struct hpk_ctx *ctx, uint32_t num) {
	ctx->maxsize = num;
	while (!VTAILQ_EMPTY(&ctx->dyntbl) && ctx->maxsize < ctx->size)
		pop_header(ctx);
	return (hpk_done);
}

static const struct txt *
tbl_get_field(struct hpk_ctx *ctx, uint32_t index, int key) {
	struct dynhdr *dh;
	assert(ctx);
	if (index > 61 + ctx->size)
		return (NULL);
	else if (index <= 61) {
		if (key)
			return (&ctx->sttbl[index].key);
		else
			return (&ctx->sttbl[index].value);
	}

	index -= 62;
	VTAILQ_FOREACH(dh, &ctx->dyntbl, list)
		if (!index--)
			break;
	if (index && dh) {
		if (key)
			return (&dh->header.key);
		else
			return (&dh->header.value);
	} else
		return (NULL);
}

const struct txt *
tbl_get_key(struct hpk_ctx *ctx, uint32_t index) {
	return (tbl_get_field(ctx, index, 1));
}

const struct txt *
tbl_get_value(struct hpk_ctx *ctx, uint32_t index) {
	return (tbl_get_field(ctx, index, 0));
}

const struct hpk_hdr *
HPK_GetHdr(struct hpk_ctx *ctx, uint32_t index) {
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
HPK_GetTblSize(struct hpk_ctx *ctx) {
	return ctx->size;
}

uint32_t
HPK_GetTblLength(struct hpk_ctx *ctx) {
	struct dynhdr *dh;
	uint32_t l = 0;
	VTAILQ_FOREACH(dh, &ctx->dyntbl, list)
		l++;
	return (l);
}

void
dump_dyn_tbl(struct hpk_ctx *ctx) {
	int i = 0;
	struct dynhdr *dh;
	printf("DUMPING %d/%d\n", ctx->size, ctx->maxsize);
	VTAILQ_FOREACH(dh, &ctx->dyntbl, list) {
		printf(" (%d) %s: %s\n", i++, dh->header.key.ptr, dh->header.value.ptr);
	}
	printf("DONE\n");
}

struct hpk_ctx *HPK_NewCtx(uint32_t maxsize) {
	struct hpk_ctx *ctx = calloc(1, sizeof(*ctx));
	assert(ctx);
	ctx->sttbl = sttbl;
	ctx->maxsize = maxsize;
	ctx->size = 0;
	return (ctx);
}

void HPK_FreeCtx(struct hpk_ctx *ctx) {

	while(!VTAILQ_EMPTY(&ctx->dyntbl))
		pop_header(ctx);
	free(ctx);
}