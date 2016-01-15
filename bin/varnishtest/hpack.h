#include <stdint.h>

enum hpk_result{
	hpk_more = 0,
	hpk_done,
	hpk_err,
};

enum hpk_indexed {
	hpk_idx = 0,
	hpk_inc,
	hpk_not,
	hpk_never,
};

struct txt {
	char *ptr;
	int size;
	int huff;
};

struct hpk_hdr {
	struct txt key;
	struct txt value;
	enum hpk_indexed t;
	int i;
};

struct hpk_ctx;
struct hpk_iter;

struct hpk_ctx *
HPK_NewCtx(int tblsize);
void
HPK_FreeCtx(struct hpk_ctx *ctx);

struct hpk_iter *
HPK_NewIter(struct hpk_ctx *ctx, char *buf, int size);
void
HPK_FreeIter(struct hpk_iter *iter);

enum hpk_result
HPK_DecHdr(struct hpk_iter *iter, struct hpk_hdr *header);
enum hpk_result
HPK_EncHdr(struct hpk_iter *iter, struct hpk_hdr *header);

int gethpk_iterLen(struct hpk_iter *iter);

enum hpk_result
HPK_ResizeTbl(struct hpk_ctx *ctx, uint32_t num);

const struct hpk_hdr *
HPK_GetHdr(struct hpk_ctx *ctx, uint32_t index);

uint32_t
HPK_GetTblSize(struct hpk_ctx *ctx);

/* DEBUG */
void
dump_dyn_tbl(struct hpk_ctx *ctx);
