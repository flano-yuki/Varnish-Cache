#include <stdint.h>

enum HdrRet{
	HdrMore = 0,
	HdrDone,
	HdrErr,
};

enum HdrType {
	HdrIdx = 0,
	HdrInc,
	HdrNot,
	HdrNever,
};

struct txt {
	char *ptr;
	int size;
	int huff;
};

struct hdrng {
	struct txt key;
	struct txt value;
	enum HdrType t;
	int i;
};

struct stm_ctx;
struct HdrIter;

struct stm_ctx *
initStmCtx(int tblsize);
void
destroyStmCtx(struct stm_ctx *ctx);

struct HdrIter *
newHdrIter(struct stm_ctx *ctx, char *buf, int size);
enum HdrRet
decNextHdr(struct HdrIter *iter, struct hdrng *header);
enum HdrRet
encNextHdr(struct HdrIter *iter, struct hdrng *header);
void
destroyHdrIter(struct HdrIter *iter);

int getHdrIterLen(struct HdrIter *iter);

enum HdrRet
resizeTable(struct stm_ctx *ctx, uint64_t num);

/* DEBUG */
void
dump_dyn_tbl(struct stm_ctx *ctx);
