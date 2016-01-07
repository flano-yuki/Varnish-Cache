#include "vqueue.h"
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

int
hpack_decode(char *str, int n, struct HdrIter *iter, int size);

int
hpack_encode(struct HdrIter *iter, char *str);


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
int
hpack_simulate(char *str, int huff);
int 
HdrSimulate(struct hdr *header, enum HdrType type, int idxName, int nhuff, int vhuff);

enum HdrRet
str_encode(struct HdrIter *iter, char *str, int huff);
int
str_decode(struct HdrIter *iter, struct txt *t);
