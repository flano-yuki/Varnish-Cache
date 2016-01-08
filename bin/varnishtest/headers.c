#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <vas.h>

#include "hpack.h"
#include "hpack_priv.h"

static inline void
txtcpy(struct txt *to, struct txt *from) {
	//AZ(to->ptr);
	to->ptr = malloc(from->size);
	AN(to->ptr);
	memcpy(to->ptr, from->ptr, from->size);
	to->size = from->size;
}

enum HdrRet
decNextHdr(struct HdrIter *iter, struct hdrng *header) {
	int pref = 0;
	struct txt *t;
	uint64_t num;
	int must_index = 0;
	assert(iter->buf < iter->end);

	/* Indexed Header Field */
	if (*iter->buf & 128) {
		header->t = HdrIdx;
		if (HdrErr == num_decode(&num, iter, 7))
			return (HdrErr);

		if (num) { /* indexed name and value*/
			t = tbl_get_name(iter, num);
			if (!t)
				return (HdrErr);
			txtcpy(&header->key, t);

			t = tbl_get_value(iter, num);
			if (!t) {
				free(header->key.ptr);
				return (HdrErr);
			}

			txtcpy(&header->value, t);

			if (iter->buf < iter->end)
				return (HdrMore);
			else
				return (HdrDone);
		} else if (iter->buf == iter->end)
			return (HdrErr);

	}
	/* Literal Header Field with Incremental Indexing */
	else if (*iter->buf >> 6 == 1) {
		header->t = HdrInc;
		pref = 6;
		must_index = 1;
	}
	/* Literal Header Field without Indexing */
	else if (*iter->buf >> 4 == 0) {
		header->t = HdrNot;
		pref = 4;
	}
	/* Literal Header Field never Indexed */
	else if (*iter->buf >> 4 == 1) {
		header->t = HdrNever;
		pref = 4;
	}
	/* Dynamic Table Size Update */
	else if (*iter->buf >> 5 == 1) {
		if (HdrDone != num_decode(&num, iter, 5))
			return (HdrErr);		
		return resizeTable(iter->ctx, num);
	} else {
		return (HdrErr);
	}

	assert(pref);
	if (HdrMore != num_decode(&num, iter, pref))
		return (HdrErr);

	header->i = num;
	if (num) { /* indexed name */
		t = tbl_get_name(iter, num);
		if (!t)
			return (HdrErr);
		txtcpy(&header->key, t);
	} else {
		if (!str_decode(iter, &header->key))
			return (HdrErr);
	}

	if (!str_decode(iter, &header->value))
		return (HdrErr);

	if (must_index)
		push_header(iter->ctx, header);
	if (iter->buf < iter->end)
		return (HdrMore);
	else
		return (HdrDone);
}

enum HdrRet
encNextHdr(struct HdrIter *iter, struct hdrng *h) {
	int pref;
	int must_index = 0;
	enum HdrRet ret;
	switch (h->t) {
		case HdrIdx:
			*iter->buf = 0x80;
			num_encode(iter, 7, h->i);
			return (HdrErr);
		case HdrInc:
			*iter->buf = 0x40;
			pref = 6;
			must_index = 1;
			break;
		case HdrNot:
			*iter->buf = 0x00;
			pref = 4;
			break;
		case HdrNever:
			*iter->buf = 0x10;
			pref = 4;
			break;
		default:
			assert(1);
	}
	if (h->i) {
		if (HdrMore != num_encode(iter, pref, h->i))
			return (HdrErr);
	} else {
		iter->buf++;
		if (HdrMore != str_encode(iter, h->key.ptr, h->key.huff))
			return (HdrErr);
	}
	ret = str_encode(iter, h->value.ptr, h->value.huff);
	if (ret == HdrErr)
		return (HdrErr);
	if (must_index)
		push_header(iter->ctx, h);
	return (ret);

}
