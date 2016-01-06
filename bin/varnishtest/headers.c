#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "hpack.h"
#include "hpack_priv.h"

enum HdrRet
decNextHdr(struct HdrIter *iter, struct hdr *header) {
	int pref = 0;
	char *s;
	uint64_t num;
	int must_index = 0;
	assert(iter->buf < iter->end);

	/* Indexed Header Field */
	if (*iter->buf & 128) {
		if (HdrErr == num_decode(&num, iter, 7))
			return (HdrErr);

		if (num) { /* indexed name and value*/
			s = tbl_get_name(iter, num);
			if (!s)
				return (HdrErr);
			header->name = strdup(s);
			s = tbl_get_value(iter, num);
			if (!s)
				return (HdrErr);
			header->value = strdup(s);
			if (iter->buf < iter->end)
				return (HdrMore);
			else
				return (HdrDone);
		} else if (iter->buf == iter->end)
			return (HdrErr);

	}
	/* Literal Header Field with Incremental Indexing */
	else if (*iter->buf >> 6 == 1) {
		pref = 6;
		must_index = 1;
	}
	/* Literal Header Field without Indexing */
	else if (*iter->buf >> 4 == 0) {
		pref = 4;
	}
	/* Literal Header Field never Indexed */
	else if (*iter->buf >> 4 == 1) {
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

	if (num) { /* indexed name */
		s = tbl_get_name(iter, num);
		if (!s)
			return (HdrErr);
		header->name = strdup(s);
	} else {
		header->name = str_decode(iter);
		if (!header->name)
			return (HdrErr);
	}


	header->value = str_decode(iter);
	if (!header->value) {
		free(header->name);
		return (HdrErr);
	}
	if (must_index)
		push_header(iter->ctx, header);
	if (iter->buf < iter->end)
		return (HdrMore);
	else
		return (HdrDone);
}

enum HdrRet
encNextHdr(struct HdrIter *iter, struct hdr *header, enum HdrType type, int idxName, int nhuff, int vhuff) {
	int pref;
	int must_index = 0;
	enum HdrRet ret;
	switch (type) {
		case HdrIdx:
			*iter->buf = 0x80;
			num_encode(iter, 7, idxName);
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
	if (idxName) {
		if (HdrMore != num_encode(iter, pref, idxName))
			return (HdrErr);
	} else {
		iter->buf++;
		if (HdrMore != str_encode(iter, header->name, nhuff))
			return (HdrErr);
	}
	ret = str_encode(iter, header->value, vhuff);
	if (ret == HdrErr)
		return (HdrErr);
	if (must_index)
		push_header(iter->ctx, header);
	return (ret);

}

int 
HdrSimulate(struct hdr *header, enum HdrType type, int idxName, int nhuff, int vhuff) {
	int len = 1;
	int res, pref;
	switch (type) {
		case HdrIdx:
			return (1);
			break;
		case HdrInc:
			pref = 6;
			break;
		case HdrNot:
			pref = 4;
			break;
		case HdrNever:
			pref = 4;
			break;
		default:
			assert(1);
	}
	res = hpack_simulate(header->value, vhuff);
	len += res;
	res = num_simulate(7, res);
	len += res;

	if (!idxName) {
		res = hpack_simulate(header->name, nhuff);
		len += res;
		len += num_simulate(pref, res);
	}
	return (len);
}
