#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vas.h>

#include "hpack.h"
#include "vtc_h2_priv.h"

struct symbol {
	int val;
	short size;
};

static struct symbol coding_table[] = {
#define HPACK(i, v, l) {v, l},
#include "vtc_h2_enctbl.h"
#undef HPACK
	{0, 0}
};

#include "vtc_h2_dectbl.h"

struct symbol *EOS = &coding_table[256];

static int
huff_decode(char *str, int nm, struct hpk_iter *iter, int size) {
	int cursor = 0;
	int len = 0;
	size *= 8;
	int prefix;
	int idx = 0;
	char nent;
	struct pair *p;
	while(cursor < size && nm--) {
		prefix = 0;
		while (cursor < size) {
			if (!((iter->buf[cursor/8] >> (7 - (cursor%8))) & 1))
				break;
			if (++prefix >= 30)
				return (0);
			cursor++;
		}
		if (cursor == size) {
			/* check that last bit is 1 */
			if (iter->buf[(cursor-1)/8] & 1) {
				iter->buf += (cursor + 7)/8;
				return (len);
			} else
				return (0);
		}
		idx = 0;
		nent = decoding_table.desc[prefix].nentries;
		p = &decoding_table.pairs[decoding_table.desc[prefix].offset];
		AN(nent);
		do {
			/* set the first bit of prefix to 1, and keep
			 * gobbling bits until we find it in the table
			 * this allows to not mess up because of the leading 0s
			 */
			if (idx)
				idx = idx * 2 + ((iter->buf[cursor/8] >> (7 - (cursor%8))) & 1);
			else
				idx = 1;
			cursor++;
			while (nent && p->suffix < idx) {
				p++;
				nent--;
			}
			if (p->suffix == idx) { /* found it! */
				*str++ = p->sym;
				len++;
				break;
			} else if (!nent) /* We went too far, Marty! */
				return (0);
		} while (cursor < size);
	}
	iter->buf += (cursor + 7)/8;
	return (len);
}

static int
huff_encode(struct hpk_iter *iter, char *str, int size) {
	short r, s;
	int v;
	int l = 0;
	char *b;
	int cursor = 0;
	while (size--) {
		v = coding_table[(unsigned char)*str].val;
		r = coding_table[(unsigned char)*str].size;

		while (r > 0) {
			b = iter->buf + (cursor / 8);
			if (b >= iter->end)
				return (1);
			s = 8 - (cursor % 8);
			if (!(cursor%8))
				*b = 0;
			if (r >= s) {
				*b |= (0xff >> (7 - s)) & (v >> (r - s));
				r -= s;
				cursor += s;
			} else {
				*b |= 0xff & (v<< (s - r));
				cursor += r;
				r = 0;
			}
		}
		str++;
	}

	/* add padding */
	l = cursor % 8;
	iter->buf[cursor/8] |= 0xff >> l;
	iter->buf += (cursor + 7)/8;
	return (0);
}

static int
huff_simulate(char *str, int size, int huff) {
	int len = 0;
	if (!huff)
		return (size);
	do {
		assert(str);
		len += coding_table[(unsigned char)*str].size;	
	} while (*(++str) != '\0');
	return ((len+7)/8);
}

static enum hpk_result
num_decode(uint32_t *result, struct hpk_iter *iter, uint8_t prefix) {
	uint8_t shift = 0;

	assert(iter->buf < iter->end);
	assert(prefix);
	assert(prefix <= 8);

	*result = 0;
	*result = *iter->buf & (0xff >> (8-prefix));
	if (*result < (1 << prefix) - 1) {
		iter->buf++;
		return (ITER_DONE(iter));
	}
	do {
		iter->buf++;
		if (iter->end == iter->buf)
			return (hpk_err);
		/* check for overflow */
		if ((UINT32_MAX - *result) >> shift < (*iter->buf & 0x7f))
			return (hpk_err);

		*result += (uint32_t)(*iter->buf & 0x7f) << shift;
		shift += 7;
	} while (*iter->buf & 0x80);
	iter->buf++;

	return (ITER_DONE(iter));
}

static enum hpk_result
num_encode(struct hpk_iter *iter, uint8_t prefix, uint32_t num) {
	assert(prefix);
	assert(prefix <= 8);
	assert(iter->buf < iter->end);

	uint8_t pmax = (1 << prefix) - 1;

	*iter->buf &= 0xff << prefix;
	if (num <=  pmax) {
		*iter->buf++ |= num;
		return (ITER_DONE(iter));
	} else if (iter->end - iter->buf < 2)
		return (hpk_err);

	iter->buf[0] |= pmax;
	num -= pmax;
	do {
		iter->buf++;
		if (iter->end == iter->buf)
			return (hpk_err);
		*iter->buf = num % 128;
		*iter->buf |= 0x80;
		num /= 128;
	} while (num);
	*iter->buf++ &= 127;
	return (ITER_DONE(iter));
}

static enum hpk_result
str_encode(struct hpk_iter *iter, struct txt *t) {
	int slen = huff_simulate(t->ptr, t->size, t->huff);
	assert(iter->buf < iter->end);
	if (t->huff)
		*iter->buf = 0x80;
	else
		*iter->buf = 0;

	if (hpk_err == num_encode(iter, 7, slen))
		return (hpk_err);

	if (slen > iter->end - iter->buf)
		return (hpk_err);

	if (t->huff) {
		return (huff_encode(iter, t->ptr, t->size));
	} else {
		memcpy(iter->buf, t->ptr, slen);
		iter->buf += slen;
		return (ITER_DONE(iter));
	}
}

static enum hpk_result
str_decode(struct hpk_iter *iter, struct txt *t) {
	uint32_t num;
	int huff;
	assert(iter->buf < iter->end);
	huff = (*iter->buf & 0x80);
	if (hpk_more != num_decode(&num, iter, 7))
		return (hpk_err);
	if (num > iter->end - iter->buf)
		return (hpk_err);
	if (huff) { /*Huffman encoding */
		t->ptr = malloc((num * 8) / 5 + 1);
		AN(t->ptr);
		num = huff_decode(t->ptr, (num * 8) / 5, iter, num);
		if (!num) {
			free(t->ptr);
			return (hpk_err);
		}
		t->huff = 1;
		/* XXX: do we care? */
		t->ptr = realloc(t->ptr, num + 1);
		AN(t->ptr);
		memcpy(t->ptr, t->ptr, num);
	} else { /* literal string */
		t->huff = 0;
		t->ptr = malloc(num + 1);
		AN(t->ptr);
		memcpy(t->ptr, iter->buf, num);
		iter->buf += num;
	}

	t->ptr[num] = '\0';
	t->size = num;
	
	return (ITER_DONE(iter));
}

static inline void
txtcpy(struct txt *to, const struct txt *from) {
	//AZ(to->ptr);
	to->ptr = malloc(from->size + 1);
	AN(to->ptr);
	memcpy(to->ptr, from->ptr, from->size + 1);
	to->size = from->size;
}

int gethpk_iterLen(struct hpk_iter *iter) {
	return (iter->buf - iter->orig);
}

enum hpk_result
HPK_DecHdr(struct hpk_iter *iter, struct hpk_hdr *header) {
	int pref = 0;
	const struct txt *t;
	uint32_t num;
	int must_index = 0;
	assert(iter);
	assert(iter->buf < iter->end);
	/* Indexed Header Field */
	if (*iter->buf & 128) {
		header->t = hpk_idx;
		if (hpk_err == num_decode(&num, iter, 7))
			return (hpk_err);

		if (num) { /* indexed key and value*/
			t = tbl_get_key(iter->ctx, num);
			if (!t)
				return (hpk_err);
			txtcpy(&header->key, t);

			t = tbl_get_value(iter->ctx, num);
			if (!t) {
				free(header->key.ptr);
				return (hpk_err);
			}

			txtcpy(&header->value, t);

			if (iter->buf < iter->end)
				return (hpk_more);
			else
				return (hpk_done);
		} else
			return (hpk_err);

	}
	/* Literal Header Field with Incremental Indexing */
	else if (*iter->buf >> 6 == 1) {
		header->t = hpk_inc;
		pref = 6;
		must_index = 1;
	}
	/* Literal Header Field without Indexing */
	else if (*iter->buf >> 4 == 0) {
		header->t = hpk_not;
		pref = 4;
	}
	/* Literal Header Field never Indexed */
	else if (*iter->buf >> 4 == 1) {
		header->t = hpk_never;
		pref = 4;
	}
	/* Dynamic Table Size Update */
	/* XXX if under max allowed value */
	else if (*iter->buf >> 5 == 1) {
		if (hpk_done != num_decode(&num, iter, 5))
			return (hpk_err);
		return HPK_ResizeTbl(iter->ctx, num);
	} else {
		return (hpk_err);
	}

	assert(pref);
	if (hpk_more != num_decode(&num, iter, pref))
		return (hpk_err);

	header->i = num;
	if (num) { /* indexed key */
		t = tbl_get_key(iter->ctx, num);
		if (!t)
			return (hpk_err);
		txtcpy(&header->key, t);
	} else {
		if (hpk_more != str_decode(iter, &header->key))
			return (hpk_err);
	}

	if (hpk_err == str_decode(iter, &header->value))
		return (hpk_err);

	if (must_index)
		push_header(iter->ctx, header);
	return (ITER_DONE(iter));
}

enum hpk_result
HPK_EncHdr(struct hpk_iter *iter, struct hpk_hdr *h) {
	int pref;
	int must_index = 0;
	enum hpk_result ret;
	switch (h->t) {
		case hpk_idx:
			*iter->buf = 0x80;
			num_encode(iter, 7, h->i);
			return (ITER_DONE(iter));
		case hpk_inc:
			*iter->buf = 0x40;
			pref = 6;
			must_index = 1;
			break;
		case hpk_not:
			*iter->buf = 0x00;
			pref = 4;
			break;
		case hpk_never:
			*iter->buf = 0x10;
			pref = 4;
			break;
		default:
			INCOMPL();
	}
	if (h->i) {
		if (hpk_more != num_encode(iter, pref, h->i))
			return (hpk_err);
	} else {
		iter->buf++;
		if (hpk_more != str_encode(iter, &h->key))
			return (hpk_err);
	}
	ret = str_encode(iter, &h->value);
	if (ret == hpk_err)
		return (hpk_err);
	if (must_index)
		push_header(iter->ctx, h);
	return (ret);

}
