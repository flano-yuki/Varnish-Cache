#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vas.h>

#include "hpack.h"
#include "hpack_priv.h"

struct symbol {
	int val;
	short size;
};

static struct symbol coding_table[] = {
#define HPACK(i, v, l) {v, l},
#include "inc.h"
#undef HPACK
	{0, 0}
};

#include "vtc_h2_dectbl.h"

struct symbol *EOS = &coding_table[256];

static int
hpack_decode(char *str, int nm, struct HdrIter *iter, int size) {
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
hpack_encode(struct HdrIter *iter, char *str, int size) {
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
hpack_simulate(char *str, int size, int huff) {
	int len = 0;
	assert(str);
	if (!huff)
		return (size);
	do {
		len += coding_table[(unsigned char)*str].size;	
	} while (*(++str) != '\0');
	return ((len+7)/8);
}

enum HdrRet
str_encode(struct HdrIter *iter, struct txt *t) {
	int slen = hpack_simulate(t->ptr, t->size, t->huff);
	assert(iter->buf < iter->end);
	if (t->huff)
		*iter->buf = 0x80;
	else
		*iter->buf = 0;

	if (HdrErr == num_encode(iter, 7, slen))
		return (HdrErr);

	if (slen > iter->end - iter->buf)
		return (HdrErr);

	if (t->huff) {
		return (hpack_encode(iter, t->ptr, t->size));
	} else {
		memcpy(iter->buf, t->ptr, slen);
		iter->buf += slen;
		return (ITER_DONE(iter));
	}
}

enum HdrRet
str_decode(struct HdrIter *iter, struct txt *t) {
	uint64_t num;
	int huff;
	assert(iter->buf < iter->end);
	huff = (*iter->buf & 0x80);
	if (HdrMore != num_decode(&num, iter, 7))
		return (HdrErr);
	if (num > iter->end - iter->buf)
		return (HdrErr);
	if (huff) { /*Huffman encoding */
		t->ptr = malloc((num * 8) / 5 + 1);
		AN(t->ptr);
		num = hpack_decode(t->ptr, (num * 8) / 5, iter, num);
		if (!num) {
			free(t->ptr);
			return (HdrErr);
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

enum HdrRet
num_decode(uint64_t *result, struct HdrIter *iter, uint8_t prefix) {
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
			return (HdrErr);
		/* check for overflow */
		if (UINT64_MAX - *result < (uint64_t)(*iter->buf & 0x7f) << shift)
			return (HdrErr);

		*result += (uint64_t)(*iter->buf & 0x7f) << shift;
		shift += 7;
	} while (*iter->buf & 0x80);
	iter->buf++;

	return (ITER_DONE(iter));
}

enum HdrRet
num_encode(struct HdrIter *iter, uint8_t prefix, uint64_t num) {
	assert(prefix);
	assert(prefix <= 8);
	assert(iter->buf < iter->end);

	uint8_t pmax = (1 << prefix) - 1;

	*iter->buf &= 0xff << prefix;
	if (num <=  pmax) {
		*iter->buf++ |= num;
		return (ITER_DONE(iter));
	} else if (iter->end - iter->buf < 2)
		return (HdrErr);

	iter->buf[0] |= pmax;
	num -= pmax;
	do {
		iter->buf++;
		if (iter->end == iter->buf)
			return (HdrErr);
		*iter->buf = num % 128;
		*iter->buf |= 0x80;
		num /= 128;
	} while (num);
	*iter->buf++ &= 127;
	return (ITER_DONE(iter));
}

uint8_t
num_simulate(uint8_t prefix, uint64_t num) {
	uint8_t len = 1;
	uint8_t pmax = (1 << prefix) - 1;
	if (num <  pmax)
		return (len);
	num -= pmax;
	do {
		len++;
		num /= 128;
	} while (num);
	return (len);
}

int getHdrIterLen(struct HdrIter *iter) {
	return (iter->buf - iter->orig);
}
