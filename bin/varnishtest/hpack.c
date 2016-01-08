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

#include "tiptopdec.h"

struct symbol *EOS = &coding_table[256];

int
hpack_decode(char *str, int nm, struct HdrIter *iter, int size) {
	int cursor = 0;
	size *= 8;
	int prefix;
	int idx = 0;
	//struct array_desc *entry;
	char nent;
	struct pair *p;
	while(cursor < size && nm--) {
		prefix = 0;
		while (cursor < size) {
			if (!((iter->buf[cursor/8] >> (7 - (cursor%8))) & 1))
				break;
			prefix++;
			cursor++;
		}
		if (prefix >= 30)
			return (0);
		if (cursor == size) {
			/* check that last bit is 1 */
			if (iter->buf[(cursor-1)/8] & 1)
				return (cursor/8);
			else
				return (0);
		}
		idx = 0;
		nent = decoding_table.desc[prefix].nentries;
		p = &decoding_table.pairs[decoding_table.desc[prefix].offset];
		do {
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
				break;
			} else if (!nent) /* We went too far, Marty! */
				return (0);
		} while (cursor < size);
	}
	assert(cursor = size + 1);
	return (cursor/8);
}

int
hpack_encode(struct HdrIter *iter, char *str) {
	short r, size;
	int v;
	int l = 0;
	char *b;
	int cursor = 0;
	while (*str != '\0') {
		v = coding_table[(unsigned char)*str].val;
		r = coding_table[(unsigned char)*str].size;

		while (r > 0) {
			b = iter->buf + (cursor / 8);
			size = 8 - (cursor % 8);
			if (!(cursor%8))
				*b = 0;
			if (r >= size) {
				*b |= (0xff >> (7 - size)) & (v >> (r - size));
				r -= size;
				cursor += size;
			} else {
				*b |= 0xff & (v<< (size - r));
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

int
hpack_simulate(char *str, int huff) {
	int len = 0;
	assert(str);
	if (!huff)
		return (strlen(str));
	do {
		len += coding_table[(unsigned char)*str].size;	
	} while (*(++str) != '\0');
	return ((len+7)/8);
}

enum HdrRet
str_encode(struct HdrIter *iter, char *str, int huff) {
	int slen = hpack_simulate(str, huff);
	assert(iter->buf < iter->end);
	if (huff)
		*iter->buf = 0x80;
	else
		*iter->buf = 0;

	if (HdrErr == num_encode(iter, 7, slen))
		return (HdrErr);

	if (slen > iter->end - iter->buf)
		return (HdrErr);

	if (huff) {
		return (hpack_encode(iter, str));
	} else {
		memcpy(iter->buf, str, slen);
		iter->buf += slen;
		return (iter->buf == iter->end ? HdrDone : HdrMore);
	}
}

int
str_decode(struct HdrIter *iter, struct txt *t) {
	char str[512] = {0};
	uint64_t num;
	int huff, ndec;
	assert(iter->buf < iter->end);
	huff = (*iter->buf & 0x80);
	if (HdrMore != num_decode(&num, iter, 7))
		return (0);
	if (num > iter->end - iter->buf)
		return (0);
	if (huff) { /*Huffman encoding */
		ndec = hpack_decode(str, 512, iter, num);
		if (!ndec)
			return (0);
		assert(ndec <= num);
		t->huff = 1;
		t->ptr = malloc(ndec + 1);
		AN(t->ptr);
		memcpy(t->ptr, str, ndec);
		t->ptr[ndec] = '\0';
		t->size = ndec;
	} else { /* literal string */
		t->huff = 0;
		t->ptr = malloc(num + 1);
		AN(t->ptr);
		memcpy(t->ptr, iter->buf, num);
		t->ptr[num] = '\0';
		t->size = num;
	}
	iter->buf += num;
	
	return (1);
}

enum HdrRet
num_decode(uint64_t *result, struct HdrIter *iter, uint8_t prefix) {
	uint8_t shift = 0;

	assert(iter->buf < iter->end);
	assert(prefix);
	assert(prefix <= 8);

	*result = 0;
	*result = *iter->buf & (0xff >> (8-prefix));
	if (*result < (1 << prefix) - 1)
		return (++iter->buf == iter->end ? HdrDone : HdrMore);

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

	return (iter->buf == iter->end ? HdrDone : HdrMore);
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
		return (iter->buf == iter->end ? HdrDone : HdrMore);
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
	return (iter->buf == iter->end ? HdrDone : HdrMore);
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
