#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "hpack.h"
#include "hpack_priv.h"

struct symbol {
	char chr;
	int val;
	short size;
};

struct node {
	struct node *left;
	struct node *right;
	struct symbol *sym;
};

static struct symbol coding_table[] = {
#define HPACK(i, v, l) {i, v, l},
#include "inc.h"
#undef HPACK
	{0, 0, 0}
};

#include "tree.h"

#include "tiptopdec.h"

struct symbol *EOS = &coding_table[256];

static struct node *decoding_tree = &n_0;

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
hpack_decode2(char *str, int nm, struct HdrIter *iter, int size) {
	int cursor = 0;
	size *= 8;
	int l = 0;
	struct node *n;
	while(cursor < size && nm--) {
		n = decoding_tree;
		int isEOS = 1;
		assert(n);
		while ((n->left || n->right) && cursor < size) {
			if ((iter->buf[cursor/8] >> (7 - (cursor%8))) & 1) {
				if (n->left)
					n = n->left;
				else
					return (0);
			} else {
				isEOS = 0;
				if (n->right)
					n = n->right;
				else
					return (0);
			}
			cursor++;
		}
		if (cursor == size && isEOS)
			return (cursor/8);
		if (!n->sym)
			return (0); /* decoding error */
		*(str++) = n->sym->chr;
	}
	/* XXX ensure cursor == size ?*/
	l = 8 - (cursor % 8);
	if (l > 8 && ((iter->buf[cursor/8] | (0xff >> l)) == (0xff >> l)))
	{
		printf("not EOS\n");
		return (0); /* not EOS */
	}
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

char *
str_decode(struct HdrIter *iter) {
	char str[512] = {0};
	uint64_t num;
	int huff, ndec;
	assert(iter->buf < iter->end);
	huff = (*iter->buf & 0x80);
	if (HdrMore != num_decode(&num, iter, 7))
		return (NULL);
	if (num > iter->end - iter->buf)
		return (NULL);
	if (huff) { /*Huffman encoding */
		ndec = hpack_decode(str, 512, iter, num);
		if (!ndec)
			return (NULL);
		assert(ndec <= num);
	} else { /* literal string */
		if (num >= 512)
			return (NULL);
		snprintf(str, num+1, "%s", iter->buf);
	}
	iter->buf += num;
	
	return (strdup(str));
}

enum HdrRet
num_decode(uint64_t *result, struct HdrIter *iter, uint8_t prefix) {
	uint8_t shift = 0;
	uint8_t len = 1;

	assert(iter->buf < iter->end);
	assert(prefix);
	assert(prefix <= 8);

	*result = 0;
	*result = *iter->buf & (0xff >> (8-prefix));
	if (*result < (1 << prefix) - 1)
		return (++iter->buf == iter->end ? HdrDone : HdrMore);

	do {
		if (iter->end - iter->buf == len)
			return (HdrErr);
		iter->buf++;
		len += 1;
		/* check for overflow */
		if (UINT64_MAX - *result < (uint64_t)(*iter->buf & 0x7f) << shift)
			return (HdrErr);

		*result += (uint64_t)(*iter->buf & 0x7f) << shift;
		shift += 7;
	} while (*iter->buf & 0x80);

	return (iter->buf == iter->end ? HdrDone : HdrMore);
}

enum HdrRet
num_encode(struct HdrIter *iter, uint8_t prefix, uint64_t num) {
	assert(prefix);
	assert(prefix <= 8);
	assert(iter->buf < iter->end);

	uint8_t len = 0;
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
		len++;
		iter->buf[len] |= 0x80;
		iter->buf[len] = num % 128;
		num /= 128;
		if (len > iter->end - iter->buf)
			return (HdrErr);
	} while (num);
	iter->buf += len;
	return (iter->buf == iter->end ? HdrDone : HdrMore);
}

uint8_t
num_simulate(uint8_t prefix, uint64_t num) {
	uint8_t len = 0;
	uint8_t pmax = (1 << prefix) - 1;
	if (num <=  pmax)
		return 1;
	do {
		len++;
		num /= 128;
	} while (num);
	return (len);
}

int getHdrIterLen(struct HdrIter *iter) {
	return (iter->buf - iter->orig);
}
