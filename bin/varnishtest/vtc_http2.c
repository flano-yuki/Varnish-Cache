/*-
 * Copyright (c) 2008-2015 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>

#include "vtc.h"

#include "vct.h"
#include "vgz.h"
#include "vnum.h"
#include "vre.h"
#include "vtcp.h"
#include "hpack.h"

/* SECTION: h2.both H/2 clients and servers
 *
 * Clients and servers are very similar in semantics under H/2 (mainly because
 * they just encapsulate H/1 that isn't that symetrical). For this reason, both
 * entities are described here under the same section.
 *
 * Both are described and handled in a similar manner:
 *
 * * h2client cNAME [SPEC] [ACTION]
 * * h2server sNAME [SPEC] [ACTION]
 *
 * Names cNAME (sname) must start by "c" ("s").
 *
 * SPEC is a string describing the actions undertaken by the entity, and is
 * mostly composed of streams declaration and management. The string can be
 * quoted "like this" for single line statements, or enclosed in curly brackets
 * for multi-line confort.
 *
 * ACTION can be:
 *
 * * -start: start a thread of the entity and continue parsing the specification
 *   immediately
 * * -wait: block until the thread returns
 * * -run: equivalent to calling -run then -wait
 * * -break: stop the running entity
 *
 */

#define MAX_HDR		50

#define ERR_MAX 13

static const char *h2_errs[] = {
	"NO_ERROR",
	"PROTOCOL_ERROR",
	"INTERNAL_ERROR",	
	"FLOW_CONTROL_ERROR",
	"SETTINGS_TIMEOUT",
	"STREAM_CLOSED",
	"FRAME_SIZE_ERROR",
	"REFUSED_STREAM",
	"CANCEL",
	"COMPRESSION_ERROR",
	"CONNECT_ERROR",
	"ENHANCE_YOUR_CALM",
	"INADEQUATE_SECURITY",
	"HTTP_1_1_REQUIRED",
	NULL
};

static const char *h2_types[] = {
	"DATA",
	"HEADERS",
	"PRIORITY",
	"RST_STREAM",
	"SETTINGS",
	"PUSH_PROMISE",
	"PING",
	"GOAWAY",
	"WINDOW_UPDATE",
	"CONTINUATION",
	NULL
};

#define SETTINGS_MAX 0x06

static const char *h2_settings[] = {
	"unknown",
	"HEADER_TABLE_SIZE",
	"ENABLE_PUSH",
	"MAX_CONCURRENT_STREAMS",
	"INITIAL_WINDOW_SIZE",
	"MAX_FRAME_SIZE",
	"MAX_HEADER_LIST_SIZE",
	NULL
};

enum {
	TYPE_DATA,
	TYPE_HEADERS,
	TYPE_PRIORITY,
	TYPE_RST,
	TYPE_SETTINGS,
	TYPE_PUSH,
	TYPE_PING,
	TYPE_GOAWAY,
	TYPE_WINUP,
	TYPE_CONT,
	TYPE_MAX
};

enum {
	ACK = 0x1,
	END_STREAM = 0x1,
	PADDED = 0x8,
	END_HEADERS = 0x4,
	PRIORITY = 0x20,

};

struct stream {
	unsigned		magic;
#define STREAM_MAGIC		0x63f1fac2
	unsigned long		id;
	char			*spec;
	char			*name;
	VTAILQ_ENTRY(stream)    list;
	unsigned		running;
	pthread_cond_t          cond;
	struct frame		*frame;
	pthread_t		tp;
	unsigned		reading;
	struct http2		*hp;
	uint64_t		ws;

	VTAILQ_HEAD(, frame)   fq;

	char			*body;
	int			bodylen;
	struct hpk_hdr		hdrs[MAX_HDR];
	int			nhdrs;

	int			dependency;
	int			weight;
};

struct http2 {
	unsigned		magic;
#define HTTP2_MAGIC		0x0b71d23a
	int			fd;
	int			*sfd;
	int			timeout;
	struct vtclog		*vl;

	int			fatal;
	int			wf;

	pthread_t		tp;
	unsigned		running;
	VTAILQ_HEAD(, stream)   streams;
	pthread_mutex_t		mtx;
	pthread_cond_t          cond;
	struct hpk_ctx		*outctx;
	struct hpk_ctx		*inctx;
	uint64_t		ws;
};

#define ONLY_CLIENT(hp, av)						\
	do {								\
		if (hp->sfd != NULL)					\
			vtc_log(hp->vl, 0,				\
			    "\"%s\" only possible in client", av[0]);	\
	} while (0)

#define ONLY_SERVER(hp, av)						\
	do {								\
		if (hp->sfd == NULL)					\
			vtc_log(hp->vl, 0,				\
			    "\"%s\" only possible in server", av[0]);	\
	} while (0)

static void
http_write(const struct http2 *hp, int lvl, char *buf, int s, const char *pfx)
{
	ssize_t l;

	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);
	AN(buf);
	AN(pfx);

	vtc_dump(hp->vl, lvl, pfx, buf, s);
	l = write(hp->fd, buf, s);
	if (l != s)
		vtc_log(hp->vl, hp->fatal, "Write failed: (%zd vs %d) %s",
		    l, s, strerror(errno));
}

static int
get_bytes(struct http2 *hp, char *buf, int n) {
	int i;
	struct pollfd pfd[1];

	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);
	AN(buf);

	while (n > 0) {
		pfd[0].fd = hp->fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		i = poll(pfd, 1, hp->timeout);
		if (i < 0 && errno == EINTR)
			continue;
		if (i == 0)
			vtc_log(hp->vl, hp->fatal,
			    "HTTP2 rx timeout (fd:%d %u ms)",
			    hp->fd, hp->timeout);
		if (i < 0)
			vtc_log(hp->vl, hp->fatal,
			    "HTTP2 rx failed (fd:%d poll: %s)",
			    hp->fd, strerror(errno));
		assert(i > 0);
		i = read(hp->fd, buf, n);
		if (!(pfd[0].revents & POLLIN))
			vtc_log(hp->vl, 4,
			    "HTTP2 rx poll (fd:%d revents: %x n=%d, i=%d)",
			    hp->fd, pfd[0].revents, n, i);
		if (i == 0)
			vtc_log(hp->vl, hp->fatal,
			    "HTTP2 rx EOF (fd:%d read: %s)",
			    hp->fd, strerror(errno));
		if (i < 0)
			vtc_log(hp->vl, hp->fatal,
			    "HTTP2 rx failed (fd:%d read: %s)",
			    hp->fd, strerror(errno));
		n -= i;
	}
	return (1);

}

VTAILQ_HEAD(fq_head, frame);

struct frame {
	unsigned	magic;
#define	FRAME_MAGIC	0x5dd3ec4
	uint32_t        size;
	uint32_t	stid;
	uint8_t         type;
	uint8_t         flags;
	char		*data;

	VTAILQ_ENTRY(frame)    list;

	union {
		struct {
			uint32_t stream;
			uint8_t  exclusive;
			uint8_t  weight;
		}		prio;
		uint32_t	rst_err;
		double settings[SETTINGS_MAX+1];
		struct {
			char data[9];
			int ack;
		}		ping;
		struct {
			uint32_t err;
			uint32_t stream;
			char	 *debug;
		}		goaway;
		uint32_t	winup_size;
	} md;
};

static void
readFrameHeader(struct frame *f, char *buf)
{
	CHECK_OBJ_NOTNULL(f, FRAME_MAGIC);
	AN(buf);

	f->size  = (unsigned char)buf[0] << 16;
	f->size += (unsigned char)buf[1] << 8;
	f->size += (unsigned char)buf[2];

	f->type = (unsigned char)buf[3];

	f->flags = (unsigned char)buf[4];

	f->stid  = (0xff & (unsigned char)buf[5]) << 24;
	f->stid += (0xff & (unsigned char)buf[6]) << 16;
	f->stid += (0xff & (unsigned char)buf[7]) <<  8;
	f->stid += (0xff & (unsigned char)buf[8]);
};

static void
writeFrameHeader(char *buf, struct frame *f)
{
	CHECK_OBJ_NOTNULL(f, FRAME_MAGIC);
	AN(buf);
	buf[0] = (f->size >> 16) & 0xff;
	buf[1] = (f->size >>  8) & 0xff;
	buf[2] = (f->size      ) & 0xff;

	buf[3] = f->type;

	buf[4] = f->flags;

	buf[5] = (f->stid >> 24) & 0xff;
	buf[6] = (f->stid >> 16) & 0xff;
	buf[7] = (f->stid >>  8) & 0xff;
	buf[8] = (f->stid      ) & 0xff;
}

#define INIT_FRAME(f, ty, sz, id, fl) \
do { \
	f.magic = FRAME_MAGIC; \
	f.type = TYPE_ ## ty; \
	f.size = sz; \
	f.stid = id; \
	f.flags = fl; \
	f.data = NULL; \
} while(0)

static void
clean_frame(struct frame **f)
{
	AN(f);
	if (!*f)
		return;

	CHECK_OBJ_NOTNULL(*f, FRAME_MAGIC);

	if ((*f)->type == TYPE_GOAWAY)
		free((*f)->md.goaway.debug);
	free((*f)->data);
	free(*f);
	*f = NULL;
}

static void
write_frame(struct http2 *hp, struct frame *f)
{
	ssize_t l;
	const char *type;
	char hdr[9];

	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);
	CHECK_OBJ_NOTNULL(f, FRAME_MAGIC);

	writeFrameHeader(hdr, f);

	if (f->type <= TYPE_MAX)
		type = h2_types[f->type];
	else
		type = "?";
	vtc_log(hp->vl, 3, "tx: stream: %d, type: %s (%d), "
			"flags: 0x%02x, size: %d",
			f->stid, type, f->type, f->flags, f->size);

	AZ(pthread_mutex_lock(&hp->mtx));
	l = write(hp->fd, hdr, sizeof(hdr));
	if (l != sizeof(hdr))
		vtc_log(hp->vl, hp->fatal, "Write failed: (%zd vs %zd) %s",
		    l, sizeof(hdr), strerror(errno));

	if (f->size) {
		AN(f->data);
		l = write(hp->fd, f->data, f->size);
		if (l != f->size)
			vtc_log(hp->vl, hp->fatal,
					"Write failed: (%zd vs %d) %s",
					l, f->size, strerror(errno));
	}
	AZ(pthread_mutex_unlock(&hp->mtx));
}

static void
exclusive_stream_dependency(struct stream *s)
{
	struct stream *target = NULL;
	struct http2 *hp = s->hp;
	
	if (s->id == 0)
		return;
	
	VTAILQ_FOREACH(target, &hp->streams, list) {
		if (target->id != s->id && target->dependency == s->dependency)
			target->dependency = s->id;
	}
}

/* read a frame and queue it in the relevant stream, wait if not present yet.
 */
static void *
receive_frame(void *priv) {
	struct http2 *hp;
	char hdr[9];
	struct frame *f;
	struct stream *s;
	const char *type;

	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);

	AZ(pthread_mutex_lock(&hp->mtx));
	while (hp->running) {
		/*no wanted frames? */
		if (hp->wf == 0) {
			AZ(pthread_cond_wait(&hp->cond, &hp->mtx));
			continue;
		}
		AZ(pthread_mutex_unlock(&hp->mtx));

		if (!get_bytes(hp, hdr, 9)) {
			vtc_log(hp->vl, 1, "could not get header");
			return (NULL);
		}
		ALLOC_OBJ(f, FRAME_MAGIC);
		readFrameHeader(f, hdr);

		if (f->type <= TYPE_MAX)
			type = h2_types[f->type];
		else
			type = "UNKNOWN";
		vtc_log(hp->vl, 3, "rx: stream: %d, type: %s (%d), "
				"flags: 0x%02x, size: %d",
				f->stid, type, f->type, f->flags, f->size);

		if (f->size) {
			f->data = malloc(f->size + 1);
			AN(f->data);
			f->data[f->size] = '\0';
			get_bytes(hp, f->data, f->size);
		}

		/* is the corresponding stream waiting? */
		s = NULL;
		while (!s) {
			VTAILQ_FOREACH(s, &hp->streams, list) {
				if (s->id == f->stid)
					break;
			}
			if (!s)
				AZ(pthread_cond_wait(&hp->cond, &hp->mtx));
			if (!hp->running) {
				clean_frame(&f);
				return (NULL);
			}
		}
		/* parse the frame according to it type, and fill the metada */
		if (f->type == TYPE_DATA) {
			if (!f->size) {
				vtc_log(hp->vl, 4, "s%lu - no data", s->id);
			}

			if (s->id)
				s->ws -= f->size;
			s->hp->ws -= f->size;

			if (s->body) {
				s->body = realloc(s->body, s->bodylen + f->size + 1);
			} else {
				AZ(s->bodylen);
				s->body = malloc(f->size + 1);
			}
			AN(s->body);
			memcpy(s->body + s->bodylen, f->data, f->size);
			s->bodylen += f->size;
			s->body[s->bodylen] = '\0';

			vtc_log(hp->vl, 3, "s%lu - data: %s", s->id, f->data);
		} else if (f->type == TYPE_HEADERS || f->type == TYPE_CONT) {
			struct hpk_iter *iter;
			enum hpk_result r = hpk_err;
			int shift = 0;
			int exclusive = 0;
			int n;
			if (f->type == TYPE_HEADERS && f->flags & PRIORITY){
				shift = 5;
				n = ntohl(*(uint32_t*)f->data);
				s->dependency = n & ~(1 << 31);
				exclusive = n >> 31;

				s->weight = f->data[4];
				if (exclusive)
					exclusive_stream_dependency(s);

				vtc_log(hp->vl, 4, "s%lu - stream->dependency: %u", s->id, s->dependency);
				vtc_log(hp->vl, 4, "s%lu - stream->weight: %u", s->id, s->weight);
			}
			iter = HPK_NewIter(s->hp->inctx, f->data + shift, f->size - shift);

			while (s->nhdrs < MAX_HDR) {
				r = HPK_DecHdr(iter, s->hdrs + s->nhdrs);
				if (r == hpk_err )
					break;
				vtc_log(hp->vl, 4,
						"s%lu - header: %s : %s (%d)",
						s->id,
						s->hdrs[s->nhdrs].key.ptr,
						s->hdrs[s->nhdrs].value.ptr,
						s->nhdrs);
				s->nhdrs++;
				if (r == hpk_done)
					break;
			}
			//XXX document too many headers errors
			if (r != hpk_done)
				vtc_log(hp->vl, hp->fatal ? 4 : 0,
						"Header decoding failed (%d)",
						hp->fatal);
			HPK_FreeIter(iter);
		} else if (f->type == TYPE_PRIORITY) {
			char *buf;
			int n;
			if (f->size != 5)
				vtc_log(hp->vl, 0, "Size should be 5, but isn't (%d)", f->size);

			buf = f->data;
			AN(buf);

			n = ntohl(*(uint32_t*)f->data);
			f->md.prio.stream = n & ~(1 << 31);

			s->dependency = f->md.prio.stream;
			if (n >> 31){
				f->md.prio.exclusive = 1;
				exclusive_stream_dependency(s);
			}

			buf += 4;
			f->md.prio.weight = *buf;
			s->weight = f->md.prio.weight;

			vtc_log(hp->vl, 3, "s%lu - prio->stream: %u", s->id, f->md.prio.stream);
			vtc_log(hp->vl, 3, "s%lu - prio->weight: %u", s->id, f->md.prio.weight);
		} if (f->type == TYPE_RST) {
			uint32_t err;
			const char *buf;
			if (f->size != 4)
				vtc_log(hp->vl, 0, "Size should be 4, but isn't (%d)", f->size);

			err = ntohl(*(uint32_t*)f->data);
			f->md.rst_err = err;

			vtc_log(hp->vl, 2, "ouch");
			if (err <= ERR_MAX)
				buf = h2_errs[err];
			else
				buf = "unknown";
			vtc_log(hp->vl, 4, "s%lu - rst->err: %s (%d)", s->id, buf, err);
		} else if (f->type == TYPE_SETTINGS) {
			int i, t, v;
			const char *buf;
			if (f->size % 6)
				vtc_log(hp->vl, 0, "Size should be a multiple of 6, but isn't (%d)", f->size);

			for (i = 0; i <= SETTINGS_MAX; i++)
				f->md.settings[i] = NAN;

			for (i = 0; i < f->size;) {
				t = ntohs(*(uint16_t *)(f->data + i));
				i += 2;
				v = ntohl(*(uint32_t *)(f->data + i));
				if (t <= SETTINGS_MAX) {
					buf = h2_settings[t];
					f->md.settings[t] = v;
				} else
					buf = "unknown";
				i += 4;

				if (t == 1 )
					HPK_ResizeTbl(s->hp->outctx, v);

				vtc_log(hp->vl, 4, "s%lu - settings->%s (%d): %d", s->id, buf, t, v);
			}
		} else if (f->type == TYPE_PING) {
			if (f->size != 8)
				vtc_log(hp->vl, 0, "Size should be 8, but isn't (%d)", f->size);
			f->md.ping.ack = f->flags & 1;
			memcpy(f->md.ping.data, f->data, 8);
			f->md.ping.data[8] = '\0';

			vtc_log(hp->vl, 4, "s%lu - ping->data: %s", s->id, f->md.ping.data);
		} else if (f->type == TYPE_GOAWAY) {
			const char *err_buf;
			uint32_t err, stid;
			if (f->size < 8)
				vtc_log(hp->vl, 0, "Size should be at least 8, but isn't (%d)", f->size);
			if (f->data[0] & (1<<7))
				vtc_log(hp->vl, 0, "First bit of data is reserved and should be 0");

			stid = ntohl(((uint32_t*)f->data)[0]);
			err = ntohl(((uint32_t*)f->data)[1]);
			f->md.goaway.err = err;
			f->md.goaway.stream = stid;

			if (err <= ERR_MAX)
				err_buf = h2_errs[err];
			else
				err_buf = "unknown";

			if (f->size > 8) {
				f->md.goaway.debug = malloc(f->size - 8 + 1);
				AN(f->md.goaway.debug);
				f->md.goaway.debug[f->size - 8] = '\0';

				memcpy(f->md.goaway.debug, f->data + 8, f->size - 8);
			}

			vtc_log(hp->vl, 3, "s%lu - goaway->laststream: %d", s->id, stid);
			vtc_log(hp->vl, 3, "s%lu - goaway->err: %s (%d)", s->id, err_buf, err);
			if (f->md.goaway.debug)
				vtc_log(hp->vl, 3, "s%lu - goaway->debug: %s", s->id, f->md.goaway.debug);
		} else 	if (f->type == TYPE_WINUP) {
			uint32_t size;
			if (f->size != 4)
				vtc_log(hp->vl, 0, "Size should be 4, but isn't (%d)", f->size);
			if (f->data[0] & (1<<7))
				vtc_log(hp->vl, s->hp->fatal, "First bit of data is reserved and should be 0");

			size = ntohl(*(uint32_t*)f->data);
			f->md.winup_size = size;

			vtc_log(hp->vl, 3, "s%lu - winup->size: %d", s->id, size);
		}

		VTAILQ_INSERT_HEAD(&s->fq, f, list);
		hp->wf--;
		AZ(pthread_cond_signal(&s->cond));
		AZ(pthread_mutex_lock(&hp->mtx));
		continue;
	}
	AZ(pthread_mutex_unlock(&hp->mtx));

	return (NULL);
}

#define STRTOU32(n, s, p, v, c) \
	n = strtoul(s, &p, 0); \
	if (*p != '\0') { \
		vtc_log(v, 0, "%s takes an integer as argument" \
			"(found %s)", c, s); \
		WRONG("Couldn't convert to integer");\
	}

#define CHECK_LAST_FRAME(TYPE) \
	if (!f || f->type != TYPE_ ## TYPE) { \
		vtc_log(s->hp->vl, 0, "Last frame was not of type " #TYPE); \
	}

#define RETURN_SETTINGS(idx) \
{ \
	if isnan(f->md.settings[idx]) { \
		return (NULL); \
	} \
	snprintf(buf, 20, "%.0f", f->md.settings[idx]); \
	return (buf); \
} while (0);

#define RETURN_BUFFED(val) \
{ \
	snprintf(buf, 20, "%d", val); \
	return (buf); \
} while (0)

static char *
find_header(struct stream *s, char *k, int kl) {
	struct hpk_hdr *h = s->hdrs;
	int n = s->nhdrs;

	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	AN(k);

	while (n--) {
		if (kl == h->key.len  && !memcmp(h->key.ptr, k, kl))
			return h->value.ptr;
		h++;
	}
	return (NULL);
}

static const char *
cmd_var_resolve(struct stream *s, char *spec, char *buf)
{
	uint32_t idx;
	int n;
	const struct hpk_hdr *h;
	struct hpk_ctx *ctx;
	struct frame *f = s->frame;

	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	CHECK_OBJ_NOTNULL(s->hp, HTTP2_MAGIC);
	AN(spec);
	AN(buf);

	n = 0;
	if (!strcmp(spec, "ping.data")) {
		CHECK_LAST_FRAME(PING);
		return (f->md.ping.data);
	}
	else if (!strcmp(spec, "ping.ack")) {
		CHECK_LAST_FRAME(PING);
		if (f->flags & 1)
			snprintf(buf, 20, "true");
		else
			snprintf(buf, 20, "false");
		return (buf);
	}
	else if (!strcmp(spec, "winup.size")) {
		CHECK_LAST_FRAME(WINUP);
		RETURN_BUFFED(f->md.winup_size);
	}
	else if (!strcmp(spec, "prio.stream")) {
		CHECK_LAST_FRAME(PRIORITY);
		RETURN_BUFFED(f->md.prio.stream);
	}
	else if (!strcmp(spec, "prio.exclusive")) {
		CHECK_LAST_FRAME(PRIORITY);
		if (f->md.prio.exclusive)
				snprintf(buf, 20, "true");
			else
				snprintf(buf, 20, "false");
			return (buf);
	}
	else if (!strcmp(spec, "prio.weight")) {
		CHECK_LAST_FRAME(PRIORITY);
		RETURN_BUFFED(f->md.prio.weight);
	}
	else if (!strcmp(spec, "rst.err")) {
		CHECK_LAST_FRAME(RST);
		RETURN_BUFFED(f->md.rst_err);
	} /* SETTINGS */
	else if (!strncmp(spec, "settings.", 9)) {
		CHECK_LAST_FRAME(SETTINGS);
		spec += 9;
		if (!strcmp(spec, "ack")) {
			if (f->flags & 1)
				snprintf(buf, 20, "true");
			else
				snprintf(buf, 20, "false");
			return (buf);
		}
		else if (!strcmp(spec, "push")) {
			if (isnan(f->md.settings[2]))
				return (NULL);
			else if (f->md.settings[2] == 1)
				snprintf(buf, 20, "true");
			else
				snprintf(buf, 20, "false");
			return (buf);
		}
		else if (!strcmp(spec, "hdrtbl"))     { RETURN_SETTINGS(1); }
		else if (!strcmp(spec, "maxstreams")) { RETURN_SETTINGS(3); }
		else if (!strcmp(spec, "winsize"))    { RETURN_SETTINGS(4); }
		else if (!strcmp(spec, "framesize"))  { RETURN_SETTINGS(5); }
		else if (!strcmp(spec, "hdrsize"))    { RETURN_SETTINGS(6); }
	} /* GOAWAY */
	else if (!strncmp(spec, "goaway.", 7)) {
		spec += 7;
		CHECK_LAST_FRAME(GOAWAY);

		if (!strcmp(spec, "err")) {
			RETURN_BUFFED(f->md.goaway.err);
		}
		else if (!strcmp(spec, "laststream")) {
			RETURN_BUFFED(f->md.goaway.stream);
		}
		else if (!strcmp(spec, "debug")) {
			return (f->md.goaway.debug);
		}
	} /* GENERIC FRAME */
	else if (!strncmp(spec, "frame.", 6)) {
		spec += 6;
		if (!f)
			vtc_log(s->hp->vl, 0, "No frame received yet.");
		     if (!strcmp(spec, "data"))   { return (f->data); }
		else if (!strcmp(spec, "type"))   { RETURN_BUFFED(f->type); }
		else if (!strcmp(spec, "size"))	  { RETURN_BUFFED(f->size); }
		else if (!strcmp(spec, "stream")) { RETURN_BUFFED(f->stid); }
	}
	else if (!strcmp(spec, "stream.window")) {
		if (s->id) {
			snprintf(buf, 20, "%ld", s->ws);
			return (buf);
		} else {
			snprintf(buf, 20, "%ld", s->hp->ws);
			return (buf);
		}
	}
	else if (!strcmp(spec, "stream.weight")) {
		if (s->id) {
			snprintf(buf, 20, "%d", s->weight);
			return (buf);
		} else {
			return NULL;
		}
	}
	else if (!strcmp(spec, "stream.dependency")) {
		if (s->id) {
			snprintf(buf, 20, "%d", s->dependency);
			return (buf);
		} else {
			return NULL;
		}
	}
	else if (!memcmp(spec, "intable", 7) ||
			!memcmp(spec, "outtable", 8)) {
		if (spec[0] == 'i') {
			spec += 7;
			ctx = s->hp->inctx;
		} else {
			spec += 8;
			ctx = s->hp->outctx;
		}

		if (1 == sscanf(spec, "[%u].key%n", &idx, &n) &&
				spec[n] == '\0') {
			h = HPK_GetHdr(ctx, idx + 61);
			return (h ? h->key.ptr : NULL);
		}
		else if (1 == sscanf(spec, "[%u].value%n", &idx, &n) &&
				spec[n] == '\0') {
			h = HPK_GetHdr(ctx, idx + 61);
			return (h ? h->value.ptr : NULL);
		}
		else if (!strcmp(spec, ".size")) {
			RETURN_BUFFED(HPK_GetTblSize(ctx));
		}
		else if (!strcmp(spec, ".length")) {
			RETURN_BUFFED(HPK_GetTblLength(ctx));
		}
	}
	else if (!strcmp(spec, "req.bodylen")) {
		RETURN_BUFFED(s->bodylen);
	}
	else if (!strcmp(spec, "resp.bodylen")) {
		RETURN_BUFFED(s->bodylen);
	}
	else if (!strcmp(spec, "req.body")) {
		return (s->body);
	}
	else if (!strcmp(spec, "resp.body")) {
		return (s->body);
	}
	else if (!memcmp(spec, "req.http.", 9)) {
		return (find_header(s, spec + 9, strlen(spec + 9)));
	}
	else if (!memcmp(spec, "resp.http.", 10)) {
		return (find_header(s, spec + 10, strlen(spec + 10)));
	}
	else
		return (spec);
	return(NULL);
}


char pri_string[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static void
cmd_http_txpri(CMD_ARGS)
{
	struct http2 *hp;
	(void)cmd;
	(void)av;
	(void)vl;
	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);
	http_write(hp, 4, pri_string, sizeof(pri_string) - 1, "txpri");
}

static void
cmd_http_rxpri(CMD_ARGS)
{
	struct http2 *hp;
	char buf[sizeof(pri_string)];
	(void)cmd;
	(void)av;
	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);

	(void)get_bytes(hp, buf, sizeof(pri_string) - 1);
	if (strncmp(pri_string, buf, strlen(pri_string) - 1))
		vtc_log(vl, hp->fatal, "HTTP rxpri failed");
}

static void
cmd_txframe(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *q;
	char *buf;
	char tmp[3];
	int i;
	unsigned size = 0;
	(void)cmd;

	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	CAST_OBJ_NOTNULL(hp, s->hp, HTTP2_MAGIC);
	AN(av[1]);
	AZ(av[2]);

	q = av[1];
	size = strlen(q)/2;
	buf = malloc(size);
	for (i = 0; i < size; i++) {
		while (vct_issp(*q))
			q++;
		if (*q == '\0')
			break;
		memcpy(tmp, q, 2);
		q += 2;
		tmp[2] = '\0';
		if (!vct_ishex(tmp[0]) || !vct_ishex(tmp[1]))
			vtc_log(vl, 0, "Illegal Hex char \"%c%c\"",
					tmp[0], tmp[1]);
		buf[i] = (uint8_t)strtoul(tmp, NULL, 16);
	}
	AZ(pthread_mutex_lock(&hp->mtx));
	http_write(hp, 4, buf, size, "txframe");

	AZ(pthread_mutex_unlock(&hp->mtx));
	vtc_hexdump(vl, 4, "txframe", (void *)buf, size);
}

static void
clean_headers(struct stream *s) {
	struct hpk_hdr *h = s->hdrs;
	
	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);

	while (s->nhdrs--) {
		if (h->key.len)
			free(h->key.ptr);
		if (h->value.len)
			free(h->value.ptr);
		h++;
	}
	s->nhdrs = 0;
	memset(s->hdrs, 0, sizeof(s->hdrs));
}

#define ENC(hdr, k, v) \
{ \
	hdr.key.ptr = strdup(k); \
	AN(hdr.key.ptr); \
	hdr.key.len = strlen(k); \
	hdr.value.ptr = strdup(v); \
	AN(hdr.value.ptr); \
	hdr.value.len = strlen(v); \
	HPK_EncHdr(iter, &hdr); \
	free(hdr.key.ptr);\
	free(hdr.value.ptr); \
}

/* handles txcont, txreq and txresp */
static void
cmd_tx11obj(CMD_ARGS)
{
	struct stream *s;
	int status_done = 1;
	int req_done = 1;
	int url_done = 1;
	int scheme_done = 1;
	uint32_t stid = 0;
	uint32_t weight = 16;
	int exclusive = 0;
	char buf[1024*2048];
	uint32_t *ubuf = (uint32_t *)buf;
	struct hpk_iter *iter;
	struct frame f;
	char *body = NULL;
	/*XXX: do we need a better api? yes we do */
	struct hpk_hdr hdr;
	char *cmd_str = *av;
	char *p;
	(void)cmd;

	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	INIT_FRAME(f, CONT, 0, s->id, END_HEADERS);

	if (strcmp(cmd_str, "txcont")) {
		f.type = TYPE_HEADERS;
		f.flags |= END_STREAM;
		if (!strcmp(cmd_str, "txreq")) {
			req_done = 0;
			url_done = 0;
			scheme_done = 0;
		} else {
			status_done = 0;
		}
	}

	iter = HPK_NewIter(s->hp->outctx, buf, 1024*2048);
	while (*++av) {
		hdr.t = hpk_not;
		hdr.i = 0;
		hdr.key.huff = 0;
		hdr.key.ptr = NULL;
		hdr.key.len = 0; 
		hdr.value.huff = 0;
		hdr.value.ptr = NULL;
		hdr.value.len = 0;
		if (!strcmp(*av, "-noadd")) {
			url_done = 1;
			status_done = 1;
			req_done = 1;
			scheme_done = 1;
		} else if (!strcmp(*av, "-status") &&
				!strcmp(cmd_str, "txresp")) {
			ENC(hdr, ":status", av[1]);
			av++;
			status_done = 1;
		} else if (!strcmp(*av, "-url") &&
				!strcmp(cmd_str, "txreq")) {
			ENC(hdr, ":path", av[1]);
			av++;
			url_done = 1;
		} else if (!strcmp(*av, "-req") &&
				!strcmp(cmd_str, "txreq")) {
			ENC(hdr, ":method", av[1]);
			av++;
			req_done = 1;
		} else if (!strcmp(*av, "-scheme") &&
				!strcmp(cmd_str, "txreq")) {
			ENC(hdr, ":scheme", av[1]);
			av++;
			scheme_done = 1;
		} else if (!strcmp(*av, "-hdr")) {
			ENC(hdr, av[1], av[2]);
			av += 2;
		} else if (!strcmp(*av, "-idxHdr")) {
			AN(++av);
			hdr.t = hpk_idx;
			STRTOU32(hdr.i, *av, p, vl, "-idxHdr");
			HPK_EncHdr(iter, &hdr);
		} else if (!strcmp(*av, "-litIdxHdr")) {
			av++;
			if (!strcmp(*av, "inc")) {
				hdr.t = hpk_inc;
			} else if (!strcmp(*av, "not")) {
				hdr.t = hpk_not;
			} else if (!strcmp(*av, "never")) {
				hdr.t = hpk_never;
			} else
				vtc_log(vl, 0, "first -litidxHdr arg can be inc, not, never (got: %s)", *av);
			av++;
			AN(*av);
			STRTOU32(hdr.i, *av, p, vl, "second -litidxHdr arg");
			av++;
			if (!strcmp(*av, "plain")) {
			} else if (!strcmp(*av, "huf")) {
				hdr.value.huff = 1;
			} else
				vtc_log(vl, 0, "third -litidxHdr arg can be huf or plain (got: %s)", *av);
			av++;
			AN(*av);
			hdr.key.ptr = NULL;
			hdr.key.len = 0;
			hdr.value.ptr = *av;
			hdr.value.len = strlen(*av);
			HPK_EncHdr(iter, &hdr);
		} else if (!strcmp(*av, "-litHdr")) {
			av++;
			if (!strcmp(*av, "inc")) {
				hdr.t = hpk_inc;
			} else if (!strcmp(*av, "not")) {
				hdr.t = hpk_not;
			} else if (!strcmp(*av, "never")) {
				hdr.t = hpk_never;
			} else
				vtc_log(vl, 0, "first -litHdr arg can be inc, not, never (got: %s)", *av);

			av++;
			if (!strcmp(*av, "plain")) {
			} else if (!strcmp(*av, "huf")) {
				hdr.key.huff = 1;
			} else
				vtc_log(vl, 0, "second -litHdr arg can be huf or plain (got: %s)", *av);
			av++;
			AN(*av);
			hdr.key.ptr = *av;
			hdr.key.len = strlen(*av);

			av++;
			if (!strcmp(*av, "plain")) {
			} else if (!strcmp(*av, "huf")) {
				hdr.value.huff = 1;
			} else
				vtc_log(vl, 0, "fourth -litHdr arg can be huf or plain (got: %s)", *av);
			av++;
			AN(*av);
			hdr.value.ptr = *av;
			hdr.value.len = strlen(*av);
			vtc_log(vl, 4,"sending (%s)(%s)", hdr.key.ptr, hdr.value.ptr);
			HPK_EncHdr(iter, &hdr);
		} else if (!strcmp(*av, "-body") &&
				strcmp(cmd_str, "txcont")) {
			AZ(body);
			REPLACE(body, av[1]);
			f.flags &= ~END_STREAM;
			av++;
		} else if (!strcmp(*av, "-bodylen") &&
				strcmp(cmd_str, "txcont")) {
			AZ(body);
			body = synth_body(av[1], 0);
			f.flags &= ~END_STREAM;
			av++;
		} else if (!strcmp(*av, "-nostrend") &&
				strcmp(cmd_str, "txcont")) {
			f.flags &= ~END_STREAM;
		} else if (!strcmp(*av, "-nohdrend")) {
			f.flags &= ~END_HEADERS;
		} else if (!strcmp(*av, "-dep")) {
		        av++;
		        STRTOU32(stid, *av, p, vl, "-dep");
		        f.flags |= PRIORITY;
		} else if (!strcmp(*av, "-ex")) {
		        exclusive = 1 << 31;
		        f.flags |= PRIORITY;
		} else if (!strcmp(*av, "-weight")) {
		        av++;
		        STRTOU32(weight, *av, p, vl, "-weight");
		        if (weight >= 256)
		                vtc_log(vl, 0,
		                        "Weight must be a 8-bits integer "
		                                "(found %s)", *av);
		        f.flags |= PRIORITY;
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(s->hp->vl, 0, "Unknown %s spec: %s\n", cmd_str, *av);

	hdr.t = hpk_not;
	hdr.i = 0;
	hdr.key.huff = 0;
	hdr.value.huff = 0;

	if (!status_done)
		ENC(hdr, ":status", "200");
	if (!url_done)
		ENC(hdr, ":path", "/");
	if (!req_done)
		ENC(hdr, ":method", "GET");
	if (!scheme_done)
		ENC(hdr, ":scheme", "http");

	f.size = gethpk_iterLen(iter);
	if (f.flags & PRIORITY){
		s->weight = weight & 0xff;
		s->dependency = stid;

	        memmove(buf + 5, buf, f.size);
		*(uint32_t *)ubuf = htonl(stid | exclusive);
		buf[4] = s->weight;
		f.size += 5;

		vtc_log(s->hp->vl, 4, "s%lu - stream->dependency: %u", s->id, s->dependency);
		vtc_log(s->hp->vl, 4, "s%lu - stream->weight: %u", s->id, s->weight);
		if (exclusive)
			exclusive_stream_dependency(s);
	}
	f.data = buf;	
	HPK_FreeIter(iter);
	write_frame(s->hp, &f);

	if (!body)
		return;

	INIT_FRAME(f, DATA, strlen(body), s->id, END_STREAM);
	f.data = body;

	write_frame(s->hp, &f);
	free(body);
}

static void
cmd_txdata(CMD_ARGS)
{
	struct stream *s;
	struct frame f;
	char *body = NULL;
	(void)cmd;

	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	INIT_FRAME(f, DATA, 0, s->id, END_STREAM);

	while (*++av) {
		if (!strcmp(*av, "-data")) {
			body = strdup(av[1]);
			av++;
		} else if (!strcmp(*av, "-nostrend"))
			f.flags &= ~END_STREAM;
		else
			break;
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown txdata spec: %s\n", *av);

	if (!body)
		body = strdup("");

	f.size = strlen(body);
	f.data = body;
	write_frame(s->hp, &f);
	free(body);
}
/* SECTION: h2.both.streams.txrst txrst
 *
 * The RST_STREAM frame (rfc7540#6.4) terminates a stream, and embed an error
 * code to inform the other end of the reason for the termination.
 *
 * The only possible argument is ``err`` and sets the error code. It can be an
 * integer or a string describing the error, such as NO_ERROR, or CANCEL (see
 * rfc7540#11.4 for more strings).
 *
 * By default, txrst will send a 0 error code (NO_ERROR).
 */
static void
cmd_txrst(CMD_ARGS)
{
	struct stream *s;
	char *p;
	uint32_t err;
	struct frame f;
	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	INIT_FRAME(f, RST, 4, s->id, 0);

	while (*++av) {
		if (!strcmp(*av, "-err")) {
			++av;
			for (err=0; h2_errs[err]; err++) {
				if (!strcmp(h2_errs[err], *av))
					break;
			}

			if (h2_errs[err])
				continue;

			STRTOU32(err, *av, p, vl, "-err");
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown txrst spec: %s\n", *av);

	err = htonl(err);
	f.data = (void *)&err;
	write_frame(s->hp, &f);
}

/* SECTION: h2.both.streams.txprio txprio
 * 
 * The PRIORITY (rfc7540#6.3) allows the client to define a priority between
 * streams that the server is free to follow or not.
 *
 * Possible arguments are:
 *
 * * -stream INT: indicate the id of the stream the sender stream depends on
 * * -ex: the dependency should be made exclusive (only this streams depends on
 *   the parent stream)
 * * -weight INT: an 8-bits integer is used to balance priority between streams
 *   depending on the same streams. 
 */
static void
cmd_txprio(CMD_ARGS)
{
	struct stream *s;
	char *p;
	uint32_t stid = 0;
	struct frame f;
	uint32_t weight = 0;
	int exclusive = 0;
	char buf[5];
	uint32_t *ubuf = (uint32_t *)buf;

	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	INIT_FRAME(f, PRIORITY, 5, s->id, 0);
	f.data = (void *)buf;

	while (*++av) {
		if (!strcmp(*av, "-stream")) {
			av++;
			STRTOU32(stid, *av, p, vl, "-stream");
		} else if (!strcmp(*av, "-ex")) {
			exclusive = 1 << 31;
		} else if (!strcmp(*av, "-weight")) {
			av++;
			STRTOU32(weight, *av, p, vl, "-weight");
			if (weight >= 256)
				vtc_log(vl, 0,
					"Weight must be a 8-bits integer "
						"(found %s)", *av);
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown txprio spec: %s\n", *av);
	s->weight = weight & 0xff;
	s->dependency = stid;

	if(exclusive)
		exclusive_stream_dependency(s);

	*ubuf = htonl(stid | exclusive);
	buf[4] = s->weight;
	write_frame(s->hp, &f);
}

#define PUT_KV(vl, name, val, code) \
	do {\
		av++;\
		STRTOU32(val, *av, p, vl, #name); \
		*(uint16_t *)cursor = htons(code);\
		cursor += sizeof(uint16_t);\
		*(uint32_t *)cursor = htonl(val);\
		cursor += sizeof(uint32_t);\
		f.size += 6; \
	} while(0)

/* SECTION: h2.both.streams.txsettings txsettings
 * 
 * SETTINGS frames (rfc7540#6.5) are used to announce the conditions of the
 * transactions to the peer.
 *
 * SETTINGS frames must be acknowledge, arguments are as follow (most of them
 * are from  rfc7540#6.5.2):
 *
 * * -hdrtbl INT: headers table size
 * * -push BOOL: whether push frames are accepted or not
 * * -maxstreams INT: maximum concurrent streams allowed
 * * -winsize INT: sender's initial window size
 * * -framesize INT: largest frame size authorized
 * * -hdrsize INT: maximum size of the header list authorized
 * * -ack: set the ack bit
 */
static void
cmd_txsettings(CMD_ARGS)
{
	struct stream *s;
	struct http2 *hp;
	char *p;
	uint32_t val = 0;
	struct frame f;
	//TODO dynamic alloc
	char buf[512];
	char *cursor = buf;

	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	CAST_OBJ_NOTNULL(hp, s->hp, HTTP2_MAGIC);

	memset(buf, 0, 512);
	INIT_FRAME(f, SETTINGS, 0, s->id, 0);
	f.data = buf;

	while (*++av) {
		if (!strcmp(*av, "-push")) {
			++av;
			*(uint16_t *)cursor = htons(0x2);
			cursor += sizeof(uint16_t);
			if (!strcmp(*av, "false"))
				*(uint32_t *)cursor = htonl(0);
			else if (!strcmp(*av, "true"))
				*(uint32_t *)cursor = htonl(1);
			else
				vtc_log(vl, 0, "Push parameter is either "
						"\"true\" or \"false\", not %s",
						*av);
			cursor += sizeof(uint32_t);
			f.size += 6;
		}
		else if (!strcmp(*av, "-hdrtbl")) {
			PUT_KV(vl, hdrtbl, val, 0x1);
			HPK_ResizeTbl(s->hp->inctx, val);
		}
		else if (!strcmp(*av, "-maxstreams")) {
			PUT_KV(vl, maxstreams, val, 0x3);
		}
		else if (!strcmp(*av, "-winsize"))	{
			PUT_KV(vl, winsize, val, 0x4);
		}
		else if (!strcmp(*av, "-framesize"))	{
			PUT_KV(vl, framesize, val, 0x5);
		}
		else if (!strcmp(*av, "-hdrsize")){
			PUT_KV(vl, hdrsize, val, 0x6);
		}
		else if (!strcmp(*av, "-ack")) {
			f.flags |= 1;
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown txsettings spec: %s\n", *av);

	write_frame(hp, &f);
}

/*
static void
cmd_txpush(CMD_ARGS)

static void
cmd_rxpush(CMD_ARGS)
*/
static void
cmd_txping(CMD_ARGS)
{
	struct stream *s;
	struct frame f;
	char buf[8];

	(void)cmd;
	memset(buf, 0, 8);
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	INIT_FRAME(f, PING, 8, s->id, 0);

	while (*++av) {
		if (!strcmp(*av, "-data")) {
			av++;
			if (f.data)
				vtc_log(vl, 0, "this frame already has data");
			if (strlen(*av) != 8)
				vtc_log(vl, 0, "data must be a 8-char string, found  (%s)", *av);
			f.data = *av;
		} else if (!strcmp(*av, "-ack")) {
			f.flags |= 1;
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown txping spec: %s\n", *av);
	if (!f.data)
		f.data = buf;
	write_frame(s->hp, &f);
}

static void
cmd_txgoaway(CMD_ARGS)
{
	struct stream *s;
	char *p;
	uint32_t err = 0;
	uint32_t ls = 0;
	struct frame f;
	char buf[8];

	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	memset(buf, 0, 8);

	INIT_FRAME(f, GOAWAY, 8, s->id, 0);

	while (*++av) {
		if (!strcmp(*av, "-err")) {
			++av;
			for (err=0; h2_errs[err]; err++) {
				if (!strcmp(h2_errs[err], *av))
					break;
			}

			if (h2_errs[err])
				continue;

			STRTOU32(err, *av, p, vl, "-err");
		} else if (!strcmp(*av, "-laststream")) {
			++av;
			STRTOU32(ls, *av, p, vl, "-laststream");
			if (ls & (1 << 31)) {
				vtc_log(vl, 0, "-laststream must be a 31-bits integer "
						"(found %s)", *av);
			}
		} else if (!strcmp(*av, "-debug")) {
			++av;
			if (f.data)
				vtc_log(vl, 0, "this frame already has debug data");
			f.size = 8 + strlen(*av);
			f.data = malloc(f.size);
			memcpy(f.data + 8, *av, f.size - 8);
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown txgoaway spec: %s\n", *av);

	if (!f.data)
		f.data = malloc(2);
	((uint32_t*)f.data)[0] = htonl(ls);
	((uint32_t*)f.data)[1] = htonl(err);
	write_frame(s->hp, &f);
	free(f.data);
}

static void
cmd_txwinup(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *p;
	struct frame f;
	char buf[8];
	uint32_t size = 0; 

	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	CAST_OBJ_NOTNULL(hp, s->hp, HTTP2_MAGIC);
	memset(buf, 0, 8);

	AN(av[1]);
	AN(av[2]);

	INIT_FRAME(f, WINUP, 4, s->id, 0);
	f.data = buf;

	while (*++av) {
		if (!strcmp(*av, "-size")) {
			AN(++av);
			STRTOU32(size, *av, p, vl, "-size");
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown txwinup spec: %s\n", *av);

	AZ(pthread_mutex_lock(&hp->mtx));
	if (s->id == 0)
		hp->ws += size;
	s->ws += size;
	AZ(pthread_mutex_unlock(&hp->mtx));

	size = htonl(size);
	f.data = (void *)&size;
	write_frame(hp, &f);
}

static struct frame *
rxstuff(struct stream *s) {
	struct frame *f;

	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);

	AZ(pthread_mutex_lock(&s->hp->mtx));
	s->hp->wf++;
	if (VTAILQ_EMPTY(&s->fq)) {
		AZ(pthread_cond_signal(&s->hp->cond));
		AZ(pthread_cond_wait(&s->cond, &s->hp->mtx));
	}
	if (VTAILQ_EMPTY(&s->fq)) {
		AZ(pthread_mutex_unlock(&s->hp->mtx));
		return (NULL);
	}
	clean_frame(&s->frame);
	f = VTAILQ_LAST(&s->fq, fq_head);
	VTAILQ_REMOVE(&s->fq, f, list);
	AZ(pthread_mutex_unlock(&s->hp->mtx));

	CHECK_OBJ_NOTNULL(f, FRAME_MAGIC);
	return (f);
}

#define CHKFRAME(rt, wt, rcv, func) \
	if (rt != wt) { \
		vtc_log(vl, 0, "Frame #%d for %s was of type %d" \
				"instead of %d", \
				rcv, func, rt, wt); \
	}

static void
cmd_rxhdrs(CMD_ARGS)
{
	struct stream *s;
	struct frame *f = NULL;
	char *p;
	int loop = 0;
	int times = 1;
	int rcv = 0;
	// XXX make it an enum
	int expect = TYPE_HEADERS;

	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	while (*++av) {
		if (!strcmp(*av, "-some")) {
			STRTOU32(times, *av, p, vl, "-some");
			AN(times);
		} else if (!strcmp(*av, "-all")) {
			loop = 1;
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown rxhdrs spec: %s\n", *av);

	while (rcv++ < times || (loop && !(f->flags | END_HEADERS))) {
		f = rxstuff(s);
		if (!f)
			return;
		CHKFRAME(f->type, expect, rcv, "rxhdrs");
		expect = TYPE_CONT;
	}
	s->frame = f;
}

static void
cmd_rxcont(CMD_ARGS)
{
	struct stream *s;
	struct frame *f = NULL;
	char *p;
	int loop = 0;
	int times = 1;
	int rcv = 0;

	(void)cmd;
	(void)av;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	while (*++av) {
		if (!strcmp(*av, "-some")) {
			STRTOU32(times, *av, p, vl, "-some");
		} else if (!strcmp(*av, "-all")) {
			loop = 1;
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown rxcont spec: %s\n", *av);

	while (rcv++ < times || (loop && !(f->flags | END_HEADERS))) {
		f = rxstuff(s);
		if (!f)
			return;
		CHKFRAME(f->type, TYPE_CONT, rcv, "rxcont");
	}
	s->frame = f;
}


static void
cmd_rxdata(CMD_ARGS)
{
	struct stream *s;
	struct frame *f = NULL;
	char *p;
	int loop = 0;
	int times = 1;
	int rcv = 0;

	(void)cmd;
	(void)av;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	while (*++av) {
		if (!strcmp(*av, "-some")) {
			STRTOU32(times, *av, p, vl, "-some");
		} else if (!strcmp(*av, "-all")) {
			loop = 1;
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown rxdata spec: %s\n", *av);

	while (rcv++ < times || (loop && !(f->flags | END_STREAM))) {
		f = rxstuff(s);
		if (!f)
			return;
		CHKFRAME(f->type, TYPE_DATA, rcv, "rxhdata");
	}
	s->frame = f;
}

static void
cmd_rxreqsp(CMD_ARGS)
{
	struct stream *s;
	struct frame *f;
	int end_stream;
	int rcv = 0;

	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	clean_headers(s);
	f = rxstuff(s);
	if (!f)
		return;

	rcv++;
	CHKFRAME(f->type, TYPE_HEADERS, rcv, *av);

	end_stream = f->flags & END_STREAM;

	while (!(f->flags | END_HEADERS)) {
		f = rxstuff(s);
		if (!f)
			return;
		rcv++;
		CHKFRAME(f->type, TYPE_CONT, rcv, *av);
	}

	while (!end_stream && (f = rxstuff(s))) {
		rcv++;
		CHKFRAME(f->type, TYPE_DATA, rcv, *av);
		end_stream = f->flags & END_STREAM;
	}
	s->frame = f;
}

#define RXFUNC(lctype, upctype) \
	static void \
	cmd_rx ## lctype(CMD_ARGS) { \
		struct stream *s; \
		(void)cmd; \
		(void)av; \
		CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC); \
		if ((s->frame = rxstuff(s))) \
				return; \
		if (s->frame->type != TYPE_ ## upctype) \
			vtc_log(vl, 0, "Received frame of type %d " \
					"is invalid for %s", \
					s->frame->type, "rx ## lctype"); \
	}

RXFUNC(prio,	PRIORITY)
RXFUNC(rst,	RST)
RXFUNC(settings,SETTINGS)
RXFUNC(ping,	PING)
RXFUNC(goaway,	GOAWAY)
RXFUNC(winup,	WINUP)

static void
cmd_rxframe(CMD_ARGS) {
	struct stream *s;
	(void)cmd;
	(void)vl;
	(void)av;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	rxstuff(s);
}



static void
cmd_http_expect(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	const char *lhs, *clhs;
	char *cmp;
	const char *rhs, *crhs;
	vre_t *vre;
	const char *error;
	int erroroffset;
	int i, retval = -1;
	char buf[20];

	(void)cmd;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);

	AZ(strcmp(av[0], "expect"));
	av++;

	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);
	AZ(pthread_mutex_lock(&s->hp->mtx));
	lhs = cmd_var_resolve(s, av[0], buf);
	cmp = av[1];
	rhs = cmd_var_resolve(s, av[2], buf);

	clhs = lhs ? lhs : "<undef>";
	crhs = rhs ? rhs : "<undef>";

	if (!strcmp(cmp, "~") || !strcmp(cmp, "!~")) {
		vre = VRE_compile(crhs, 0, &error, &erroroffset);
		if (vre == NULL)
			vtc_log(vl, 0, "REGEXP error: %s (@%d) (%s)",
			    error, erroroffset, crhs);
		i = VRE_exec(vre, clhs, strlen(clhs), 0, 0, NULL, 0, 0);
		retval = (i >= 0 && *cmp == '~') || (i < 0 && *cmp == '!');
		VRE_free(&vre);
	} else if (!strcmp(cmp, "==")) {
		retval = strcmp(clhs, crhs) == 0;
	} else if (!strcmp(cmp, "!=")) {
		retval = strcmp(clhs, crhs) != 0;
	} else if (lhs == NULL || rhs == NULL) {
		// fail inequality comparisons if either side is undef'ed
		retval = 0;
	} else if (!strcmp(cmp, "<")) {
		retval = isless(VNUM(lhs), VNUM(rhs));
	} else if (!strcmp(cmp, ">")) {
		retval = isgreater(VNUM(lhs), VNUM(rhs));
	} else if (!strcmp(cmp, "<=")) {
		retval = islessequal(VNUM(lhs), VNUM(rhs));
	} else if (!strcmp(cmp, ">=")) {
		retval = isgreaterequal(VNUM(lhs), VNUM(rhs));
	}

	if (retval == -1)
		vtc_log(vl, 0,
		    "EXPECT %s (%s) %s %s (%s) test not implemented",
		    av[0], clhs, av[1], av[2], crhs);
	else
		vtc_log(vl, retval ? 4 : 0, "(s%ld) EXPECT %s (%s) %s \"%s\" %s",
		    s->id, av[0], clhs, cmp, crhs, retval ? "match" : "failed");
	AZ(pthread_mutex_unlock(&s->hp->mtx));
}

static void
cmd_fatal(CMD_ARGS)
{
	struct http2 *hp;
	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);

	AZ(av[1]);
	if (!strcmp(av[0], "fatal"))
		hp->fatal = 0;
	else if (!strcmp(av[0], "non-fatal"))
		hp->fatal = -1;
	else
		vtc_log(vl, 0, "XXX: fatal %s", cmd->name);
}

static const struct cmds stream_cmds[] = {
	{ "expect",		cmd_http_expect },
	{ "txframe",		cmd_txframe },
	{ "rxframe",		cmd_rxframe },
	{ "txdata",		cmd_txdata },
	{ "rxdata",		cmd_rxdata },
	{ "rxhdrs",		cmd_rxhdrs },
	{ "txreq",		cmd_tx11obj },
	{ "rxreq",		cmd_rxreqsp },
	{ "txresp",		cmd_tx11obj },
	{ "rxresp",		cmd_rxreqsp },
	{ "txprio",		cmd_txprio },
	{ "rxprio",		cmd_rxprio },
	{ "txrst",		cmd_txrst },
	{ "rxrst",		cmd_rxrst },
	{ "txsettings",		cmd_txsettings },
	{ "rxsettings",		cmd_rxsettings },
	//push
	{ "txping",		cmd_txping },
	{ "rxping",		cmd_rxping },
	{ "txgoaway",		cmd_txgoaway },
	{ "rxgoaway",		cmd_rxgoaway },
	{ "txwinup",		cmd_txwinup },
	{ "rxwinup",		cmd_rxwinup },
	{ "txcont",		cmd_tx11obj },
	{ "rxcont",		cmd_rxcont },
	{ "delay",		cmd_delay },
	{ "sema",		cmd_sema },
	//timeout
	//expect_close
	//close
	//accept
	{ NULL,			NULL }
};

static void *
stream_thread(void *priv)
{
	struct stream *s;

	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	parse_string(s->spec, stream_cmds, s, s->hp->vl);

	clean_headers(s);
	vtc_log(s->hp->vl, 2, "Ending stream %lu", s->id);
	return (NULL);
}
/**********************************************************************
 * Allocate and initialize a stream
 */

static struct stream *
stream_new(const char *name, struct http2 *h)
{
	char *p;
	struct stream *s;

	AN(name);
	ALLOC_OBJ(s, STREAM_MAGIC);
	AN(s);
	pthread_cond_init(&s->cond, NULL);
	REPLACE(s->name, name);
	VTAILQ_INIT(&s->fq);
	s->ws = 0xffff;

	s->weight = 16;
	s->dependency = 0;

	STRTOU32(s->id, name, p, h->vl, "-some");
	if (s->id & (1 << 31))
		vtc_log(h->vl, 0, "Stream id must be a 31-bits integer "
				"(found %s)", name);

	CHECK_OBJ_NOTNULL(h, HTTP2_MAGIC);
	s->hp = h;

	//bprintf(s->connect, "%s", "${v1_sock}");
	AZ(pthread_mutex_lock(&h->mtx));
	VTAILQ_INSERT_HEAD(&h->streams, s, list);
	AZ(pthread_mutex_unlock(&h->mtx));
	return (s);
}

/**********************************************************************
 * Clean up stream
 */

static void
stream_delete(struct stream *s)
{
	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	free(s->spec);
	free(s->name);
	/* XXX: MEMLEAK (?)*/
	FREE_OBJ(s);
}

/**********************************************************************
 * Start the stream thread
 */

static void
stream_start(struct stream *s)
{
	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	vtc_log(s->hp->vl, 2, "Starting stream %p", s);
	AZ(pthread_create(&s->tp, NULL, stream_thread, s));
	s->running = 1;
}

/**********************************************************************
 * Wait for stream thread to stop
 */
//TODO clean ->fq too
static void
stream_wait(struct stream *s)
{
	void *res;
	struct frame *f, *f2;

	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	vtc_log(s->hp->vl, 2, "Waiting for stream %lu", s->id);
	AZ(pthread_join(s->tp, &res));
	if (res != NULL)
		vtc_log(s->hp->vl, 0, "Stream %lu returned \"%s\"", s->id, (char *)res);

	VTAILQ_FOREACH_SAFE(f, &s->fq, list, f2)
		clean_frame(&f);
	clean_frame(&s->frame);
	s->tp = 0;
	s->running = 0;
}

/**********************************************************************
 * Run the stream thread
 */

static void
stream_run(struct stream *s)
{
	stream_start(s);
	stream_wait(s);
}



/**********************************************************************
 * Client command dispatch
 */

/* SECTION: h2.both.streams Streams
 *
 * Streams map roughly to a request in H/2, a request is sent on stream N,
 * the response too, then the stream is discarded. The main exception is the
 * first stream, 0, that serves as coordinator.
 *
 * Stream syntax follow the client/server one:
 *
 * * stream ID [SPEC] [ACTION]
 *
 * ID is the H/2 stream number, while SPEC describes what will be done in that
 * stream.
 *
 * ACTION can be -start, -wait or -run, with the same meanings as for
 * client/server
 */

static void
cmd_stream(CMD_ARGS)
{
	struct stream *s, *s2;

	struct http2 *h = (struct http2 *)priv;
	(void)cmd;
	(void)vl;
	CAST_OBJ_NOTNULL(h, priv, HTTP2_MAGIC);

	if (av == NULL) {
		VTAILQ_FOREACH_SAFE(s, &h->streams, list, s2) {
			VTAILQ_REMOVE(&h->streams, s, list);
			if (s->tp != 0)
				stream_wait(s);
			stream_delete(s);
		}
		return;
	}

	AZ(strcmp(av[0], "stream"));
	av++;

	VTAILQ_FOREACH(s, &h->streams, list)
		if (!strcmp(s->name, av[0]))
			break;
	if (s == NULL)
		s = stream_new(av[0], h);
	av++;

	for (; *av != NULL; av++) {
		if (vtc_error)
			break;

		if (!strcmp(*av, "-wait")) {
			stream_wait(s);
			continue;
		}

		/* Don't muck about with a running client */
		if (s->running)
			stream_wait(s);

		if (!strcmp(*av, "-start")) {
			stream_start(s);
			continue;
		}
		if (!strcmp(*av, "-run")) {
			stream_run(s);
			continue;
		}
		if (**av == '-')
			vtc_log(s->hp->vl, 0, "Unknown client argument: %s", *av);
		REPLACE(s->spec, *av);
	}
}

static const struct cmds http2_cmds[] = {
	{ "stream",		cmd_stream },
	{ "delay",		cmd_delay },
	{ "fatal",		cmd_fatal },
	{ "non-fatal",		cmd_fatal },
	{ NULL,			NULL }
};

int
http2_process(struct vtclog *vl, const char *spec, int sock, int *sfd,
		unsigned nosettings)
{
	struct stream *s;
	struct http2 *hp;
	int retval;

	(void)sfd;
	ALLOC_OBJ(hp, HTTP2_MAGIC);
	AN(hp);
	pthread_mutex_init(&hp->mtx, NULL);
	pthread_cond_init(&hp->cond, NULL);
	VTAILQ_INIT(&hp->streams);
	hp->fd = sock;
	hp->timeout = vtc_maxdur * 1000 / 2;
	hp->sfd = sfd;
	hp->vl = vl;
	hp->ws = 0xffff;

	hp->running = 1;
	if (sfd) {
		cmd_http_rxpri(NULL, hp, NULL, vl);
	} else  {
		cmd_http_txpri(NULL, hp, NULL, vl);
	}
	hp->inctx = HPK_NewCtx(4096);
	hp->outctx = HPK_NewCtx(4096);
	AZ(pthread_create(&hp->tp, NULL, receive_frame, hp));

	if (!nosettings) {
			vtc_log(vl, 3, "============parsing extra stuff");
		parse_string("stream 0 {\n"
				"txsettings\n"
				"rxsettings\n"
				"txsettings -ack\n"
				"rxsettings\n"
				"expect settings.ack == true"
			     "} -run\n", http2_cmds, hp, vl);
	}

	parse_string(spec, http2_cmds, hp, vl);

	VTAILQ_FOREACH(s, &hp->streams, list) {
		while (s->running)
			stream_wait(s);
	}

	// kill the frame dispatcher 
	AZ(pthread_mutex_lock(&hp->mtx));
	hp->running = 0;
	AZ(pthread_cond_signal(&hp->cond));
	AZ(pthread_mutex_unlock(&hp->mtx));
	AZ(pthread_join(hp->tp, NULL));

	HPK_FreeCtx(hp->inctx);
	HPK_FreeCtx(hp->outctx);

	retval = hp->fd;
	free(hp);
	return (retval);
}
