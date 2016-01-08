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

#define MAX_HDR		50

#define ERR_MAX 13

static char *h2_errs[] = {
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

static char *h2_types[] = {
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

static char *h2_settings[] = {
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
	long		ws;
	int			ftype;
	union {
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
		uint32_t	rst_err;
		double settings[SETTINGS_MAX+1];
	} md;

	char			*body;
	int			bodylen;
	struct hdrng		hdrs[MAX_HDR];		
	int			nhdrs;
};

struct http2 {
	unsigned		magic;
#define HTTP2_MAGIC		0x0b71d23a
	int			fd;
	int			*sfd;
	int			timeout;
	struct vtclog		*vl;

	int			fatal;

	pthread_t		tp;
	unsigned		running;
	VTAILQ_HEAD(, stream)   streams;
	pthread_mutex_t		mtx;
	pthread_cond_t          cond;
	struct stm_ctx		*h2ctx;
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

struct frame {
	unsigned	magic;
#define	FRAME_MAGIC	0x5dd3ec4
	uint32_t        size;
	uint32_t	stid;
	uint8_t         type;
	uint8_t         flags;
	char		*data;
};

void                                                                                                                                                                                                               
readFrameHeader(struct frame *f, char *buf) {
	f->size  = buf[0] << 16;
	f->size += buf[1] << 8;
	f->size += buf[2];

	f->type = buf[3];

	f->flags = buf[4];

	f->stid  = (0xff & buf[5]) << 24;
	f->stid += (0xff & buf[6]) << 16;
	f->stid += (0xff & buf[7]) <<  8;
	f->stid += (0xff & buf[8]);
};

void                                                                                                                                                                                                               
writeFrameHeader(char *buf, struct frame *f) {                                                                                                                                                                  
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

static void
free_frame_data(struct stream *s) {
	if (!s->frame)
		return;
	if (s->frame->type == TYPE_GOAWAY)
		free(s->md.goaway.debug);
	memset(&s->md, 0, sizeof(s->md));
	free(s->frame->data);
	free(s->frame);
	s->frame = NULL;
}

static void
wait_frame(struct stream *s) {
	struct http2 *hp;
	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	AZ(s->reading);
	free_frame_data(s);

	hp = s->hp;
	AZ(pthread_mutex_lock(&hp->mtx));
	s->reading = 1;
	AZ(pthread_cond_signal(&hp->cond));
	AZ(pthread_cond_wait(&s->cond, &hp->mtx));
	AZ(pthread_mutex_unlock(&hp->mtx));
}

#define INIT_FRAME(f, ty, sz, id, fl) \
do { \
	f.type = TYPE_ ## ty; \
	f.size = sz; \
	f.stid = id; \
	f.flags = fl; \
	f.data = NULL; \
} while(0)


#define MAXFRAMESIZE 2048 * 1024

static void
write_frame(struct http2 *hp, struct frame *f, int lvl, const char *pfx) {
	ssize_t l;
	char *type;
	char hdr[9];
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

/* read a frame and pass it to the stream waiting on it.
 * If no stream is there to receive the frame, cond_wait until there is
 */
static void *
receive_frame(void *priv) {
	struct http2 *hp = (struct http2 *)priv;
	char hdr[9];
	struct frame *f;
	struct stream *s;
	unsigned need_read;
	char *type;

	AZ(pthread_mutex_lock(&hp->mtx));
	while (hp->running) {
		need_read = 0;
		VTAILQ_FOREACH(s, &hp->streams, list) {
			if (s->reading) {
				need_read = 1;
				break;
			}
		}
		if (!need_read) {
			AZ(pthread_cond_wait(&hp->cond, &hp->mtx));
			continue;
		}
		AZ(pthread_mutex_unlock(&hp->mtx));

		if (!get_bytes(hp, hdr, 9)) {
			vtc_log(hp->vl, 3, "could not get header");
			return (NULL);
		}
		ALLOC_OBJ(f, FRAME_MAGIC);
		readFrameHeader(f, hdr);

		if (f->type <= TYPE_MAX)
			type = h2_types[f->type];
		else
			type = "?";
		vtc_log(hp->vl, 3, "rx: stream: %d, type: %s (%d), "
				"flags: 0x%02x, size: %d",
				f->stid, type, f->type, f->flags, f->size);

		if (f->size) {
			f->data = malloc(f->size + 1);
			AN(f->data);
			f->data[f->size] = '\0';
			get_bytes(hp, f->data, f->size);
		}

		AZ(pthread_mutex_lock(&hp->mtx));
		while (f) {
			VTAILQ_FOREACH(s, &hp->streams, list) {
				if (s->id != f->stid || !s->reading) {
					continue;
				}
				AZ(s->frame);
				s->ftype = f->type;
				s->reading = 0;
				s->frame = f;
				f = NULL;
				AZ(pthread_cond_signal(&s->cond));
				break;
			}
			if (f)
				AZ(pthread_cond_wait(&hp->cond, &hp->mtx));
		}
	}
	AZ(pthread_mutex_unlock(&hp->mtx));

	return (NULL);
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
	else {
		vtc_log(vl, 0, "XXX: fatal %s", cmd->name);
	}
}
#define TRUST_ME(ptr)   ((void*)(uintptr_t)(ptr))

char pri_string[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static void
cmd_http_txpri(CMD_ARGS)
{
	struct http2 *hp;
	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);
	http_write(hp, 4, pri_string, sizeof(pri_string) - 1, "txpri");
}

static void
cmd_http_rxpri(CMD_ARGS)
{
	struct http2 *hp;
	char buf[sizeof(pri_string)];
	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);

	(void)get_bytes(hp, buf, sizeof(pri_string) - 1);
	if (strncmp(pri_string, buf, strlen(pri_string) - 1))
		vtc_log(hp->vl, hp->fatal, "HTTP rxpri failed");
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
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);
	AN(av[1]);
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
			vtc_log(hp->vl, 0, "Illegal Hex char \"%c%c\"",
					tmp[0], tmp[1]);
		buf[i] = (uint8_t)strtoul(tmp, NULL, 16);
	}
	AZ(pthread_mutex_lock(&hp->mtx));
	http_write(hp, 4, buf, size, "txframe");

	AZ(pthread_mutex_unlock(&hp->mtx));
	vtc_hexdump(hp->vl, 4, "txframe", (void *)buf, size);
}

static void
cmd_rxframe(CMD_ARGS)
{
	struct stream *s;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
}

static void
clean_headers(struct stream *s) {
	struct hdrng *h = s->hdrs;
	while (s->nhdrs--) {
		if (h->key.size)
			free(h->key.ptr);
		if (h->value.size)
			free(h->value.ptr);
		h++;
	}
	s->nhdrs = 0;
	memset(s->hdrs, 0, sizeof(s->hdrs));
}

static int
grab_hdr(struct stream *s, struct vtclog *vl, int type) {
	int r;
	struct HdrIter *iter;
	wait_frame(s);
	if (!s->frame)
		return (0);

	assert(type == TYPE_HEADERS || type == TYPE_CONT);

	if (s->frame->type != type)
		vtc_log(vl, 0, "Received something that is not a %s frame (type=0x%x)", type == 1 ? "header" : "continuation", s->frame->type);

	iter = newHdrIter(s->hp->h2ctx, s->frame->data, s->frame->size);


	while (s->nhdrs < MAX_HDR) {
		r = decNextHdr(iter, s->hdrs + s->nhdrs);
		if (r == HdrErr )
			break;
		vtc_log(vl, 3, "s%lu - header: %s : %s (%d)",
				s->id, s->hdrs[s->nhdrs].key.ptr, s->hdrs[s->nhdrs].value.ptr, s->nhdrs);
		s->nhdrs++;
		if (r == HdrDone)
			break;
	}
	//XXX document too many headers errors
	if (r != HdrDone)
		vtc_log(vl, s->hp->fatal, "Header decoding failed");
	destroyHdrIter(iter);
	return (1);
}

/* XXX padding */
static int
grab_data(struct stream *s, struct vtclog *vl) {
	struct frame *f;
	wait_frame(s);
	if (!s->frame)
		return (0);
	f = s->frame;

	if (f->type != TYPE_DATA)
		vtc_log(vl, 0, "Received something that is not a data frame (type=0x%x)", f->type);

	if (!f->size) {
		vtc_log(vl, 3, "s%lu - no data", s->id);
		return (1);
	}

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

	vtc_log(vl, 3, "s%lu - data: %s - full body: %s", s->id, f->data, s->body);
	return (1);
}

#define ENC(hdr, k, v) \
{ \
	hdr.key.ptr = k; \
	hdr.key.size = strlen(k); \
	hdr.value.ptr = v; \
	hdr.value.size = strlen(v); \
	encNextHdr(iter, &hdr); \
}

/* handles txcont, txreq and txresp */
static void
cmd_tx11obj(CMD_ARGS)
{
	struct stream *s;
	int status_done = 1;
	int req_done = 1;
	int url_done = 1;
	char buf[1024*2048];
	struct HdrIter *iter;
	struct frame f;
	char *body = NULL;
	/*XXX: do we need a better api? yes we do */
	struct hdrng hdr;
	char *cmd_str = *av;

	hdr.t = HdrNot;
	hdr.i = 0;
	hdr.key.huff = 0;
	hdr.value.huff = 0;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	INIT_FRAME(f, CONT, 0, s->id, END_HEADERS);

	if (strcmp(cmd_str, "txcont")) {
		f.type = TYPE_HEADERS;
		f.flags |= END_STREAM;
		if (!strcmp(cmd_str, "txreq")) {
			req_done = 0;
			url_done = 0;
		} else {
			status_done = 0;
		}
	}

	iter = newHdrIter(s->hp->h2ctx, buf, 1024*2048);
	while (*++av) {
		if (!strcmp(*av, "-status") &&
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
		} else if (!strcmp(*av, "-hdr")) {
			ENC(hdr, av[1], av[2]);
			av += 2;
		} else if (!strcmp(*av, "-body") &&
				strcmp(cmd_str, "txcont")) {
			body = av[1];
			f.flags &= ~END_STREAM;
			av++;
		} else if (!strcmp(*av, "-nostrend") &&
				strcmp(cmd_str, "txcont")) {
			f.flags &= ~END_STREAM;
		} else if (!strcmp(*av, "-nohdrend")) {
			f.flags &= ~END_HEADERS;
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(s->hp->vl, 0, "Unknown txsettings spec: %s\n", *av);

	if (!status_done) {
		ENC(hdr, ":status", "200");
	} if (!url_done)
		ENC(hdr, ":path", "/");
	if (!req_done)
		ENC(hdr, ":method", "GET");

	f.size = getHdrIterLen(iter);
	f.data = buf;	
	destroyHdrIter(iter);
	write_frame(s->hp, &f, 4, "txreq (H)");

	if (!body)
		return;

	INIT_FRAME(f, DATA, strlen(body), s->id, END_STREAM);
	f.data = body;

	write_frame(s->hp, &f, 4, "txreq (B)");
}

static void
cmd_txdata(CMD_ARGS)
{
	struct stream *s;
	struct frame f;
	char *body = NULL;

	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	INIT_FRAME(f, DATA, 0, s->id, END_STREAM);

	while (*++av) {
		if (!strcmp(*av, "-data")) {
			body = av[1];
			av++;
		} else if (!strcmp(*av, "-nostrend"))
			f.flags &= ~END_STREAM;
		else
			break;
	}
	if (*av != NULL)
		vtc_log(s->hp->vl, 0, "Unknown txsettings spec: %s\n", *av);

	if (!body)
		body = "";

	f.size = strlen(body);
	f.data = body;
	write_frame(s->hp, &f, 4, "txreq (B)");
}

static void
cmd_rxdata(CMD_ARGS)
{
	struct stream *s;
	char *p;
	int loop = 0;
	uint32_t times = 1;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	while (*++av) {
		if (!strcmp(*av, "-some")) {
			times = strtoul(*++av, &p, 0);
			if (*p != '\0') {
				vtc_log(vl, 0, "-some requires an integer arg (%s)", *av);
			}
		} else if (!strcmp(*av, "-all")) {
			loop = 1;
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown rx*body spec: %s\n", *av);

	while (times-- || (loop && !(s->frame->flags | END_STREAM)))
		if (!grab_data(s, vl))
			return;
}


static void
cmd_rxreqsp(CMD_ARGS)
{
	struct stream *s;
	int end_stream;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	//clean_headers(s);
	if (!grab_hdr(s, vl, 1))
		return;
	end_stream = s->frame->flags & END_STREAM;

	while (!(s->frame->flags | END_HEADERS))
		if (!grab_hdr(s, vl, TYPE_CONT))
			return;

	while (!end_stream && grab_data(s, vl))
		end_stream = s->frame->flags & END_STREAM;
}

static void
cmd_rxhdrs(CMD_ARGS)
{
	struct stream *s;
	char *p;
	int loop = 0;
	uint32_t times = 1;
	// XXX make it an enum
	int expect = TYPE_HEADERS;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	while (*++av) {
		if (!strcmp(*av, "-some")) {
			times = strtoul(*++av, &p, 0);
			if (*p != '\0') {
				vtc_log(vl, 0, "-some requires an integer arg (%s)", *av);
			}
		} else if (!strcmp(*av, "-all")) {
			loop = 1;
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown rx*hdrs spec: %s\n", *av);

	while (times-- || (loop && !(s->frame->flags | END_HEADERS))) {
		if (!grab_hdr(s, vl, expect))
			return;
		expect = TYPE_CONT;
	}
}


static void
cmd_txrst(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *p;
	uint32_t err;
	struct frame f;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);

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
				
			err = strtoul(*av, &p, 0);
			if (*p != '\0' || err > UINT32_MAX) {
				vtc_log(hp->vl, 0, "Stream id must be a 32-bits integer "
						"(found %s)", *av);
			}
			//XXX: if not fatal, reset size
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(hp->vl, 0, "Unknown txrst spec: %s\n", *av);

	err = htonl(err);
	f.data = (void *)&err;
	write_frame(hp, &f, 4, "txrst");
}


static void
cmd_rxrst(CMD_ARGS)
{
	struct frame *f;
	struct stream *s;
	uint32_t err;
	char *buf;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s->frame)
		return;
	f = s->frame;

	if (f->type != TYPE_RST)
		vtc_log(vl, 0, "Received something that is not a reset (type=0x%x)", f->type);
	if (f->size != 4)
		vtc_log(vl, 0, "Size should be 4, but isn't (%d)", f->size);

	err = ntohl(*(uint32_t*)f->data);
	s->md.rst_err = err;

	if (err <= ERR_MAX)
		buf = h2_errs[err];
	else
		buf = "unknown";
	vtc_log(vl, 3, "s%lu - rst->err: %s (%d)", s->id, buf, err);
}

#define PUT_KV(name, code) \
	av++;\
	val = strtoul(*av, &p, 0);\
	if (*p != '\0' || val > UINT32_MAX) {\
		vtc_log(hp->vl, 0, "name must be a 32-bits integer "\
			"(found %s)", *av);\
	}\
	*(uint16_t *)cursor = htons(code);\
	cursor += sizeof(uint16_t);\
	*(uint32_t *)cursor = htonl(val);\
	cursor += sizeof(uint32_t);\
	f.size += 6;\

static void
cmd_txsettings(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *p;
	uint32_t val = 0;
	struct frame f;
	//TODO dynamic alloc
	char buf[512];
	char *cursor = buf;
	memset(buf, 0, 512);
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);

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
				vtc_log(hp->vl, 0, "Push parameter is either "
						"\"true\" or \"false\", not %s",
						*av);
			cursor += sizeof(uint32_t);
			f.size += 6;
		} else if (!strcmp(*av, "-hdrtbl"))	{ PUT_KV(hdrtbl, 0x1)
		} else if (!strcmp(*av, "-maxstreams")) { PUT_KV(maxstreams, 0x3)
		} else if (!strcmp(*av, "-winsize"))	{ PUT_KV(winsize, 0x4)
		} else if (!strcmp(*av, "-framesize"))	{ PUT_KV(framesize, 0x5)
		} else if (!strcmp(*av, "-hdrsize"))	{ PUT_KV(hdrsize, 0x6)
		} else if (!strcmp(*av, "-ack")) {
			f.flags |= 1;
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(hp->vl, 0, "Unknown txsettings spec: %s\n", *av);

	write_frame(hp, &f, 4, "txsettings");
}

static void
cmd_rxsettings(CMD_ARGS)
{
	struct stream *s;
	char *buf;
	int i = 0;
	uint16_t t;
	uint32_t v;
	struct frame *f;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s->frame)
		return;
	f = s->frame;

	if (f->type != TYPE_SETTINGS)
		vtc_log(vl, 0, "Received something that is not a settings (type=0x%x)", f->type);
	if (f->size % 6)
		vtc_log(vl, 0, "Size should be a multiple of 6, but isn't (%d)", f->size);

	for (i = 0; i < SETTINGS_MAX; i++)
		s->md.settings[i] = NAN;

	for (i = 0; i < f->size;) {
		t = ntohs(*(uint16_t *)(f->data + i));
		i += 2;
		v = ntohl(*(uint32_t *)(f->data + i));
		if (t <= SETTINGS_MAX) {
			buf = h2_settings[t];
			s->md.settings[t] = v;
			vtc_log(vl, 3, "putting %d into %d", v, t);
		} else
			buf = "unknown";
		i += 4;

		vtc_log(vl, 3, "s%lu - settings->%s (%d): %d", s->id, buf, t, v);
	}
}

/*
static void
cmd_txpush(CMD_ARGS)

static void
cmd_txpush(CMD_ARGS)
*/
static void
cmd_txping(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	struct frame f;
	char buf[8];
	memset(buf, 0, 8);
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);

	INIT_FRAME(f, PING, 8, s->id, 0);

	while (*++av) {
		if (!strcmp(*av, "-data")) {
			av++;
			if (f.data)
				vtc_log(hp->vl, 0, "this frame already has data");
			if (strlen(*av) != 8) {
				vtc_log(hp->vl, 0, "data must be a 8-char string, found  (%s)", *av);
			}
			f.data = *av;
		} else if (!strcmp(*av, "-ack")) {
			f.flags |= 1;
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(hp->vl, 0, "Unknown txping spec: %s\n", *av);
	if (!f.data)
		f.data = buf;
	write_frame(hp, &f, 4, "txping");
}

static void
cmd_rxping(CMD_ARGS)
{
	struct stream *s;
	struct frame *f;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s->frame)
		return;
	f = s->frame;

	if (f->type != TYPE_PING)
		vtc_log(vl, 0, "Received something that is not a ping (type=0x%x)", f->type);
	if (f->size != 8)
		vtc_log(vl, 0, "Size should be 8, but isn't (%d)", f->size);

	s->md.ping.ack = f->flags & 1;
	memcpy(s->md.ping.data, f->data, 8);
	s->md.ping.data[8] = '\0';

	vtc_log(vl, 3, "s%lu - ping->data: %s", s->id, s->md.ping.data);
}


static void
cmd_txgoaway(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *p;
	uint32_t err = 0;
	uint32_t ls = 0;
	struct frame f;
	char buf[8];
	f.data = buf;
	memset(buf, 0, 8);
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);

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
				
			err = strtoul(*av, &p, 0);
			if (*p != '\0' || err > UINT32_MAX) {
				vtc_log(hp->vl, 0, "Error must be a 32-bits integer "
						"(found %s)", *av);
			}
			//XXX: if not fatal, reset size
		} else if (!strcmp(*av, "-laststream")) {
			++av;
			ls = strtoul(*av, &p, 0);
			if (*p != '\0' || ls >= (1 << 31)) {
				vtc_log(hp->vl, 0, "Last stream id must be a 31-bits integer "
						"(found %s)", *av);
			}
		} else if (!strcmp(*av, "-debug")) {
			++av;
			if (f.data)
				vtc_log(hp->vl, 0, "this frame already has debug data");
			f.size = 8 + strlen(*av);
			f.data = malloc(f.size);
			memcpy(f.data + 8, *av, f.size - 8);
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(hp->vl, 0, "Unknown txgoaway spec: %s\n", *av);

	if (!f.data)
		f.data = malloc(2);
	((uint32_t*)f.data)[0] = htonl(ls);
	((uint32_t*)f.data)[1] = htonl(err);
	write_frame(hp, &f, 4, "txgoaway");
	free(f.data);
}

static void
cmd_rxgoaway(CMD_ARGS)
{
	struct frame *f;
	struct stream *s;
	char *err_buf;
	uint32_t err, stid;

	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s->frame)
		return;
	f = s->frame;

	if (f->type != TYPE_GOAWAY)
		vtc_log(vl, 0, "Received something that is not a goaway (type=0x%x)", f->type);
	if (f->size < 8)
		vtc_log(vl, 0, "Size should be at least 8, but isn't (%d)", f->size);
	if (f->data[0] & (1<<7))
		vtc_log(vl, 0, "First bit of data is reserved and should be 0");

	stid = ntohl(((uint32_t*)f->data)[0]);
	err = ntohl(((uint32_t*)f->data)[1]);
	s->md.goaway.err = err;
	s->md.goaway.stream = stid;

	if (err <= ERR_MAX)
		err_buf = h2_errs[err];
	else
		err_buf = "unknown";

	if (f->size > 8) {
		s->md.goaway.debug = malloc(f->size - 8 + 1);
		AN(s->md.goaway.debug);
		s->md.goaway.debug[f->size - 8] = '\0';

		memcpy(s->md.goaway.debug, f->data + 8, f->size - 8);
	}

	vtc_log(vl, 3, "s%lu - goaway->laststream: %d", s->id, stid);
	vtc_log(vl, 3, "s%lu - goaway->err: %s (%d)", s->id, err_buf, err);
	if (s->md.goaway.debug)
		vtc_log(vl, 3, "s%lu - goaway->debug: %s", s->id, s->md.goaway.debug);
}
static void
cmd_txwinup(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *p;
	struct frame f;
	char buf[8];
	uint32_t size = 0x7fffffff; 
	f.data = buf;
	memset(buf, 0, 8);
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);

	INIT_FRAME(f, WINUP, 4, s->id, 0);

	while (*++av) {
		if (!strcmp(*av, "-size")) {
			size = strtoul(*++av, &p, 0);
			if (*p != '\0' || size >= (1 << 31)) {
				vtc_log(hp->vl, 0, "Stream id must be a 31-bits integer "
						"(found %s)", *av);
			}
			//XXX: if not fatal, reset size
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(hp->vl, 0, "Unknown txwinup spec: %s\n", *av);
	if (0x7fffffff - s->ws < size)
		s->ws = size;
	else
		s->ws += size;

	size = htonl(size);
	f.data = (void *)&size;
	write_frame(hp, &f, 4, "txwinup");
}

static void
cmd_rxwinup(CMD_ARGS)
{
	struct stream *s;
	struct frame *f;
	uint32_t size;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s->frame)
		return;
	f = s->frame;

	if (f->type != TYPE_WINUP)
		vtc_log(vl, 0, "Received something that is not a ping (type=0x%x)", f->type);
	if (f->size != 4)
		vtc_log(vl, 0, "Size should be 4, but isn't (%d)", f->size);
	if (f->data[0] & (1<<7))
		vtc_log(vl, 0, "First bit of data is reserved and should be 0");

	size = ntohl(*(uint32_t*)f->data);
	s->md.winup_size = size;

	vtc_log(vl, 3, "s%lu - winup->size: %d", s->id, size);
}

static void
cmd_rxcont(CMD_ARGS)
{
	struct stream *s;
	char *p;
	int loop = 0;
	uint32_t times = 1;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	while (*++av) {
		if (!strcmp(*av, "-some")) {
			times = strtoul(*++av, &p, 0);
			if (*p != '\0') {
				vtc_log(vl, 0, "-some requires an integer arg (%s)", *av);
			}
		} else if (!strcmp(*av, "-all")) {
			loop = 1;
		} else
			break;	
	}
	if (*av != NULL)
		vtc_log(vl, 0, "Unknown rxcont spec: %s\n", *av);

	while (times-- || (loop && !(s->frame->flags | END_HEADERS)))
		if (!grab_hdr(s, vl, 9))
			return;
}

#define CHECK_LAST_FRAME(TYPE) \
	if (s->ftype != TYPE_ ## TYPE) { \
		vtc_log(s->hp->vl, 0, "Last frame was not of type " #TYPE); \
	}

#define RETURN_SETTINGS(idx) \
{ \
	if isnan(s->md.settings[idx]) { \
		return (NULL); \
	} \
	snprintf(buf, 20, "%.0f", s->md.settings[idx]); \
	return (buf); \
} while (0);

#define RETURN_BUFFED(val) \
{ \
	snprintf(buf, 20, "%d", val); \
	return (buf); \
} while (0)

static char *
find_header(struct stream *s, char *k, int ks) {
	struct hdrng *h = s->hdrs;
	int n = s->nhdrs;
	while (n--) {
		if (ks == h->key.size  && !memcmp(h->key.ptr, k, ks))
			return h->value.ptr;
		h++;
	}
	return (NULL);
}

static const char *
cmd_var_resolve(struct stream *s, char *spec, char *buf)
{
	struct frame *f = s->frame;
	if (!f)
		vtc_log(s->hp->vl, 0, "No frame received yet.");
	AN(buf);
	if (!strcmp(spec, "ping.data")) {
		CHECK_LAST_FRAME(PING);
		return (s->md.ping.data);
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
		RETURN_BUFFED(s->md.winup_size);
	}
	else if (!strcmp(spec, "rst.err")) {
		CHECK_LAST_FRAME(RST);
		RETURN_BUFFED(s->md.rst_err);
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
			if (isnan(s->md.settings[2]))
				return (NULL);
			else if (s->md.settings[2] == 1)
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
			RETURN_BUFFED(s->md.goaway.err);
		}
		else if (!strcmp(spec, "laststream")) {
			RETURN_BUFFED(s->md.goaway.stream);
		}
		else if (!strcmp(spec, "debug")) {
			return (s->md.goaway.debug);
		}
	} /* GENERIC FRAME */
	else if (!strncmp(spec, "frame.", 6)) {
		spec += 6;
		     if (!strcmp(spec, "data"))   { return (f->data); }
		else if (!strcmp(spec, "type"))   { RETURN_BUFFED(f->type); }
		else if (!strcmp(spec, "size"))	  { RETURN_BUFFED(f->size); }
		else if (!strcmp(spec, "stream")) { RETURN_BUFFED(f->stid); }
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
	(void)vl;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);

	AZ(strcmp(av[0], "expect"));
	av++;

	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);
	lhs = cmd_var_resolve(s, av[0], buf);
	cmp = av[1];
	rhs = cmd_var_resolve(s, av[2], buf);

	clhs = lhs ? lhs : "<undef>";
	crhs = rhs ? rhs : "<undef>";

	if (!strcmp(cmp, "~") || !strcmp(cmp, "!~")) {
		vre = VRE_compile(crhs, 0, &error, &erroroffset);
		if (vre == NULL)
			vtc_log(hp->vl, 0, "REGEXP error: %s (@%d) (%s)",
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
		vtc_log(hp->vl, 0,
		    "EXPECT %s (%s) %s %s (%s) test not implemented",
		    av[0], clhs, av[1], av[2], crhs);
	else
		vtc_log(hp->vl, retval ? 4 : 0, "EXPECT %s (%s) %s \"%s\" %s",
		    av[0], clhs, cmp, crhs, retval ? "match" : "failed");
}


static const struct cmds stream_cmds[] = {
	{ "txframe",		cmd_txframe },
	{ "rxframe",		cmd_rxframe },
	{ "txping",		cmd_txping },
	{ "rxping",		cmd_rxping },
	{ "txwinup",		cmd_txwinup },
	{ "rxwinup",		cmd_rxwinup },
	{ "txrst",		cmd_txrst },
	{ "rxrst",		cmd_rxrst },
	{ "txgoaway",		cmd_txgoaway },
	{ "rxgoaway",		cmd_rxgoaway },
	{ "txsettings",		cmd_txsettings },
	{ "rxsettings",		cmd_rxsettings },
	{ "txreq",		cmd_tx11obj },
	{ "rxreq",		cmd_rxreqsp },
	{ "txresp",		cmd_tx11obj },
	{ "rxresp",		cmd_rxreqsp },
	{ "rxhdrs",		cmd_rxhdrs },
	{ "rxcont",		cmd_rxcont },
	{ "txdata",		cmd_txdata },
	{ "rxdata",		cmd_rxdata },
	{ "txcont",		cmd_tx11obj },
	{ "expect",		cmd_http_expect },
	{ "delay",		cmd_delay },
	{ "sema",		cmd_sema },
	{ "fatal",		cmd_fatal },
	{ "non-fatal",		cmd_fatal },
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
	s->ws = 0xffff;

	s->id = strtoul(name, &p, 0);
	if (*p != '\0' || s->id >= (1 << 31)) {
		vtc_log(h->vl, 0, "Stream id must be a 31-bits integer "
				"(found %s)", name);
	}

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

static void
stream_wait(struct stream *s)
{
	void *res;

	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	vtc_log(s->hp->vl, 2, "Waiting for stream %lu", s->id);
	AZ(pthread_join(s->tp, &res));
	if (res != NULL)
		vtc_log(s->hp->vl, 0, "Stream %lu returned \"%s\"", s->id, (char *)res);
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

static void
cmd_stream(CMD_ARGS)
{
	struct stream *s, *s2;

	struct http2 *h = (struct http2 *)priv;
	(void)cmd;
	(void)vl;

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
	{ NULL,			NULL }
};

int
http2_process(struct vtclog *vl, const char *spec, int sock, int *sfd)
{
	struct stream *s;
	struct http2 *hp;
	int retval;

	(void)sfd;
	ALLOC_OBJ(hp, HTTP2_MAGIC);
	AN(hp);
	pthread_mutex_init(&hp->mtx, NULL);
	pthread_cond_init(&hp->cond, NULL);
	hp->fd = sock;
	hp->timeout = vtc_maxdur * 1000 / 2;
	hp->sfd = sfd;
	hp->vl = vl;

	hp->running = 1;
	if (sfd) {
		cmd_http_rxpri(NULL, hp, NULL, vl);
	} else  {
		cmd_http_txpri(NULL, hp, NULL, vl);
	}
	hp->h2ctx = initStmCtx(0);
	AZ(pthread_create(&hp->tp, NULL, receive_frame, hp));

	parse_string(spec, http2_cmds, hp, vl);

	VTAILQ_FOREACH(s, &hp->streams, list) {
		while (s->running)
			stream_wait(s);
	}

	// kill the frame dispatcher 
	AZ(pthread_mutex_lock(&hp->mtx));
	hp->running = 0;
	pthread_cond_signal(&hp->cond);
	AZ(pthread_mutex_unlock(&hp->mtx));

	AZ(pthread_join(hp->tp, NULL));
	destroyStmCtx(hp->h2ctx);

	retval = hp->fd;
	free(hp);
	return (retval);
}
