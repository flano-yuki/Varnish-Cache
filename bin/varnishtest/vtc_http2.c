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

#define MAX_HDR		50
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
};

struct http2 {
	unsigned		magic;
#define HTTP2_MAGIC		0x0b71d23a
	int			fd;
	int			*sfd;
	int			timeout;
	struct vtclog		*vl;

	struct vsb		*vsb;

	int			nrxbuf;
	char			*rxbuf;
	int			prxbuf;
	char			*body;
	unsigned		bodyl;
	char			bodylen[20];
	char			chunklen[20];

	char			*req[MAX_HDR];
	char			*resp[MAX_HDR];

	int			gziplevel;
	int			gzipresidual;

	int			fatal;

	pthread_t		tp;
	unsigned		running;
	VTAILQ_HEAD(, stream)   streams;
	pthread_mutex_t		mtx;
	pthread_cond_t          cond;
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


/* XXX: we may want to vary this */
static const char * const nl = "\r\n";

/**********************************************************************
 * Finish and write the vsb to the fd
 */

static void
http_write(const struct http2 *hp, int lvl, const char *pfx)
{
	ssize_t l;

	AZ(VSB_finish(hp->vsb));
	//vtc_dump(hp->vl, lvl, pfx, VSB_data(hp->vsb), VSB_len(hp->vsb));
	l = write(hp->fd, VSB_data(hp->vsb), VSB_len(hp->vsb));
	if (l != VSB_len(hp->vsb))
		vtc_log(hp->vl, hp->fatal, "Write failed: (%zd vs %zd) %s",
		    l, VSB_len(hp->vsb), strerror(errno));
}

/**********************************************************************
 * Receive another character
 */

static int
http_rxchar(struct http2 *hp, int n, int eof)
{
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
		assert(hp->prxbuf + n < hp->nrxbuf);
		i = read(hp->fd, hp->rxbuf + hp->prxbuf, n);
		if (!(pfd[0].revents & POLLIN))
			vtc_log(hp->vl, 4,
			    "HTTP2 rx poll (fd:%d revents: %x n=%d, i=%d)",
			    hp->fd, pfd[0].revents, n, i);
		if (i == 0 && eof)
			return (i);
		if (i == 0)
			vtc_log(hp->vl, hp->fatal,
			    "HTTP2 rx EOF (fd:%d read: %s)",
			    hp->fd, strerror(errno));
		if (i < 0)
			vtc_log(hp->vl, hp->fatal,
			    "HTTP2 rx failed (fd:%d read: %s)",
			    hp->fd, strerror(errno));
		hp->prxbuf += i;
		hp->rxbuf[hp->prxbuf] = '\0';
		n -= i;
	}
	return (1);
}

static int
get_bytes(struct http2 *hp, char *buf, int n, int eof) {
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
		if (i == 0 && eof)
			return (i);
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
	unsigned long	stid;
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
free_frame(struct frame *f) {
	if (!f)
		return;
	free(f->data);
	free(f);
}

static void
wait_frame(struct stream *s) {
	struct http2 *hp;
	CHECK_OBJ_NOTNULL(s, STREAM_MAGIC);
	AZ(s->reading);
	free_frame(s->frame);

	hp = s->hp;
	AZ(pthread_mutex_lock(&hp->mtx));
	s->reading = 1;
	AZ(pthread_cond_signal(&hp->cond));
	AZ(pthread_cond_wait(&s->cond, &hp->mtx));
	AZ(pthread_mutex_unlock(&hp->mtx));
}

#define MAXFRAMESIZE 2048 * 1024

static void
write_frame(struct http2 *hp, struct frame *f, int lvl, const char *pfx) {
	ssize_t l;
	char hdr[9];
	writeFrameHeader(hdr, f);

	char info[64];
	snprintf(info, 64,
			"TYPE: %d | FLAGS: 0x%02x | STREAM: %lu | SIZE: %d",
			f->type, f->flags, f->stid, f->size);

	AZ(pthread_mutex_lock(&hp->mtx));
	VSB_clear(hp->vsb);
	VSB_bcat(hp->vsb, hdr, 9); 
	if (f->size) {
		AN(f->data);
		VSB_bcat(hp->vsb, f->data, f->size); 
	}
	AZ(VSB_finish(hp->vsb));
	vtc_dump(hp->vl, lvl, pfx, info, strlen(info));
	l = write(hp->fd, VSB_data(hp->vsb), VSB_len(hp->vsb));
	if (l != VSB_len(hp->vsb))
		vtc_log(hp->vl, hp->fatal, "Write failed: (%zd vs %zd) %s",
		    l, VSB_len(hp->vsb), strerror(errno));

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
	char info[64];

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

		if (!get_bytes(hp, hdr, 9, 0)) {
			vtc_log(hp->vl, 3, "could not get header");
			return (NULL);
		}
		ALLOC_OBJ(f, FRAME_MAGIC);
		readFrameHeader(f, hdr);

		snprintf(info, 64,
				"TYPE: %d | FLAGS: 0x%02x | STREAM: %lu | SIZE: %d",
				f->type, f->flags, f->stid, f->size);
		vtc_dump(hp->vl, 3, "received", info, strlen(info));

		assert(f->size <= MAXFRAMESIZE );
		if (f->size) {
			f->data = malloc(f->size);
			//FATAL
			get_bytes(hp, f->data, f->size, 0);
		}

		AZ(pthread_mutex_lock(&hp->mtx));
		while (f) {
			VTAILQ_FOREACH(s, &hp->streams, list) {
				if (s->id != f->stid || !s->reading) {
					continue;
				}
				s->reading = 0;
				s->frame = f;
				f = NULL;
				AZ(pthread_cond_signal(&s->cond));
			}
			if (f)
				AZ(pthread_cond_wait(&hp->cond, &hp->mtx));
		}
	}
	AZ(pthread_mutex_unlock(&hp->mtx));

	return (NULL);
}

#define TRUST_ME(ptr)   ((void*)(uintptr_t)(ptr))

char *pri_string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static void
cmd_http_txpri(CMD_ARGS)
{
	struct http2 *hp;
	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);
	VSB_printf(hp->vsb, pri_string);
	http_write(hp, 4, "txpri");
}

static void
cmd_http_rxpri(CMD_ARGS)
{
	struct http2 *hp;
	CAST_OBJ_NOTNULL(hp, priv, HTTP2_MAGIC);

	(void)http_rxchar(hp, strlen(pri_string), 0);
	if (strncmp(pri_string, hp->rxbuf + hp->prxbuf - strlen(pri_string), strlen(pri_string)))
		vtc_log(hp->vl, hp->fatal, "HTTP rxpri failed");
}

static void
cmd_txframe(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *c;
	unsigned size = 0;
	char n;
	// XXX should be enough, right? right?
	char buf[1024];
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);
	CHECK_OBJ_NOTNULL(hp->vsb, VSB_MAGIC);
	// TODO check that we have an even number of char
	AN(av[1]);
	vtc_log(hp->vl, 3, "working with \"%s\" (%d)", av[1], strncmp(av[1], "0x", 2));
	if (strncmp(av[1], "0x", 2))
		vtc_log(hp->vl, 0, "Expected hex number, got \"%s\"", av[1]);
	c = av[1] + 2;
	while (c[size]) {
		if (!isxdigit(c[size]))
			vtc_log(hp->vl, 0, "Expected hex number, got \"%s\"", av[1]);
		if (c[size] >= 'a')
			n = c[size] - 'a' + 10;
		else if (c[size] >= 'A')
			n = c[size] - 'A' + 10;
		else
			n = c[size] - '0';
		if (size % 2)
			buf[size/2] |= 0xf & n;
		else
			buf[size/2] = n << 4;
		size++;
	}

	AZ(pthread_mutex_lock(&hp->mtx));
	VSB_clear(hp->vsb);
	VSB_bcat(hp->vsb, buf, size/2); 
	http_write(hp, 4, "txframe");

	AZ(pthread_mutex_unlock(&hp->mtx));
	vtc_hexdump(hp->vl, 4, "txframe", (void *)buf, size/2);
}

static void
cmd_rxframe(CMD_ARGS)
{
	struct stream *s;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
}

static void
cmd_txping(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *c;
	unsigned size = 0;
	char n;
	struct frame f;
	char buf[8];
	f.data = buf;
	memset(buf, 0, 8);
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);
	CHECK_OBJ_NOTNULL(hp->vsb, VSB_MAGIC);

	f.type = 0x6;
	f.size = 8;
	f.stid = s->id;
	f.flags = 0;

	while (*++av) {
		if (!strcmp(*av, "-data")) {
			av++;
			// TODO check that we have an even number of char
			if (strncmp(*av, "0x", 2))
				vtc_log(hp->vl, 0, "Expected hex number, got \"%s\"", *av);
			c = *av + 2;
			if (strlen(c) != 16)
				vtc_log(hp->vl, 0, "txping -data requires and 8-bytes payload (%s)", *av);
			while (c[size]) {
				if (!isxdigit(c[size]))
					vtc_log(hp->vl, 0, "Expected hex number, got \"%s\"", *av);
				if (c[size] >= 'a')
					n = c[size] - 'a' + 10;
				else if (c[size] >= 'A')
					n = c[size] - 'A' + 10;
				else
					n = c[size] - '0';
				if (size % 2)
					buf[size/2] |= 0xf & n;
				else
					buf[size/2] = n << 4;
				size++;
			}
		} else if (!strcmp(*av, "-ack")) {
			f.flags |= 1;
		} else
			break;
	}
	if (*av != NULL)
		vtc_log(hp->vl, 0, "Unknown txping spec: %s\n", *av);
	write_frame(hp, &f, 4, "txping");
}

static void
cmd_rxping(CMD_ARGS)
{
	struct stream *s;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s)
		return;
	
	if (s->frame->type != 0x6)
		vtc_log(vl, 0, "Received something that is not a ping (type=0x%x)", s->frame->type);
	if (s->frame->size != 8)
		vtc_log(vl, 0, "Size should be 8, but isn't (%d)", s->frame->size);
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
	CHECK_OBJ_NOTNULL(hp->vsb, VSB_MAGIC);

	f.type = 0x8;
	f.size = 4;
	f.stid = s->id;
	f.flags = 0;

	while (*++av) {
		if (!strcmp(*av, "-size")) {
			size = strtoul(*++av, &p, 0);
			if (*p != '\0' || s->id >= (1 << 31)) {
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
	vtc_log(hp->vl, 3, "winup is %02x%02x%02x%02x", f.data[0]& 0xff, f.data[1]& 0xff, f.data[2]& 0xff, f.data[3]& 0xff );
	write_frame(hp, &f, 4, "txwinup");
}


static void
cmd_rxwinup(CMD_ARGS)
{
	struct stream *s;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s)
		return;

	vtc_log(vl, 3, "winup is %02x%02x%02x%02x (%x)", s->frame->data[0]& 0xff, s->frame->data[1]& 0xff, s->frame->data[2]& 0xff, s->frame->data[3]& 0xff,  s->frame->data[0] |(1<<7) );
	if (s->frame->type != 0x8)
		vtc_log(vl, 0, "Received something that is not a ping (type=0x%x)", s->frame->type);
	if (s->frame->size != 4)
		vtc_log(vl, 0, "Size should be 4, but isn't (%d)", s->frame->size);
	if (s->frame->data[0] & (1<<7))
		vtc_log(vl, 0, "First bit of data is reserved and should be 0");
}

static void
cmd_txrst(CMD_ARGS)
{
	struct http2 *hp;
	struct stream *s;
	char *p;
	uint32_t err;
	struct frame f;
	char buf[8];
	f.data = buf;
	memset(buf, 0, 8);
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	hp = s->hp;
	CHECK_OBJ_NOTNULL(hp, HTTP2_MAGIC);
	CHECK_OBJ_NOTNULL(hp->vsb, VSB_MAGIC);

	f.type = 0x3;
	f.size = 4;
	f.stid = s->id;
	f.flags = 0;

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
		vtc_log(hp->vl, 0, "Unknown txwinup spec: %s\n", *av);

	err = htonl(err);
	f.data = (void *)&err;
	write_frame(hp, &f, 4, "txrst");
}


static void
cmd_rxrst(CMD_ARGS)
{
	struct stream *s;
	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);
	wait_frame(s);
	if (!s)
		return;

	if (s->frame->type != 0x03)
		vtc_log(vl, 0, "Received something that is not a reset (type=0x%x)", s->frame->type);
	if (s->frame->size != 4)
		vtc_log(vl, 0, "Size should be 4, but isn't (%d)", s->frame->size);
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
	{ "delay",		cmd_delay },
	{ "sema",		cmd_sema },
	{ NULL,			NULL }
};

static void *
stream_thread(void *priv)
{
	struct stream *s;

	CAST_OBJ_NOTNULL(s, priv, STREAM_MAGIC);

	parse_string(s->spec, stream_cmds, s, s->hp->vl);

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
	hp->fd = sock;
	hp->timeout = vtc_maxdur * 1000 / 2;
	hp->nrxbuf = 2048*1024;
	hp->vsb = VSB_new_auto();
	CHECK_OBJ_NOTNULL(hp->vsb, VSB_MAGIC);
	hp->rxbuf = malloc(hp->nrxbuf);		/* XXX */
	hp->sfd = sfd;
	hp->vl = vl;
	hp->gziplevel = 0;
	hp->gzipresidual = -1;
	AN(hp->rxbuf);
	AN(hp->vsb);

	hp->running = 1;
	if (sfd) {
		cmd_http_rxpri(NULL, hp, NULL, vl);
	} else  {
		cmd_http_txpri(NULL, hp, NULL, vl);
	}
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

	retval = hp->fd;
	VSB_delete(hp->vsb);
	free(hp->rxbuf);
	free(hp);
	return (retval);
}
