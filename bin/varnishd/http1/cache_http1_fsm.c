/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2015 Varnish Software AS
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
 *
 * This file contains the two central state machine for pushing HTTP1
 * sessions through their states.
 *
 */

#include "config.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>

#include "cache/cache.h"
#include "hash/hash_slinger.h"

#include "vcl.h"
#include "vtcp.h"
#include "vtim.h"

/*----------------------------------------------------------------------
 * Collect a request from the client.
 */

static enum req_fsm_nxt
http1_wait(struct sess *sp, struct worker *wrk, struct req *req)
{
	int j, tmo;
	struct pollfd pfd[1];
	double now, when;
	enum sess_close why = SC_NULL;
	enum http1_status_e hs;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);

	assert(req->sp == sp);

	AZ(req->vcl);
	AZ(req->esi_level);
	AZ(isnan(sp->t_idle));
	assert(isnan(req->t_first));
	assert(isnan(req->t_prev));
	assert(isnan(req->t_req));

	tmo = (int)(1e3 * cache_param->timeout_linger);
	while (1) {
		pfd[0].fd = sp->fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		j = poll(pfd, 1, tmo);
		assert(j >= 0);
		now = VTIM_real();
		if (j != 0)
			hs = HTTP1_Rx(req->htc);
		else
			hs = HTTP1_Complete(req->htc);
		if (hs == HTTP1_COMPLETE) {
			/* Got it, run with it */
			if (isnan(req->t_first))
				req->t_first = now;
			if (isnan(req->t_req))
				req->t_req = now;
			req->acct.req_hdrbytes +=
			    req->htc->rxbuf_e - req->htc->rxbuf_b;
			return (REQ_FSM_MORE);
		} else if (hs == HTTP1_ERROR_EOF) {
			why = SC_REM_CLOSE;
			break;
		} else if (hs == HTTP1_OVERFLOW) {
			why = SC_RX_OVERFLOW;
			break;
		} else if (hs == HTTP1_ALL_WHITESPACE) {
			/* Nothing but whitespace */
			when = sp->t_idle + cache_param->timeout_idle;
			if (when < now) {
				why = SC_RX_TIMEOUT;
				break;
			}
			when = sp->t_idle + cache_param->timeout_linger;
			tmo = (int)(1e3 * (when - now));
			if (when < now || tmo == 0) {
				wrk->stats->sess_herd++;
				SES_ReleaseReq(req);
				if (VTCP_nonblocking(sp->fd))
					SES_Close(sp, SC_REM_CLOSE);
				else
					SES_Wait(sp);
				return (REQ_FSM_DONE);
			}
		} else {
			/* Working on it */
			if (isnan(req->t_first))
				/* Record first byte received time stamp */
				req->t_first = now;
			when = req->t_first + cache_param->timeout_req;
			tmo = (int)(1e3 * (when - now));
			if (when < now || tmo == 0) {
				why = SC_RX_TIMEOUT;
				break;
			}
		}
	}
	req->acct.req_hdrbytes += req->htc->rxbuf_e - req->htc->rxbuf_b;
	CNT_AcctLogCharge(wrk->stats, req);
	SES_ReleaseReq(req);
	assert(why != SC_NULL);
	SES_Delete(sp, why, now);
	return (REQ_FSM_DONE);
}

/*----------------------------------------------------------------------
 * This is the final state, figure out if we should close or recycle
 * the client connection
 */

enum http1_cleanup_ret {
	SESS_DONE_RET_GONE,
	SESS_DONE_RET_WAIT,
	SESS_DONE_RET_START,
};

static enum http1_cleanup_ret
http1_cleanup(struct sess *sp, struct worker *wrk, struct req *req)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	CHECK_OBJ_ORNULL(req->vcl, VCL_CONF_MAGIC);

	req->director_hint = NULL;
	req->restarts = 0;

	AZ(req->esi_level);
	assert(req->top == req);

	if (req->vcl != NULL) {
		if (wrk->vcl != NULL)
			VCL_Rel(&wrk->vcl);
		wrk->vcl = req->vcl;
		req->vcl = NULL;
	}

	VRTPRIV_dynamic_kill(sp->privs, (uintptr_t)req);
	VRTPRIV_dynamic_kill(sp->privs, (uintptr_t)&req->top);

	/* Charge and log byte counters */
	AN(req->vsl->wid);
	CNT_AcctLogCharge(wrk->stats, req);
	req->req_bodybytes = 0;

	VSL_End(req->vsl);

	if (!isnan(req->t_prev) && req->t_prev > 0.)
		sp->t_idle = req->t_prev;
	else
		sp->t_idle = W_TIM_real(wrk);

	req->t_first = NAN;
	req->t_prev = NAN;
	req->t_req = NAN;
	req->req_body_status = REQ_BODY_INIT;

	req->hash_always_miss = 0;
	req->hash_ignore_busy = 0;
	req->is_hit = 0;

	if (sp->fd >= 0 && req->doclose != SC_NULL)
		SES_Close(sp, req->doclose);

	if (sp->fd < 0) {
		wrk->stats->sess_closed++;
		AZ(req->vcl);
		SES_ReleaseReq(req);
		SES_Delete(sp, SC_NULL, NAN);
		return (SESS_DONE_RET_GONE);
	}

	WS_Reset(req->ws, NULL);
	WS_Reset(wrk->aws, NULL);

	if (HTTP1_Reinit(req->htc) == HTTP1_COMPLETE) {
		AZ(req->vsl->wid);
		req->t_first = req->t_req = sp->t_idle;
		wrk->stats->sess_pipeline++;
		req->acct.req_hdrbytes +=
		    req->htc->rxbuf_e - req->htc->rxbuf_b;
		return (SESS_DONE_RET_START);
	} else {
		if (req->htc->rxbuf_e != req->htc->rxbuf_b)
			wrk->stats->sess_readahead++;
		return (SESS_DONE_RET_WAIT);
	}
}

/*----------------------------------------------------------------------
 */

static enum req_fsm_nxt
http1_dissect(struct worker *wrk, struct req *req)
{
	const char *r_100 = "HTTP/1.1 100 Continue\r\n\r\n";
	const char *r_400 = "HTTP/1.1 400 Bad Request\r\n\r\n";
	const char *r_417 = "HTTP/1.1 417 Expectation Failed\r\n\r\n";
	const char *p;
	ssize_t r;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);

	/* Allocate a new vxid now that we know we'll need it. */
	AZ(req->vsl->wid);
	req->vsl->wid = VXID_Get(wrk, VSL_CLIENTMARKER);

	VSLb(req->vsl, SLT_Begin, "req %u rxreq", VXID(req->sp->vxid));
	VSL(SLT_Link, req->sp->vxid, "req %u rxreq", VXID(req->vsl->wid));
	AZ(isnan(req->t_first)); /* First byte timestamp set by http1_wait */
	AZ(isnan(req->t_req));	 /* Complete req rcvd set by http1_wait */
	req->t_prev = req->t_first;
	VSLb_ts_req(req, "Start", req->t_first);
	VSLb_ts_req(req, "Req", req->t_req);

	/* Borrow VCL reference from worker thread */
	VCL_Refresh(&wrk->vcl);
	req->vcl = wrk->vcl;
	wrk->vcl = NULL;

	HTTP_Setup(req->http, req->ws, req->vsl, SLT_ReqMethod);
	req->err_code = HTTP1_DissectRequest(req->htc, req->http);

	/* If we could not even parse the request, just close */
	if (req->err_code != 0) {
		VSLb(req->vsl, SLT_HttpGarbage, "%.*s",
		    (int)(req->htc->rxbuf_e - req->htc->rxbuf_b),
		    req->htc->rxbuf_b);
		wrk->stats->client_req_400++;
		r = write(req->sp->fd, r_400, strlen(r_400));
		if (r > 0)
			req->acct.resp_hdrbytes += r;
		SES_Close(req->sp, SC_RX_JUNK);
		return (REQ_FSM_DONE);
	}

	assert (req->req_body_status == REQ_BODY_INIT);

	if (req->htc->body_status == BS_CHUNKED) {
		req->req_body_status = REQ_BODY_WITHOUT_LEN;
	} else if (req->htc->body_status == BS_LENGTH) {
		req->req_body_status = REQ_BODY_WITH_LEN;
	} else if (req->htc->body_status == BS_NONE) {
		req->req_body_status = REQ_BODY_NONE;
	} else if (req->htc->body_status == BS_EOF) {
		req->req_body_status = REQ_BODY_WITHOUT_LEN;
	} else {
		WRONG("Unknown req.body_length situation");
	}

	if (http_GetHdr(req->http, H_Expect, &p)) {
		if (strcasecmp(p, "100-continue")) {
			wrk->stats->client_req_417++;
			req->err_code = 417;
			r = write(req->sp->fd, r_417, strlen(r_417));
			if (r > 0)
				req->acct.resp_hdrbytes += r;
			SES_Close(req->sp, SC_RX_JUNK);
			return (REQ_FSM_DONE);
		}
		r = write(req->sp->fd, r_100, strlen(r_100));
		if (r > 0)
			req->acct.resp_hdrbytes += r;
		if (r != strlen(r_100)) {
			SES_Close(req->sp, SC_REM_CLOSE);
			return (REQ_FSM_DONE);
		}
		http_Unset(req->http, H_Expect);
	}

	wrk->stats->client_req++;
	wrk->stats->s_req++;

	AZ(req->err_code);
	req->ws_req = WS_Snapshot(req->ws);

	req->doclose = http_DoConnection(req->http);
	if (req->doclose == SC_RX_BAD) {
		r = write(req->sp->fd, r_400, strlen(r_400));
		if (r > 0)
			req->acct.resp_hdrbytes += r;
		SES_Close(req->sp, req->doclose);
		return (REQ_FSM_DONE);
	}

	assert(req->req_body_status != REQ_BODY_INIT);

	HTTP_Copy(req->http0, req->http);	// For ESI & restart

	return (REQ_FSM_MORE);
}

/*----------------------------------------------------------------------
 */

void
HTTP1_Session(struct worker *wrk, struct req *req)
{
	enum req_fsm_nxt nxt = REQ_FSM_MORE;
	struct sess *sp;
	enum http1_cleanup_ret sdr;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	sp = req->sp;
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	/*
	 * Whenever we come in from the acceptor or waiter, we need to set
	 * blocking mode.  It would be simpler to do this in the acceptor
	 * or waiter, but we'd rather do the syscall in the worker thread.
	 * On systems which return errors for ioctl, we close early
	 */
	if (sp->sess_step == S_STP_NEWREQ && VTCP_blocking(sp->fd)) {
		if (errno == ECONNRESET)
			SES_Close(sp, SC_REM_CLOSE);
		else
			SES_Close(sp, SC_TX_ERROR);
		sdr = http1_cleanup(sp, wrk, req);
		assert(sdr == SESS_DONE_RET_GONE);
		return;
	}

	/*
	 * Return from waitinglist. Check to see if the remote has left.
	 */
	if (req->req_step == R_STP_LOOKUP && VTCP_check_hup(sp->fd)) {
		AN(req->hash_objhead);
		(void)HSH_DerefObjHead(wrk, &req->hash_objhead);
		AZ(req->hash_objhead);
		SES_Close(sp, SC_REM_CLOSE);
		sdr = http1_cleanup(sp, wrk, req);
		assert(sdr == SESS_DONE_RET_GONE);
		return;
	}

	if (sp->sess_step == S_STP_NEWREQ) {
		req->htc->fd = sp->fd;
		HTTP1_RxInit(req->htc, req->ws,
		    cache_param->http_req_size, cache_param->http_req_hdr_len);
	}

	while (1) {
		assert(
		    sp->sess_step == S_STP_NEWREQ ||
		    req->req_step == R_STP_LOOKUP ||
		    req->req_step == R_STP_RECV);

		if (sp->sess_step == S_STP_WORKING) {
			if (req->req_step == R_STP_RECV)
				nxt = http1_dissect(wrk, req);
			if (nxt == REQ_FSM_MORE)
				nxt = CNT_Request(wrk, req);
			if (nxt == REQ_FSM_DISEMBARK)
				return;
			assert(nxt == REQ_FSM_DONE);
			sdr = http1_cleanup(sp, wrk, req);
			switch (sdr) {
			case SESS_DONE_RET_GONE:
				return;
			case SESS_DONE_RET_WAIT:
				sp->sess_step = S_STP_NEWREQ;
				break;
			case SESS_DONE_RET_START:
				sp->sess_step = S_STP_WORKING;
				req->req_step = R_STP_RECV;
				break;
			default:
				WRONG("Illegal enum http1_cleanup_ret");
			}
		}

		if (sp->sess_step == S_STP_NEWREQ) {
			nxt = http1_wait(sp, wrk, req);
			if (nxt != REQ_FSM_MORE)
				return;
			sp->sess_step = S_STP_WORKING;
			req->req_step = R_STP_RECV;
		}
	}
}
