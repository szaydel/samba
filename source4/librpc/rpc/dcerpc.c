/* 
   Unix SMB/CIFS implementation.
   raw dcerpc operations

   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Jelmer Vernooij 2004-2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define SOURCE4_LIBRPC_INTERNALS 1

#include "includes.h"
#include "lib/util/util_file.h"
#include "system/filesys.h"
#include "../lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "librpc/rpc/dcerpc_util.h"
#include "librpc/rpc/dcerpc_pkt_auth.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/gensec/gensec.h"
#include "param/param.h"
#include "lib/util/tevent_ntstatus.h"
#include "librpc/rpc/rpc_common.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/smb/tstream_smbXcli_np.h"


enum rpc_request_state {
	RPC_REQUEST_QUEUED,
	RPC_REQUEST_PENDING,
	RPC_REQUEST_DONE
};

/*
  handle for an async dcerpc request
*/
struct rpc_request {
	struct rpc_request *next, *prev;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	uint32_t call_id;
	enum rpc_request_state state;
	DATA_BLOB payload;
	uint32_t flags;
	uint32_t fault_code;

	/* this is used to distinguish bind and alter_context requests
	   from normal requests */
	void (*recv_handler)(struct rpc_request *conn, 
			     DATA_BLOB *blob, struct ncacn_packet *pkt);

	const struct GUID *object;
	uint16_t opnum;
	DATA_BLOB request_data;
	bool ignore_timeout;
	bool wait_for_sync;
	bool verify_bitmask1;
	bool verify_pcontext;

	struct {
		void (*callback)(struct rpc_request *);
		void *private_data;
	} async;
};

_PUBLIC_ NTSTATUS dcerpc_init(void)
{
	return gensec_init();
}

static void dcerpc_connection_dead(struct dcecli_connection *conn, NTSTATUS status);
static void dcerpc_schedule_io_trigger(struct dcecli_connection *c);

static struct rpc_request *dcerpc_request_send(TALLOC_CTX *mem_ctx,
					       struct dcerpc_pipe *p,
					       const struct GUID *object,
					       uint16_t opnum,
					       DATA_BLOB *stub_data);
static NTSTATUS dcerpc_request_recv(struct rpc_request *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *stub_data);
static NTSTATUS dcerpc_ndr_validate_in(struct dcecli_connection *c,
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB blob,
				       size_t struct_size,
				       ndr_push_flags_fn_t ndr_push,
				       ndr_pull_flags_fn_t ndr_pull);
static NTSTATUS dcerpc_ndr_validate_out(struct dcecli_connection *c,
					struct ndr_pull *pull_in,
					void *struct_ptr,
					size_t struct_size,
					ndr_push_flags_fn_t ndr_push,
					ndr_pull_flags_fn_t ndr_pull,
					ndr_print_function_t ndr_print);
static NTSTATUS dcerpc_shutdown_pipe(struct dcecli_connection *p, NTSTATUS status);
static NTSTATUS dcerpc_send_request(struct dcecli_connection *p, DATA_BLOB *data,
			     bool trigger_read);
static NTSTATUS dcerpc_send_read(struct dcecli_connection *p);

/* destroy a dcerpc connection */
static int dcerpc_connection_destructor(struct dcecli_connection *conn)
{
	if (conn->dead) {
		conn->free_skipped = true;
		return -1;
	}
	dcerpc_connection_dead(conn, NT_STATUS_LOCAL_DISCONNECT);
	return 0;
}


/* initialise a dcerpc connection. 
   the event context is optional
*/
static struct dcecli_connection *dcerpc_connection_init(TALLOC_CTX *mem_ctx, 
						 struct tevent_context *ev)
{
	struct dcecli_connection *c;

	c = talloc_zero(mem_ctx, struct dcecli_connection);
	if (!c) {
		return NULL;
	}

	c->event_ctx = ev;

	if (c->event_ctx == NULL) {
		talloc_free(c);
		return NULL;
	}

	c->call_id = 1;
	c->security_state.auth_type = DCERPC_AUTH_TYPE_NONE;
	c->security_state.auth_level = DCERPC_AUTH_LEVEL_NONE;
	c->security_state.auth_context_id = 0;
	c->security_state.session_key = dcecli_generic_session_key;
	c->security_state.generic_state = NULL;
	c->flags = 0;
	/*
	 * Windows uses 5840 for ncacn_ip_tcp,
	 * so we also use it (for every transport)
	 * by default. But we give the transport
	 * the chance to overwrite it.
	 */
	c->srv_max_xmit_frag = 5840;
	c->srv_max_recv_frag = 5840;
	c->max_total_response_size = DCERPC_NCACN_RESPONSE_DEFAULT_MAX_SIZE;
	c->pending = NULL;

	c->io_trigger = tevent_create_immediate(c);
	if (c->io_trigger == NULL) {
		talloc_free(c);
		return NULL;
	}

	talloc_set_destructor(c, dcerpc_connection_destructor);

	return c;
}

struct dcerpc_bh_state {
	struct dcerpc_pipe *p;
};

static const struct dcerpc_binding *dcerpc_bh_get_binding(struct dcerpc_binding_handle *h)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	return hs->p->binding;
}

static bool dcerpc_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	if (!hs->p) {
		return false;
	}

	if (!hs->p->conn) {
		return false;
	}

	if (hs->p->conn->dead) {
		return false;
	}

	return true;
}

static uint32_t dcerpc_bh_set_timeout(struct dcerpc_binding_handle *h,
				      uint32_t timeout)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	uint32_t old;

	if (!hs->p) {
		return DCERPC_REQUEST_TIMEOUT;
	}

	old = hs->p->request_timeout;
	hs->p->request_timeout = timeout;

	return old;
}

static bool dcerpc_bh_transport_encrypted(struct dcerpc_binding_handle *h)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	if (hs->p == NULL) {
		return false;
	}

	if (hs->p->conn == NULL) {
		return false;
	}

	return hs->p->conn->transport.encrypted;
}

static NTSTATUS dcerpc_bh_transport_session_key(struct dcerpc_binding_handle *h,
						TALLOC_CTX *mem_ctx,
						DATA_BLOB *session_key)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	struct dcecli_security *sec = NULL;
	DATA_BLOB sk = { .length = 0, };
	NTSTATUS status;

	if (hs->p == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (hs->p->conn == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	sec = &hs->p->conn->security_state;

	if (sec->session_key == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	status = sec->session_key(hs->p->conn, &sk);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sk.length = MIN(sk.length, 16);

	*session_key = data_blob_dup_talloc(mem_ctx, sk);
	if (session_key->length != sk.length) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_keep_secret(session_key->data);
	return NT_STATUS_OK;
}

static void dcerpc_bh_auth_info(struct dcerpc_binding_handle *h,
				enum dcerpc_AuthType *auth_type,
				enum dcerpc_AuthLevel *auth_level)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	if (hs->p == NULL) {
		return;
	}

	if (hs->p->conn == NULL) {
		return;
	}

	*auth_type = hs->p->conn->security_state.auth_type;
	*auth_level = hs->p->conn->security_state.auth_level;
}

static NTSTATUS dcerpc_bh_auth_session_key(struct dcerpc_binding_handle *h,
					   TALLOC_CTX *mem_ctx,
					   DATA_BLOB *session_key)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	struct dcecli_security *sec = NULL;
	NTSTATUS status;

	if (hs->p == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (hs->p->conn == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	sec = &hs->p->conn->security_state;

	if (sec->auth_type == DCERPC_AUTH_TYPE_NONE) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (sec->generic_state == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	status = gensec_session_key(sec->generic_state,
				    mem_ctx,
				    session_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	talloc_keep_secret(session_key->data);
	return NT_STATUS_OK;
}

struct dcerpc_bh_raw_call_state {
	struct tevent_context *ev;
	struct dcerpc_binding_handle *h;
	DATA_BLOB in_data;
	DATA_BLOB out_data;
	uint32_t out_flags;
};

static void dcerpc_bh_raw_call_done(struct rpc_request *subreq);

static struct tevent_req *dcerpc_bh_raw_call_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct dcerpc_binding_handle *h,
						  const struct GUID *object,
						  uint32_t opnum,
						  uint32_t in_flags,
						  const uint8_t *in_data,
						  size_t in_length)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	struct tevent_req *req;
	struct dcerpc_bh_raw_call_state *state;
	bool ok;
	struct rpc_request *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_bh_raw_call_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->h = h;
	state->in_data.data = discard_const_p(uint8_t, in_data);
	state->in_data.length = in_length;

	ok = dcerpc_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_request_send(state,
				     hs->p,
				     object,
				     opnum,
				     &state->in_data);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	subreq->async.callback = dcerpc_bh_raw_call_done;
	subreq->async.private_data = req;

	return req;
}

static void dcerpc_bh_raw_call_done(struct rpc_request *subreq)
{
	struct tevent_req *req =
		talloc_get_type_abort(subreq->async.private_data,
		struct tevent_req);
	struct dcerpc_bh_raw_call_state *state =
		tevent_req_data(req,
		struct dcerpc_bh_raw_call_state);
	NTSTATUS status;
	uint32_t fault_code;

	state->out_flags = 0;
	if (subreq->flags & DCERPC_PULL_BIGENDIAN) {
		state->out_flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	fault_code = subreq->fault_code;

	status = dcerpc_request_recv(subreq, state, &state->out_data);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		status = dcerpc_fault_to_nt_status(fault_code);
	}

	/*
	 * We trigger the callback in the next event run
	 * because the code in this file might trigger
	 * multiple request callbacks from within a single
	 * while loop.
	 *
	 * In order to avoid segfaults from within
	 * dcerpc_connection_dead() we call
	 * tevent_req_defer_callback().
	 */
	tevent_req_defer_callback(req, state->ev);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS dcerpc_bh_raw_call_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags)
{
	struct dcerpc_bh_raw_call_state *state =
		tevent_req_data(req,
		struct dcerpc_bh_raw_call_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_data = talloc_move(mem_ctx, &state->out_data.data);
	*out_length = state->out_data.length;
	*out_flags = state->out_flags;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct dcerpc_bh_disconnect_state {
	uint8_t _dummy;
};

static struct tevent_req *dcerpc_bh_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	struct tevent_req *req;
	struct dcerpc_bh_disconnect_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_bh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	ok = dcerpc_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	/* TODO: do a real disconnect ... */
	hs->p = NULL;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS dcerpc_bh_disconnect_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static bool dcerpc_bh_push_bigendian(struct dcerpc_binding_handle *h)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	if (hs->p->conn->flags & DCERPC_PUSH_BIGENDIAN) {
		return true;
	}

	return false;
}

static bool dcerpc_bh_ref_alloc(struct dcerpc_binding_handle *h)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	if (hs->p->conn->flags & DCERPC_NDR_REF_ALLOC) {
		return true;
	}

	return false;
}

static bool dcerpc_bh_use_ndr64(struct dcerpc_binding_handle *h)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	if (hs->p->conn->flags & DCERPC_NDR64) {
		return true;
	}

	return false;
}

static void dcerpc_bh_do_ndr_print(struct dcerpc_binding_handle *h,
				   ndr_flags_type ndr_flags,
				   const void *_struct_ptr,
				   const struct ndr_interface_call *call)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	void *struct_ptr = discard_const(_struct_ptr);
	bool print_in = false;
	bool print_out = false;

	if (hs->p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		print_in = true;
	}

	if (hs->p->conn->flags & DCERPC_DEBUG_PRINT_OUT) {
		print_out = true;
	}

	if (CHECK_DEBUGLVLC(DBGC_RPC_PARSE, 11)) {
		print_in = true;
		print_out = true;
	}

	if (ndr_flags & NDR_IN) {
		if (print_in) {
			ndr_print_function_debug(call->ndr_print,
						 call->name,
						 ndr_flags,
						 struct_ptr);
		}
	}
	if (ndr_flags & NDR_OUT) {
		if (print_out) {
			ndr_print_function_debug(call->ndr_print,
						 call->name,
						 ndr_flags,
						 struct_ptr);
		}
	}
}

static void dcerpc_bh_ndr_push_failed(struct dcerpc_binding_handle *h,
				      NTSTATUS error,
				      const void *struct_ptr,
				      const struct ndr_interface_call *call)
{
	DEBUG(2,("Unable to ndr_push structure for %s - %s\n",
		 call->name, nt_errstr(error)));
}

static void dcerpc_bh_ndr_pull_failed(struct dcerpc_binding_handle *h,
				      NTSTATUS error,
				      const DATA_BLOB *blob,
				      const struct ndr_interface_call *call)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	const uint32_t num_examples = 20;
	uint32_t i;

	DEBUG(2,("Unable to ndr_pull structure for %s - %s\n",
		 call->name, nt_errstr(error)));

	if (hs->p->conn->packet_log_dir == NULL) return;

	for (i=0;i<num_examples;i++) {
		char *name=NULL;
		int ret;

		ret = asprintf(&name, "%s/rpclog/%s-out.%d",
			       hs->p->conn->packet_log_dir,
			       call->name, i);
		if (ret == -1) {
			return;
		}
		if (!file_exist(name)) {
			if (file_save(name, blob->data, blob->length)) {
				DEBUG(10,("Logged rpc packet to %s\n", name));
			}
			free(name);
			break;
		}
		free(name);
	}
}

static NTSTATUS dcerpc_bh_ndr_validate_in(struct dcerpc_binding_handle *h,
					  TALLOC_CTX *mem_ctx,
					  const DATA_BLOB *blob,
					  const struct ndr_interface_call *call)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);

	if (hs->p->conn->flags & DCERPC_DEBUG_VALIDATE_IN) {
		NTSTATUS status;

		status = dcerpc_ndr_validate_in(hs->p->conn,
						mem_ctx,
						*blob,
						call->struct_size,
						call->ndr_push,
						call->ndr_pull);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Validation [in] failed for %s - %s\n",
				 call->name, nt_errstr(status)));
			return status;
		}
	}

	DEBUG(10,("rpc request data:\n"));
	dump_data(10, blob->data, blob->length);

	return NT_STATUS_OK;
}

static NTSTATUS dcerpc_bh_ndr_validate_out(struct dcerpc_binding_handle *h,
					   struct ndr_pull *pull_in,
					   const void *_struct_ptr,
					   const struct ndr_interface_call *call)
{
	struct dcerpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct dcerpc_bh_state);
	void *struct_ptr = discard_const(_struct_ptr);

	DEBUG(10,("rpc reply data:\n"));
	dump_data(10, pull_in->data, pull_in->data_size);

	if (pull_in->offset != pull_in->data_size) {
		DEBUG(0,("Warning! ignoring %u unread bytes at ofs:%u (0x%08X) for %s!\n",
			 pull_in->data_size - pull_in->offset,
			 pull_in->offset, pull_in->offset,
			 call->name));
		/* we used to return NT_STATUS_INFO_LENGTH_MISMATCH here,
		   but it turns out that early versions of NT
		   (specifically NT3.1) add junk onto the end of rpc
		   packets, so if we want to interoperate at all with
		   those versions then we need to ignore this error */
	}

	if (hs->p->conn->flags & DCERPC_DEBUG_VALIDATE_OUT) {
		NTSTATUS status;

		status = dcerpc_ndr_validate_out(hs->p->conn,
						 pull_in,
						 struct_ptr,
						 call->struct_size,
						 call->ndr_push,
						 call->ndr_pull,
						 call->ndr_print);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2,("Validation [out] failed for %s - %s\n",
				 call->name, nt_errstr(status)));
			return status;
		}
	}

	return NT_STATUS_OK;
}

static const struct dcerpc_binding_handle_ops dcerpc_bh_ops = {
	.name			= "dcerpc",
	.get_binding		= dcerpc_bh_get_binding,
	.is_connected		= dcerpc_bh_is_connected,
	.set_timeout		= dcerpc_bh_set_timeout,
	.transport_encrypted	= dcerpc_bh_transport_encrypted,
	.transport_session_key	= dcerpc_bh_transport_session_key,
	.auth_info		= dcerpc_bh_auth_info,
	.auth_session_key	= dcerpc_bh_auth_session_key,
	.raw_call_send		= dcerpc_bh_raw_call_send,
	.raw_call_recv		= dcerpc_bh_raw_call_recv,
	.disconnect_send	= dcerpc_bh_disconnect_send,
	.disconnect_recv	= dcerpc_bh_disconnect_recv,

	.push_bigendian		= dcerpc_bh_push_bigendian,
	.ref_alloc		= dcerpc_bh_ref_alloc,
	.use_ndr64		= dcerpc_bh_use_ndr64,
	.do_ndr_print		= dcerpc_bh_do_ndr_print,
	.ndr_push_failed	= dcerpc_bh_ndr_push_failed,
	.ndr_pull_failed	= dcerpc_bh_ndr_pull_failed,
	.ndr_validate_in	= dcerpc_bh_ndr_validate_in,
	.ndr_validate_out	= dcerpc_bh_ndr_validate_out,
};

/* initialise a dcerpc pipe. */
struct dcerpc_binding_handle *dcerpc_pipe_binding_handle(struct dcerpc_pipe *p,
							 const struct GUID *object,
							 const struct ndr_interface_table *table)
{
	struct dcerpc_binding_handle *h;
	struct dcerpc_bh_state *hs;

	h = dcerpc_binding_handle_create(p,
					 &dcerpc_bh_ops,
					 object,
					 table,
					 &hs,
					 struct dcerpc_bh_state,
					 __location__);
	if (h == NULL) {
		return NULL;
	}
	hs->p = p;

	dcerpc_binding_handle_set_sync_ev(h, p->conn->event_ctx);

	return h;
}

/* initialise a dcerpc pipe. */
_PUBLIC_ struct dcerpc_pipe *dcerpc_pipe_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	struct dcerpc_pipe *p;

	p = talloc_zero(mem_ctx, struct dcerpc_pipe);
	if (!p) {
		return NULL;
	}

	p->conn = dcerpc_connection_init(p, ev);
	if (p->conn == NULL) {
		talloc_free(p);
		return NULL;
	}

	p->request_timeout = DCERPC_REQUEST_TIMEOUT;

	if (DEBUGLVL(100)) {
		p->conn->flags |= DCERPC_DEBUG_PRINT_BOTH;
	}

	return p;
}


/* 
   choose the next call id to use
*/
static uint32_t next_call_id(struct dcecli_connection *c)
{
	c->call_id++;
	if (c->call_id == 0) {
		c->call_id++;
	}
	return c->call_id;
}

/**
  setup for a ndr pull, also setting up any flags from the binding string
*/
static struct ndr_pull *ndr_pull_init_flags(struct dcecli_connection *c, 
					    DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	struct ndr_pull *ndr = ndr_pull_init_blob(blob, mem_ctx);

	if (ndr == NULL) return ndr;

	if (c->flags & DCERPC_DEBUG_PAD_CHECK) {
		ndr->flags |= LIBNDR_FLAG_PAD_CHECK;
	}

	if (c->flags & DCERPC_NDR_REF_ALLOC) {
		ndr->flags |= LIBNDR_FLAG_REF_ALLOC;
	}

	if (c->flags & DCERPC_NDR64) {
		ndr->flags |= LIBNDR_FLAG_NDR64;
	}

	return ndr;
}

/* 
   parse the authentication information on a dcerpc response packet
*/
static NTSTATUS ncacn_pull_pkt_auth(struct dcecli_connection *c,
				    TALLOC_CTX *mem_ctx,
				    enum dcerpc_pkt_type ptype,
				    uint8_t required_flags,
				    uint8_t optional_flags,
				    uint8_t payload_offset,
				    DATA_BLOB *payload_and_verifier,
				    DATA_BLOB *raw_packet,
				    const struct ncacn_packet *pkt)
{
	const struct dcerpc_auth tmp_auth = {
		.auth_type = c->security_state.auth_type,
		.auth_level = c->security_state.auth_level,
		.auth_context_id = c->security_state.auth_context_id,
	};
	NTSTATUS status;

	status = dcerpc_ncacn_pull_pkt_auth(&tmp_auth,
					    c->security_state.generic_state,
					    true, /* check_pkt_auth_fields */
					    mem_ctx,
					    ptype,
					    required_flags,
					    optional_flags,
					    payload_offset,
					    payload_and_verifier,
					    raw_packet,
					    pkt);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}


/* 
   push a dcerpc request packet into a blob, possibly signing it.
*/
static NTSTATUS ncacn_push_request_sign(struct dcecli_connection *c, 
					 DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
					 size_t sig_size,
					 struct ncacn_packet *pkt)
{
	const struct dcerpc_auth tmp_auth = {
		.auth_type = c->security_state.auth_type,
		.auth_level = c->security_state.auth_level,
		.auth_context_id = c->security_state.auth_context_id,
	};
	NTSTATUS status;
	uint8_t payload_offset = DCERPC_REQUEST_LENGTH;

	if (pkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		payload_offset += 16;
	}

	status = dcerpc_ncacn_push_pkt_auth(&tmp_auth,
					    c->security_state.generic_state,
					    mem_ctx, blob,
					    sig_size,
					    payload_offset,
					    &pkt->u.request.stub_and_verifier,
					    pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}


/* 
   fill in the fixed values in a dcerpc header 
*/
static void init_ncacn_hdr(struct dcecli_connection *c, struct ncacn_packet *pkt)
{
	pkt->rpc_vers = 5;
	pkt->rpc_vers_minor = 0;
	if (c->flags & DCERPC_PUSH_BIGENDIAN) {
		pkt->drep[0] = 0;
	} else {
		pkt->drep[0] = DCERPC_DREP_LE;
	}
	pkt->drep[1] = 0;
	pkt->drep[2] = 0;
	pkt->drep[3] = 0;
}

/*
  map a bind nak reason to a NTSTATUS
*/
static NTSTATUS dcerpc_map_nak_reason(enum dcerpc_bind_nak_reason reason)
{
	switch (reason) {
	case DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED:
		return NT_STATUS_REVISION_MISMATCH;
	case DCERPC_BIND_NAK_REASON_INVALID_AUTH_TYPE:
		return NT_STATUS_INVALID_PARAMETER;
	default:
		break;
	}
	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS dcerpc_map_ack_reason(const struct dcerpc_ack_ctx *ack)
{
	if (ack == NULL) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	switch (ack->result) {
	case DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK:
		/*
		 * We have not asked for this...
		 */
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	default:
		break;
	}

	switch (ack->reason.value) {
	case DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED:
		return NT_STATUS_RPC_UNSUPPORTED_NAME_SYNTAX;
	case DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED:
		return NT_STATUS_RPC_UNSUPPORTED_NAME_SYNTAX;
	default:
		break;
	}
	return NT_STATUS_UNSUCCESSFUL;
}

/*
  remove requests from the pending or queued queues
 */
static int dcerpc_req_dequeue(struct rpc_request *req)
{
	switch (req->state) {
	case RPC_REQUEST_QUEUED:
		DLIST_REMOVE(req->p->conn->request_queue, req);
		break;
	case RPC_REQUEST_PENDING:
		DLIST_REMOVE(req->p->conn->pending, req);
		break;
	case RPC_REQUEST_DONE:
		break;
	}
	return 0;
}


/*
  mark the dcerpc connection dead. All outstanding requests get an error
*/
static void dcerpc_connection_dead(struct dcecli_connection *conn, NTSTATUS status)
{
	if (conn->dead) return;

	conn->dead = true;

	TALLOC_FREE(conn->io_trigger);
	conn->io_trigger_pending = false;

	dcerpc_shutdown_pipe(conn, status);

	/* all pending requests get the error */
	while (conn->pending) {
		struct rpc_request *req = conn->pending;
		dcerpc_req_dequeue(req);
		req->state = RPC_REQUEST_DONE;
		req->status = status;
		if (req->async.callback) {
			req->async.callback(req);
		}
	}	

	/* all requests, which are not shipped */
	while (conn->request_queue) {
		struct rpc_request *req = conn->request_queue;
		dcerpc_req_dequeue(req);
		req->state = RPC_REQUEST_DONE;
		req->status = status;
		if (req->async.callback) {
			req->async.callback(req);
		}
	}

	talloc_set_destructor(conn, NULL);
	if (conn->free_skipped) {
		talloc_free(conn);
	}
}

/*
  forward declarations of the recv_data handlers for the types of
  packets we need to handle
*/
static void dcerpc_request_recv_data(struct dcecli_connection *c, 
				     DATA_BLOB *raw_packet, struct ncacn_packet *pkt);

/*
  receive a dcerpc reply from the transport. Here we work out what
  type of reply it is (normal request, bind or alter context) and
  dispatch to the appropriate handler
*/
static void dcerpc_recv_data(struct dcecli_connection *conn, DATA_BLOB *blob, NTSTATUS status)
{
	struct ncacn_packet pkt;

	if (conn->dead) {
		return;
	}

	if (NT_STATUS_IS_OK(status) && blob->length == 0) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	/* the transport may be telling us of a severe error, such as
	   a dropped socket */
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(blob);
		dcerpc_connection_dead(conn, status);
		return;
	}

	/* parse the basic packet to work out what type of response this is */
	status = dcerpc_pull_ncacn_packet(blob->data, blob, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(blob);
		dcerpc_connection_dead(conn, status);
		return;
	}

	dcerpc_request_recv_data(conn, blob, &pkt);
}

/*
  handle timeouts of individual dcerpc requests
*/
static void dcerpc_timeout_handler(struct tevent_context *ev, struct tevent_timer *te, 
				   struct timeval t, void *private_data)
{
	struct rpc_request *req = talloc_get_type(private_data, struct rpc_request);

	if (req->ignore_timeout) {
		dcerpc_req_dequeue(req);
		req->state = RPC_REQUEST_DONE;
		req->status = NT_STATUS_IO_TIMEOUT;
		if (req->async.callback) {
			req->async.callback(req);
		}
		return;
	}

	dcerpc_connection_dead(req->p->conn, NT_STATUS_IO_TIMEOUT);
}

struct dcerpc_bind_state {
	struct tevent_context *ev;
	struct dcerpc_pipe *p;
};

static void dcerpc_bind_fail_handler(struct rpc_request *subreq);
static void dcerpc_bind_recv_handler(struct rpc_request *subreq,
				     DATA_BLOB *raw_packet,
				     struct ncacn_packet *pkt);

struct tevent_req *dcerpc_bind_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct dcerpc_pipe *p,
				    const struct ndr_syntax_id *syntax,
				    const struct ndr_syntax_id *transfer_syntax)
{
	struct tevent_req *req;
	struct dcerpc_bind_state *state;
	struct ncacn_packet pkt;
	DATA_BLOB blob;
	NTSTATUS status;
	struct rpc_request *subreq;
	uint32_t flags;
	struct ndr_syntax_id bind_time_features;

	bind_time_features = dcerpc_construct_bind_time_features(
			DCERPC_BIND_TIME_SECURITY_CONTEXT_MULTIPLEXING |
			DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN);

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_bind_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->p = p;

	p->syntax = *syntax;
	p->transfer_syntax = *transfer_syntax;

	flags = dcerpc_binding_get_flags(p->binding);

	init_ncacn_hdr(p->conn, &pkt);

	pkt.ptype = DCERPC_PKT_BIND;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = p->conn->call_id;
	pkt.auth_length = 0;

	if (flags & DCERPC_CONCURRENT_MULTIPLEX) {
		pkt.pfc_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	if (p->conn->flags & DCERPC_PROPOSE_HEADER_SIGNING) {
		pkt.pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
	}

	pkt.u.bind.max_xmit_frag = p->conn->srv_max_xmit_frag;
	pkt.u.bind.max_recv_frag = p->conn->srv_max_recv_frag;
	pkt.u.bind.assoc_group_id = dcerpc_binding_get_assoc_group_id(p->binding);
	pkt.u.bind.num_contexts = 2;
	pkt.u.bind.ctx_list = talloc_zero_array(state, struct dcerpc_ctx_list,
						pkt.u.bind.num_contexts);
	if (tevent_req_nomem(pkt.u.bind.ctx_list, req)) {
		return tevent_req_post(req, ev);
	}
	pkt.u.bind.ctx_list[0].context_id = p->context_id;
	pkt.u.bind.ctx_list[0].num_transfer_syntaxes = 1;
	pkt.u.bind.ctx_list[0].abstract_syntax = p->syntax;
	pkt.u.bind.ctx_list[0].transfer_syntaxes = &p->transfer_syntax;
	pkt.u.bind.ctx_list[1].context_id = p->context_id + 1;
	pkt.u.bind.ctx_list[1].num_transfer_syntaxes = 1;
	pkt.u.bind.ctx_list[1].abstract_syntax = p->syntax;
	pkt.u.bind.ctx_list[1].transfer_syntaxes = &bind_time_features;
	pkt.u.bind.auth_info = data_blob(NULL, 0);

	/* construct the NDR form of the packet */
	status = dcerpc_ncacn_push_auth(&blob,
				state,
				&pkt,
				p->conn->security_state.tmp_auth_info.out);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * we allocate a dcerpc_request so we can be in the same
	 * request queue as normal requests
	 */
	subreq = talloc_zero(state, struct rpc_request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	subreq->state = RPC_REQUEST_PENDING;
	subreq->call_id = pkt.call_id;
	subreq->async.private_data = req;
	subreq->async.callback = dcerpc_bind_fail_handler;
	subreq->p = p;
	subreq->recv_handler = dcerpc_bind_recv_handler;
	DLIST_ADD_END(p->conn->pending, subreq);
	talloc_set_destructor(subreq, dcerpc_req_dequeue);

	status = dcerpc_send_request(p->conn, &blob, true);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_add_timer(ev, subreq,
			 timeval_current_ofs(DCERPC_REQUEST_TIMEOUT, 0),
			 dcerpc_timeout_handler, subreq);

	return req;
}

static void dcerpc_bind_fail_handler(struct rpc_request *subreq)
{
	struct tevent_req *req =
		talloc_get_type_abort(subreq->async.private_data,
		struct tevent_req);
	struct dcerpc_bind_state *state =
		tevent_req_data(req,
		struct dcerpc_bind_state);
	NTSTATUS status = subreq->status;

	TALLOC_FREE(subreq);

	/*
	 * We trigger the callback in the next event run
	 * because the code in this file might trigger
	 * multiple request callbacks from within a single
	 * while loop.
	 *
	 * In order to avoid segfaults from within
	 * dcerpc_connection_dead() we call
	 * tevent_req_defer_callback().
	 */
	tevent_req_defer_callback(req, state->ev);

	tevent_req_nterror(req, status);
}

static void dcerpc_bind_recv_handler(struct rpc_request *subreq,
				     DATA_BLOB *raw_packet,
				     struct ncacn_packet *pkt)
{
	struct tevent_req *req =
		talloc_get_type_abort(subreq->async.private_data,
		struct tevent_req);
	struct dcerpc_bind_state *state =
		tevent_req_data(req,
		struct dcerpc_bind_state);
	struct dcecli_connection *conn = state->p->conn;
	struct dcecli_security *sec = &conn->security_state;
	struct dcerpc_binding *b = NULL;
	NTSTATUS status;
	uint32_t flags;

	/*
	 * Note that pkt is allocated under raw_packet->data,
	 * while raw_packet->data is a child of subreq.
	 */
	talloc_steal(state, raw_packet->data);
	TALLOC_FREE(subreq);

	/*
	 * We trigger the callback in the next event run
	 * because the code in this file might trigger
	 * multiple request callbacks from within a single
	 * while loop.
	 *
	 * In order to avoid segfaults from within
	 * dcerpc_connection_dead() we call
	 * tevent_req_defer_callback().
	 */
	tevent_req_defer_callback(req, state->ev);

	if (pkt->ptype == DCERPC_PKT_BIND_NAK) {
		status = dcerpc_map_nak_reason(pkt->u.bind_nak.reject_reason);

		DEBUG(2,("dcerpc: bind_nak reason %d - %s\n",
			 pkt->u.bind_nak.reject_reason, nt_errstr(status)));

		tevent_req_nterror(req, status);
		return;
	}

	status = dcerpc_verify_ncacn_packet_header(pkt,
					DCERPC_PKT_BIND_ACK,
					pkt->u.bind_ack.auth_info.length,
					DCERPC_PFC_FLAG_FIRST |
					DCERPC_PFC_FLAG_LAST,
					DCERPC_PFC_FLAG_CONC_MPX |
					DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN);
	if (!NT_STATUS_IS_OK(status)) {
		state->p->last_fault_code = DCERPC_NCA_S_PROTO_ERROR;
		tevent_req_nterror(req, NT_STATUS_NET_WRITE_FAULT);
		return;
	}

	if (pkt->u.bind_ack.num_results < 1) {
		state->p->last_fault_code = DCERPC_NCA_S_PROTO_ERROR;
		tevent_req_nterror(req, NT_STATUS_NET_WRITE_FAULT);
		return;
	}

	if (pkt->u.bind_ack.ctx_list[0].result != 0) {
		status = dcerpc_map_ack_reason(&pkt->u.bind_ack.ctx_list[0]);
		DEBUG(2,("dcerpc: bind_ack failed - reason %d - %s\n",
			 pkt->u.bind_ack.ctx_list[0].reason.value,
			 nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}

	if (pkt->u.bind_ack.num_results >= 2) {
		if (pkt->u.bind_ack.ctx_list[1].result == DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK) {
			conn->bind_time_features = pkt->u.bind_ack.ctx_list[1].reason.negotiate;
		} else {
			status = dcerpc_map_ack_reason(&pkt->u.bind_ack.ctx_list[1]);
			DEBUG(10,("dcerpc: bind_time_feature failed - reason %d - %s\n",
				 pkt->u.bind_ack.ctx_list[1].reason.value,
				 nt_errstr(status)));
			status = NT_STATUS_OK;
		}
	}

	/*
	 * DCE-RPC 1.1 (c706) specifies
	 * CONST_MUST_RCV_FRAG_SIZE as 1432
	 */
	if (pkt->u.bind_ack.max_xmit_frag < 1432) {
		state->p->last_fault_code = DCERPC_NCA_S_PROTO_ERROR;
		tevent_req_nterror(req, NT_STATUS_NET_WRITE_FAULT);
		return;
	}
	if (pkt->u.bind_ack.max_recv_frag < 1432) {
		state->p->last_fault_code = DCERPC_NCA_S_PROTO_ERROR;
		tevent_req_nterror(req, NT_STATUS_NET_WRITE_FAULT);
		return;
	}
	conn->srv_max_xmit_frag = MIN(conn->srv_max_xmit_frag,
				      pkt->u.bind_ack.max_xmit_frag);
	conn->srv_max_recv_frag = MIN(conn->srv_max_recv_frag,
				      pkt->u.bind_ack.max_recv_frag);

	flags = dcerpc_binding_get_flags(state->p->binding);

	if (flags & DCERPC_CONCURRENT_MULTIPLEX) {
		if (pkt->pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) {
			conn->flags |= DCERPC_CONCURRENT_MULTIPLEX;
		} else {
			conn->flags &= ~DCERPC_CONCURRENT_MULTIPLEX;
		}
	}

	if (!(conn->flags & DCERPC_CONCURRENT_MULTIPLEX)) {
		struct dcerpc_binding *pb =
			discard_const_p(struct dcerpc_binding, state->p->binding);
		/*
		 * clear DCERPC_CONCURRENT_MULTIPLEX
		 */
		status = dcerpc_binding_set_flags(pb, 0,
						  DCERPC_CONCURRENT_MULTIPLEX);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}
	if ((conn->flags & DCERPC_PROPOSE_HEADER_SIGNING) &&
	    (pkt->pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN)) {
		conn->flags |= DCERPC_HEADER_SIGNING;
	}

	/* the bind_ack might contain a reply set of credentials */
	if (pkt->auth_length != 0 && sec->tmp_auth_info.in != NULL) {
		status = dcerpc_pull_auth_trailer(pkt, sec->tmp_auth_info.mem,
						  &pkt->u.bind_ack.auth_info,
						  sec->tmp_auth_info.in,
						  NULL, true);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	/*
	 * We're the owner of the binding, so we're allowed to modify it.
	 */
	b = discard_const_p(struct dcerpc_binding, state->p->binding);
	status = dcerpc_binding_set_assoc_group_id(b,
						   pkt->u.bind_ack.assoc_group_id);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	status = dcerpc_binding_set_abstract_syntax(b, &state->p->syntax);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS dcerpc_bind_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/* 
   perform a continued bind (and auth3)
*/
NTSTATUS dcerpc_auth3(struct dcerpc_pipe *p,
		      TALLOC_CTX *mem_ctx)
{
	struct ncacn_packet pkt;
	NTSTATUS status;
	DATA_BLOB blob;
	uint32_t flags;

	flags = dcerpc_binding_get_flags(p->binding);

	init_ncacn_hdr(p->conn, &pkt);

	pkt.ptype = DCERPC_PKT_AUTH3;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = next_call_id(p->conn);
	pkt.auth_length = 0;
	pkt.u.auth3.auth_info = data_blob(NULL, 0);

	if (flags & DCERPC_CONCURRENT_MULTIPLEX) {
		pkt.pfc_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	/* construct the NDR form of the packet */
	status = dcerpc_ncacn_push_auth(&blob,
				mem_ctx,
				&pkt,
				p->conn->security_state.tmp_auth_info.out);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* send it on its way */
	status = dcerpc_send_request(p->conn, &blob, false);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;	
}


/*
  process a fragment received from the transport layer during a
  request

  This function frees the data 
*/
static void dcerpc_request_recv_data(struct dcecli_connection *c, 
				     DATA_BLOB *raw_packet, struct ncacn_packet *pkt)
{
	struct rpc_request *req;
	unsigned int length;
	NTSTATUS status = NT_STATUS_OK;

	/*
	  if this is an authenticated connection then parse and check
	  the auth info. We have to do this before finding the
	  matching packet, as the request structure might have been
	  removed due to a timeout, but if it has been we still need
	  to run the auth routines so that we don't get the sign/seal
	  info out of step with the server
	*/
	switch (pkt->ptype) {
	case DCERPC_PKT_RESPONSE:
		status = ncacn_pull_pkt_auth(c, raw_packet->data,
				   DCERPC_PKT_RESPONSE,
				   0, /* required_flags */
				   DCERPC_PFC_FLAG_FIRST |
				   DCERPC_PFC_FLAG_LAST,
				   DCERPC_REQUEST_LENGTH,
				   &pkt->u.response.stub_and_verifier,
				   raw_packet, pkt);
		break;
	default:
		break;
	}

	/* find the matching request */
	for (req=c->pending;req;req=req->next) {
		if (pkt->call_id == req->call_id) break;
	}

#if 0
	/* useful for testing certain vendors RPC servers */
	if (req == NULL && c->pending && pkt->call_id == 0) {
		DEBUG(0,("HACK FOR INCORRECT CALL ID\n"));
		req = c->pending;
	}
#endif

	if (req == NULL) {
		DEBUG(2,("dcerpc_request: unmatched call_id %u in response packet\n", pkt->call_id));
		data_blob_free(raw_packet);
		return;
	}

	talloc_steal(req, raw_packet->data);

	if (req->recv_handler != NULL) {
		dcerpc_req_dequeue(req);
		req->state = RPC_REQUEST_DONE;

		/*
		 * We have to look at shipping further requests before calling
		 * the async function, that one might close the pipe
		 */
		dcerpc_schedule_io_trigger(c);

		req->recv_handler(req, raw_packet, pkt);
		return;
	}

	if (pkt->ptype == DCERPC_PKT_FAULT) {
		status = dcerpc_fault_to_nt_status(pkt->u.fault.status);
		DEBUG(5,("rpc fault: %s\n", dcerpc_errstr(c, pkt->u.fault.status)));
		if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {
			dcerpc_connection_dead(c, status);
			return;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR)) {
			dcerpc_connection_dead(c, status);
			return;
		}
		req->fault_code = pkt->u.fault.status;
		req->status = NT_STATUS_NET_WRITE_FAULT;
		goto req_done;
	}

	if (pkt->ptype != DCERPC_PKT_RESPONSE) {
		DEBUG(2,("Unexpected packet type %d in dcerpc response\n",
			 (int)pkt->ptype)); 
		dcerpc_connection_dead(c, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	/* now check the status from the auth routines, and if it failed then fail
	   this request accordingly */
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_connection_dead(c, status);
		return;
	}

	length = pkt->u.response.stub_and_verifier.length;

	if (req->payload.length + length > c->max_total_response_size) {
		DEBUG(2,("Unexpected total payload 0x%X > 0x%X dcerpc response\n",
			 (unsigned)req->payload.length + length,
			 (unsigned)c->max_total_response_size));
		dcerpc_connection_dead(c, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	if (length > 0) {
		req->payload.data = talloc_realloc(req, 
						   req->payload.data, 
						   uint8_t,
						   req->payload.length + length);
		if (!req->payload.data) {
			req->status = NT_STATUS_NO_MEMORY;
			goto req_done;
		}
		memcpy(req->payload.data+req->payload.length, 
		       pkt->u.response.stub_and_verifier.data, length);
		req->payload.length += length;
	}

	if (!(pkt->pfc_flags & DCERPC_PFC_FLAG_LAST)) {
		data_blob_free(raw_packet);
		dcerpc_send_read(c);
		return;
	}

	if (req->verify_bitmask1) {
		req->p->conn->security_state.verified_bitmask1 = true;
	}
	if (req->verify_pcontext) {
		req->p->verified_pcontext = true;
	}

	if (!(pkt->drep[0] & DCERPC_DREP_LE)) {
		req->flags |= DCERPC_PULL_BIGENDIAN;
	} else {
		req->flags &= ~DCERPC_PULL_BIGENDIAN;
	}

req_done:
	data_blob_free(raw_packet);

	/* we've got the full payload */
	dcerpc_req_dequeue(req);
	req->state = RPC_REQUEST_DONE;

	/*
	 * We have to look at shipping further requests before calling
	 * the async function, that one might close the pipe
	 */
	dcerpc_schedule_io_trigger(c);

	if (req->async.callback) {
		req->async.callback(req);
	}
}

static NTSTATUS dcerpc_request_prepare_vt(struct rpc_request *req);

/*
  perform the send side of a async dcerpc request
*/
static struct rpc_request *dcerpc_request_send(TALLOC_CTX *mem_ctx,
					       struct dcerpc_pipe *p,
					       const struct GUID *object,
					       uint16_t opnum,
					       DATA_BLOB *stub_data)
{
	struct rpc_request *req;
	NTSTATUS status;

	req = talloc_zero(mem_ctx, struct rpc_request);
	if (req == NULL) {
		return NULL;
	}

	req->p = p;
	req->call_id = next_call_id(p->conn);
	req->state = RPC_REQUEST_QUEUED;

	if (object != NULL) {
		req->object = (struct GUID *)talloc_memdup(req, (const void *)object, sizeof(*object));
		if (req->object == NULL) {
			talloc_free(req);
			return NULL;
		}
	}

	req->opnum = opnum;
	req->request_data.length = stub_data->length;
	req->request_data.data = stub_data->data;

	status = dcerpc_request_prepare_vt(req);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	DLIST_ADD_END(p->conn->request_queue, req);
	talloc_set_destructor(req, dcerpc_req_dequeue);

	dcerpc_schedule_io_trigger(p->conn);

	if (p->request_timeout) {
		tevent_add_timer(p->conn->event_ctx, req,
				timeval_current_ofs(p->request_timeout, 0), 
				dcerpc_timeout_handler, req);
	}

	return req;
}

static NTSTATUS dcerpc_request_prepare_vt(struct rpc_request *req)
{
	struct dcecli_security *sec = &req->p->conn->security_state;
	struct dcerpc_sec_verification_trailer *t;
	struct dcerpc_sec_vt *c = NULL;
	struct ndr_push *ndr = NULL;
	enum ndr_err_code ndr_err;

	if (sec->auth_level < DCERPC_AUTH_LEVEL_PACKET) {
		return NT_STATUS_OK;
	}

	t = talloc_zero(req, struct dcerpc_sec_verification_trailer);
	if (t == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!sec->verified_bitmask1) {
		t->commands = talloc_realloc(t, t->commands,
					     struct dcerpc_sec_vt,
					     t->count.count + 1);
		if (t->commands == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		c = &t->commands[t->count.count++];
		ZERO_STRUCTP(c);

		c->command = DCERPC_SEC_VT_COMMAND_BITMASK1;
		if (req->p->conn->flags & DCERPC_PROPOSE_HEADER_SIGNING) {
			c->u.bitmask1 = DCERPC_SEC_VT_CLIENT_SUPPORTS_HEADER_SIGNING;
		}
		req->verify_bitmask1 = true;
	}

	if (!req->p->verified_pcontext) {
		t->commands = talloc_realloc(t, t->commands,
					     struct dcerpc_sec_vt,
					     t->count.count + 1);
		if (t->commands == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		c = &t->commands[t->count.count++];
		ZERO_STRUCTP(c);

		c->command = DCERPC_SEC_VT_COMMAND_PCONTEXT;
		c->u.pcontext.abstract_syntax = req->p->syntax;
		c->u.pcontext.transfer_syntax = req->p->transfer_syntax;

		req->verify_pcontext = true;
	}

	if (!(req->p->conn->flags & DCERPC_HEADER_SIGNING)) {
		t->commands = talloc_realloc(t, t->commands,
					     struct dcerpc_sec_vt,
					     t->count.count + 1);
		if (t->commands == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		c = &t->commands[t->count.count++];
		ZERO_STRUCTP(c);

		c->command = DCERPC_SEC_VT_COMMAND_HEADER2;
		c->u.header2.ptype = DCERPC_PKT_REQUEST;
		if (req->p->conn->flags & DCERPC_PUSH_BIGENDIAN) {
			c->u.header2.drep[0] = 0;
		} else {
			c->u.header2.drep[0] = DCERPC_DREP_LE;
		}
		c->u.header2.drep[1] = 0;
		c->u.header2.drep[2] = 0;
		c->u.header2.drep[3] = 0;
		c->u.header2.call_id = req->call_id;
		c->u.header2.context_id = req->p->context_id;
		c->u.header2.opnum = req->opnum;
	}

	if (t->count.count == 0) {
		TALLOC_FREE(t);
		return NT_STATUS_OK;
	}

	c = &t->commands[t->count.count - 1];
	c->command |= DCERPC_SEC_VT_COMMAND_END;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(dcerpc_sec_verification_trailer, t);
	}

	ndr = ndr_push_init_ctx(req);
	if (ndr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * for now we just copy and append
	 */

	ndr_err = ndr_push_bytes(ndr, req->request_data.data,
				 req->request_data.length);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	ndr_err = ndr_push_dcerpc_sec_verification_trailer(ndr,
						NDR_SCALARS | NDR_BUFFERS,
						t);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}
	req->request_data = ndr_push_blob(ndr);

	return NT_STATUS_OK;
}

/*
  Send a request using the transport
*/

static void dcerpc_ship_next_request(struct dcecli_connection *c)
{
	struct rpc_request *req;
	struct dcerpc_pipe *p;
	DATA_BLOB *stub_data;
	struct ncacn_packet pkt;
	DATA_BLOB blob;
	uint32_t remaining, chunk_size;
	bool first_packet = true;
	size_t sig_size = 0;
	bool need_async = false;
	bool can_async = true;

	req = c->request_queue;
	if (req == NULL) {
		return;
	}

	p = req->p;
	stub_data = &req->request_data;

	if (c->pending) {
		need_async = true;
	}

	if (c->security_state.auth_level >= DCERPC_AUTH_LEVEL_PACKET) {
		can_async = gensec_have_feature(c->security_state.generic_state,
						GENSEC_FEATURE_ASYNC_REPLIES);
	}

	if (need_async && !can_async) {
		req->wait_for_sync = true;
		return;
	}

	DLIST_REMOVE(c->request_queue, req);
	DLIST_ADD(c->pending, req);
	req->state = RPC_REQUEST_PENDING;

	init_ncacn_hdr(p->conn, &pkt);

	remaining = stub_data->length;

	/* we can write a full max_recv_frag size, minus the dcerpc
	   request header size */
	chunk_size = p->conn->srv_max_recv_frag;
	chunk_size -= DCERPC_REQUEST_LENGTH;
	if (c->security_state.auth_level >= DCERPC_AUTH_LEVEL_PACKET) {
		size_t max_payload = chunk_size;

		max_payload -= DCERPC_AUTH_TRAILER_LENGTH;
		max_payload -= (max_payload % DCERPC_AUTH_PAD_ALIGNMENT);

		sig_size = gensec_sig_size(c->security_state.generic_state,
					   max_payload);
		if (sig_size) {
			chunk_size -= DCERPC_AUTH_TRAILER_LENGTH;
			chunk_size -= sig_size;
		}
	}
	chunk_size -= (chunk_size % DCERPC_AUTH_PAD_ALIGNMENT);

	pkt.ptype = DCERPC_PKT_REQUEST;
	pkt.call_id = req->call_id;
	pkt.auth_length = 0;
	pkt.pfc_flags = 0;
	pkt.u.request.context_id = p->context_id;
	pkt.u.request.opnum = req->opnum;

	if (req->object) {
		pkt.u.request.object.object = *req->object;
		pkt.pfc_flags |= DCERPC_PFC_FLAG_OBJECT_UUID;
		chunk_size -= ndr_size_GUID(req->object,0);
	}

	/* we send a series of pdus without waiting for a reply */
	while (remaining > 0 || first_packet) {
		uint32_t chunk = MIN(chunk_size, remaining);
		bool last_frag = false;
		bool do_trans = false;

		first_packet = false;
		pkt.pfc_flags &= ~(DCERPC_PFC_FLAG_FIRST |DCERPC_PFC_FLAG_LAST);

		if (remaining == stub_data->length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_FIRST;
		}
		if (chunk == remaining) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_LAST;
			last_frag = true;
		}

		pkt.u.request.alloc_hint = remaining;
		pkt.u.request.stub_and_verifier.data = stub_data->data + 
			(stub_data->length - remaining);
		pkt.u.request.stub_and_verifier.length = chunk;

		req->status = ncacn_push_request_sign(p->conn, &blob, req, sig_size, &pkt);
		if (!NT_STATUS_IS_OK(req->status)) {
			req->state = RPC_REQUEST_DONE;
			DLIST_REMOVE(p->conn->pending, req);
			return;
		}

		if (last_frag && !need_async) {
			do_trans = true;
		}

		req->status = dcerpc_send_request(p->conn, &blob, do_trans);
		if (!NT_STATUS_IS_OK(req->status)) {
			req->state = RPC_REQUEST_DONE;
			DLIST_REMOVE(p->conn->pending, req);
			return;
		}		

		if (last_frag && !do_trans) {
			req->status = dcerpc_send_read(p->conn);
			if (!NT_STATUS_IS_OK(req->status)) {
				req->state = RPC_REQUEST_DONE;
				DLIST_REMOVE(p->conn->pending, req);
				return;
			}
		}

		remaining -= chunk;
	}
}

static void dcerpc_io_trigger(struct tevent_context *ctx,
			      struct tevent_immediate *im,
			      void *private_data)
{
	struct dcecli_connection *c =
		talloc_get_type_abort(private_data,
		struct dcecli_connection);

	c->io_trigger_pending = false;

	dcerpc_schedule_io_trigger(c);

	dcerpc_ship_next_request(c);
}

static void dcerpc_schedule_io_trigger(struct dcecli_connection *c)
{
	if (c->dead) {
		return;
	}

	if (c->request_queue == NULL) {
		return;
	}

	if (c->request_queue->wait_for_sync && c->pending) {
		return;
	}

	if (c->io_trigger_pending) {
		return;
	}

	c->io_trigger_pending = true;

	tevent_schedule_immediate(c->io_trigger,
				  c->event_ctx,
				  dcerpc_io_trigger,
				  c);
}

/*
  perform the receive side of a async dcerpc request
*/
static NTSTATUS dcerpc_request_recv(struct rpc_request *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *stub_data)
{
	NTSTATUS status;

	while (req->state != RPC_REQUEST_DONE) {
		struct tevent_context *ctx = req->p->conn->event_ctx;
		if (tevent_loop_once(ctx) != 0) {
			return NT_STATUS_CONNECTION_DISCONNECTED;
		}
	}
	*stub_data = req->payload;
	status = req->status;
	if (stub_data->data) {
		stub_data->data = talloc_steal(mem_ctx, stub_data->data);
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		req->p->last_fault_code = req->fault_code;
	}
	talloc_unlink(talloc_parent(req), req);
	return status;
}

/*
  this is a paranoid NDR validator. For every packet we push onto the wire
  we pull it back again, then push it again. Then we compare the raw NDR data
  for that to the NDR we initially generated. If they don't match then we know
  we must have a bug in either the pull or push side of our code
*/
static NTSTATUS dcerpc_ndr_validate_in(struct dcecli_connection *c, 
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB blob,
				       size_t struct_size,
				       ndr_push_flags_fn_t ndr_push,
				       ndr_pull_flags_fn_t ndr_pull)
{
	void *st;
	struct ndr_pull *pull;
	struct ndr_push *push;
	DATA_BLOB blob2;
	enum ndr_err_code ndr_err;

	st = talloc_size(mem_ctx, struct_size);
	if (!st) {
		return NT_STATUS_NO_MEMORY;
	}

	pull = ndr_pull_init_flags(c, &blob, mem_ctx);
	if (!pull) {
		return NT_STATUS_NO_MEMORY;
	}
	pull->flags |= LIBNDR_FLAG_REF_ALLOC;

	if (c->flags & DCERPC_PUSH_BIGENDIAN) {
		pull->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	if (c->flags & DCERPC_NDR64) {
		pull->flags |= LIBNDR_FLAG_NDR64;
	}

	ndr_err = ndr_pull(pull, NDR_IN, st);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		ndr_err = ndr_pull_error(pull, NDR_ERR_VALIDATE,
					 "failed input validation pull - %s",
					 nt_errstr(status));
		return ndr_map_error2ntstatus(ndr_err);
	}

	push = ndr_push_init_ctx(mem_ctx);
	if (!push) {
		return NT_STATUS_NO_MEMORY;
	}	

	if (c->flags & DCERPC_PUSH_BIGENDIAN) {
		push->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	if (c->flags & DCERPC_NDR64) {
		push->flags |= LIBNDR_FLAG_NDR64;
	}

	ndr_err = ndr_push(push, NDR_IN, st);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		ndr_err = ndr_pull_error(pull, NDR_ERR_VALIDATE,
					 "failed input validation push - %s",
					 nt_errstr(status));
		return ndr_map_error2ntstatus(ndr_err);
	}

	blob2 = ndr_push_blob(push);

	if (data_blob_cmp(&blob, &blob2) != 0) {
		DEBUG(3,("original:\n"));
		dump_data(3, blob.data, blob.length);
		DEBUG(3,("secondary:\n"));
		dump_data(3, blob2.data, blob2.length);
		ndr_err = ndr_pull_error(pull, NDR_ERR_VALIDATE,
					 "failed input validation blobs doesn't match");
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

/*
  this is a paranoid NDR input validator. For every packet we pull
  from the wire we push it back again then pull and push it
  again. Then we compare the raw NDR data for that to the NDR we
  initially generated. If they don't match then we know we must have a
  bug in either the pull or push side of our code
*/
static NTSTATUS dcerpc_ndr_validate_out(struct dcecli_connection *c,
					struct ndr_pull *pull_in,
					void *struct_ptr,
					size_t struct_size,
					ndr_push_flags_fn_t ndr_push,
					ndr_pull_flags_fn_t ndr_pull,
					ndr_print_function_t ndr_print)
{
	void *st;
	struct ndr_pull *pull;
	struct ndr_push *push;
	DATA_BLOB blob, blob2;
	TALLOC_CTX *mem_ctx = pull_in;
	char *s1, *s2;
	enum ndr_err_code ndr_err;

	st = talloc_size(mem_ctx, struct_size);
	if (!st) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(st, struct_ptr, struct_size);

	push = ndr_push_init_ctx(mem_ctx);
	if (!push) {
		return NT_STATUS_NO_MEMORY;
	}	

	ndr_err = ndr_push(push, NDR_OUT, struct_ptr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		ndr_err = ndr_push_error(push, NDR_ERR_VALIDATE,
					 "failed output validation push - %s",
					 nt_errstr(status));
		return ndr_map_error2ntstatus(ndr_err);
	}

	blob = ndr_push_blob(push);

	pull = ndr_pull_init_flags(c, &blob, mem_ctx);
	if (!pull) {
		return NT_STATUS_NO_MEMORY;
	}

	pull->flags |= LIBNDR_FLAG_REF_ALLOC;
	ndr_err = ndr_pull(pull, NDR_OUT, st);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		ndr_err = ndr_pull_error(pull, NDR_ERR_VALIDATE,
					 "failed output validation pull - %s",
					 nt_errstr(status));
		return ndr_map_error2ntstatus(ndr_err);
	}

	push = ndr_push_init_ctx(mem_ctx);
	if (!push) {
		return NT_STATUS_NO_MEMORY;
	}	

	ndr_err = ndr_push(push, NDR_OUT, st);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		ndr_err = ndr_push_error(push, NDR_ERR_VALIDATE,
					 "failed output validation push2 - %s",
					 nt_errstr(status));
		return ndr_map_error2ntstatus(ndr_err);
	}

	blob2 = ndr_push_blob(push);

	if (data_blob_cmp(&blob, &blob2) != 0) {
		DEBUG(3,("original:\n"));
		dump_data(3, blob.data, blob.length);
		DEBUG(3,("secondary:\n"));
		dump_data(3, blob2.data, blob2.length);
		ndr_err = ndr_push_error(push, NDR_ERR_VALIDATE,
					 "failed output validation blobs doesn't match");
		return ndr_map_error2ntstatus(ndr_err);
	}

	/* this checks the printed forms of the two structures, which effectively
	   tests all of the value() attributes */
	s1 = ndr_print_function_string(mem_ctx, ndr_print, "VALIDATE", 
				       NDR_OUT, struct_ptr);
	s2 = ndr_print_function_string(mem_ctx, ndr_print, "VALIDATE", 
				       NDR_OUT, st);
	if (strcmp(s1, s2) != 0) {
#if 1
		DEBUG(3,("VALIDATE ERROR:\nWIRE:\n%s\n GEN:\n%s\n", s1, s2));
#else
		/* this is sometimes useful */
		printf("VALIDATE ERROR\n");
		file_save("wire.dat", s1, strlen(s1));
		file_save("gen.dat", s2, strlen(s2));
		system("diff -u wire.dat gen.dat");
#endif
		ndr_err = ndr_push_error(push, NDR_ERR_VALIDATE,
					 "failed output validation strings doesn't match");
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

/*
  a useful function for retrieving the server name we connected to
*/
_PUBLIC_ const char *dcerpc_server_name(struct dcerpc_pipe *p)
{
	return p->conn ? p->conn->server_name : NULL;
}


/*
  get the dcerpc auth_level for a open connection
*/
uint32_t dcerpc_auth_level(struct dcecli_connection *c) 
{
	uint8_t auth_level;

	if (c->flags & DCERPC_SEAL) {
		auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	} else if (c->flags & DCERPC_SIGN) {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	} else if (c->flags & DCERPC_PACKET) {
		auth_level = DCERPC_AUTH_LEVEL_PACKET;
	} else if (c->flags & DCERPC_CONNECT) {
		auth_level = DCERPC_AUTH_LEVEL_CONNECT;
	} else {
		auth_level = DCERPC_AUTH_LEVEL_NONE;
	}
	return auth_level;
}

struct dcerpc_alter_context_state {
	struct tevent_context *ev;
	struct dcerpc_pipe *p;
};

static void dcerpc_alter_context_fail_handler(struct rpc_request *subreq);
static void dcerpc_alter_context_recv_handler(struct rpc_request *req,
					      DATA_BLOB *raw_packet,
					      struct ncacn_packet *pkt);

struct tevent_req *dcerpc_alter_context_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct dcerpc_pipe *p,
					     const struct ndr_syntax_id *syntax,
					     const struct ndr_syntax_id *transfer_syntax)
{
	struct tevent_req *req;
	struct dcerpc_alter_context_state *state;
	struct ncacn_packet pkt;
	DATA_BLOB blob;
	NTSTATUS status;
	struct rpc_request *subreq;
	uint32_t flags;

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_alter_context_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->p = p;

	p->syntax = *syntax;
	p->transfer_syntax = *transfer_syntax;

	flags = dcerpc_binding_get_flags(p->binding);

	init_ncacn_hdr(p->conn, &pkt);

	pkt.ptype = DCERPC_PKT_ALTER;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.call_id = p->conn->call_id;
	pkt.auth_length = 0;

	if (flags & DCERPC_CONCURRENT_MULTIPLEX) {
		pkt.pfc_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	pkt.u.alter.max_xmit_frag = p->conn->srv_max_xmit_frag;
	pkt.u.alter.max_recv_frag = p->conn->srv_max_recv_frag;
	pkt.u.alter.assoc_group_id = dcerpc_binding_get_assoc_group_id(p->binding);
	pkt.u.alter.num_contexts = 1;
	pkt.u.alter.ctx_list = talloc_zero_array(state, struct dcerpc_ctx_list,
						 pkt.u.alter.num_contexts);
	if (tevent_req_nomem(pkt.u.alter.ctx_list, req)) {
		return tevent_req_post(req, ev);
	}
	pkt.u.alter.ctx_list[0].context_id = p->context_id;
	pkt.u.alter.ctx_list[0].num_transfer_syntaxes = 1;
	pkt.u.alter.ctx_list[0].abstract_syntax = p->syntax;
	pkt.u.alter.ctx_list[0].transfer_syntaxes = &p->transfer_syntax;
	pkt.u.alter.auth_info = data_blob(NULL, 0);

	/* construct the NDR form of the packet */
	status = dcerpc_ncacn_push_auth(&blob,
				state,
				&pkt,
				p->conn->security_state.tmp_auth_info.out);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * we allocate a dcerpc_request so we can be in the same
	 * request queue as normal requests
	 */
	subreq = talloc_zero(state, struct rpc_request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	subreq->state = RPC_REQUEST_PENDING;
	subreq->call_id = pkt.call_id;
	subreq->async.private_data = req;
	subreq->async.callback = dcerpc_alter_context_fail_handler;
	subreq->p = p;
	subreq->recv_handler = dcerpc_alter_context_recv_handler;
	DLIST_ADD_END(p->conn->pending, subreq);
	talloc_set_destructor(subreq, dcerpc_req_dequeue);

	status = dcerpc_send_request(p->conn, &blob, true);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_add_timer(ev, subreq,
			 timeval_current_ofs(DCERPC_REQUEST_TIMEOUT, 0),
			 dcerpc_timeout_handler, subreq);

	return req;
}

static void dcerpc_alter_context_fail_handler(struct rpc_request *subreq)
{
	struct tevent_req *req =
		talloc_get_type_abort(subreq->async.private_data,
		struct tevent_req);
	struct dcerpc_alter_context_state *state =
		tevent_req_data(req,
		struct dcerpc_alter_context_state);
	NTSTATUS status = subreq->status;

	TALLOC_FREE(subreq);

	/*
	 * We trigger the callback in the next event run
	 * because the code in this file might trigger
	 * multiple request callbacks from within a single
	 * while loop.
	 *
	 * In order to avoid segfaults from within
	 * dcerpc_connection_dead() we call
	 * tevent_req_defer_callback().
	 */
	tevent_req_defer_callback(req, state->ev);

	tevent_req_nterror(req, status);
}

static void dcerpc_alter_context_recv_handler(struct rpc_request *subreq,
					      DATA_BLOB *raw_packet,
					      struct ncacn_packet *pkt)
{
	struct tevent_req *req =
		talloc_get_type_abort(subreq->async.private_data,
		struct tevent_req);
	struct dcerpc_alter_context_state *state =
		tevent_req_data(req,
		struct dcerpc_alter_context_state);
	struct dcecli_connection *conn = state->p->conn;
	struct dcecli_security *sec = &conn->security_state;
	struct dcerpc_binding *b = NULL;
	NTSTATUS status;

	/*
	 * Note that pkt is allocated under raw_packet->data,
	 * while raw_packet->data is a child of subreq.
	 */
	talloc_steal(state, raw_packet->data);
	TALLOC_FREE(subreq);

	/*
	 * We trigger the callback in the next event run
	 * because the code in this file might trigger
	 * multiple request callbacks from within a single
	 * while loop.
	 *
	 * In order to avoid segfaults from within
	 * dcerpc_connection_dead() we call
	 * tevent_req_defer_callback().
	 */
	tevent_req_defer_callback(req, state->ev);

	if (pkt->ptype == DCERPC_PKT_FAULT) {
		DEBUG(5,("dcerpc: alter_resp - rpc fault: %s\n",
			 dcerpc_errstr(state, pkt->u.fault.status)));
		if (pkt->u.fault.status == DCERPC_FAULT_ACCESS_DENIED) {
			state->p->last_fault_code = pkt->u.fault.status;
			tevent_req_nterror(req, NT_STATUS_LOGON_FAILURE);
		} else if (pkt->u.fault.status == DCERPC_FAULT_SEC_PKG_ERROR) {
			state->p->last_fault_code = pkt->u.fault.status;
			tevent_req_nterror(req, NT_STATUS_LOGON_FAILURE);
		} else {
			state->p->last_fault_code = pkt->u.fault.status;
			status = dcerpc_fault_to_nt_status(pkt->u.fault.status);
			tevent_req_nterror(req, status);
		}
		return;
	}

	status = dcerpc_verify_ncacn_packet_header(pkt,
					DCERPC_PKT_ALTER_RESP,
					pkt->u.alter_resp.auth_info.length,
					DCERPC_PFC_FLAG_FIRST |
					DCERPC_PFC_FLAG_LAST,
					DCERPC_PFC_FLAG_CONC_MPX |
					DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN);
	if (!NT_STATUS_IS_OK(status)) {
		state->p->last_fault_code = DCERPC_NCA_S_PROTO_ERROR;
		tevent_req_nterror(req, NT_STATUS_NET_WRITE_FAULT);
		return;
	}

	if (pkt->u.alter_resp.num_results != 1) {
		state->p->last_fault_code = DCERPC_NCA_S_PROTO_ERROR;
		tevent_req_nterror(req, NT_STATUS_NET_WRITE_FAULT);
		return;
	}

	if (pkt->u.alter_resp.ctx_list[0].result != 0) {
		status = dcerpc_map_ack_reason(&pkt->u.alter_resp.ctx_list[0]);
		DEBUG(2,("dcerpc: alter_resp failed - reason %d - %s\n",
			 pkt->u.alter_resp.ctx_list[0].reason.value,
			 nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}

	/* the alter_resp might contain a reply set of credentials */
	if (pkt->auth_length != 0 && sec->tmp_auth_info.in != NULL) {
		status = dcerpc_pull_auth_trailer(pkt, sec->tmp_auth_info.mem,
						  &pkt->u.alter_resp.auth_info,
						  sec->tmp_auth_info.in,
						  NULL, true);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	/*
	 * We're the owner of the binding, so we're allowed to modify it.
	 */
	b = discard_const_p(struct dcerpc_binding, state->p->binding);
	status = dcerpc_binding_set_abstract_syntax(b, &state->p->syntax);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS dcerpc_alter_context_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/* 
   send a dcerpc alter_context request
*/
_PUBLIC_ NTSTATUS dcerpc_alter_context(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx,
			      const struct ndr_syntax_id *syntax,
			      const struct ndr_syntax_id *transfer_syntax)
{
	struct tevent_req *subreq;
	struct tevent_context *ev = p->conn->event_ctx;
	bool ok;

	/* TODO: create a new event context here */

	subreq = dcerpc_alter_context_send(mem_ctx, ev,
					   p, syntax, transfer_syntax);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		NTSTATUS status;
		status = map_nt_error_from_unix_common(errno);
		return status;
	}

	return dcerpc_alter_context_recv(subreq);
}

static void dcerpc_transport_dead(struct dcecli_connection *c, NTSTATUS status)
{
	if (c->transport.stream == NULL) {
		return;
	}

	tevent_queue_stop(c->transport.write_queue);
	TALLOC_FREE(c->transport.read_subreq);
	TALLOC_FREE(c->transport.stream);

	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	if (NT_STATUS_EQUAL(NT_STATUS_OK, status)) {
		status = NT_STATUS_END_OF_FILE;
	}

	dcerpc_recv_data(c, NULL, status);
}


/*
   shutdown SMB pipe connection
*/
struct dcerpc_shutdown_pipe_state {
	struct dcecli_connection *c;
	NTSTATUS status;
};

static void dcerpc_shutdown_pipe_done(struct tevent_req *subreq);

static NTSTATUS dcerpc_shutdown_pipe(struct dcecli_connection *c, NTSTATUS status)
{
	struct dcerpc_shutdown_pipe_state *state;
	struct tevent_req *subreq;

	if (c->transport.stream == NULL) {
		return NT_STATUS_OK;
	}

	state = talloc_zero(c, struct dcerpc_shutdown_pipe_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->c = c;
	state->status = status;

	subreq = tstream_disconnect_send(state, c->event_ctx, c->transport.stream);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, dcerpc_shutdown_pipe_done, state);

	return status;
}

static void dcerpc_shutdown_pipe_done(struct tevent_req *subreq)
{
	struct dcerpc_shutdown_pipe_state *state =
		tevent_req_callback_data(subreq, struct dcerpc_shutdown_pipe_state);
	struct dcecli_connection *c = state->c;
	NTSTATUS status = state->status;
	int error;

	/*
	 * here we ignore the return values...
	 */
	tstream_disconnect_recv(subreq, &error);
	TALLOC_FREE(subreq);

	TALLOC_FREE(state);

	dcerpc_transport_dead(c, status);
}



struct dcerpc_send_read_state {
	struct dcecli_connection *p;
};

static int dcerpc_send_read_state_destructor(struct dcerpc_send_read_state *state)
{
	struct dcecli_connection *p = state->p;

	p->transport.read_subreq = NULL;

	return 0;
}

static void dcerpc_send_read_done(struct tevent_req *subreq);

static NTSTATUS dcerpc_send_read(struct dcecli_connection *p)
{
	struct dcerpc_send_read_state *state;

	if (p->transport.read_subreq != NULL) {
		p->transport.pending_reads++;
		return NT_STATUS_OK;
	}

	state = talloc_zero(p, struct dcerpc_send_read_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->p = p;

	talloc_set_destructor(state, dcerpc_send_read_state_destructor);

	p->transport.read_subreq = dcerpc_read_ncacn_packet_send(state,
							  p->event_ctx,
							  p->transport.stream);
	if (p->transport.read_subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(p->transport.read_subreq, dcerpc_send_read_done, state);

	return NT_STATUS_OK;
}

static void dcerpc_send_read_done(struct tevent_req *subreq)
{
	struct dcerpc_send_read_state *state =
		tevent_req_callback_data(subreq,
					 struct dcerpc_send_read_state);
	struct dcecli_connection *p = state->p;
	NTSTATUS status;
	struct ncacn_packet *pkt;
	DATA_BLOB blob;

	status = dcerpc_read_ncacn_packet_recv(subreq, state,
					       &pkt, &blob);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state);
		dcerpc_transport_dead(p, status);
		return;
	}

	/*
	 * here we steal into thet connection context,
	 * but p->transport.recv_data() will steal or free it again
	 */
	talloc_steal(p, blob.data);
	TALLOC_FREE(state);

	if (p->transport.pending_reads > 0) {
		p->transport.pending_reads--;

		status = dcerpc_send_read(p);
		if (!NT_STATUS_IS_OK(status)) {
			dcerpc_transport_dead(p, status);
			return;
		}
	}

	dcerpc_recv_data(p, &blob, NT_STATUS_OK);
}

struct dcerpc_send_request_state {
	struct dcecli_connection *p;
	DATA_BLOB blob;
	struct iovec iov;
};

static int dcerpc_send_request_state_destructor(struct dcerpc_send_request_state *state)
{
	struct dcecli_connection *p = state->p;

	p->transport.read_subreq = NULL;

	return 0;
}

static void dcerpc_send_request_wait_done(struct tevent_req *subreq);
static void dcerpc_send_request_done(struct tevent_req *subreq);

static NTSTATUS dcerpc_send_request(struct dcecli_connection *p, DATA_BLOB *data,
				    bool trigger_read)
{
	struct dcerpc_send_request_state *state;
	struct tevent_req *subreq;
	bool use_trans = trigger_read;

	if (p->transport.stream == NULL) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	state = talloc_zero(p, struct dcerpc_send_request_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->p = p;

	state->blob = data_blob_talloc(state, data->data, data->length);
	if (state->blob.data == NULL) {
		TALLOC_FREE(state);
		return NT_STATUS_NO_MEMORY;
	}
	state->iov.iov_base = (void *)state->blob.data;
	state->iov.iov_len = state->blob.length;

	if (p->transport.read_subreq != NULL) {
		use_trans = false;
	}

	if (!tstream_is_smbXcli_np(p->transport.stream)) {
		use_trans = false;
	}

	if (use_trans) {
		/*
		 * we need to block reads until our write is
		 * the next in the write queue.
		 */
		p->transport.read_subreq = tevent_queue_wait_send(state, p->event_ctx,
							     p->transport.write_queue);
		if (p->transport.read_subreq == NULL) {
			TALLOC_FREE(state);
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(p->transport.read_subreq,
					dcerpc_send_request_wait_done,
					state);

		talloc_set_destructor(state, dcerpc_send_request_state_destructor);

		trigger_read = false;
	}

	subreq = tstream_writev_queue_send(state, p->event_ctx,
					   p->transport.stream,
					   p->transport.write_queue,
					   &state->iov, 1);
	if (subreq == NULL) {
		TALLOC_FREE(state);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, dcerpc_send_request_done, state);

	if (trigger_read) {
		dcerpc_send_read(p);
	}

	return NT_STATUS_OK;
}

static void dcerpc_send_request_wait_done(struct tevent_req *subreq)
{
	struct dcerpc_send_request_state *state =
		tevent_req_callback_data(subreq,
		struct dcerpc_send_request_state);
	struct dcecli_connection *p = state->p;
	NTSTATUS status;
	bool ok;

	p->transport.read_subreq = NULL;
	talloc_set_destructor(state, NULL);

	ok = tevent_queue_wait_recv(subreq);
	if (!ok) {
		TALLOC_FREE(state);
		dcerpc_transport_dead(p, NT_STATUS_NO_MEMORY);
		return;
	}

	if (tevent_queue_length(p->transport.write_queue) <= 2) {
		status = tstream_smbXcli_np_use_trans(p->transport.stream);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(state);
			dcerpc_transport_dead(p, status);
			return;
		}
	}

	/* we free subreq after tstream_cli_np_use_trans */
	TALLOC_FREE(subreq);

	dcerpc_send_read(p);
}

static void dcerpc_send_request_done(struct tevent_req *subreq)
{
	struct dcerpc_send_request_state *state =
		tevent_req_callback_data(subreq,
		struct dcerpc_send_request_state);
	int ret;
	int error;

	ret = tstream_writev_queue_recv(subreq, &error);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		struct dcecli_connection *p = state->p;
		NTSTATUS status = map_nt_error_from_unix_common(error);

		TALLOC_FREE(state);
		dcerpc_transport_dead(p, status);
		return;
	}

	TALLOC_FREE(state);
}
