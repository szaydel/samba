/* 
   Unix SMB/CIFS implementation.

   SMB2 client library header

   Copyright (C) Andrew Tridgell 2005
   
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

#ifndef __LIBCLI_SMB2_SMB2_H__
#define __LIBCLI_SMB2_SMB2_H__

#include "libcli/raw/request.h"
#include "libcli/raw/libcliraw.h"

struct smb2_handle;
struct smb2_lease_break;

struct smb2_request_buffer {
	/* the raw SMB2 buffer, including the 4 byte length header */
	uint8_t *buffer;

	/* the size of the raw buffer, including 4 byte header */
	size_t size;

	/* how much has been allocated - on reply the buffer is over-allocated to
	   prevent too many realloc() calls
	*/
	size_t allocated;

	/* the start of the SMB2 header - this is always buffer+4 */
	uint8_t *hdr;

	/* the packet body */
	uint8_t *body;
	size_t body_fixed;
	size_t body_size;

	/* this point to the next dynamic byte that can be used
	 * this will be moved when some dynamic data is pushed
	 */
	uint8_t *dynamic;

	/* this is used to range check and align strings and buffers */
	struct request_bufinfo bufinfo;
};

/* this is the context for the smb2 transport layer */
struct smb2_transport {
	struct tevent_context *ev; /* TODO: remove this !!! */
	struct smbXcli_conn *conn;

	/* the details for coumpounded requests */
	struct {
		bool related;
		struct tevent_req **reqs;
	} compound;

	/* an idle function - if this is defined then it will be
	   called once every period microseconds while we are waiting
	   for a packet */
	struct {
		void (*func)(struct smb2_transport *, void *);
		void *private_data;
		unsigned int period;
		struct tevent_timer *te;
	} idle;

	struct {
		/* a oplock break request handler */
		bool (*handler)(struct smb2_transport *transport,
				const struct smb2_handle *handle,
				uint8_t level, void *private_data);
		/* private data passed to the oplock handler */
		void *private_data;
	} oplock;

	struct {
		/* a lease break request handler */
		bool (*handler)(struct smb2_transport *transport,
				const struct smb2_lease_break *lease_break,
				void *private_data);
		/* private data passed to the oplock handler */
		void *private_data;
	} lease;
	struct tevent_req *break_subreq;

	struct smbcli_options options;
};


/*
  SMB2 LSA state
*/
struct smb2lsa_state {
	struct dcerpc_binding_handle *binding_handle;
	struct smb2_tree *ipc_tree;
	struct policy_handle handle;
};


/*
  SMB2 tree context
*/
struct smb2_tree {
	struct smb2_session *session;
	struct smbXcli_tcon *smbXcli;
	struct smb2lsa_state *lsa;
};

/*
  SMB2 session context
*/
struct smb2_session {
	struct smb2_transport *transport;
	struct gensec_security *gensec;
	struct smbXcli_session *smbXcli;
	bool needs_bind;
	bool anonymous_session_key;
	bool debug_encryption;
	const char *wireshark_keyfile;
	DATA_BLOB forced_session_key;
};



/*
  a client request moves between the following 4 states.
*/
enum smb2_request_state {SMB2_REQUEST_INIT, /* we are creating the request */
			SMB2_REQUEST_RECV, /* we are waiting for a matching reply */
			SMB2_REQUEST_DONE, /* the request is finished */
			SMB2_REQUEST_ERROR}; /* a packet or transport level error has occurred */

/* the context for a single SMB2 request */
struct smb2_request {
	/* each request is in one of 3 possible states */
	enum smb2_request_state state;

	struct tevent_req *subreq;

	struct smb2_transport *transport;
	struct smb2_session   *session;
	struct smb2_tree      *tree;

	struct {
		bool can_cancel;
	} cancel;

	/* the NT status for this request. Set by packet receive code
	   or code detecting error. */
	NTSTATUS status;

	struct smb2_request_buffer in;
	struct smb2_request_buffer out;
	struct iovec *recv_iov;

	uint16_t credit_charge;

	/* information on what to do with a reply when it is received
	   asynchronously. If this is not setup when a reply is received then
	   the reply is discarded

	   The private pointer is private to the caller of the client
	   library (the application), not private to the library
	*/
	struct {
		void (*fn)(struct smb2_request *);
		void *private_data;
	} async;
};


#define SMB2_MIN_SIZE 0x42
#define SMB2_MIN_SIZE_NO_BODY 0x40

/*
  check that a body has the expected size
*/
#define SMB2_CHECK_PACKET_RECV(req, size, dynamic) do { \
	size_t is_size = req->in.body_size; \
	uint16_t field_size = SVAL(req->in.body, 0); \
	uint16_t want_size = ((dynamic)?(size)+1:(size)); \
	if (is_size < (size)) { \
		DEBUG(0,("%s: buffer too small 0x%x. Expected 0x%x\n", \
			 __location__, (unsigned)is_size, (unsigned)want_size)); \
		return NT_STATUS_BUFFER_TOO_SMALL; \
	}\
	if (field_size != want_size) { \
		DEBUG(0,("%s: unexpected fixed body size 0x%x. Expected 0x%x\n", \
			 __location__, (unsigned)field_size, (unsigned)want_size)); \
		return NT_STATUS_INVALID_PARAMETER; \
	} \
} while (0)

#endif
