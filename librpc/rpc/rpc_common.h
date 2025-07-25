/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2010-2011
   Copyright (C) Andrew Tridgell 2010-2011
   Copyright (C) Simo Sorce 2010

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

#ifndef __DEFAULT_LIBRPC_RPCCOMMON_H__
#define __DEFAULT_LIBRPC_RPCCOMMON_H__

#include "lib/util/data_blob.h"

#include "gen_ndr/dcerpc.h"
#include "lib/util/attr.h"

#include "librpc/ndr/libndr.h"

struct dcerpc_binding_handle;
struct GUID;
struct ndr_interface_table;
struct ndr_interface_call;
struct ndr_push;
struct ndr_pull;
struct ncacn_packet;
struct epm_floor;
struct epm_tower;
struct tevent_context;
struct tstream_context;
struct gensec_security;

enum dcerpc_transport_t {
	NCA_UNKNOWN, NCACN_NP, NCACN_IP_TCP, NCACN_IP_UDP, NCACN_VNS_IPC,
	NCACN_VNS_SPP, NCACN_AT_DSP, NCADG_AT_DDP, NCALRPC, NCACN_UNIX_STREAM,
	NCADG_UNIX_DGRAM, NCACN_HTTP, NCADG_IPX, NCACN_SPX, NCACN_INTERNAL };

/** this describes a binding to a particular transport/pipe */
struct dcerpc_binding;

/* dcerpc pipe flags */
#define DCERPC_DEBUG_PRINT_IN          (1<<0)
#define DCERPC_DEBUG_PRINT_OUT         (1<<1)
#define DCERPC_DEBUG_PRINT_BOTH (DCERPC_DEBUG_PRINT_IN | DCERPC_DEBUG_PRINT_OUT)

#define DCERPC_DEBUG_VALIDATE_IN       (1<<2)
#define DCERPC_DEBUG_VALIDATE_OUT      (1<<3)
#define DCERPC_DEBUG_VALIDATE_BOTH (DCERPC_DEBUG_VALIDATE_IN | DCERPC_DEBUG_VALIDATE_OUT)

#define DCERPC_CONNECT                 (1<<4)
#define DCERPC_SIGN                    (1<<5)
#define DCERPC_SEAL                    (1<<6)

#define DCERPC_PUSH_BIGENDIAN          (1<<7)
#define DCERPC_PULL_BIGENDIAN          (1<<8)

#define DCERPC_SCHANNEL                (1<<9)

#define DCERPC_ANON_FALLBACK           (1<<10)

/* use a 128 bit session key */
#define DCERPC_SCHANNEL_128            (1<<12)

/* check incoming pad bytes */
#define DCERPC_DEBUG_PAD_CHECK         (1<<13)

/* set LIBNDR_FLAG_REF_ALLOC flag when decoding NDR */
#define DCERPC_NDR_REF_ALLOC           (1<<14)

#define DCERPC_AUTH_OPTIONS    (DCERPC_SEAL|DCERPC_SIGN|DCERPC_SCHANNEL|DCERPC_AUTH_SPNEGO|DCERPC_AUTH_KRB5|DCERPC_AUTH_NTLM)

/* select spnego auth */
#define DCERPC_AUTH_SPNEGO             (1<<15)

/* select krb5 auth */
#define DCERPC_AUTH_KRB5               (1<<16)

#define DCERPC_SMB2                    (1<<17)

/* select NTLM auth */
#define DCERPC_AUTH_NTLM               (1<<18)

/* this triggers the DCERPC_PFC_FLAG_CONC_MPX flag in the bind request */
#define DCERPC_CONCURRENT_MULTIPLEX     (1<<19)

/* this indicates DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN flag was negotiated */
#define DCERPC_HEADER_SIGNING          (1<<20)

/* use NDR64 transport */
#define DCERPC_NDR64                   (1<<21)

/* handle upgrades or downgrades automatically */
#define DCERPC_SCHANNEL_AUTO           (1<<23)

/* use aes schannel with hmac-sh256 session key */
#define DCERPC_SCHANNEL_AES            (1<<24)

/* this triggers the DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN flag in the bind request */
#define DCERPC_PROPOSE_HEADER_SIGNING          (1<<25)

#define DCERPC_PACKET			(1<<26)

#define DCERPC_SMB1                    (1<<27)

#define DCERPC_SCHANNEL_KRB5           (1<<28)

/* The following definitions come from ../librpc/rpc/dcerpc_error.c  */

const char *dcerpc_errstr(TALLOC_CTX *mem_ctx, uint32_t fault_code);
NTSTATUS dcerpc_fault_to_nt_status(uint32_t fault_code);
uint32_t dcerpc_fault_from_nt_status(NTSTATUS nt_status);

/* The following definitions come from ../librpc/rpc/binding.c  */

const char *epm_floor_string(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
char *dcerpc_floor_get_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
enum dcerpc_transport_t dcerpc_transport_by_endpoint_protocol(int prot);
struct dcerpc_binding *dcerpc_binding_dup(TALLOC_CTX *mem_ctx,
					  const struct dcerpc_binding *b);
NTSTATUS dcerpc_binding_build_tower(TALLOC_CTX *mem_ctx,
				    const struct dcerpc_binding *binding,
				    struct epm_tower *tower);
NTSTATUS dcerpc_binding_from_tower(TALLOC_CTX *mem_ctx,
				   struct epm_tower *tower,
				   struct dcerpc_binding **b_out);
NTSTATUS dcerpc_parse_binding(TALLOC_CTX *mem_ctx, const char *s, struct dcerpc_binding **b_out);
char *dcerpc_binding_string(TALLOC_CTX *mem_ctx, const struct dcerpc_binding *b);
struct GUID dcerpc_binding_get_object(const struct dcerpc_binding *b);
NTSTATUS dcerpc_binding_set_object(struct dcerpc_binding *b,
				   struct GUID object);
enum dcerpc_transport_t dcerpc_binding_get_transport(const struct dcerpc_binding *b);
NTSTATUS dcerpc_binding_set_transport(struct dcerpc_binding *b,
				      enum dcerpc_transport_t transport);
void dcerpc_binding_get_auth_info(const struct dcerpc_binding *b,
				  enum dcerpc_AuthType *_auth_type,
				  enum dcerpc_AuthLevel *_auth_level);
uint32_t dcerpc_binding_get_assoc_group_id(const struct dcerpc_binding *b);
NTSTATUS dcerpc_binding_set_assoc_group_id(struct dcerpc_binding *b,
					   uint32_t assoc_group_id);
struct ndr_syntax_id dcerpc_binding_get_abstract_syntax(const struct dcerpc_binding *b);
NTSTATUS dcerpc_binding_set_abstract_syntax(struct dcerpc_binding *b,
					    const struct ndr_syntax_id *syntax);
const char *dcerpc_binding_get_string_option(const struct dcerpc_binding *b,
					     const char *name);
char *dcerpc_binding_copy_string_option(TALLOC_CTX *mem_ctx,
					const struct dcerpc_binding *b,
					const char *name);
NTSTATUS dcerpc_binding_set_string_option(struct dcerpc_binding *b,
					  const char *name,
					  const char *value);
uint32_t dcerpc_binding_get_flags(const struct dcerpc_binding *b);
NTSTATUS dcerpc_binding_set_flags(struct dcerpc_binding *b,
				  uint32_t additional,
				  uint32_t clear);
NTSTATUS dcerpc_floor_get_uuid_full(const struct epm_floor *epm_floor, struct ndr_syntax_id *syntax);
const char *derpc_transport_string_by_transport(enum dcerpc_transport_t t);
enum dcerpc_transport_t dcerpc_transport_by_name(const char *name);
enum dcerpc_transport_t dcerpc_transport_by_tower(const struct epm_tower *tower);

/* The following definitions come from ../librpc/rpc/binding_handle.c  */

struct dcerpc_binding_handle_ops {
	const char *name;

	const struct dcerpc_binding *(*get_binding)(struct dcerpc_binding_handle *h);

	bool (*is_connected)(struct dcerpc_binding_handle *h);
	uint32_t (*set_timeout)(struct dcerpc_binding_handle *h,
				uint32_t timeout);

	bool (*transport_encrypted)(struct dcerpc_binding_handle *h);
	NTSTATUS (*transport_session_key)(struct dcerpc_binding_handle *h,
					  TALLOC_CTX *mem_ctx,
					  DATA_BLOB *session_key);

	void (*auth_info)(struct dcerpc_binding_handle *h,
			  enum dcerpc_AuthType *auth_type,
			  enum dcerpc_AuthLevel *auth_level);
	NTSTATUS (*auth_session_key)(struct dcerpc_binding_handle *h,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *session_key);

	struct tevent_req *(*raw_call_send)(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct dcerpc_binding_handle *h,
					    const struct GUID *object,
					    uint32_t opnum,
					    uint32_t in_flags,
					    const uint8_t *in_data,
					    size_t in_length);
	NTSTATUS (*raw_call_recv)(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  uint8_t **out_data,
				  size_t *out_length,
				  uint32_t *out_flags);

	struct tevent_req *(*disconnect_send)(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct dcerpc_binding_handle *h);
	NTSTATUS (*disconnect_recv)(struct tevent_req *req);

	/* TODO: remove the following functions */
	bool (*push_bigendian)(struct dcerpc_binding_handle *h);
	bool (*ref_alloc)(struct dcerpc_binding_handle *h);
	bool (*use_ndr64)(struct dcerpc_binding_handle *h);
	void (*do_ndr_print)(struct dcerpc_binding_handle *h,
			     ndr_flags_type ndr_flags,
			     const void *struct_ptr,
			     const struct ndr_interface_call *call);
	void (*ndr_push_failed)(struct dcerpc_binding_handle *h,
				NTSTATUS error,
				const void *struct_ptr,
				const struct ndr_interface_call *call);
	void (*ndr_pull_failed)(struct dcerpc_binding_handle *h,
				NTSTATUS error,
				const DATA_BLOB *blob,
				const struct ndr_interface_call *call);
	NTSTATUS (*ndr_validate_in)(struct dcerpc_binding_handle *h,
				    TALLOC_CTX *mem_ctx,
				    const DATA_BLOB *blob,
				    const struct ndr_interface_call *call);
	NTSTATUS (*ndr_validate_out)(struct dcerpc_binding_handle *h,
				     struct ndr_pull *pull_in,
				     const void *struct_ptr,
				     const struct ndr_interface_call *call);
};

struct dcerpc_binding_handle *_dcerpc_binding_handle_create(TALLOC_CTX *mem_ctx,
					const struct dcerpc_binding_handle_ops *ops,
					const struct GUID *object,
					const struct ndr_interface_table *table,
					void *pstate,
					size_t psize,
					const char *type,
					const char *location);
#define dcerpc_binding_handle_create(mem_ctx, ops, object, table, \
				state, type, location) \
	_dcerpc_binding_handle_create(mem_ctx, ops, object, table, \
				state, sizeof(type), #type, location)

void *_dcerpc_binding_handle_data(struct dcerpc_binding_handle *h);
#define dcerpc_binding_handle_data(_h, _type) \
	talloc_get_type_abort(_dcerpc_binding_handle_data(_h), _type)

_DEPRECATED_ void dcerpc_binding_handle_set_sync_ev(struct dcerpc_binding_handle *h,
						    struct tevent_context *ev);

const struct dcerpc_binding *dcerpc_binding_handle_get_binding(struct dcerpc_binding_handle *h);

enum dcerpc_transport_t dcerpc_binding_handle_get_transport(struct dcerpc_binding_handle *h);

bool dcerpc_binding_handle_is_connected(struct dcerpc_binding_handle *h);

uint32_t dcerpc_binding_handle_set_timeout(struct dcerpc_binding_handle *h,
					   uint32_t timeout);

bool dcerpc_binding_handle_transport_encrypted(struct dcerpc_binding_handle *h);

NTSTATUS dcerpc_binding_handle_transport_session_key(
		struct dcerpc_binding_handle *h,
		TALLOC_CTX *mem_ctx,
		DATA_BLOB *session_key);

void dcerpc_binding_handle_auth_info(struct dcerpc_binding_handle *h,
				     enum dcerpc_AuthType *auth_type,
				     enum dcerpc_AuthLevel *auth_level);

NTSTATUS dcerpc_binding_handle_auth_session_key(
		struct dcerpc_binding_handle *h,
		TALLOC_CTX *mem_ctx,
		DATA_BLOB *session_key);

struct tevent_req *dcerpc_binding_handle_raw_call_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h,
						const struct GUID *object,
						uint32_t opnum,
						uint32_t in_flags,
						const uint8_t *in_data,
						size_t in_length);
NTSTATUS dcerpc_binding_handle_raw_call_recv(struct tevent_req *req,
					     TALLOC_CTX *mem_ctx,
					     uint8_t **out_data,
					     size_t *out_length,
					     uint32_t *out_flags);
NTSTATUS dcerpc_binding_handle_raw_call(struct dcerpc_binding_handle *h,
					const struct GUID *object,
					uint32_t opnum,
					uint32_t in_flags,
					const uint8_t *in_data,
					size_t in_length,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags);

struct tevent_req *dcerpc_binding_handle_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h);
NTSTATUS dcerpc_binding_handle_disconnect_recv(struct tevent_req *req);

struct tevent_req *dcerpc_binding_handle_call_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct dcerpc_binding_handle *h,
					const struct GUID *object,
					const struct ndr_interface_table *table,
					uint32_t opnum,
					TALLOC_CTX *r_mem,
					void *r_ptr);
NTSTATUS dcerpc_binding_handle_call_recv(struct tevent_req *req);
NTSTATUS dcerpc_binding_handle_call(struct dcerpc_binding_handle *h,
				    const struct GUID *object,
				    const struct ndr_interface_table *table,
				    uint32_t opnum,
				    TALLOC_CTX *r_mem,
				    void *r_ptr);

/**
 * Extract header information from a ncacn_packet
 * as a dcerpc_sec_vt_header2 as used by the security verification trailer.
 *
 * @param[in] pkt a packet
 *
 * @return a dcerpc_sec_vt_header2
 */
struct dcerpc_sec_vt_header2 dcerpc_sec_vt_header2_from_ncacn_packet(const struct ncacn_packet *pkt);


/**
 * Test if two dcerpc_sec_vt_header2 structures are equal
 * without consideration of reserved fields.
 *
 * @param v1 a pointer to a dcerpc_sec_vt_header2 structure
 * @param v2 a pointer to a dcerpc_sec_vt_header2 structure
 *
 * @retval true if *v1 equals *v2
 */
bool dcerpc_sec_vt_header2_equal(const struct dcerpc_sec_vt_header2 *v1,
				 const struct dcerpc_sec_vt_header2 *v2);

/**
 * Check for consistency of the security verification trailer with the PDU header.
 * See <a href="http://msdn.microsoft.com/en-us/library/cc243559.aspx">MS-RPCE 2.2.2.13</a>.
 * A check with an empty trailer succeeds.
 *
 * @param[in] vt a pointer to the security verification trailer.
 * @param[in] bitmask1 which flags were negotiated on the connection.
 * @param[in] pcontext the syntaxes negotiated for the presentation context.
 * @param[in] header2 some fields from the PDU header.
 *
 * @retval true on success.
 */
bool dcerpc_sec_verification_trailer_check(
		const struct dcerpc_sec_verification_trailer *vt,
		const uint32_t *bitmask1,
		const struct dcerpc_sec_vt_pcontext *pcontext,
		const struct dcerpc_sec_vt_header2 *header2);

/**
 * @brief check and optionally extract the Bind Time Features from
 * the given ndr_syntax_id.
 *
 * <a href="http://msdn.microsoft.com/en-us/library/cc243715.aspx">MS-RPCE 3.3.1.5.3 Bind Time Feature Negotiation</a>.
 *
 * @param[in]  s the syntax that should be checked.
 *
 * @param[out] features This is optional, it will be filled with the extracted
 *                      features the on success, otherwise it's filled with 0.
 *
 * @return true if the syntax matches the 6CB71C2C-9812-4540 prefix with version 1, false otherwise.
 *
 * @see dcerpc_construct_bind_time_features
 */
bool dcerpc_extract_bind_time_features(struct ndr_syntax_id syntax, uint64_t *features);

/**
 * @brief Construct a ndr_syntax_id used for Bind Time Features Negotiation.
 *
 * <a href="http://msdn.microsoft.com/en-us/library/cc243715.aspx">MS-RPCE 3.3.1.5.3 Bind Time Feature Negotiation</a>.
 *
 * @param[in] features The supported features.
 *
 * @return The ndr_syntax_id with the given features.
 *
 * @see dcerpc_extract_bind_time_features
 */
struct ndr_syntax_id dcerpc_construct_bind_time_features(uint64_t features);

#define DCERPC_AUTH_PAD_LENGTH(stub_length) (\
	(((stub_length) % DCERPC_AUTH_PAD_ALIGNMENT) > 0)?\
	(DCERPC_AUTH_PAD_ALIGNMENT - (stub_length) % DCERPC_AUTH_PAD_ALIGNMENT):\
	0)

NTSTATUS dcerpc_generic_session_key(DATA_BLOB *session_key);

NTSTATUS dcerpc_ncacn_push_auth(DATA_BLOB *blob,
				TALLOC_CTX *mem_ctx,
				struct ncacn_packet *pkt,
				struct dcerpc_auth *auth_info);

void dcerpc_log_packet(const char *packet_log_dir,
		       const char *interface_name,
		       uint32_t opnum, ndr_flags_type flags,
		       const DATA_BLOB *pkt,
		       const char *why);

#ifdef DEVELOPER
void dcerpc_save_ndr_fuzz_seed(TALLOC_CTX *mem_ctx,
			       DATA_BLOB raw_blob,
			       const char *dump_dir,
			       const char *iface_name,
			       ndr_flags_type flags,
			       int opnum,
			       bool ndr64);
#else
static inline void dcerpc_save_ndr_fuzz_seed(TALLOC_CTX *mem_ctx,
					     DATA_BLOB raw_blob,
					     const char *dump_dir,
					     const char *iface_name,
					     ndr_flags_type flags,
					     int opnum,
					     bool ndr64)
{
	return;
}
#endif

#endif /* __DEFAULT_LIBRPC_RPCCOMMON_H__ */
