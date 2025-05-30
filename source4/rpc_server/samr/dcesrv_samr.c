/*
   Unix SMB/CIFS implementation.

   endpoint server for the samr pipe

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Matthias Dieter Wallnöfer 2009

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

#include "includes.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "rpc_server/samr/dcesrv_samr.h"
#include "system/time.h"
#include <ldb.h>
#include <ldb_errors.h>
#include "../libds/common/flags.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "libcli/ldap/ldap_ndr.h"
#include "libcli/security/security.h"
#include "rpc_server/samr/proto.h"
#include "../lib/util/util_ldb.h"
#include "param/param.h"
#include "lib/util/tsort.h"
#include "libds/common/flag_mapping.h"

#undef strcasecmp

#define DCESRV_INTERFACE_SAMR_BIND(context, iface) \
       dcesrv_interface_samr_bind(context, iface)
static NTSTATUS dcesrv_interface_samr_bind(struct dcesrv_connection_context *context,
					     const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_reject_connect(context, iface);
}

/* these query macros make samr_Query[User|Group|Alias]Info a bit easier to read */

#define QUERY_STRING(msg, field, attr) \
	info->field.string = ldb_msg_find_attr_as_string(msg, attr, "");
#define QUERY_UINT(msg, field, attr) \
	info->field = ldb_msg_find_attr_as_uint(msg, attr, 0);
#define QUERY_RID(msg, field, attr) \
	info->field = samdb_result_rid_from_sid(mem_ctx, msg, attr, 0);
#define QUERY_UINT64(msg, field, attr) \
	info->field = ldb_msg_find_attr_as_uint64(msg, attr, 0);
#define QUERY_APASSC(msg, field, attr) \
	info->field = samdb_result_allow_password_change(sam_ctx, mem_ctx, \
							 a_state->domain_state->domain_dn, msg, attr);
#define QUERY_BPWDCT(msg, field, attr) \
	info->field = samdb_result_effective_badPwdCount(sam_ctx, mem_ctx, \
							 a_state->domain_state->domain_dn, msg);
#define QUERY_LHOURS(msg, field, attr) \
	info->field = samdb_result_logon_hours(mem_ctx, msg, attr);
#define QUERY_AFLAGS(msg, field, attr) \
	info->field = samdb_result_acct_flags(msg, attr);


/* these are used to make the Set[User|Group]Info code easier to follow */

#define SET_STRING(msg, field, attr) do {				\
	struct ldb_message_element *set_el;				\
	if (r->in.info->field.string == NULL) return NT_STATUS_INVALID_PARAMETER; \
        if (r->in.info->field.string[0] == '\0') {			\
		if (ldb_msg_add_empty(msg, attr, LDB_FLAG_MOD_DELETE, NULL) != LDB_SUCCESS) { \
			return NT_STATUS_NO_MEMORY;			\
		}							\
	}								\
        if (ldb_msg_add_string(msg, attr, r->in.info->field.string) != LDB_SUCCESS) { \
		return NT_STATUS_NO_MEMORY;				\
	}								\
        set_el = ldb_msg_find_element(msg, attr);			\
        set_el->flags = LDB_FLAG_MOD_REPLACE;				\
} while (0)

#define SET_UINT(msg, field, attr) do {					\
	struct ldb_message_element *set_el;				\
	if (samdb_msg_add_uint(sam_ctx, mem_ctx, msg, attr, r->in.info->field) != LDB_SUCCESS) { \
		return NT_STATUS_NO_MEMORY;				\
	}								\
        set_el = ldb_msg_find_element(msg, attr);			\
 	set_el->flags = LDB_FLAG_MOD_REPLACE;				\
} while (0)

#define SET_INT64(msg, field, attr) do {				\
	struct ldb_message_element *set_el;				\
	if (samdb_msg_add_int64(sam_ctx, mem_ctx, msg, attr, r->in.info->field) != LDB_SUCCESS) { \
		return NT_STATUS_NO_MEMORY;				\
	}								\
        set_el = ldb_msg_find_element(msg, attr);			\
 	set_el->flags = LDB_FLAG_MOD_REPLACE;				\
} while (0)

#define SET_UINT64(msg, field, attr) do {				\
	struct ldb_message_element *set_el;				\
	if (samdb_msg_add_uint64(sam_ctx, mem_ctx, msg, attr, r->in.info->field) != LDB_SUCCESS) { \
		return NT_STATUS_NO_MEMORY;				\
	}								\
        set_el = ldb_msg_find_element(msg, attr);			\
 	set_el->flags = LDB_FLAG_MOD_REPLACE;				\
} while (0)

/* Set account flags, discarding flags that cannot be set with SAMR */
#define SET_AFLAGS(msg, field, attr) do {				\
	struct ldb_message_element *set_el;				\
	if (samdb_msg_add_acct_flags(sam_ctx, mem_ctx, msg, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY;				\
	}								\
        set_el = ldb_msg_find_element(msg, attr);			\
 	set_el->flags = LDB_FLAG_MOD_REPLACE;				\
} while (0)

#define SET_LHOURS(msg, field, attr) do {				\
	struct ldb_message_element *set_el;				\
	if (samdb_msg_add_logon_hours(sam_ctx, mem_ctx, msg, attr, &r->in.info->field) != LDB_SUCCESS) { \
		return NT_STATUS_NO_MEMORY;				\
	}								\
        set_el = ldb_msg_find_element(msg, attr);			\
 	set_el->flags = LDB_FLAG_MOD_REPLACE;				\
} while (0)

#define SET_PARAMETERS(msg, field, attr) do {				\
	struct ldb_message_element *set_el;				\
	if (r->in.info->field.length != 0) {				\
		if (samdb_msg_add_parameters(sam_ctx, mem_ctx, msg, attr, &r->in.info->field) != LDB_SUCCESS) { \
			return NT_STATUS_NO_MEMORY;			\
		}							\
		set_el = ldb_msg_find_element(msg, attr);		\
		set_el->flags = LDB_FLAG_MOD_REPLACE;			\
	}								\
} while (0)

/*
 * Clear a GUID cache
 */
static void clear_guid_cache(struct samr_guid_cache *cache)
{
	cache->handle = 0;
	cache->size = 0;
	TALLOC_FREE(cache->entries);
}

/*
 * initialize a GUID cache
 */
static void initialize_guid_cache(struct samr_guid_cache *cache)
{
	cache->handle = 0;
	cache->size = 0;
	cache->entries = NULL;
}

static NTSTATUS load_guid_cache(
	struct samr_guid_cache *cache,
	struct samr_domain_state *d_state,
	unsigned int ldb_cnt,
	struct ldb_message **res)
{
	NTSTATUS status = NT_STATUS_OK;
	unsigned int i;
	TALLOC_CTX *frame = talloc_stackframe();

	clear_guid_cache(cache);

	/*
	 * Store the GUID's in the cache.
	 */
	cache->handle = 0;
	cache->size = ldb_cnt;
	cache->entries = talloc_array(d_state, struct GUID, ldb_cnt);
	if (cache->entries == NULL) {
		clear_guid_cache(cache);
		status = NT_STATUS_NO_MEMORY;
		goto exit;
	}

	/*
	 * Extract a list of the GUIDs for all the matching objects
	 * we cache just the GUIDS to reduce the memory overhead of
	 * the result cache.
	 */
	for (i = 0; i < ldb_cnt; i++) {
		cache->entries[i] = samdb_result_guid(res[i], "objectGUID");
	}
exit:
	TALLOC_FREE(frame);
	return status;
}

/*
  samr_Connect

  create a connection to the SAM database
*/
static NTSTATUS dcesrv_samr_Connect(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct samr_Connect *r)
{
	struct samr_connect_state *c_state;
	struct dcesrv_handle *handle;

	ZERO_STRUCTP(r->out.connect_handle);

	c_state = talloc(mem_ctx, struct samr_connect_state);
	if (!c_state) {
		return NT_STATUS_NO_MEMORY;
	}

	/* make sure the sam database is accessible */
	c_state->sam_ctx = dcesrv_samdb_connect_as_user(c_state, dce_call);
	if (c_state->sam_ctx == NULL) {
		talloc_free(c_state);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	handle = dcesrv_handle_create(dce_call, SAMR_HANDLE_CONNECT);
	if (!handle) {
		talloc_free(c_state);
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = talloc_steal(handle, c_state);

	c_state->access_mask = r->in.access_mask;
	*r->out.connect_handle = handle->wire_handle;

	return NT_STATUS_OK;
}


/*
  samr_Close
*/
static NTSTATUS dcesrv_samr_Close(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			   struct samr_Close *r)
{
	struct dcesrv_handle *h;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	talloc_free(h);

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/*
  samr_SetSecurity
*/
static NTSTATUS dcesrv_samr_SetSecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_SetSecurity *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_QuerySecurity
*/
static NTSTATUS dcesrv_samr_QuerySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_QuerySecurity *r)
{
	struct dcesrv_handle *h;
	struct sec_desc_buf *sd;

	*r->out.sdbuf = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	sd = talloc(mem_ctx, struct sec_desc_buf);
	if (sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sd->sd = samdb_default_security_descriptor(mem_ctx);

	*r->out.sdbuf = sd;

	return NT_STATUS_OK;
}


/*
  samr_Shutdown

  we refuse this operation completely. If a admin wants to shutdown samr
  in Samba then they should use the samba admin tools to disable the samr pipe
*/
static NTSTATUS dcesrv_samr_Shutdown(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Shutdown *r)
{
	return NT_STATUS_ACCESS_DENIED;
}


/*
  samr_LookupDomain

  this maps from a domain name to a SID
*/
static NTSTATUS dcesrv_samr_LookupDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_LookupDomain *r)
{
	struct samr_connect_state *c_state;
	struct dcesrv_handle *h;
	struct dom_sid *sid;
	const char * const dom_attrs[] = { "objectSid", NULL};
	struct ldb_message **dom_msgs;
	int ret;

	*r->out.sid = NULL;

	DCESRV_PULL_HANDLE(h, r->in.connect_handle, SAMR_HANDLE_CONNECT);

	c_state = h->data;

	if (r->in.domain_name->string == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strcasecmp(r->in.domain_name->string, "BUILTIN") == 0) {
		ret = gendb_search(c_state->sam_ctx,
				   mem_ctx, NULL, &dom_msgs, dom_attrs,
				   "(objectClass=builtinDomain)");
	} else if (strcasecmp_m(r->in.domain_name->string, lpcfg_sam_name(dce_call->conn->dce_ctx->lp_ctx)) == 0) {
		ret = gendb_search_dn(c_state->sam_ctx,
				      mem_ctx, ldb_get_default_basedn(c_state->sam_ctx),
				      &dom_msgs, dom_attrs);
	} else {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	if (ret != 1) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	sid = samdb_result_dom_sid(mem_ctx, dom_msgs[0],
				   "objectSid");

	if (sid == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	*r->out.sid = sid;

	return NT_STATUS_OK;
}


/*
  samr_EnumDomains

  list the domains in the SAM
*/
static NTSTATUS dcesrv_samr_EnumDomains(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_EnumDomains *r)
{
	struct dcesrv_handle *h;
	struct samr_SamArray *array;
	uint32_t i, start_i;

	*r->out.resume_handle = 0;
	*r->out.sam = NULL;
	*r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.connect_handle, SAMR_HANDLE_CONNECT);

	*r->out.resume_handle = 2;

	start_i = *r->in.resume_handle;

	if (start_i >= 2) {
		/* search past end of list is not an error for this call */
		return NT_STATUS_OK;
	}

	array = talloc(mem_ctx, struct samr_SamArray);
	if (array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	array->count = 0;
	array->entries = NULL;

	array->entries = talloc_array(mem_ctx, struct samr_SamEntry, 2 - start_i);
	if (array->entries == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<2-start_i;i++) {
		array->entries[i].idx = start_i + i;
		if (i == 0) {
			array->entries[i].name.string = lpcfg_sam_name(dce_call->conn->dce_ctx->lp_ctx);
		} else {
			array->entries[i].name.string = "BUILTIN";
		}
	}

	*r->out.sam = array;
	*r->out.num_entries = i;
	array->count = *r->out.num_entries;

	return NT_STATUS_OK;
}


/*
  samr_OpenDomain
*/
static NTSTATUS dcesrv_samr_OpenDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_OpenDomain *r)
{
	struct dcesrv_handle *h_conn, *h_domain;
	struct samr_connect_state *c_state;
	struct samr_domain_state *d_state;
	const char * const dom_attrs[] = { "cn", NULL};
	struct ldb_message **dom_msgs;
	int ret;
	unsigned int i;

	ZERO_STRUCTP(r->out.domain_handle);

	DCESRV_PULL_HANDLE(h_conn, r->in.connect_handle, SAMR_HANDLE_CONNECT);

	c_state = h_conn->data;

	if (r->in.sid == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	d_state = talloc(mem_ctx, struct samr_domain_state);
	if (!d_state) {
		return NT_STATUS_NO_MEMORY;
	}

	d_state->domain_sid = talloc_steal(d_state, r->in.sid);

	if (dom_sid_equal(d_state->domain_sid, &global_sid_Builtin)) {
		d_state->builtin = true;
		d_state->domain_name = "BUILTIN";
	} else {
		d_state->builtin = false;
		d_state->domain_name = lpcfg_sam_name(dce_call->conn->dce_ctx->lp_ctx);
	}

	ret = gendb_search(c_state->sam_ctx,
			   mem_ctx, ldb_get_default_basedn(c_state->sam_ctx), &dom_msgs, dom_attrs,
			   "(objectSid=%s)",
			   ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));

	if (ret == 0) {
		talloc_free(d_state);
		return NT_STATUS_NO_SUCH_DOMAIN;
	} else if (ret > 1) {
		talloc_free(d_state);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else if (ret == -1) {
		talloc_free(d_state);
		DEBUG(1, ("Failed to open domain %s: %s\n", dom_sid_string(mem_ctx, r->in.sid), ldb_errstring(c_state->sam_ctx)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	d_state->domain_dn = talloc_steal(d_state, dom_msgs[0]->dn);
	d_state->role = lpcfg_server_role(dce_call->conn->dce_ctx->lp_ctx);
	d_state->connect_state = talloc_reference(d_state, c_state);
	d_state->sam_ctx = c_state->sam_ctx;
	d_state->access_mask = r->in.access_mask;
	d_state->domain_users_cached = NULL;

	d_state->lp_ctx = dce_call->conn->dce_ctx->lp_ctx;

	for (i = 0; i < SAMR_LAST_CACHE; i++) {
		initialize_guid_cache(&d_state->guid_caches[i]);
	}

	h_domain = dcesrv_handle_create(dce_call, SAMR_HANDLE_DOMAIN);
	if (!h_domain) {
		talloc_free(d_state);
		return NT_STATUS_NO_MEMORY;
	}

	h_domain->data = talloc_steal(h_domain, d_state);

	*r->out.domain_handle = h_domain->wire_handle;

	return NT_STATUS_OK;
}

/*
  return DomInfo1
*/
static NTSTATUS dcesrv_samr_info_DomInfo1(struct samr_domain_state *state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message **dom_msgs,
					  struct samr_DomInfo1 *info)
{
	info->min_password_length =
		ldb_msg_find_attr_as_uint(dom_msgs[0], "minPwdLength", 0);
	info->password_history_length =
		ldb_msg_find_attr_as_uint(dom_msgs[0], "pwdHistoryLength", 0);
	info->password_properties =
		ldb_msg_find_attr_as_uint(dom_msgs[0], "pwdProperties", 0);
	info->max_password_age =
		ldb_msg_find_attr_as_int64(dom_msgs[0], "maxPwdAge", 0);
	info->min_password_age =
		ldb_msg_find_attr_as_int64(dom_msgs[0], "minPwdAge", 0);

	return NT_STATUS_OK;
}

/*
  return DomInfo2
*/
static NTSTATUS dcesrv_samr_info_DomGeneralInformation(struct samr_domain_state *state,
						       TALLOC_CTX *mem_ctx,
						       struct ldb_message **dom_msgs,
						       struct samr_DomGeneralInformation *info)
{
	size_t count = 0;
	const enum ldb_scope scope = LDB_SCOPE_SUBTREE;
	int ret = 0;

	/* MS-SAMR 2.2.4.1 - ReplicaSourceNodeName: "domainReplica" attribute */
	info->primary.string = ldb_msg_find_attr_as_string(dom_msgs[0],
							   "domainReplica",
							   "");

	info->force_logoff_time = ldb_msg_find_attr_as_uint64(dom_msgs[0], "forceLogoff",
							    0x8000000000000000LL);

	info->oem_information.string = ldb_msg_find_attr_as_string(dom_msgs[0],
								   "oEMInformation",
								   "");
	info->domain_name.string  = state->domain_name;

	info->sequence_num = ldb_msg_find_attr_as_uint64(dom_msgs[0], "modifiedCount",
						 0);
	switch (state->role) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* This pulls the NetBIOS name from the
		   cn=NTDS Settings,cn=<NETBIOS name of PDC>,....
		   string */
		if (samdb_is_pdc(state->sam_ctx)) {
			info->role = SAMR_ROLE_DOMAIN_PDC;
		} else {
			info->role = SAMR_ROLE_DOMAIN_BDC;
		}
		break;
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
	case ROLE_IPA_DC:
	case ROLE_AUTO:
		return NT_STATUS_INTERNAL_ERROR;
	case ROLE_DOMAIN_MEMBER:
		info->role = SAMR_ROLE_DOMAIN_MEMBER;
		break;
	case ROLE_STANDALONE:
		info->role = SAMR_ROLE_STANDALONE;
		break;
	}

	/*
	 * Users are not meant to be in BUILTIN
	 * so to speed up the query we do not filter on domain_sid
	 */
	ret = dsdb_domain_count(
		state->sam_ctx,
		&count,
		state->domain_dn,
		NULL,
		scope,
		"(objectClass=user)");
	if (ret != LDB_SUCCESS || count > UINT32_MAX) {
		goto error;
	}
	info->num_users = count;

	/*
	 * Groups are not meant to be in BUILTIN
	 * so to speed up the query we do not filter on domain_sid
	 */
	ret = dsdb_domain_count(
		state->sam_ctx,
		&count,
		state->domain_dn,
		NULL,
		scope,
		"(&(objectClass=group)(|(groupType=%d)(groupType=%d)))",
		GTYPE_SECURITY_UNIVERSAL_GROUP,
		GTYPE_SECURITY_GLOBAL_GROUP);
	if (ret != LDB_SUCCESS || count > UINT32_MAX) {
		goto error;
	}
	info->num_groups = count;

	ret = dsdb_domain_count(
		state->sam_ctx,
		&count,
		state->domain_dn,
		state->domain_sid,
		scope,
		"(&(objectClass=group)(|(groupType=%d)(groupType=%d)))",
		GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
		GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (ret != LDB_SUCCESS || count > UINT32_MAX) {
		goto error;
	}
	info->num_aliases = count;

	return NT_STATUS_OK;

error:
	if (count > UINT32_MAX) {
		return NT_STATUS_INTEGER_OVERFLOW;
	}
	return dsdb_ldb_err_to_ntstatus(ret);

}

/*
  return DomInfo3
*/
static NTSTATUS dcesrv_samr_info_DomInfo3(struct samr_domain_state *state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message **dom_msgs,
					  struct samr_DomInfo3 *info)
{
	info->force_logoff_time = ldb_msg_find_attr_as_uint64(dom_msgs[0], "forceLogoff",
						      0x8000000000000000LL);

	return NT_STATUS_OK;
}

/*
  return DomInfo4
*/
static NTSTATUS dcesrv_samr_info_DomOEMInformation(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomOEMInformation *info)
{
	info->oem_information.string = ldb_msg_find_attr_as_string(dom_msgs[0],
								   "oEMInformation",
								   "");

	return NT_STATUS_OK;
}

/*
  return DomInfo5
*/
static NTSTATUS dcesrv_samr_info_DomInfo5(struct samr_domain_state *state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message **dom_msgs,
					  struct samr_DomInfo5 *info)
{
	info->domain_name.string  = state->domain_name;

	return NT_STATUS_OK;
}

/*
  return DomInfo6
*/
static NTSTATUS dcesrv_samr_info_DomInfo6(struct samr_domain_state *state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message **dom_msgs,
					  struct samr_DomInfo6 *info)
{
	/* MS-SAMR 2.2.4.1 - ReplicaSourceNodeName: "domainReplica" attribute */
	info->primary.string = ldb_msg_find_attr_as_string(dom_msgs[0],
							   "domainReplica",
							   "");

	return NT_STATUS_OK;
}

/*
  return DomInfo7
*/
static NTSTATUS dcesrv_samr_info_DomInfo7(struct samr_domain_state *state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message **dom_msgs,
					  struct samr_DomInfo7 *info)
{

	switch (state->role) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* This pulls the NetBIOS name from the
		   cn=NTDS Settings,cn=<NETBIOS name of PDC>,....
		   string */
		if (samdb_is_pdc(state->sam_ctx)) {
			info->role = SAMR_ROLE_DOMAIN_PDC;
		} else {
			info->role = SAMR_ROLE_DOMAIN_BDC;
		}
		break;
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
	case ROLE_IPA_DC:
	case ROLE_AUTO:
		return NT_STATUS_INTERNAL_ERROR;
	case ROLE_DOMAIN_MEMBER:
		info->role = SAMR_ROLE_DOMAIN_MEMBER;
		break;
	case ROLE_STANDALONE:
		info->role = SAMR_ROLE_STANDALONE;
		break;
	}

	return NT_STATUS_OK;
}

/*
  return DomInfo8
*/
static NTSTATUS dcesrv_samr_info_DomInfo8(struct samr_domain_state *state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message **dom_msgs,
					  struct samr_DomInfo8 *info)
{
	info->sequence_num = ldb_msg_find_attr_as_uint64(dom_msgs[0], "modifiedCount",
					       time(NULL));

	info->domain_create_time = ldb_msg_find_attr_as_uint(dom_msgs[0], "creationTime",
						     0x0LL);

	return NT_STATUS_OK;
}

/*
  return DomInfo9
*/
static NTSTATUS dcesrv_samr_info_DomInfo9(struct samr_domain_state *state,
					  TALLOC_CTX *mem_ctx,
					  struct ldb_message **dom_msgs,
					  struct samr_DomInfo9 *info)
{
	info->domain_server_state = DOMAIN_SERVER_ENABLED;

	return NT_STATUS_OK;
}

/*
  return DomInfo11
*/
static NTSTATUS dcesrv_samr_info_DomGeneralInformation2(struct samr_domain_state *state,
							TALLOC_CTX *mem_ctx,
							struct ldb_message **dom_msgs,
							struct samr_DomGeneralInformation2 *info)
{
	NTSTATUS status;
	status = dcesrv_samr_info_DomGeneralInformation(state, mem_ctx, dom_msgs, &info->general);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	info->lockout_duration = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutDuration",
						    -18000000000LL);
	info->lockout_window = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockOutObservationWindow",
						    -18000000000LL);
	info->lockout_threshold = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutThreshold", 0);

	return NT_STATUS_OK;
}

/*
  return DomInfo12
*/
static NTSTATUS dcesrv_samr_info_DomInfo12(struct samr_domain_state *state,
					   TALLOC_CTX *mem_ctx,
					   struct ldb_message **dom_msgs,
					   struct samr_DomInfo12 *info)
{
	info->lockout_duration = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutDuration",
						    -18000000000LL);
	info->lockout_window = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockOutObservationWindow",
						    -18000000000LL);
	info->lockout_threshold = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutThreshold", 0);

	return NT_STATUS_OK;
}

/*
  return DomInfo13
*/
static NTSTATUS dcesrv_samr_info_DomInfo13(struct samr_domain_state *state,
					   TALLOC_CTX *mem_ctx,
					   struct ldb_message **dom_msgs,
					   struct samr_DomInfo13 *info)
{
	info->sequence_num = ldb_msg_find_attr_as_uint64(dom_msgs[0], "modifiedCount",
					       time(NULL));

	info->domain_create_time = ldb_msg_find_attr_as_uint(dom_msgs[0], "creationTime",
						     0x0LL);

	info->modified_count_at_last_promotion = 0;

	return NT_STATUS_OK;
}

/*
  samr_QueryDomainInfo
*/
static NTSTATUS dcesrv_samr_QueryDomainInfo(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct samr_QueryDomainInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	union samr_DomainInfo *info;

	struct ldb_message **dom_msgs;
	const char * const *attrs = NULL;

	*r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	switch (r->in.level) {
	case 1:
	{
		static const char * const attrs2[] = { "minPwdLength",
						       "pwdHistoryLength",
						       "pwdProperties",
						       "maxPwdAge",
						       "minPwdAge",
						       NULL };
		attrs = attrs2;
		break;
	}
	case 2:
	{
		static const char * const attrs2[] = {"forceLogoff",
						      "oEMInformation",
						      "modifiedCount",
						      "domainReplica",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 3:
	{
		static const char * const attrs2[] = {"forceLogoff",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 4:
	{
		static const char * const attrs2[] = {"oEMInformation",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 5:
	{
		attrs = NULL;
		break;
	}
	case 6:
	{
		static const char * const attrs2[] = { "domainReplica",
						       NULL };
		attrs = attrs2;
		break;
	}
	case 7:
	{
		attrs = NULL;
		break;
	}
	case 8:
	{
		static const char * const attrs2[] = { "modifiedCount",
						       "creationTime",
						       NULL };
		attrs = attrs2;
		break;
	}
	case 9:
	{
		attrs = NULL;
		break;
	}
	case 11:
	{
		static const char * const attrs2[] = { "oEMInformation",
						       "forceLogoff",
						       "modifiedCount",
						       "lockoutDuration",
						       "lockOutObservationWindow",
						       "lockoutThreshold",
						       NULL};
		attrs = attrs2;
		break;
	}
	case 12:
	{
		static const char * const attrs2[] = { "lockoutDuration",
						       "lockOutObservationWindow",
						       "lockoutThreshold",
						       NULL};
		attrs = attrs2;
		break;
	}
	case 13:
	{
		static const char * const attrs2[] = { "modifiedCount",
						       "creationTime",
						       NULL };
		attrs = attrs2;
		break;
	}
	default:
	{
		return NT_STATUS_INVALID_INFO_CLASS;
	}
	}

	/* some levels don't need a search */
	if (attrs) {
		int ret;
		ret = gendb_search_dn(d_state->sam_ctx, mem_ctx,
				      d_state->domain_dn, &dom_msgs, attrs);
		if (ret == 0) {
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
		if (ret != 1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	/* allocate the info structure */
	info = talloc_zero(mem_ctx, union samr_DomainInfo);
	if (info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*r->out.info = info;

	switch (r->in.level) {
	case 1:
		return dcesrv_samr_info_DomInfo1(d_state, mem_ctx, dom_msgs,
						 &info->info1);
	case 2:
		return dcesrv_samr_info_DomGeneralInformation(d_state, mem_ctx, dom_msgs,
							      &info->general);
	case 3:
		return dcesrv_samr_info_DomInfo3(d_state, mem_ctx, dom_msgs,
						 &info->info3);
	case 4:
		return dcesrv_samr_info_DomOEMInformation(d_state, mem_ctx, dom_msgs,
							  &info->oem);
	case 5:
		return dcesrv_samr_info_DomInfo5(d_state, mem_ctx, dom_msgs,
						 &info->info5);
	case 6:
		return dcesrv_samr_info_DomInfo6(d_state, mem_ctx, dom_msgs,
						 &info->info6);
	case 7:
		return dcesrv_samr_info_DomInfo7(d_state, mem_ctx, dom_msgs,
						 &info->info7);
	case 8:
		return dcesrv_samr_info_DomInfo8(d_state, mem_ctx, dom_msgs,
						 &info->info8);
	case 9:
		return dcesrv_samr_info_DomInfo9(d_state, mem_ctx, dom_msgs,
						 &info->info9);
	case 11:
		return dcesrv_samr_info_DomGeneralInformation2(d_state, mem_ctx, dom_msgs,
							       &info->general2);
	case 12:
		return dcesrv_samr_info_DomInfo12(d_state, mem_ctx, dom_msgs,
						  &info->info12);
	case 13:
		return dcesrv_samr_info_DomInfo13(d_state, mem_ctx, dom_msgs,
						  &info->info13);
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}
}


/*
  samr_SetDomainInfo
*/
static NTSTATUS dcesrv_samr_SetDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetDomainInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message *msg;
	int ret;
	struct ldb_context *sam_ctx;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;
	sam_ctx = d_state->sam_ctx;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_reference(mem_ctx, d_state->domain_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case 1:
		SET_UINT  (msg, info1.min_password_length,     "minPwdLength");
		SET_UINT  (msg, info1.password_history_length, "pwdHistoryLength");
		SET_UINT  (msg, info1.password_properties,     "pwdProperties");
		SET_INT64  (msg, info1.max_password_age,       "maxPwdAge");
		SET_INT64  (msg, info1.min_password_age,       "minPwdAge");
		break;
	case 3:
		SET_UINT64  (msg, info3.force_logoff_time,     "forceLogoff");
		break;
	case 4:
		SET_STRING(msg, oem.oem_information,           "oEMInformation");
		break;

	case 6:
	case 7:
	case 9:
		/* No op, we don't know where to set these */
		return NT_STATUS_OK;

	case 12:
		/*
		 * It is not possible to set lockout_duration < lockout_window.
		 * (The test is the other way around since the negative numbers
		 *  are stored...)
		 *
		 * TODO:
		 *   This check should be moved to the backend, i.e. to some
		 *   ldb module under dsdb/samdb/ldb_modules/ .
		 *
		 * This constraint is documented here for the samr rpc service:
		 * MS-SAMR 3.1.1.6 Attribute Constraints for Originating Updates
		 * http://msdn.microsoft.com/en-us/library/cc245667%28PROT.10%29.aspx
		 *
		 * And here for the ldap backend:
		 * MS-ADTS 3.1.1.5.3.2 Constraints
		 * http://msdn.microsoft.com/en-us/library/cc223462(PROT.10).aspx
		 */
		if (r->in.info->info12.lockout_duration >
		    r->in.info->info12.lockout_window)
		{
			return NT_STATUS_INVALID_PARAMETER;
		}
		SET_INT64  (msg, info12.lockout_duration,      "lockoutDuration");
		SET_INT64  (msg, info12.lockout_window,        "lockOutObservationWindow");
		SET_INT64  (msg, info12.lockout_threshold,     "lockoutThreshold");
		break;

	default:
		/* many info classes are not valid for SetDomainInfo */
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* modify the samdb record */
	ret = ldb_modify(sam_ctx, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,("Failed to modify record %s: %s\n",
			 ldb_dn_get_linearized(d_state->domain_dn),
			 ldb_errstring(sam_ctx)));
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	return NT_STATUS_OK;
}

/*
  samr_CreateDomainGroup
*/
static NTSTATUS dcesrv_samr_CreateDomainGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct samr_CreateDomainGroup *r)
{
	NTSTATUS status;
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *groupname;
	struct dom_sid *group_sid;
	struct ldb_dn *group_dn;
	struct dcesrv_handle *g_handle;

	ZERO_STRUCTP(r->out.group_handle);
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (d_state->builtin) {
		DEBUG(5, ("Cannot create a domain group in the BUILTIN domain\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	groupname = r->in.name->string;

	if (groupname == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dsdb_add_domain_group(d_state->sam_ctx, mem_ctx, groupname, &group_sid, &group_dn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	a_state = talloc(mem_ctx, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, group_dn);

	a_state->account_name = talloc_steal(a_state, groupname);

	/* create the policy handle */
	g_handle = dcesrv_handle_create(dce_call, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = talloc_steal(g_handle, a_state);

	*r->out.group_handle = g_handle->wire_handle;
	*r->out.rid = group_sid->sub_auths[group_sid->num_auths-1];

	return NT_STATUS_OK;
}


/*
  comparison function for sorting SamEntry array
*/
static int compare_SamEntry(struct samr_SamEntry *e1, struct samr_SamEntry *e2)
{
	return NUMERIC_CMP(e1->idx, e2->idx);
}

static int compare_msgRid(struct ldb_message **m1, struct ldb_message **m2) {
	struct dom_sid *sid1 = NULL;
	struct dom_sid *sid2 = NULL;
	uint32_t rid1;
	uint32_t rid2;
	int res = 0;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	sid1 = samdb_result_dom_sid(frame, *m1, "objectSid");
	sid2 = samdb_result_dom_sid(frame, *m2, "objectSid");

	/*
	 * If entries don't have a SID we want to sort them to the end of
	 * the list.
	 */
	if (sid1 == NULL && sid2 == NULL) {
		res = 0;
		goto exit;
	} else if (sid2 == NULL) {
		res = 1;
		goto exit;
	} else if (sid1 == NULL) {
		res = -1;
		goto exit;
	}

	/*
	 * Get and compare the rids. If we fail to extract a rid (because
	 * there are no subauths) the msg goes to the end of the list, but
	 * before the NULL SIDs.
	 */
	status = dom_sid_split_rid(NULL, sid1, NULL, &rid1);
	if (!NT_STATUS_IS_OK(status)) {
		res = 1;
		goto exit;
	}

	status = dom_sid_split_rid(NULL, sid2, NULL, &rid2);
	if (!NT_STATUS_IS_OK(status)) {
		res = -1;
		goto exit;
	}

	if (rid1 == rid2) {
		res = 0;
	}
	else if (rid1 > rid2) {
		res = 1;
	}
	else {
		res = -1;
	}
exit:
	TALLOC_FREE(frame);
	return res;
}

/*
  samr_EnumDomainGroups
*/
static NTSTATUS dcesrv_samr_EnumDomainGroups(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct samr_EnumDomainGroups *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	uint32_t i;
	uint32_t count;
	uint32_t results;
	uint32_t max_entries;
	uint32_t remaining_entries;
	uint32_t resume_handle;
	struct samr_SamEntry *entries;
	const char * const attrs[] = { "objectSid", "sAMAccountName", NULL };
	const char * const cache_attrs[] = { "objectSid", "objectGUID", NULL };
	struct samr_SamArray *sam;
	struct samr_guid_cache *cache = NULL;

	*r->out.resume_handle = 0;
	*r->out.sam = NULL;
	*r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;
	cache = &d_state->guid_caches[SAMR_ENUM_DOMAIN_GROUPS_CACHE];

	/*
	 * If the resume_handle is zero, query the database and cache the
	 * matching GUID's
	 */
	if (*r->in.resume_handle == 0) {
		NTSTATUS status;
		int ldb_cnt;
		clear_guid_cache(cache);
		/*
		 * search for all domain groups in this domain.
		 */
		ldb_cnt = samdb_search_domain(
		    d_state->sam_ctx,
		    mem_ctx,
		    d_state->domain_dn,
		    &res,
		    cache_attrs,
		    d_state->domain_sid,
		    "(&(|(groupType=%d)(groupType=%d))(objectClass=group))",
		    GTYPE_SECURITY_UNIVERSAL_GROUP,
		    GTYPE_SECURITY_GLOBAL_GROUP);
		if (ldb_cnt < 0) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		/*
		 * Sort the results into RID order, while the spec states there
		 * is no order, Windows appears to sort the results by RID and
		 * so it is possible that there are clients that depend on
		 * this ordering
		 */
		TYPESAFE_QSORT(res, ldb_cnt, compare_msgRid);

		/*
		 * cache the sorted GUID's
		 */
		status = load_guid_cache(cache, d_state, ldb_cnt, res);
		TALLOC_FREE(res);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		cache->handle = 0;
	}


	/*
	 * If the resume handle is out of range we return an empty response
	 * and invalidate the cache.
	 *
	 * From the specification:
	 * Servers SHOULD validate that EnumerationContext is an expected
	 * value for the server's implementation. Windows does NOT validate
	 * the input, though the result of malformed information merely results
	 * in inconsistent output to the client.
	 */
	if (*r->in.resume_handle >= cache->size) {
		clear_guid_cache(cache);
		sam = talloc(mem_ctx, struct samr_SamArray);
		if (!sam) {
			return NT_STATUS_NO_MEMORY;
		}
		sam->entries = NULL;
		sam->count = 0;

		*r->out.sam = sam;
		*r->out.resume_handle = 0;
		return NT_STATUS_OK;
	}


	/*
	 * Calculate the number of entries to return limit by max_size.
	 * Note that we use the w2k3 element size value of 54
	 */
	max_entries = 1 + (r->in.max_size/SAMR_ENUM_USERS_MULTIPLIER);
	remaining_entries = cache->size - *r->in.resume_handle;
	results = MIN(remaining_entries, max_entries);

	/*
	 * Process the list of result GUID's.
	 * Read the details of each object and populate the Entries
	 * for the current level.
	 */
	count = 0;
	resume_handle = *r->in.resume_handle;
	entries = talloc_array(mem_ctx, struct samr_SamEntry, results);
	if (entries == NULL) {
		clear_guid_cache(cache);
		return NT_STATUS_NO_MEMORY;
	}
	for (i = 0; i < results; i++) {
		struct dom_sid *objectsid;
		uint32_t rid;
		struct ldb_result *rec;
		const uint32_t idx = *r->in.resume_handle + i;
		int ret;
		NTSTATUS status;
		const char *name = NULL;
		resume_handle++;
		/*
		 * Read an object from disk using the GUID as the key
		 *
		 * If the object can not be read, or it does not have a SID
		 * it is ignored.
		 *
		 * As a consequence of this, if all the remaining GUID's
		 * have been deleted an empty result will be returned.
		 * i.e. even if the previous call returned a non zero
		 * resume_handle it is possible for no results to be returned.
		 *
		 */
		ret = dsdb_search_by_dn_guid(d_state->sam_ctx,
					     mem_ctx,
					     &rec,
					     &cache->entries[idx],
					     attrs,
					     0);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			struct GUID_txt_buf guid_buf;
			DBG_WARNING(
			    "GUID [%s] not found\n",
			    GUID_buf_string(&cache->entries[idx], &guid_buf));
			continue;
		} else if (ret != LDB_SUCCESS) {
			clear_guid_cache(cache);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		objectsid = samdb_result_dom_sid(mem_ctx,
						 rec->msgs[0],
						 "objectSID");
		if (objectsid == NULL) {
			struct GUID_txt_buf guid_buf;
			DBG_WARNING(
			    "objectSID for GUID [%s] not found\n",
			    GUID_buf_string(&cache->entries[idx], &guid_buf));
			continue;
		}
		status = dom_sid_split_rid(NULL,
					   objectsid,
					   NULL,
					   &rid);
		if (!NT_STATUS_IS_OK(status)) {
			struct dom_sid_buf sid_buf;
			struct GUID_txt_buf guid_buf;
			DBG_WARNING(
			    "objectSID [%s] for GUID [%s] invalid\n",
			    dom_sid_str_buf(objectsid, &sid_buf),
			    GUID_buf_string(&cache->entries[idx], &guid_buf));
			continue;
		}

		entries[count].idx = rid;
		name = ldb_msg_find_attr_as_string(
		    rec->msgs[0], "sAMAccountName", "");
		entries[count].name.string = talloc_strdup(entries, name);
		count++;
	}

	sam = talloc(mem_ctx, struct samr_SamArray);
	if (!sam) {
		clear_guid_cache(cache);
		return NT_STATUS_NO_MEMORY;
	}

	sam->entries = entries;
	sam->count = count;

	*r->out.sam = sam;
	*r->out.resume_handle = resume_handle;
	*r->out.num_entries = count;

	/*
	 * Signal no more results by returning zero resume handle,
	 * the cache is also cleared at this point
	 */
	if (*r->out.resume_handle >= cache->size) {
		*r->out.resume_handle = 0;
		clear_guid_cache(cache);
		return NT_STATUS_OK;
	}
	/*
	 * There are more results to be returned.
	 */
	return STATUS_MORE_ENTRIES;
}


/*
  samr_CreateUser2

  This call uses transactions to ensure we don't get a new conflicting
  user while we are processing this, and to ensure the user either
  completely exists, or does not.
*/
static NTSTATUS dcesrv_samr_CreateUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_CreateUser2 *r)
{
	NTSTATUS status;
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	struct ldb_dn *dn;
	struct dom_sid *sid;
	struct dcesrv_handle *u_handle;
	const char *account_name;

	ZERO_STRUCTP(r->out.user_handle);
	*r->out.access_granted = 0;
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (d_state->builtin) {
		DEBUG(5, ("Cannot create a user in the BUILTIN domain\n"));
		return NT_STATUS_ACCESS_DENIED;
	} else if (r->in.acct_flags == ACB_DOMTRUST) {
		/* Domain trust accounts must be created by the LSA calls */
		return NT_STATUS_ACCESS_DENIED;
	}
	account_name = r->in.account_name->string;

	if (account_name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dsdb_add_user(d_state->sam_ctx, mem_ctx, account_name, r->in.acct_flags, NULL,
			       &sid, &dn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	a_state = talloc(mem_ctx, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, dn);

	a_state->account_name = talloc_steal(a_state, account_name);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_create(dce_call, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = talloc_steal(u_handle, a_state);

	*r->out.user_handle = u_handle->wire_handle;
	*r->out.access_granted = 0xf07ff; /* TODO: fix access mask calculations */

	*r->out.rid = sid->sub_auths[sid->num_auths-1];

	return NT_STATUS_OK;
}


/*
  samr_CreateUser
*/
static NTSTATUS dcesrv_samr_CreateUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_CreateUser *r)
{
	struct samr_CreateUser2 r2;
	uint32_t access_granted = 0;


	/* a simple wrapper around samr_CreateUser2 works nicely */

	r2 = (struct samr_CreateUser2) {
		.in.domain_handle = r->in.domain_handle,
		.in.account_name = r->in.account_name,
		.in.acct_flags = ACB_NORMAL,
		.in.access_mask = r->in.access_mask,
		.out.user_handle = r->out.user_handle,
		.out.access_granted = &access_granted,
		.out.rid = r->out.rid
	};

	return dcesrv_samr_CreateUser2(dce_call, mem_ctx, &r2);
}

struct enum_dom_users_ctx {
	struct samr_SamEntry *entries;
	uint32_t num_entries;
	uint32_t acct_flags;
	struct dom_sid *domain_sid;
};

static int user_iterate_callback(struct ldb_request *req,
				 struct ldb_reply *ares);

/*
 * Iterate users and add all those that match a domain SID and pass an acct
 * flags check to an array of SamEntry objects.
 */
static int user_iterate_callback(struct ldb_request *req,
				 struct ldb_reply *ares)
{
	struct enum_dom_users_ctx *ac =\
		talloc_get_type(req->context, struct enum_dom_users_ctx);
	int ret = LDB_ERR_OPERATIONS_ERROR;

	if (!ares) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_request_done(req, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
	{
		struct ldb_message *msg = ares->message;
		const struct ldb_val *val;
		struct samr_SamEntry *ent;
		struct dom_sid objectsid;
		uint32_t rid;
		size_t entries_array_len = 0;
		NTSTATUS status;
		ssize_t sid_size;

		if (ac->acct_flags && ((samdb_result_acct_flags(msg, NULL) &
					ac->acct_flags) == 0)) {
			ret = LDB_SUCCESS;
			break;
		}

		val = ldb_msg_find_ldb_val(msg, "objectSID");
		if (val == NULL) {
			DBG_WARNING("objectSID for DN %s not found\n",
				    ldb_dn_get_linearized(msg->dn));
			ret = ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
			break;
		}

		sid_size = sid_parse(val->data, val->length, &objectsid);
		if (sid_size == -1) {
			struct dom_sid_buf sid_buf;
			DBG_WARNING("objectsid [%s] for DN [%s] invalid\n",
				    dom_sid_str_buf(&objectsid, &sid_buf),
				    ldb_dn_get_linearized(msg->dn));
			ret = ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
			break;
		}

		if (!dom_sid_in_domain(ac->domain_sid, &objectsid)) {
			/* Ignore if user isn't in the domain */
			ret = LDB_SUCCESS;
			break;
		}

		status = dom_sid_split_rid(ares, &objectsid, NULL, &rid);
		if (!NT_STATUS_IS_OK(status)) {
			struct dom_sid_buf sid_buf;
			DBG_WARNING("Couldn't split RID from "
				    "SID [%s] of DN [%s]\n",
				    dom_sid_str_buf(&objectsid, &sid_buf),
				    ldb_dn_get_linearized(msg->dn));
			ret = ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
			break;
		}

		entries_array_len = talloc_array_length(ac->entries);
		if (ac->num_entries >= entries_array_len) {
			if (entries_array_len * 2 < entries_array_len) {
				ret = ldb_request_done(req,
					LDB_ERR_OPERATIONS_ERROR);
				break;
			}
			ac->entries = talloc_realloc(ac,
						     ac->entries,
						     struct samr_SamEntry,
						     entries_array_len * 2);
			if (ac->entries == NULL) {
				ret = ldb_request_done(req,
					LDB_ERR_OPERATIONS_ERROR);
				break;
			}
		}

		ent = &(ac->entries[ac->num_entries++]);
		val = ldb_msg_find_ldb_val(msg, "samaccountname");
		if (val == NULL) {
			DBG_WARNING("samaccountname attribute not found\n");
			ret = ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
			break;
		}
		ent->name.string = talloc_steal(ac->entries,
					        (char *)val->data);
		ent->idx = rid;
		ret = LDB_SUCCESS;
		break;
	}
	case LDB_REPLY_DONE:
	{
		if (ac->num_entries != 0 &&
		    ac->num_entries != talloc_array_length(ac->entries)) {
			ac->entries = talloc_realloc(ac,
						     ac->entries,
						     struct samr_SamEntry,
						     ac->num_entries);
			if (ac->entries == NULL) {
				ret = ldb_request_done(req,
					LDB_ERR_OPERATIONS_ERROR);
				break;
			}
		}
		ret = ldb_request_done(req, LDB_SUCCESS);
		break;
	}
	case LDB_REPLY_REFERRAL:
	{
		ret = LDB_SUCCESS;
		break;
	}
	default:
		/* Doesn't happen */
		ret = LDB_ERR_OPERATIONS_ERROR;
	}
	TALLOC_FREE(ares);

	return ret;
}

/*
 * samr_EnumDomainUsers
 * The previous implementation did an initial search and stored a list of
 * matching GUIDs on the connection handle's domain state, then did direct
 * GUID lookups for each record in a page indexed by resume_handle. That
 * approach was memory efficient, requiring only 16 bytes per record, but
 * was too slow for winbind which needs this RPC call for getpwent.
 *
 * Now we use an iterate pattern to populate a cached list of the rids and
 * names for each record. This improves runtime performance but requires
 * about 200 bytes per record which will mean for a 100k database we use
 * about 2MB, which is fine. The speedup achieved by this new approach is
 * around 50%.
 */
static NTSTATUS dcesrv_samr_EnumDomainUsers(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct samr_EnumDomainUsers *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	uint32_t results;
	uint32_t max_entries;
	uint32_t num_entries;
	uint32_t remaining_entries;
	struct samr_SamEntry *entries;
	const char * const attrs[] = { "objectSid", "sAMAccountName",
		"userAccountControl", NULL };
	struct samr_SamArray *sam;
	struct ldb_request *req;

	*r->out.resume_handle = 0;
	*r->out.sam = NULL;
	*r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;
	entries = d_state->domain_users_cached;

	/*
	 * If the resume_handle is zero, query the database and cache the
	 * matching entries.
	 */
	if (*r->in.resume_handle == 0) {
		int ret;
		struct enum_dom_users_ctx *ac;
		if (entries != NULL) {
			talloc_free(entries);
			d_state->domain_users_cached = NULL;
		}

		ac = talloc(mem_ctx, struct enum_dom_users_ctx);
		ac->num_entries = 0;
		ac->domain_sid = d_state->domain_sid;
		ac->entries = talloc_array(ac,
					   struct samr_SamEntry,
					   100);
		if (ac->entries == NULL) {
			talloc_free(ac);
			return NT_STATUS_NO_MEMORY;
		}
		ac->acct_flags = r->in.acct_flags;

		ret = ldb_build_search_req(&req,
					   d_state->sam_ctx,
					   mem_ctx,
					   d_state->domain_dn,
					   LDB_SCOPE_SUBTREE,
					   "(objectClass=user)",
					   attrs,
					   NULL,
					   ac,
					   user_iterate_callback,
					   NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return dsdb_ldb_err_to_ntstatus(ret);
		}

		ret = ldb_request(d_state->sam_ctx, req);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return dsdb_ldb_err_to_ntstatus(ret);
		}

		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
		if (ret != LDB_SUCCESS) {
			return dsdb_ldb_err_to_ntstatus(ret);
		}

		if (ac->num_entries == 0) {
			DBG_WARNING("No users in domain %s\n",
				    ldb_dn_get_linearized(d_state->domain_dn));
			talloc_free(ac);

			/*
			 * test_EnumDomainUsers_all() expects that r.out.sam
			 * should be non-NULL, even if we have no entries.
			 */
			sam = talloc_zero(mem_ctx, struct samr_SamArray);
			if (sam == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			*r->out.sam = sam;

			return NT_STATUS_OK;
		}

		entries = talloc_steal(d_state, ac->entries);
		d_state->domain_users_cached = entries;
		num_entries = ac->num_entries;
		talloc_free(ac);

		/*
		 * Sort the entries into RID order, while the spec states there
		 * is no order, Windows appears to sort the results by RID and
		 * so it is possible that there are clients that depend on
		 * this ordering
		 */
		TYPESAFE_QSORT(entries, num_entries, compare_SamEntry);
	} else {
		num_entries = talloc_array_length(entries);
	}

	/*
	 * If the resume handle is out of range we return an empty response
	 * and invalidate the cache.
	 *
	 * From the specification:
	 * Servers SHOULD validate that EnumerationContext is an expected
	 * value for the server's implementation. Windows does NOT validate
	 * the input, though the result of malformed information merely results
	 * in inconsistent output to the client.
	 */
	if (*r->in.resume_handle >= num_entries) {
		talloc_free(entries);
		d_state->domain_users_cached = NULL;
		sam = talloc(mem_ctx, struct samr_SamArray);
		if (!sam) {
			return NT_STATUS_NO_MEMORY;
		}
		sam->entries = NULL;
		sam->count = 0;

		*r->out.sam = sam;
		*r->out.resume_handle = 0;
		return NT_STATUS_OK;
	}

	/*
	 * Calculate the number of entries to return limit by max_size.
	 * Note that we use the w2k3 element size value of 54
	 */
	max_entries = 1 + (r->in.max_size / SAMR_ENUM_USERS_MULTIPLIER);
	remaining_entries = num_entries - *r->in.resume_handle;
	results = MIN(remaining_entries, max_entries);

	sam = talloc(mem_ctx, struct samr_SamArray);
	if (!sam) {
		d_state->domain_users_cached = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	sam->entries = entries + *r->in.resume_handle;
	sam->count = results;

	*r->out.sam = sam;
	*r->out.resume_handle = *r->in.resume_handle + results;
	*r->out.num_entries = results;

	/*
	 * Signal no more results by returning zero resume handle,
	 * the cache is also cleared at this point
	 */
	if (*r->out.resume_handle >= num_entries) {
		*r->out.resume_handle = 0;
		return NT_STATUS_OK;
	}
	/*
	 * There are more results to be returned.
	 */
	return STATUS_MORE_ENTRIES;
}


/*
  samr_CreateDomAlias
*/
static NTSTATUS dcesrv_samr_CreateDomAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_CreateDomAlias *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *alias_name;
	struct dom_sid *sid;
	struct dcesrv_handle *a_handle;
	struct ldb_dn *dn;
	NTSTATUS status;

	ZERO_STRUCTP(r->out.alias_handle);
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (d_state->builtin) {
		DEBUG(5, ("Cannot create a domain alias in the BUILTIN domain\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	alias_name = r->in.alias_name->string;

	if (alias_name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dsdb_add_domain_alias(d_state->sam_ctx, mem_ctx, alias_name, &sid, &dn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	a_state = talloc(mem_ctx, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}

	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, dn);

	a_state->account_name = talloc_steal(a_state, alias_name);

	/* create the policy handle */
	a_handle = dcesrv_handle_create(dce_call, SAMR_HANDLE_ALIAS);
	if (a_handle == NULL)
		return NT_STATUS_NO_MEMORY;

	a_handle->data = talloc_steal(a_handle, a_state);

	*r->out.alias_handle = a_handle->wire_handle;

	*r->out.rid = sid->sub_auths[sid->num_auths-1];

	return NT_STATUS_OK;
}


/*
  samr_EnumDomainAliases
*/
static NTSTATUS dcesrv_samr_EnumDomainAliases(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_EnumDomainAliases *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	int i, ldb_cnt;
	uint32_t first, count;
	struct samr_SamEntry *entries;
	const char * const attrs[] = { "objectSid", "sAMAccountName", NULL };
	struct samr_SamArray *sam;

	*r->out.resume_handle = 0;
	*r->out.sam = NULL;
	*r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* search for all domain aliases in this domain. This could possibly be
	   cached and resumed based on resume_key */
	ldb_cnt = samdb_search_domain(d_state->sam_ctx, mem_ctx, NULL,
				      &res, attrs,
				      d_state->domain_sid,
				      "(&(|(grouptype=%d)(grouptype=%d)))"
				      "(objectclass=group))",
				      GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
				      GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (ldb_cnt < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* convert to SamEntry format */
	entries = talloc_array(mem_ctx, struct samr_SamEntry, ldb_cnt);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}

	count = 0;

	for (i=0;i<ldb_cnt;i++) {
		struct dom_sid *alias_sid;

		alias_sid = samdb_result_dom_sid(mem_ctx, res[i],
						 "objectSid");

		if (alias_sid == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		entries[count].idx =
			alias_sid->sub_auths[alias_sid->num_auths-1];
		entries[count].name.string =
			ldb_msg_find_attr_as_string(res[i], "sAMAccountName", "");
		count += 1;
	}

	/* sort the results by rid */
	TYPESAFE_QSORT(entries, count, compare_SamEntry);

	/* find the first entry to return */
	for (first=0;
	     first<count && entries[first].idx <= *r->in.resume_handle;
	     first++) ;

	/* return the rest, limit by max_size. Note that we
	   use the w2k3 element size value of 54 */
	*r->out.num_entries = count - first;
	*r->out.num_entries = MIN(*r->out.num_entries,
				  1+(r->in.max_size/SAMR_ENUM_USERS_MULTIPLIER));

	sam = talloc(mem_ctx, struct samr_SamArray);
	if (!sam) {
		return NT_STATUS_NO_MEMORY;
	}

	sam->entries = entries+first;
	sam->count = *r->out.num_entries;

	*r->out.sam = sam;

	if (first == count) {
		return NT_STATUS_OK;
	}

	if (*r->out.num_entries < count - first) {
		*r->out.resume_handle =
			entries[first+*r->out.num_entries-1].idx;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}


/*
  samr_GetAliasMembership
*/
static NTSTATUS dcesrv_samr_GetAliasMembership(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetAliasMembership *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	char *filter;
	const char * const attrs[] = { "objectSid", NULL };
	struct ldb_message **res;
	uint32_t i;
	int count = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	filter = talloc_asprintf(mem_ctx,
				 "(&(|(grouptype=%d)(grouptype=%d))"
				 "(objectclass=group)(|",
				 GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
				 GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<r->in.sids->num_sids; i++) {
		struct dom_sid_buf buf;

		filter = talloc_asprintf_append(
			filter,
			"(member=<SID=%s>)",
			dom_sid_str_buf(r->in.sids->sids[i].sid, &buf));

		if (filter == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* Find out if we had at least one valid member SID passed - otherwise
	 * just skip the search. */
	if (strstr(filter, "member") != NULL) {
		count = samdb_search_domain(d_state->sam_ctx, mem_ctx, NULL,
					    &res, attrs, d_state->domain_sid,
					    "%s))", filter);
		if (count < 0) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	r->out.rids->count = 0;
	r->out.rids->ids = talloc_array(mem_ctx, uint32_t, count);
	if (r->out.rids->ids == NULL)
		return NT_STATUS_NO_MEMORY;

	for (i=0; i<count; i++) {
		struct dom_sid *alias_sid;

		alias_sid = samdb_result_dom_sid(mem_ctx, res[i], "objectSid");
		if (alias_sid == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		r->out.rids->ids[r->out.rids->count] =
			alias_sid->sub_auths[alias_sid->num_auths-1];
		r->out.rids->count += 1;
	}

	return NT_STATUS_OK;
}


/*
  samr_LookupNames
*/
static NTSTATUS dcesrv_samr_LookupNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_LookupNames *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	uint32_t i, num_mapped;
	NTSTATUS status = NT_STATUS_OK;
	const char * const attrs[] = { "sAMAccountType", "objectSid", NULL };
	int count;

	ZERO_STRUCTP(r->out.rids);
	ZERO_STRUCTP(r->out.types);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (r->in.num_names == 0) {
		return NT_STATUS_OK;
	}

	r->out.rids->ids = talloc_array(mem_ctx, uint32_t, r->in.num_names);
	r->out.types->ids = talloc_array(mem_ctx, uint32_t, r->in.num_names);
	if (!r->out.rids->ids || !r->out.types->ids) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.rids->count = r->in.num_names;
	r->out.types->count = r->in.num_names;

	num_mapped = 0;

	for (i=0;i<r->in.num_names;i++) {
		struct ldb_message **res;
		struct dom_sid *sid;
		uint32_t atype, rtype;

		r->out.rids->ids[i] = 0;
		r->out.types->ids[i] = SID_NAME_UNKNOWN;

		count = gendb_search(d_state->sam_ctx, mem_ctx, d_state->domain_dn, &res, attrs,
				     "sAMAccountName=%s",
				     ldb_binary_encode_string(mem_ctx, r->in.names[i].string));
		if (count != 1) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		sid = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");
		if (sid == NULL) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		atype = ldb_msg_find_attr_as_uint(res[0], "sAMAccountType", 0);
		if (atype == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		rtype = ds_atype_map(atype);

		if (rtype == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		r->out.rids->ids[i] = sid->sub_auths[sid->num_auths-1];
		r->out.types->ids[i] = rtype;
		num_mapped++;
	}

	if (num_mapped == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	return status;
}


/*
  samr_LookupRids
*/
static NTSTATUS dcesrv_samr_LookupRids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_LookupRids *r)
{
	NTSTATUS status;
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	const char **names;
	struct lsa_String *lsa_names;
	enum lsa_SidType *ids;

	ZERO_STRUCTP(r->out.names);
	ZERO_STRUCTP(r->out.types);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (r->in.num_rids == 0)
		return NT_STATUS_OK;

	lsa_names = talloc_zero_array(mem_ctx, struct lsa_String, r->in.num_rids);
	names = talloc_zero_array(mem_ctx, const char *, r->in.num_rids);
	ids = talloc_zero_array(mem_ctx, enum lsa_SidType, r->in.num_rids);

	if ((lsa_names == NULL) || (names == NULL) || (ids == NULL))
		return NT_STATUS_NO_MEMORY;

	r->out.names->names = lsa_names;
	r->out.names->count = r->in.num_rids;

	r->out.types->ids = (uint32_t *) ids;
	r->out.types->count = r->in.num_rids;

	status = dsdb_lookup_rids(d_state->sam_ctx, mem_ctx, d_state->domain_sid,
				  r->in.num_rids, r->in.rids, names, ids);
	if (NT_STATUS_IS_OK(status) || NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED) || NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		uint32_t i;
		for (i = 0; i < r->in.num_rids; i++) {
			lsa_names[i].string = names[i];
		}
	}
	return status;
}


/*
  samr_OpenGroup
*/
static NTSTATUS dcesrv_samr_OpenGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_OpenGroup *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *groupname;
	struct dom_sid *sid;
	struct ldb_message **msgs;
	struct dcesrv_handle *g_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.group_handle);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the group SID */
	sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (!sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the group record */
	if (d_state->builtin) {
		ret = gendb_search(d_state->sam_ctx,
				   mem_ctx, d_state->domain_dn, &msgs, attrs,
				   "(&(objectSid=%s)(objectClass=group)"
				   "(groupType=%d))",
				   ldap_encode_ndr_dom_sid(mem_ctx, sid),
				   GTYPE_SECURITY_BUILTIN_LOCAL_GROUP);
	} else {
		ret = gendb_search(d_state->sam_ctx,
				   mem_ctx, d_state->domain_dn, &msgs, attrs,
				   "(&(objectSid=%s)(objectClass=group)"
				   "(|(groupType=%d)(groupType=%d)))",
				   ldap_encode_ndr_dom_sid(mem_ctx, sid),
				   GTYPE_SECURITY_UNIVERSAL_GROUP,
				   GTYPE_SECURITY_GLOBAL_GROUP);
	}
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_GROUP;
	}
	if (ret != 1) {
		DEBUG(0,("Found %d records matching sid %s\n",
			 ret, dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	groupname = ldb_msg_find_attr_as_string(msgs[0], "sAMAccountName", NULL);
	if (groupname == NULL) {
		DEBUG(0,("sAMAccountName field missing for sid %s\n",
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(mem_ctx, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msgs[0]->dn);
	a_state->account_sid = talloc_steal(a_state, sid);
	a_state->account_name = talloc_strdup(a_state, groupname);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_create(dce_call, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = talloc_steal(g_handle, a_state);

	*r->out.group_handle = g_handle->wire_handle;

	return NT_STATUS_OK;
}

/*
  samr_QueryGroupInfo
*/
static NTSTATUS dcesrv_samr_QueryGroupInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryGroupInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	const char * const attrs[4] = { "sAMAccountName", "description",
					"numMembers", NULL };
	int ret;
	union samr_GroupInfo *info;

	*r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	/* pull all the group attributes */
	ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
			      a_state->account_dn, &res, attrs);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_GROUP;
	}
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	info = talloc_zero(mem_ctx, union samr_GroupInfo);
	if (info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Fill in the level */
	switch (r->in.level) {
	case GROUPINFOALL:
		QUERY_STRING(msg, all.name,        "sAMAccountName");
		info->all.attributes = SE_GROUP_DEFAULT_FLAGS; /* Do like w2k3 */
		QUERY_UINT  (msg, all.num_members,      "numMembers")
		QUERY_STRING(msg, all.description, "description");
		break;
	case GROUPINFONAME:
		QUERY_STRING(msg, name,            "sAMAccountName");
		break;
	case GROUPINFOATTRIBUTES:
		info->attributes.attributes = SE_GROUP_DEFAULT_FLAGS; /* Do like w2k3 */
		break;
	case GROUPINFODESCRIPTION:
		QUERY_STRING(msg, description, "description");
		break;
	case GROUPINFOALL2:
		QUERY_STRING(msg, all2.name,        "sAMAccountName");
		info->all.attributes = SE_GROUP_DEFAULT_FLAGS; /* Do like w2k3 */
		QUERY_UINT  (msg, all2.num_members,      "numMembers")
		QUERY_STRING(msg, all2.description, "description");
		break;
	default:
		talloc_free(info);
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	*r->out.info = info;

	return NT_STATUS_OK;
}


/*
  samr_SetGroupInfo
*/
static NTSTATUS dcesrv_samr_SetGroupInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_SetGroupInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *g_state;
	struct ldb_message *msg;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	g_state = h->data;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(mem_ctx, g_state->account_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case GROUPINFODESCRIPTION:
		SET_STRING(msg, description,         "description");
		break;
	case GROUPINFONAME:
		/* On W2k3 this does not change the name, it changes the
		 * sAMAccountName attribute */
		SET_STRING(msg, name,                "sAMAccountName");
		break;
	case GROUPINFOATTRIBUTES:
		/* This does not do anything obviously visible in W2k3 LDAP */
		return NT_STATUS_OK;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* modify the samdb record */
	ret = ldb_modify(g_state->sam_ctx, msg);
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	return NT_STATUS_OK;
}


/*
  samr_AddGroupMember
*/
static NTSTATUS dcesrv_samr_AddGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddGroupMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	struct dom_sid *membersid;
	const char *memberdn;
	struct ldb_result *res;
	const char * const attrs[] = { NULL };
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;
	d_state = a_state->domain_state;

	membersid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (membersid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* according to MS-SAMR 3.1.5.8.2 all type of accounts are accepted */
	ret = ldb_search(d_state->sam_ctx, mem_ctx, &res,
			 d_state->domain_dn, LDB_SCOPE_SUBTREE, attrs,
			 "(objectSid=%s)",
			 ldap_encode_ndr_dom_sid(mem_ctx, membersid));

	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (res->count == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}

	if (res->count > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	memberdn = ldb_dn_alloc_linearized(mem_ctx, res->msgs[0]->dn);

	if (memberdn == NULL)
		return NT_STATUS_NO_MEMORY;

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	ret = samdb_msg_add_addval(d_state->sam_ctx, mem_ctx, mod, "member",
								memberdn);
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	ret = ldb_modify(a_state->sam_ctx, mod);
	switch (ret) {
	case LDB_SUCCESS:
		return NT_STATUS_OK;
	case LDB_ERR_ENTRY_ALREADY_EXISTS:
		return NT_STATUS_MEMBER_IN_GROUP;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return dsdb_ldb_err_to_ntstatus(ret);
	}
}


/*
  samr_DeleteDomainGroup
*/
static NTSTATUS dcesrv_samr_DeleteDomainGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteDomainGroup *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	int ret;

        *r->out.group_handle = *r->in.group_handle;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	ret = ldb_delete(a_state->sam_ctx, a_state->account_dn);
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	talloc_free(h);
	ZERO_STRUCTP(r->out.group_handle);

	return NT_STATUS_OK;
}


/*
  samr_DeleteGroupMember
*/
static NTSTATUS dcesrv_samr_DeleteGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteGroupMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	struct dom_sid *membersid;
	const char *memberdn;
	struct ldb_result *res;
	const char * const attrs[] = { NULL };
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;
	d_state = a_state->domain_state;

	membersid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (membersid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* according to MS-SAMR 3.1.5.8.2 all type of accounts are accepted */
	ret = ldb_search(d_state->sam_ctx, mem_ctx, &res,
			 d_state->domain_dn, LDB_SCOPE_SUBTREE, attrs,
			 "(objectSid=%s)",
			 ldap_encode_ndr_dom_sid(mem_ctx, membersid));

	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (res->count == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}

	if (res->count > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	memberdn = ldb_dn_alloc_linearized(mem_ctx, res->msgs[0]->dn);

	if (memberdn == NULL)
		return NT_STATUS_NO_MEMORY;

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	ret = samdb_msg_add_delval(d_state->sam_ctx, mem_ctx, mod, "member",
								memberdn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_modify(a_state->sam_ctx, mod);
	switch (ret) {
	case LDB_SUCCESS:
		return NT_STATUS_OK;
	case LDB_ERR_UNWILLING_TO_PERFORM:
	case LDB_ERR_NO_SUCH_ATTRIBUTE:
		return NT_STATUS_MEMBER_NOT_IN_GROUP;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return dsdb_ldb_err_to_ntstatus(ret);
	}
}


/*
  samr_QueryGroupMember
*/
static NTSTATUS dcesrv_samr_QueryGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct samr_QueryGroupMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct samr_RidAttrArray *array;
	unsigned int i, num_members;
	struct dom_sid *members;
	NTSTATUS status;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;
	d_state = a_state->domain_state;

	status = dsdb_enum_group_mem(d_state->sam_ctx, mem_ctx,
				     a_state->account_dn, &members,
				     &num_members);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	array = talloc_zero(mem_ctx, struct samr_RidAttrArray);
	if (array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (num_members == 0) {
		*r->out.rids = array;

		return NT_STATUS_OK;
	}

	array->rids = talloc_array(array, uint32_t, num_members);
	if (array->rids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	array->attributes = talloc_array(array, uint32_t, num_members);
	if (array->attributes == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	array->count = 0;
	for (i=0; i<num_members; i++) {
		if (!dom_sid_in_domain(d_state->domain_sid, &members[i])) {
			continue;
		}

		status = dom_sid_split_rid(NULL, &members[i], NULL,
					   &array->rids[array->count]);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		array->attributes[array->count] = SE_GROUP_DEFAULT_FLAGS;
		array->count++;
	}

	*r->out.rids = array;

	return NT_STATUS_OK;
}


/*
  samr_SetMemberAttributesOfGroup
*/
static NTSTATUS dcesrv_samr_SetMemberAttributesOfGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetMemberAttributesOfGroup *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_OpenAlias
*/
static NTSTATUS dcesrv_samr_OpenAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_OpenAlias *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *alias_name;
	struct dom_sid *sid;
	struct ldb_message **msgs;
	struct dcesrv_handle *g_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.alias_handle);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the alias SID */
	sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (sid == NULL)
		return NT_STATUS_NO_MEMORY;

	/* search for the group record */
	ret = gendb_search(d_state->sam_ctx, mem_ctx, NULL, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=group)"
			   "(|(grouptype=%d)(grouptype=%d)))",
			   ldap_encode_ndr_dom_sid(mem_ctx, sid),
			   GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
			   GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_ALIAS;
	}
	if (ret != 1) {
		DEBUG(0,("Found %d records matching sid %s\n",
			 ret, dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	alias_name = ldb_msg_find_attr_as_string(msgs[0], "sAMAccountName", NULL);
	if (alias_name == NULL) {
		DEBUG(0,("sAMAccountName field missing for sid %s\n",
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(mem_ctx, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msgs[0]->dn);
	a_state->account_sid = talloc_steal(a_state, sid);
	a_state->account_name = talloc_strdup(a_state, alias_name);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_create(dce_call, SAMR_HANDLE_ALIAS);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = talloc_steal(g_handle, a_state);

	*r->out.alias_handle = g_handle->wire_handle;

	return NT_STATUS_OK;
}


/*
  samr_QueryAliasInfo
*/
static NTSTATUS dcesrv_samr_QueryAliasInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryAliasInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	const char * const attrs[4] = { "sAMAccountName", "description",
					"numMembers", NULL };
	int ret;
	union samr_AliasInfo *info;

	*r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;

	/* pull all the alias attributes */
	ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
			      a_state->account_dn, &res, attrs);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_ALIAS;
	}
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	info = talloc_zero(mem_ctx, union samr_AliasInfo);
	if (info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	switch(r->in.level) {
	case ALIASINFOALL:
		QUERY_STRING(msg, all.name, "sAMAccountName");
		QUERY_UINT  (msg, all.num_members, "numMembers");
		QUERY_STRING(msg, all.description, "description");
		break;
	case ALIASINFONAME:
		QUERY_STRING(msg, name, "sAMAccountName");
		break;
	case ALIASINFODESCRIPTION:
		QUERY_STRING(msg, description, "description");
		break;
	default:
		talloc_free(info);
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	*r->out.info = info;

	return NT_STATUS_OK;
}


/*
  samr_SetAliasInfo
*/
static NTSTATUS dcesrv_samr_SetAliasInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetAliasInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(mem_ctx, a_state->account_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case ALIASINFODESCRIPTION:
		SET_STRING(msg, description,         "description");
		break;
	case ALIASINFONAME:
		/* On W2k3 this does not change the name, it changes the
		 * sAMAccountName attribute */
		SET_STRING(msg, name,                "sAMAccountName");
		break;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* modify the samdb record */
	ret = ldb_modify(a_state->sam_ctx, msg);
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	return NT_STATUS_OK;
}


/*
  samr_DeleteDomAlias
*/
static NTSTATUS dcesrv_samr_DeleteDomAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteDomAlias *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	int ret;

        *r->out.alias_handle = *r->in.alias_handle;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;

	ret = ldb_delete(a_state->sam_ctx, a_state->account_dn);
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	talloc_free(h);
	ZERO_STRUCTP(r->out.alias_handle);

	return NT_STATUS_OK;
}


/*
  samr_AddAliasMember
*/
static NTSTATUS dcesrv_samr_AddAliasMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddAliasMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	struct ldb_message **msgs;
	const char * const attrs[] = { NULL };
	struct ldb_dn *memberdn = NULL;
	int ret;
	NTSTATUS status;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;
	d_state = a_state->domain_state;

	ret = gendb_search(d_state->sam_ctx, mem_ctx, NULL,
			   &msgs, attrs, "(objectsid=%s)",
			   ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));

	if (ret == 1) {
		memberdn = msgs[0]->dn;
	} else if (ret == 0) {
		status = samdb_create_foreign_security_principal(
			d_state->sam_ctx, mem_ctx, r->in.sid, &memberdn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		DEBUG(0,("Found %d records matching sid %s\n",
			 ret, dom_sid_string(mem_ctx, r->in.sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (memberdn == NULL) {
		DEBUG(0, ("Could not find memberdn\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	ret = samdb_msg_add_addval(d_state->sam_ctx, mem_ctx, mod, "member",
				 ldb_dn_alloc_linearized(mem_ctx, memberdn));
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	ret = ldb_modify(a_state->sam_ctx, mod);
	switch (ret) {
	case LDB_SUCCESS:
		return NT_STATUS_OK;
	case LDB_ERR_ENTRY_ALREADY_EXISTS:
		return NT_STATUS_MEMBER_IN_GROUP;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return dsdb_ldb_err_to_ntstatus(ret);
	}
}


/*
  samr_DeleteAliasMember
*/
static NTSTATUS dcesrv_samr_DeleteAliasMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteAliasMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	const char *memberdn;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;
	d_state = a_state->domain_state;

	memberdn = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL,
				       "distinguishedName", "(objectSid=%s)",
				       ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));
	if (memberdn == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	ret = samdb_msg_add_delval(d_state->sam_ctx, mem_ctx, mod, "member",
								 memberdn);
	if (ret != LDB_SUCCESS) {
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	ret = ldb_modify(a_state->sam_ctx, mod);
	switch (ret) {
	case LDB_SUCCESS:
		return NT_STATUS_OK;
	case LDB_ERR_UNWILLING_TO_PERFORM:
		return NT_STATUS_MEMBER_NOT_IN_GROUP;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return dsdb_ldb_err_to_ntstatus(ret);
	}
}


/*
  samr_GetMembersInAlias
*/
static NTSTATUS dcesrv_samr_GetMembersInAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetMembersInAlias *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct lsa_SidPtr *array;
	unsigned int i, num_members;
	struct dom_sid *members;
	NTSTATUS status;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;
	d_state = a_state->domain_state;

	status = dsdb_enum_group_mem(d_state->sam_ctx, mem_ctx,
				     a_state->account_dn, &members,
				     &num_members);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_members == 0) {
		r->out.sids->sids = NULL;

		return NT_STATUS_OK;
	}

	array = talloc_array(mem_ctx, struct lsa_SidPtr, num_members);
	if (array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_members; i++) {
		array[i].sid = &members[i];
	}

	r->out.sids->num_sids = num_members;
	r->out.sids->sids = array;

	return NT_STATUS_OK;
}

/*
  samr_OpenUser
*/
static NTSTATUS dcesrv_samr_OpenUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_OpenUser *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *account_name;
	struct dom_sid *sid;
	struct ldb_message **msgs;
	struct dcesrv_handle *u_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.user_handle);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the users SID */
	sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (!sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the user record */
	ret = gendb_search(d_state->sam_ctx,
			   mem_ctx, d_state->domain_dn, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=user))",
			   ldap_encode_ndr_dom_sid(mem_ctx, sid));
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}
	if (ret != 1) {
		DEBUG(0,("Found %d records matching sid %s\n", ret,
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	account_name = ldb_msg_find_attr_as_string(msgs[0], "sAMAccountName", NULL);
	if (account_name == NULL) {
		DEBUG(0,("sAMAccountName field missing for sid %s\n",
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(mem_ctx, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msgs[0]->dn);
	a_state->account_sid = talloc_steal(a_state, sid);
	a_state->account_name = talloc_strdup(a_state, account_name);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_create(dce_call, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = talloc_steal(u_handle, a_state);

	*r->out.user_handle = u_handle->wire_handle;

	return NT_STATUS_OK;

}


/*
  samr_DeleteUser
*/
static NTSTATUS dcesrv_samr_DeleteUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_DeleteUser *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	int ret;

	*r->out.user_handle = *r->in.user_handle;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;

	ret = ldb_delete(a_state->sam_ctx, a_state->account_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Failed to delete user: %s: %s\n",
			  ldb_dn_get_linearized(a_state->account_dn),
			  ldb_errstring(a_state->sam_ctx)));
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	talloc_free(h);
	ZERO_STRUCTP(r->out.user_handle);

	return NT_STATUS_OK;
}


/*
  samr_QueryUserInfo
*/
static NTSTATUS dcesrv_samr_QueryUserInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_QueryUserInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	int ret;
	struct ldb_context *sam_ctx;

	const char * const *attrs = NULL;
	union samr_UserInfo *info;

	NTSTATUS status;

	*r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;
	sam_ctx = a_state->sam_ctx;

	/* fill in the reply */
	switch (r->in.level) {
	case 1:
	{
		static const char * const attrs2[] = {"sAMAccountName",
						      "displayName",
						      "primaryGroupID",
						      "description",
						      "comment",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 2:
	{
		static const char * const attrs2[] = {"comment",
						      "countryCode",
						      "codePage",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 3:
	{
		static const char * const attrs2[] = {"sAMAccountName",
						      "displayName",
						      "objectSid",
						      "primaryGroupID",
						      "homeDirectory",
						      "homeDrive",
						      "scriptPath",
						      "profilePath",
						      "userWorkstations",
						      "lastLogon",
						      "lastLogoff",
						      "pwdLastSet",
						      "msDS-UserPasswordExpiryTimeComputed",
						      "logonHours",
						      "badPwdCount",
						      "badPasswordTime",
						      "logonCount",
						      "userAccountControl",
						      "msDS-User-Account-Control-Computed",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 4:
	{
		static const char * const attrs2[] = {"logonHours",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 5:
	{
		static const char * const attrs2[] = {"sAMAccountName",
						      "displayName",
						      "objectSid",
						      "primaryGroupID",
						      "homeDirectory",
						      "homeDrive",
						      "scriptPath",
						      "profilePath",
						      "description",
						      "userWorkstations",
						      "lastLogon",
						      "lastLogoff",
						      "logonHours",
						      "badPwdCount",
						      "badPasswordTime",
						      "logonCount",
						      "pwdLastSet",
						      "msDS-ResultantPSO",
						      "msDS-UserPasswordExpiryTimeComputed",
						      "accountExpires",
						      "userAccountControl",
						      "msDS-User-Account-Control-Computed",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 6:
	{
		static const char * const attrs2[] = {"sAMAccountName",
						      "displayName",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 7:
	{
		static const char * const attrs2[] = {"sAMAccountName",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 8:
	{
		static const char * const attrs2[] = {"displayName",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 9:
	{
		static const char * const attrs2[] = {"primaryGroupID",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 10:
	{
		static const char * const attrs2[] = {"homeDirectory",
						      "homeDrive",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 11:
	{
		static const char * const attrs2[] = {"scriptPath",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 12:
	{
		static const char * const attrs2[] = {"profilePath",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 13:
	{
		static const char * const attrs2[] = {"description",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 14:
	{
		static const char * const attrs2[] = {"userWorkstations",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 16:
	{
		static const char * const attrs2[] = {"userAccountControl",
						      "msDS-User-Account-Control-Computed",
						      "pwdLastSet",
						      "msDS-UserPasswordExpiryTimeComputed",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 17:
	{
		static const char * const attrs2[] = {"accountExpires",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 18:
	{
		return NT_STATUS_NOT_SUPPORTED;
	}
	case 20:
	{
		static const char * const attrs2[] = {"userParameters",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 21:
	{
		static const char * const attrs2[] = {"lastLogon",
						      "lastLogoff",
						      "pwdLastSet",
						      "msDS-ResultantPSO",
						      "msDS-UserPasswordExpiryTimeComputed",
						      "accountExpires",
						      "sAMAccountName",
						      "displayName",
						      "homeDirectory",
						      "homeDrive",
						      "scriptPath",
						      "profilePath",
						      "description",
						      "userWorkstations",
						      "comment",
						      "userParameters",
						      "objectSid",
						      "primaryGroupID",
						      "userAccountControl",
						      "msDS-User-Account-Control-Computed",
						      "logonHours",
						      "badPwdCount",
						      "badPasswordTime",
						      "logonCount",
						      "countryCode",
						      "codePage",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 23:
	case 24:
	case 25:
	case 26:
	{
		return NT_STATUS_NOT_SUPPORTED;
	}
	default:
	{
		return NT_STATUS_INVALID_INFO_CLASS;
	}
	}

	/* pull all the user attributes */
	ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
			      a_state->account_dn, &res, attrs);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	info = talloc_zero(mem_ctx, union samr_UserInfo);
	if (info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* fill in the reply */
	switch (r->in.level) {
	case 1:
		QUERY_STRING(msg, info1.account_name,          "sAMAccountName");
		QUERY_STRING(msg, info1.full_name,             "displayName");
		QUERY_UINT  (msg, info1.primary_gid,           "primaryGroupID");
		QUERY_STRING(msg, info1.description,           "description");
		QUERY_STRING(msg, info1.comment,               "comment");
		break;

	case 2:
		QUERY_STRING(msg, info2.comment,               "comment");
		QUERY_UINT  (msg, info2.country_code,          "countryCode");
		QUERY_UINT  (msg, info2.code_page,             "codePage");
		break;

	case 3:
		QUERY_STRING(msg, info3.account_name,          "sAMAccountName");
		QUERY_STRING(msg, info3.full_name,             "displayName");
		QUERY_RID   (msg, info3.rid,                   "objectSid");
		QUERY_UINT  (msg, info3.primary_gid,           "primaryGroupID");
		QUERY_STRING(msg, info3.home_directory,        "homeDirectory");
		QUERY_STRING(msg, info3.home_drive,            "homeDrive");
		QUERY_STRING(msg, info3.logon_script,          "scriptPath");
		QUERY_STRING(msg, info3.profile_path,          "profilePath");
		QUERY_STRING(msg, info3.workstations,          "userWorkstations");
		QUERY_UINT64(msg, info3.last_logon,            "lastLogon");
		QUERY_UINT64(msg, info3.last_logoff,           "lastLogoff");
		QUERY_UINT64(msg, info3.last_password_change,  "pwdLastSet");
		QUERY_APASSC(msg, info3.allow_password_change, "pwdLastSet");
		QUERY_UINT64(msg, info3.force_password_change, "msDS-UserPasswordExpiryTimeComputed");
		QUERY_LHOURS(msg, info3.logon_hours,           "logonHours");
		/* level 3 gives the raw badPwdCount value */
		QUERY_UINT  (msg, info3.bad_password_count,    "badPwdCount");
		QUERY_UINT  (msg, info3.logon_count,           "logonCount");
		QUERY_AFLAGS(msg, info3.acct_flags,            "msDS-User-Account-Control-Computed");
		break;

	case 4:
		QUERY_LHOURS(msg, info4.logon_hours,           "logonHours");
		break;

	case 5:
		QUERY_STRING(msg, info5.account_name,          "sAMAccountName");
		QUERY_STRING(msg, info5.full_name,             "displayName");
		QUERY_RID   (msg, info5.rid,                   "objectSid");
		QUERY_UINT  (msg, info5.primary_gid,           "primaryGroupID");
		QUERY_STRING(msg, info5.home_directory,        "homeDirectory");
		QUERY_STRING(msg, info5.home_drive,            "homeDrive");
		QUERY_STRING(msg, info5.logon_script,          "scriptPath");
		QUERY_STRING(msg, info5.profile_path,          "profilePath");
		QUERY_STRING(msg, info5.description,           "description");
		QUERY_STRING(msg, info5.workstations,          "userWorkstations");
		QUERY_UINT64(msg, info5.last_logon,            "lastLogon");
		QUERY_UINT64(msg, info5.last_logoff,           "lastLogoff");
		QUERY_LHOURS(msg, info5.logon_hours,           "logonHours");
		QUERY_BPWDCT(msg, info5.bad_password_count,    "badPwdCount");
		QUERY_UINT  (msg, info5.logon_count,           "logonCount");
		QUERY_UINT64(msg, info5.last_password_change,  "pwdLastSet");
		QUERY_UINT64(msg, info5.acct_expiry,           "accountExpires");
		QUERY_AFLAGS(msg, info5.acct_flags,            "msDS-User-Account-Control-Computed");
		break;

	case 6:
		QUERY_STRING(msg, info6.account_name,   "sAMAccountName");
		QUERY_STRING(msg, info6.full_name,      "displayName");
		break;

	case 7:
		QUERY_STRING(msg, info7.account_name,   "sAMAccountName");
		break;

	case 8:
		QUERY_STRING(msg, info8.full_name,      "displayName");
		break;

	case 9:
		QUERY_UINT  (msg, info9.primary_gid,    "primaryGroupID");
		break;

	case 10:
		QUERY_STRING(msg, info10.home_directory,"homeDirectory");
		QUERY_STRING(msg, info10.home_drive,    "homeDrive");
		break;

	case 11:
		QUERY_STRING(msg, info11.logon_script,  "scriptPath");
		break;

	case 12:
		QUERY_STRING(msg, info12.profile_path,  "profilePath");
		break;

	case 13:
		QUERY_STRING(msg, info13.description,   "description");
		break;

	case 14:
		QUERY_STRING(msg, info14.workstations,  "userWorkstations");
		break;

	case 16:
		QUERY_AFLAGS(msg, info16.acct_flags,    "msDS-User-Account-Control-Computed");
		break;

	case 17:
		QUERY_UINT64(msg, info17.acct_expiry,   "accountExpires");
		break;

	case 20:
		status = samdb_result_parameters(mem_ctx, msg, "userParameters", &info->info20.parameters);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(info);
			return status;
		}
		break;

	case 21:
		QUERY_UINT64(msg, info21.last_logon,           "lastLogon");
		QUERY_UINT64(msg, info21.last_logoff,          "lastLogoff");
		QUERY_UINT64(msg, info21.last_password_change, "pwdLastSet");
		QUERY_UINT64(msg, info21.acct_expiry,          "accountExpires");
		QUERY_APASSC(msg, info21.allow_password_change,"pwdLastSet");
		QUERY_UINT64(msg, info21.force_password_change, "msDS-UserPasswordExpiryTimeComputed");
		QUERY_STRING(msg, info21.account_name,         "sAMAccountName");
		QUERY_STRING(msg, info21.full_name,            "displayName");
		QUERY_STRING(msg, info21.home_directory,       "homeDirectory");
		QUERY_STRING(msg, info21.home_drive,           "homeDrive");
		QUERY_STRING(msg, info21.logon_script,         "scriptPath");
		QUERY_STRING(msg, info21.profile_path,         "profilePath");
		QUERY_STRING(msg, info21.description,          "description");
		QUERY_STRING(msg, info21.workstations,         "userWorkstations");
		QUERY_STRING(msg, info21.comment,              "comment");
		status = samdb_result_parameters(mem_ctx, msg, "userParameters", &info->info21.parameters);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(info);
			return status;
		}

		QUERY_RID   (msg, info21.rid,                  "objectSid");
		QUERY_UINT  (msg, info21.primary_gid,          "primaryGroupID");
		QUERY_AFLAGS(msg, info21.acct_flags,           "msDS-User-Account-Control-Computed");
		info->info21.fields_present = 0x08FFFFFF;
		QUERY_LHOURS(msg, info21.logon_hours,          "logonHours");
		QUERY_BPWDCT(msg, info21.bad_password_count,   "badPwdCount");
		QUERY_UINT  (msg, info21.logon_count,          "logonCount");
		if ((info->info21.acct_flags & ACB_PW_EXPIRED) != 0) {
			info->info21.password_expired = PASS_MUST_CHANGE_AT_NEXT_LOGON;
		} else {
			info->info21.password_expired = PASS_DONT_CHANGE_AT_NEXT_LOGON;
		}
		QUERY_UINT  (msg, info21.country_code,         "countryCode");
		QUERY_UINT  (msg, info21.code_page,            "codePage");
		break;


	default:
		talloc_free(info);
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	*r->out.info = info;

	return NT_STATUS_OK;
}


/*
  samr_SetUserInfo
*/
static NTSTATUS dcesrv_samr_SetUserInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_SetUserInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg;
	int ret;
	NTSTATUS status = NT_STATUS_OK;
	struct ldb_context *sam_ctx;
	DATA_BLOB session_key = data_blob_null;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;
	sam_ctx = a_state->sam_ctx;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_reference(mem_ctx, a_state->account_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_transaction_start(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to start a transaction: %s\n",
			ldb_errstring(sam_ctx));
		return NT_STATUS_LOCK_NOT_GRANTED;
	}

	switch (r->in.level) {
	case 2:
		SET_STRING(msg, info2.comment,          "comment");
		SET_UINT  (msg, info2.country_code,     "countryCode");
		SET_UINT  (msg, info2.code_page,        "codePage");
		break;

	case 4:
		SET_LHOURS(msg, info4.logon_hours,      "logonHours");
		break;

	case 6:
		SET_STRING(msg, info6.account_name,     "sAMAccountName");
		SET_STRING(msg, info6.full_name,        "displayName");
		break;

	case 7:
		SET_STRING(msg, info7.account_name,     "sAMAccountName");
		break;

	case 8:
		SET_STRING(msg, info8.full_name,        "displayName");
		break;

	case 9:
		SET_UINT(msg, info9.primary_gid,        "primaryGroupID");
		break;

	case 10:
		SET_STRING(msg, info10.home_directory,  "homeDirectory");
		SET_STRING(msg, info10.home_drive,      "homeDrive");
		break;

	case 11:
		SET_STRING(msg, info11.logon_script,    "scriptPath");
		break;

	case 12:
		SET_STRING(msg, info12.profile_path,    "profilePath");
		break;

	case 13:
		SET_STRING(msg, info13.description,     "description");
		break;

	case 14:
		SET_STRING(msg, info14.workstations,    "userWorkstations");
		break;

	case 16:
		SET_AFLAGS(msg, info16.acct_flags,      "userAccountControl");
		break;

	case 17:
		SET_UINT64(msg, info17.acct_expiry,     "accountExpires");
		break;

	case 18:
		status = samr_set_password_buffers(dce_call,
						   sam_ctx,
						   a_state->account_dn,
						   mem_ctx,
						   r->in.info->info18.lm_pwd_active ? r->in.info->info18.lm_pwd.hash : NULL,
						   r->in.info->info18.nt_pwd_active ? r->in.info->info18.nt_pwd.hash : NULL);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		if (r->in.info->info18.password_expired > 0) {
			struct ldb_message_element *set_el;
			if (samdb_msg_add_uint64(sam_ctx, mem_ctx, msg, "pwdLastSet", 0) != LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}
		break;

	case 20:
		SET_PARAMETERS(msg, info20.parameters,      "userParameters");
		break;

	case 21:
		if (r->in.info->info21.fields_present == 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

#define IFSET(bit) if (bit & r->in.info->info21.fields_present)
		IFSET(SAMR_FIELD_LAST_LOGON)
			SET_UINT64(msg, info21.last_logon,     "lastLogon");
		IFSET(SAMR_FIELD_LAST_LOGOFF)
			SET_UINT64(msg, info21.last_logoff,    "lastLogoff");
		IFSET(SAMR_FIELD_ACCT_EXPIRY)
			SET_UINT64(msg, info21.acct_expiry,    "accountExpires");
		IFSET(SAMR_FIELD_ACCOUNT_NAME)
			SET_STRING(msg, info21.account_name,   "sAMAccountName");
		IFSET(SAMR_FIELD_FULL_NAME)
			SET_STRING(msg, info21.full_name,      "displayName");
		IFSET(SAMR_FIELD_HOME_DIRECTORY)
			SET_STRING(msg, info21.home_directory, "homeDirectory");
		IFSET(SAMR_FIELD_HOME_DRIVE)
			SET_STRING(msg, info21.home_drive,     "homeDrive");
		IFSET(SAMR_FIELD_LOGON_SCRIPT)
			SET_STRING(msg, info21.logon_script,   "scriptPath");
		IFSET(SAMR_FIELD_PROFILE_PATH)
			SET_STRING(msg, info21.profile_path,   "profilePath");
		IFSET(SAMR_FIELD_DESCRIPTION)
			SET_STRING(msg, info21.description,    "description");
		IFSET(SAMR_FIELD_WORKSTATIONS)
			SET_STRING(msg, info21.workstations,   "userWorkstations");
		IFSET(SAMR_FIELD_COMMENT)
			SET_STRING(msg, info21.comment,        "comment");
		IFSET(SAMR_FIELD_PARAMETERS)
			SET_PARAMETERS(msg, info21.parameters, "userParameters");
		IFSET(SAMR_FIELD_PRIMARY_GID)
			SET_UINT(msg, info21.primary_gid,      "primaryGroupID");
		IFSET(SAMR_FIELD_ACCT_FLAGS)
			SET_AFLAGS(msg, info21.acct_flags,     "userAccountControl");
		IFSET(SAMR_FIELD_LOGON_HOURS)
			SET_LHOURS(msg, info21.logon_hours,    "logonHours");
		IFSET(SAMR_FIELD_BAD_PWD_COUNT)
			SET_UINT  (msg, info21.bad_password_count, "badPwdCount");
		IFSET(SAMR_FIELD_NUM_LOGONS)
			SET_UINT  (msg, info21.logon_count,    "logonCount");
		IFSET(SAMR_FIELD_COUNTRY_CODE)
			SET_UINT  (msg, info21.country_code,   "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)
			SET_UINT  (msg, info21.code_page,      "codePage");

		/* password change fields */
		IFSET(SAMR_FIELD_LAST_PWD_CHANGE) {
			status = NT_STATUS_ACCESS_DENIED;
			goto done;
		}

		IFSET((SAMR_FIELD_LM_PASSWORD_PRESENT
					| SAMR_FIELD_NT_PASSWORD_PRESENT)) {
			uint8_t *lm_pwd_hash = NULL, *nt_pwd_hash = NULL;

			if (r->in.info->info21.lm_password_set) {
				if ((r->in.info->info21.lm_owf_password.length != 16)
				 || (r->in.info->info21.lm_owf_password.size != 16)) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto done;
				}

				lm_pwd_hash = (uint8_t *) r->in.info->info21.lm_owf_password.array;
			}
			if (r->in.info->info21.nt_password_set) {
				if ((r->in.info->info21.nt_owf_password.length != 16)
				 || (r->in.info->info21.nt_owf_password.size != 16)) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto done;
				}

				nt_pwd_hash = (uint8_t *) r->in.info->info21.nt_owf_password.array;
			}
			status = samr_set_password_buffers(dce_call,
							   sam_ctx,
							   a_state->account_dn,
							   mem_ctx,
							   lm_pwd_hash,
							   nt_pwd_hash);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}
		}


		IFSET(SAMR_FIELD_EXPIRED_FLAG) {
			const char *t = "0";
			struct ldb_message_element *set_el;
			if (r->in.info->info21.password_expired
					== PASS_DONT_CHANGE_AT_NEXT_LOGON) {
				t = "-1";
			}
			if (ldb_msg_add_string(msg, "pwdLastSet", t) != LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}
#undef IFSET
		break;

	case 23:
		if (r->in.info->info23.info.fields_present == 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

#define IFSET(bit) if (bit & r->in.info->info23.info.fields_present)
		IFSET(SAMR_FIELD_LAST_LOGON)
			SET_UINT64(msg, info23.info.last_logon,     "lastLogon");
		IFSET(SAMR_FIELD_LAST_LOGOFF)
			SET_UINT64(msg, info23.info.last_logoff,    "lastLogoff");
		IFSET(SAMR_FIELD_ACCT_EXPIRY)
			SET_UINT64(msg, info23.info.acct_expiry,    "accountExpires");
		IFSET(SAMR_FIELD_ACCOUNT_NAME)
			SET_STRING(msg, info23.info.account_name,   "sAMAccountName");
		IFSET(SAMR_FIELD_FULL_NAME)
			SET_STRING(msg, info23.info.full_name,      "displayName");
		IFSET(SAMR_FIELD_HOME_DIRECTORY)
			SET_STRING(msg, info23.info.home_directory, "homeDirectory");
		IFSET(SAMR_FIELD_HOME_DRIVE)
			SET_STRING(msg, info23.info.home_drive,     "homeDrive");
		IFSET(SAMR_FIELD_LOGON_SCRIPT)
			SET_STRING(msg, info23.info.logon_script,   "scriptPath");
		IFSET(SAMR_FIELD_PROFILE_PATH)
			SET_STRING(msg, info23.info.profile_path,   "profilePath");
		IFSET(SAMR_FIELD_DESCRIPTION)
			SET_STRING(msg, info23.info.description,    "description");
		IFSET(SAMR_FIELD_WORKSTATIONS)
			SET_STRING(msg, info23.info.workstations,   "userWorkstations");
		IFSET(SAMR_FIELD_COMMENT)
			SET_STRING(msg, info23.info.comment,        "comment");
		IFSET(SAMR_FIELD_PARAMETERS)
			SET_PARAMETERS(msg, info23.info.parameters, "userParameters");
		IFSET(SAMR_FIELD_PRIMARY_GID)
			SET_UINT(msg, info23.info.primary_gid,      "primaryGroupID");
		IFSET(SAMR_FIELD_ACCT_FLAGS)
			SET_AFLAGS(msg, info23.info.acct_flags,     "userAccountControl");
		IFSET(SAMR_FIELD_LOGON_HOURS)
			SET_LHOURS(msg, info23.info.logon_hours,    "logonHours");
		IFSET(SAMR_FIELD_BAD_PWD_COUNT)
			SET_UINT  (msg, info23.info.bad_password_count, "badPwdCount");
		IFSET(SAMR_FIELD_NUM_LOGONS)
			SET_UINT  (msg, info23.info.logon_count,    "logonCount");

		IFSET(SAMR_FIELD_COUNTRY_CODE)
			SET_UINT  (msg, info23.info.country_code,   "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)
			SET_UINT  (msg, info23.info.code_page,      "codePage");

		/* password change fields */
		IFSET(SAMR_FIELD_LAST_PWD_CHANGE) {
			status = NT_STATUS_ACCESS_DENIED;
			goto done;
		}

		IFSET(SAMR_FIELD_NT_PASSWORD_PRESENT) {
			status = samr_set_password(dce_call,
						   sam_ctx,
						   a_state->account_dn,
						   mem_ctx,
						   &r->in.info->info23.password);
		} else IFSET(SAMR_FIELD_LM_PASSWORD_PRESENT) {
			status = samr_set_password(dce_call,
						   sam_ctx,
						   a_state->account_dn,
						   mem_ctx,
						   &r->in.info->info23.password);
		}
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		IFSET(SAMR_FIELD_EXPIRED_FLAG) {
			const char *t = "0";
			struct ldb_message_element *set_el;
			if (r->in.info->info23.info.password_expired
					== PASS_DONT_CHANGE_AT_NEXT_LOGON) {
				t = "-1";
			}
			if (ldb_msg_add_string(msg, "pwdLastSet", t) != LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}
#undef IFSET
		break;

		/* the set password levels are handled separately */
	case 24:
		status = samr_set_password(dce_call,
					   sam_ctx,
					   a_state->account_dn,
					   mem_ctx,
					   &r->in.info->info24.password);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		if (r->in.info->info24.password_expired > 0) {
			struct ldb_message_element *set_el;
			if (samdb_msg_add_uint64(sam_ctx, mem_ctx, msg, "pwdLastSet", 0) != LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}
		break;

	case 25:
		if (r->in.info->info25.info.fields_present == 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

#define IFSET(bit) if (bit & r->in.info->info25.info.fields_present)
		IFSET(SAMR_FIELD_LAST_LOGON)
			SET_UINT64(msg, info25.info.last_logon,     "lastLogon");
		IFSET(SAMR_FIELD_LAST_LOGOFF)
			SET_UINT64(msg, info25.info.last_logoff,    "lastLogoff");
		IFSET(SAMR_FIELD_ACCT_EXPIRY)
			SET_UINT64(msg, info25.info.acct_expiry,    "accountExpires");
		IFSET(SAMR_FIELD_ACCOUNT_NAME)
			SET_STRING(msg, info25.info.account_name,   "sAMAccountName");
		IFSET(SAMR_FIELD_FULL_NAME)
			SET_STRING(msg, info25.info.full_name,      "displayName");
		IFSET(SAMR_FIELD_HOME_DIRECTORY)
			SET_STRING(msg, info25.info.home_directory, "homeDirectory");
		IFSET(SAMR_FIELD_HOME_DRIVE)
			SET_STRING(msg, info25.info.home_drive,     "homeDrive");
		IFSET(SAMR_FIELD_LOGON_SCRIPT)
			SET_STRING(msg, info25.info.logon_script,   "scriptPath");
		IFSET(SAMR_FIELD_PROFILE_PATH)
			SET_STRING(msg, info25.info.profile_path,   "profilePath");
		IFSET(SAMR_FIELD_DESCRIPTION)
			SET_STRING(msg, info25.info.description,    "description");
		IFSET(SAMR_FIELD_WORKSTATIONS)
			SET_STRING(msg, info25.info.workstations,   "userWorkstations");
		IFSET(SAMR_FIELD_COMMENT)
			SET_STRING(msg, info25.info.comment,        "comment");
		IFSET(SAMR_FIELD_PARAMETERS)
			SET_PARAMETERS(msg, info25.info.parameters, "userParameters");
		IFSET(SAMR_FIELD_PRIMARY_GID)
			SET_UINT(msg, info25.info.primary_gid,      "primaryGroupID");
		IFSET(SAMR_FIELD_ACCT_FLAGS)
			SET_AFLAGS(msg, info25.info.acct_flags,     "userAccountControl");
		IFSET(SAMR_FIELD_LOGON_HOURS)
			SET_LHOURS(msg, info25.info.logon_hours,    "logonHours");
		IFSET(SAMR_FIELD_BAD_PWD_COUNT)
			SET_UINT  (msg, info25.info.bad_password_count, "badPwdCount");
		IFSET(SAMR_FIELD_NUM_LOGONS)
			SET_UINT  (msg, info25.info.logon_count,    "logonCount");
		IFSET(SAMR_FIELD_COUNTRY_CODE)
			SET_UINT  (msg, info25.info.country_code,   "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)
			SET_UINT  (msg, info25.info.code_page,      "codePage");

		/* password change fields */
		IFSET(SAMR_FIELD_LAST_PWD_CHANGE) {
			status = NT_STATUS_ACCESS_DENIED;
			goto done;
		}

		IFSET(SAMR_FIELD_NT_PASSWORD_PRESENT) {
			status = samr_set_password_ex(dce_call,
						      sam_ctx,
						      a_state->account_dn,
						      mem_ctx,
						      &r->in.info->info25.password);
		} else IFSET(SAMR_FIELD_LM_PASSWORD_PRESENT) {
			status = samr_set_password_ex(dce_call,
						      sam_ctx,
						      a_state->account_dn,
						      mem_ctx,
						      &r->in.info->info25.password);
		}
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		IFSET(SAMR_FIELD_EXPIRED_FLAG) {
			const char *t = "0";
			struct ldb_message_element *set_el;
			if (r->in.info->info25.info.password_expired
					== PASS_DONT_CHANGE_AT_NEXT_LOGON) {
				t = "-1";
			}
			if (ldb_msg_add_string(msg, "pwdLastSet", t) != LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}
#undef IFSET
		break;

		/* the set password levels are handled separately */
	case 26:
		status = samr_set_password_ex(dce_call,
					      sam_ctx,
					      a_state->account_dn,
					      mem_ctx,
					      &r->in.info->info26.password);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		if (r->in.info->info26.password_expired > 0) {
			const char *t = "0";
			struct ldb_message_element *set_el;
			if (r->in.info->info26.password_expired
					== PASS_DONT_CHANGE_AT_NEXT_LOGON) {
				t = "-1";
			}
			if (ldb_msg_add_string(msg, "pwdLastSet", t) != LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}
		break;

	case 31:
		status = dcesrv_transport_session_key(dce_call, &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_NOTICE("samr: failed to get session key: %s\n",
				   nt_errstr(status));
			goto done;
		}

		status = samr_set_password_aes(dce_call,
					       mem_ctx,
					       &session_key,
					       sam_ctx,
					       a_state->account_dn,
					       &r->in.info->info31.password,
					       DSDB_PASSWORD_RESET);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		if (r->in.info->info31.password_expired > 0) {
			const char *t = "0";
			struct ldb_message_element *set_el = NULL;

			if (r->in.info->info31.password_expired ==
			    PASS_DONT_CHANGE_AT_NEXT_LOGON) {
				t = "-1";
			}

			ret = ldb_msg_add_string(msg, "pwdLastSet", t);
			if (ret != LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}

		break;
	case 32:
		status = dcesrv_transport_session_key(dce_call, &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_NOTICE("samr: failed to get session key: %s\n",
				   nt_errstr(status));
			goto done;
		}

		if (r->in.info->info32.info.fields_present == 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

#define IFSET(bit) if (bit & r->in.info->info32.info.fields_present)
		IFSET(SAMR_FIELD_LAST_LOGON)
		{
			SET_UINT64(msg, info32.info.last_logon, "lastLogon");
		}
		IFSET(SAMR_FIELD_LAST_LOGOFF)
		{
			SET_UINT64(msg, info32.info.last_logoff, "lastLogoff");
		}
		IFSET(SAMR_FIELD_ACCT_EXPIRY)
		{
			SET_UINT64(msg,
				   info32.info.acct_expiry,
				   "accountExpires");
		}
		IFSET(SAMR_FIELD_ACCOUNT_NAME)
		{
			SET_STRING(msg,
				   info32.info.account_name,
				   "sAMAccountName");
		}
		IFSET(SAMR_FIELD_FULL_NAME)
		{
			SET_STRING(msg, info32.info.full_name, "displayName");
		}
		IFSET(SAMR_FIELD_HOME_DIRECTORY)
		{
			SET_STRING(msg,
				   info32.info.home_directory,
				   "homeDirectory");
		}
		IFSET(SAMR_FIELD_HOME_DRIVE)
		{
			SET_STRING(msg, info32.info.home_drive, "homeDrive");
		}
		IFSET(SAMR_FIELD_LOGON_SCRIPT)
		{
			SET_STRING(msg, info32.info.logon_script, "scriptPath");
		}
		IFSET(SAMR_FIELD_PROFILE_PATH)
		{
			SET_STRING(msg,
				   info32.info.profile_path,
				   "profilePath");
		}
		IFSET(SAMR_FIELD_DESCRIPTION)
		{
			SET_STRING(msg, info32.info.description, "description");
		}
		IFSET(SAMR_FIELD_WORKSTATIONS)
		{
			SET_STRING(msg,
				   info32.info.workstations,
				   "userWorkstations");
		}
		IFSET(SAMR_FIELD_COMMENT)
		{
			SET_STRING(msg, info32.info.comment, "comment");
		}
		IFSET(SAMR_FIELD_PARAMETERS)
		{
			SET_PARAMETERS(msg,
				       info32.info.parameters,
				       "userParameters");
		}
		IFSET(SAMR_FIELD_PRIMARY_GID)
		{
			SET_UINT(msg,
				 info32.info.primary_gid,
				 "primaryGroupID");
		}
		IFSET(SAMR_FIELD_ACCT_FLAGS)
		{
			SET_AFLAGS(msg,
				   info32.info.acct_flags,
				   "userAccountControl");
		}
		IFSET(SAMR_FIELD_LOGON_HOURS)
		{
			SET_LHOURS(msg, info32.info.logon_hours, "logonHours");
		}
		IFSET(SAMR_FIELD_BAD_PWD_COUNT)
		{
			SET_UINT(msg,
				 info32.info.bad_password_count,
				 "badPwdCount");
		}
		IFSET(SAMR_FIELD_NUM_LOGONS)
		{
			SET_UINT(msg, info32.info.logon_count, "logonCount");
		}
		IFSET(SAMR_FIELD_COUNTRY_CODE)
		{
			SET_UINT(msg, info32.info.country_code, "countryCode");
		}
		IFSET(SAMR_FIELD_CODE_PAGE)
		{
			SET_UINT(msg, info32.info.code_page, "codePage");
		}

		/* password change fields */
		IFSET(SAMR_FIELD_LAST_PWD_CHANGE)
		{
			status = NT_STATUS_ACCESS_DENIED;
			goto done;
		}

		IFSET(SAMR_FIELD_NT_PASSWORD_PRESENT)
		{
			status = samr_set_password_aes(
				dce_call,
				mem_ctx,
				&session_key,
				a_state->sam_ctx,
				a_state->account_dn,
				&r->in.info->info32.password,
				DSDB_PASSWORD_RESET);
		}
		else IFSET(SAMR_FIELD_LM_PASSWORD_PRESENT)
		{
			status = samr_set_password_aes(
				dce_call,
				mem_ctx,
				&session_key,
				a_state->sam_ctx,
				a_state->account_dn,
				&r->in.info->info32.password,
				DSDB_PASSWORD_RESET);
		}
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		IFSET(SAMR_FIELD_EXPIRED_FLAG)
		{
			const char *t = "0";
			struct ldb_message_element *set_el;
			if (r->in.info->info32.info.password_expired ==
			    PASS_DONT_CHANGE_AT_NEXT_LOGON) {
				t = "-1";
			}
			if (ldb_msg_add_string(msg, "pwdLastSet", t) !=
			    LDB_SUCCESS) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
			set_el = ldb_msg_find_element(msg, "pwdLastSet");
			set_el->flags = LDB_FLAG_MOD_REPLACE;
		}
#undef IFSET

		break;
	default:
		/* many info classes are not valid for SetUserInfo */
		status = NT_STATUS_INVALID_INFO_CLASS;
		goto done;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* modify the samdb record */
	if (msg->num_elements > 0) {
		ret = ldb_modify(sam_ctx, msg);
		if (ret != LDB_SUCCESS) {
			DEBUG(1,("Failed to modify record %s: %s\n",
				 ldb_dn_get_linearized(a_state->account_dn),
				 ldb_errstring(sam_ctx)));

			status = dsdb_ldb_err_to_ntstatus(ret);
			goto done;
		}
	}

	ret = ldb_transaction_commit(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to commit transaction modifying account record "
			"%s: %s\n",
			ldb_dn_get_linearized(msg->dn),
			ldb_errstring(sam_ctx));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = NT_STATUS_OK;
done:
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
	}

	return status;
}


/*
  samr_GetGroupsForUser
*/
static NTSTATUS dcesrv_samr_GetGroupsForUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetGroupsForUser *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_result *res, *res_memberof;
	const char * const attrs[] = { "primaryGroupID",
				       "memberOf",
				       NULL };
	const char * const group_attrs[] = { "objectSid",
					     NULL };

	struct samr_RidWithAttributeArray *array;
	struct ldb_message_element *memberof_el;
	int i, ret, count = 0;
	uint32_t primary_group_id;
	char *filter;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;
	d_state = a_state->domain_state;

	ret = dsdb_search_dn(a_state->sam_ctx, mem_ctx,
			     &res,
			     a_state->account_dn,
			     attrs, DSDB_SEARCH_SHOW_EXTENDED_DN);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		return NT_STATUS_NO_SUCH_USER;
	} else if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else if (res->count != 1) {
		return NT_STATUS_NO_SUCH_USER;
	}

	primary_group_id = ldb_msg_find_attr_as_uint(res->msgs[0], "primaryGroupID",
						     0);

	filter = talloc_asprintf(mem_ctx,
				 "(&(|(grouptype=%d)(grouptype=%d))"
				 "(objectclass=group)(|",
				 GTYPE_SECURITY_UNIVERSAL_GROUP,
				 GTYPE_SECURITY_GLOBAL_GROUP);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	memberof_el = ldb_msg_find_element(res->msgs[0], "memberOf");
	if (memberof_el != NULL) {
		for (i = 0; i < memberof_el->num_values; i++) {
			const struct ldb_val *memberof_sid_binary;
			char *memberof_sid_escaped;
			struct ldb_dn *memberof_dn
				= ldb_dn_from_ldb_val(mem_ctx,
						      a_state->sam_ctx,
						      &memberof_el->values[i]);
			if (memberof_dn == NULL) {
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}

			memberof_sid_binary
				= ldb_dn_get_extended_component(memberof_dn,
								"SID");
			if (memberof_sid_binary == NULL) {
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}

			memberof_sid_escaped = ldb_binary_encode(mem_ctx,
								 *memberof_sid_binary);
			if (memberof_sid_escaped == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			filter = talloc_asprintf_append(filter, "(objectSID=%s)",
							memberof_sid_escaped);
			if (filter == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		ret = dsdb_search(a_state->sam_ctx, mem_ctx,
				  &res_memberof,
				  d_state->domain_dn,
				  LDB_SCOPE_SUBTREE,
				  group_attrs, 0,
				  "%s))", filter);

		if (ret != LDB_SUCCESS) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		count = res_memberof->count;
	}

	array = talloc(mem_ctx, struct samr_RidWithAttributeArray);
	if (array == NULL)
		return NT_STATUS_NO_MEMORY;

	array->count = 0;
	array->rids = NULL;

	array->rids = talloc_array(mem_ctx, struct samr_RidWithAttribute,
				   count + 1);
	if (array->rids == NULL)
		return NT_STATUS_NO_MEMORY;

	/* Adds the primary group */

	array->rids[0].rid = primary_group_id;
	array->rids[0].attributes = SE_GROUP_DEFAULT_FLAGS;
	array->count += 1;

	/* Adds the additional groups */
	for (i = 0; i < count; i++) {
		struct dom_sid *group_sid;

		group_sid = samdb_result_dom_sid(mem_ctx,
						 res_memberof->msgs[i],
						 "objectSid");
		if (group_sid == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		array->rids[i + 1].rid =
			group_sid->sub_auths[group_sid->num_auths-1];
		array->rids[i + 1].attributes = SE_GROUP_DEFAULT_FLAGS;
		array->count += 1;
	}

	*r->out.rids = array;

	return NT_STATUS_OK;
}

/*
 * samr_QueryDisplayInfo
 *
 * A cache of the GUID's matching the last query is maintained
 * in the SAMR_QUERY_DISPLAY_INFO_CACHE guid_cache maintained o
 * n the dcesrv_handle.
 */
static NTSTATUS dcesrv_samr_QueryDisplayInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDisplayInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_result *res;
	uint32_t i;
	uint32_t results = 0;
	uint32_t count = 0;
	const char *const cache_attrs[] = {"objectGUID", NULL};
	const char *const attrs[] = {
	    "objectSID", "sAMAccountName", "displayName", "description", NULL};
	struct samr_DispEntryFull *entriesFull = NULL;
	struct samr_DispEntryFullGroup *entriesFullGroup = NULL;
	struct samr_DispEntryAscii *entriesAscii = NULL;
	struct samr_DispEntryGeneral *entriesGeneral = NULL;
	const char *filter;
	int ret;
	NTSTATUS status;
	struct samr_guid_cache *cache = NULL;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	cache = &d_state->guid_caches[SAMR_QUERY_DISPLAY_INFO_CACHE];
	/*
	 * Can the cached results be used?
	 * The cache is discarded if the start index is zero, or the requested
	 * level is different from that in the cache.
	 */
	if ((r->in.start_idx == 0) || (r->in.level != cache->handle)) {
		/*
		 * The cached results can not be used, so will need to query
		 * the database.
		 */

		/*
		 * Get the search filter for the current level
		 */
		switch (r->in.level) {
		case 1:
		case 4:
			filter = talloc_asprintf(mem_ctx,
						 "(&(objectclass=user)"
						 "(sAMAccountType=%d))",
						 ATYPE_NORMAL_ACCOUNT);
			break;
		case 2:
			filter = talloc_asprintf(mem_ctx,
						 "(&(objectclass=user)"
						 "(sAMAccountType=%d))",
						 ATYPE_WORKSTATION_TRUST);
			break;
		case 3:
		case 5:
			filter =
			    talloc_asprintf(mem_ctx,
					    "(&(|(groupType=%d)(groupType=%d))"
					    "(objectClass=group))",
					    GTYPE_SECURITY_UNIVERSAL_GROUP,
					    GTYPE_SECURITY_GLOBAL_GROUP);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
		}
		clear_guid_cache(cache);

		/*
		 * search for all requested objects in all domains.
		 */
		ret = dsdb_search(d_state->sam_ctx,
				  mem_ctx,
				  &res,
				  ldb_get_default_basedn(d_state->sam_ctx),
				  LDB_SCOPE_SUBTREE,
				  cache_attrs,
				  0,
				  "%s",
				  filter);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		if ((res->count == 0) || (r->in.max_entries == 0)) {
			return NT_STATUS_OK;
		}

		status = load_guid_cache(cache, d_state, res->count, res->msgs);
		TALLOC_FREE(res);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		cache->handle = r->in.level;
	}
	*r->out.total_size = cache->size;

	/*
	 * if there are no entries or the requested start index is greater
	 * than the number of entries, we return an empty response.
	 */
	if (r->in.start_idx >= cache->size) {
		*r->out.returned_size = 0;
		switch(r->in.level) {
		case 1:
			r->out.info->info1.count = *r->out.returned_size;
			r->out.info->info1.entries = NULL;
			break;
		case 2:
			r->out.info->info2.count = *r->out.returned_size;
			r->out.info->info2.entries = NULL;
			break;
		case 3:
			r->out.info->info3.count = *r->out.returned_size;
			r->out.info->info3.entries = NULL;
			break;
		case 4:
			r->out.info->info4.count = *r->out.returned_size;
			r->out.info->info4.entries = NULL;
			break;
		case 5:
			r->out.info->info5.count = *r->out.returned_size;
			r->out.info->info5.entries = NULL;
			break;
		}
		return NT_STATUS_OK;
	}

	/*
	 * Allocate an array of the appropriate result structures for the
	 * current query level.
	 *
	 * r->in.start_idx is always < cache->size due to the check above
	 */
	results = MIN((cache->size - r->in.start_idx), r->in.max_entries);
	switch (r->in.level) {
	case 1:
		entriesGeneral = talloc_array(
		    mem_ctx, struct samr_DispEntryGeneral, results);
		break;
	case 2:
		entriesFull =
		    talloc_array(mem_ctx, struct samr_DispEntryFull, results);
		break;
	case 3:
		entriesFullGroup = talloc_array(
		    mem_ctx, struct samr_DispEntryFullGroup, results);
		break;
	case 4:
	case 5:
		entriesAscii =
		    talloc_array(mem_ctx, struct samr_DispEntryAscii, results);
		break;
	}

	if ((entriesGeneral == NULL) && (entriesFull == NULL) &&
	    (entriesAscii == NULL) && (entriesFullGroup == NULL))
		return NT_STATUS_NO_MEMORY;

	/*
	 * Process the list of result GUID's.
	 * Read the details of each object and populate the result structure
	 * for the current level.
	 */
	count = 0;
	for (i = 0; i < results; i++) {
		struct dom_sid *objectsid;
		struct ldb_result *rec;
		const uint32_t idx = r->in.start_idx + i;
		uint32_t rid;

		/*
		 * Read an object from disk using the GUID as the key
		 *
		 * If the object can not be read, or it does not have a SID
		 * it is ignored.  In this case the number of entries returned
		 * will be less than the requested size, there will also be
		 * a gap in the idx numbers in the returned elements e.g. if
		 * there are 3 GUIDs a, b, c in the cache and b is deleted from
		 * disk then details for a, and c will be returned with
		 * idx values of 1 and 3 respectively.
		 *
		 */
		ret = dsdb_search_by_dn_guid(d_state->sam_ctx,
					     mem_ctx,
					     &rec,
					     &cache->entries[idx],
					     attrs,
					     0);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			struct GUID_txt_buf guid_buf;
			char *guid_str =
				GUID_buf_string(&cache->entries[idx],
						&guid_buf);
			DBG_WARNING("GUID [%s] not found\n", guid_str);
			continue;
		} else if (ret != LDB_SUCCESS) {
			clear_guid_cache(cache);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		objectsid = samdb_result_dom_sid(mem_ctx,
						 rec->msgs[0],
						 "objectSID");
		if (objectsid == NULL) {
			struct GUID_txt_buf guid_buf;
			DBG_WARNING(
			    "objectSID for GUID [%s] not found\n",
			    GUID_buf_string(&cache->entries[idx], &guid_buf));
			continue;
		}
		status = dom_sid_split_rid(NULL,
					   objectsid,
					   NULL,
					   &rid);
		if (!NT_STATUS_IS_OK(status)) {
			struct dom_sid_buf sid_buf;
			struct GUID_txt_buf guid_buf;
			DBG_WARNING(
			    "objectSID [%s] for GUID [%s] invalid\n",
			    dom_sid_str_buf(objectsid, &sid_buf),
			    GUID_buf_string(&cache->entries[idx], &guid_buf));
			continue;
		}

		/*
		 * Populate the result structure for the current object
		 */
		switch(r->in.level) {
		case 1:

			entriesGeneral[count].idx = idx + 1;
			entriesGeneral[count].rid = rid;

			entriesGeneral[count].acct_flags =
			    samdb_result_acct_flags(rec->msgs[0], NULL);
			entriesGeneral[count].account_name.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "sAMAccountName", "");
			entriesGeneral[count].full_name.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "displayName", "");
			entriesGeneral[count].description.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "description", "");
			break;
		case 2:
			entriesFull[count].idx = idx + 1;
			entriesFull[count].rid = rid;

			/*
			 * No idea why we need to or in ACB_NORMAL here,
			 * but this is what Win2k3 seems to do...
			 */
			entriesFull[count].acct_flags =
			    samdb_result_acct_flags(rec->msgs[0], NULL) |
			    ACB_NORMAL;
			entriesFull[count].account_name.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "sAMAccountName", "");
			entriesFull[count].description.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "description", "");
			break;
		case 3:
			entriesFullGroup[count].idx = idx + 1;
			entriesFullGroup[count].rid = rid;

			/*
			 * We get a "7" here for groups
			 */
			entriesFullGroup[count].acct_flags = SE_GROUP_DEFAULT_FLAGS;
			entriesFullGroup[count].account_name.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "sAMAccountName", "");
			entriesFullGroup[count].description.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "description", "");
			break;
		case 4:
		case 5:
			entriesAscii[count].idx = idx + 1;
			entriesAscii[count].account_name.string =
			    ldb_msg_find_attr_as_string(
				rec->msgs[0], "sAMAccountName", "");
			break;
		}
		count++;
	}

	/*
	 * Build the response based on the request level.
	 */
	*r->out.returned_size = count;
	switch(r->in.level) {
	case 1:
		r->out.info->info1.count = count;
		r->out.info->info1.entries = entriesGeneral;
		break;
	case 2:
		r->out.info->info2.count = count;
		r->out.info->info2.entries = entriesFull;
		break;
	case 3:
		r->out.info->info3.count = count;
		r->out.info->info3.entries = entriesFullGroup;
		break;
	case 4:
		r->out.info->info4.count = count;
		r->out.info->info4.entries = entriesAscii;
		break;
	case 5:
		r->out.info->info5.count = count;
		r->out.info->info5.entries = entriesAscii;
		break;
	}

	return ((r->in.start_idx + results) < cache->size)
		   ? STATUS_MORE_ENTRIES
		   : NT_STATUS_OK;
}


/*
  samr_GetDisplayEnumerationIndex
*/
static NTSTATUS dcesrv_samr_GetDisplayEnumerationIndex(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetDisplayEnumerationIndex *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_TestPrivateFunctionsDomain
*/
static NTSTATUS dcesrv_samr_TestPrivateFunctionsDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_TestPrivateFunctionsDomain *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  samr_TestPrivateFunctionsUser
*/
static NTSTATUS dcesrv_samr_TestPrivateFunctionsUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_TestPrivateFunctionsUser *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  samr_GetUserPwInfo
*/
static NTSTATUS dcesrv_samr_GetUserPwInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_GetUserPwInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;

	ZERO_STRUCTP(r->out.info);

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;

	r->out.info->min_password_length = samdb_search_uint(a_state->sam_ctx,
		mem_ctx, 0, a_state->domain_state->domain_dn, "minPwdLength",
		NULL);
	r->out.info->password_properties = samdb_search_uint(a_state->sam_ctx,
		mem_ctx, 0, a_state->account_dn, "pwdProperties", NULL);

	return NT_STATUS_OK;
}


/*
  samr_RemoveMemberFromForeignDomain
*/
static NTSTATUS dcesrv_samr_RemoveMemberFromForeignDomain(struct dcesrv_call_state *dce_call,
							  TALLOC_CTX *mem_ctx,
							  struct samr_RemoveMemberFromForeignDomain *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	const char *memberdn;
	struct ldb_message **res;
	const char *no_attrs[] = { NULL };
	int i, count;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	memberdn = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL,
				       "distinguishedName", "(objectSid=%s)",
				       ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));
	/* Nothing to do */
	if (memberdn == NULL) {
		return NT_STATUS_OK;
	}

	count = samdb_search_domain(d_state->sam_ctx, mem_ctx,
				    d_state->domain_dn, &res, no_attrs,
				    d_state->domain_sid,
				    "(&(member=%s)(objectClass=group)"
				    "(|(groupType=%d)(groupType=%d)))",
				    memberdn,
				    GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
				    GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);

	if (count < 0)
		return NT_STATUS_INTERNAL_DB_CORRUPTION;

	for (i=0; i<count; i++) {
		struct ldb_message *mod;
		int ret;

		mod = ldb_msg_new(mem_ctx);
		if (mod == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		mod->dn = res[i]->dn;

		if (samdb_msg_add_delval(d_state->sam_ctx, mem_ctx, mod,
					 "member", memberdn) != LDB_SUCCESS)
			return NT_STATUS_NO_MEMORY;

		ret = ldb_modify(d_state->sam_ctx, mod);
		talloc_free(mod);
		if (ret != LDB_SUCCESS) {
			return dsdb_ldb_err_to_ntstatus(ret);
		}
	}

	return NT_STATUS_OK;
}


/*
  samr_QueryDomainInfo2

  just an alias for samr_QueryDomainInfo
*/
static NTSTATUS dcesrv_samr_QueryDomainInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDomainInfo2 *r)
{
	struct samr_QueryDomainInfo r1;
	NTSTATUS status;

	r1 = (struct samr_QueryDomainInfo) {
		.in.domain_handle = r->in.domain_handle,
		.in.level  = r->in.level,
		.out.info  = r->out.info,
	};

	status = dcesrv_samr_QueryDomainInfo(dce_call, mem_ctx, &r1);

	return status;
}


/*
  samr_QueryUserInfo2

  just an alias for samr_QueryUserInfo
*/
static NTSTATUS dcesrv_samr_QueryUserInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct samr_QueryUserInfo2 *r)
{
	struct samr_QueryUserInfo r1;
	NTSTATUS status;

	r1 = (struct samr_QueryUserInfo) {
		.in.user_handle = r->in.user_handle,
		.in.level  = r->in.level,
		.out.info  = r->out.info
	};

	status = dcesrv_samr_QueryUserInfo(dce_call, mem_ctx, &r1);

	return status;
}


/*
  samr_QueryDisplayInfo2
*/
static NTSTATUS dcesrv_samr_QueryDisplayInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct samr_QueryDisplayInfo2 *r)
{
	struct samr_QueryDisplayInfo q;
	NTSTATUS result;

	q = (struct samr_QueryDisplayInfo) {
		.in.domain_handle = r->in.domain_handle,
		.in.level = r->in.level,
		.in.start_idx = r->in.start_idx,
		.in.max_entries = r->in.max_entries,
		.in.buf_size = r->in.buf_size,
		.out.total_size = r->out.total_size,
		.out.returned_size = r->out.returned_size,
		.out.info = r->out.info,
	};

	result = dcesrv_samr_QueryDisplayInfo(dce_call, mem_ctx, &q);

	return result;
}


/*
  samr_GetDisplayEnumerationIndex2
*/
static NTSTATUS dcesrv_samr_GetDisplayEnumerationIndex2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetDisplayEnumerationIndex2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_QueryDisplayInfo3
*/
static NTSTATUS dcesrv_samr_QueryDisplayInfo3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDisplayInfo3 *r)
{
	struct samr_QueryDisplayInfo q;
	NTSTATUS result;

	q = (struct samr_QueryDisplayInfo) {
		.in.domain_handle = r->in.domain_handle,
		.in.level = r->in.level,
		.in.start_idx = r->in.start_idx,
		.in.max_entries = r->in.max_entries,
		.in.buf_size = r->in.buf_size,
		.out.total_size = r->out.total_size,
		.out.returned_size = r->out.returned_size,
		.out.info = r->out.info,
	};

	result = dcesrv_samr_QueryDisplayInfo(dce_call, mem_ctx, &q);

	return result;
}


/*
  samr_AddMultipleMembersToAlias
*/
static NTSTATUS dcesrv_samr_AddMultipleMembersToAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddMultipleMembersToAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_RemoveMultipleMembersFromAlias
*/
static NTSTATUS dcesrv_samr_RemoveMultipleMembersFromAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_RemoveMultipleMembersFromAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_GetDomPwInfo

  this fetches the default password properties for a domain

  note that w2k3 completely ignores the domain name in this call, and
  always returns the information for the servers primary domain
*/
static NTSTATUS dcesrv_samr_GetDomPwInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_GetDomPwInfo *r)
{
	struct ldb_message **msgs;
	int ret;
	const char * const attrs[] = {"minPwdLength", "pwdProperties", NULL };
	struct ldb_context *sam_ctx;

	ZERO_STRUCTP(r->out.info);

	sam_ctx = dcesrv_samdb_connect_as_user(mem_ctx, dce_call);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* The domain name in this call is ignored */
	ret = gendb_search_dn(sam_ctx,
			   mem_ctx, NULL, &msgs, attrs);
	if (ret <= 0) {
		talloc_free(sam_ctx);

		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	if (ret > 1) {
		talloc_free(msgs);
		talloc_free(sam_ctx);

		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	r->out.info->min_password_length = ldb_msg_find_attr_as_uint(msgs[0],
		"minPwdLength", 0);
	r->out.info->password_properties = ldb_msg_find_attr_as_uint(msgs[0],
		"pwdProperties", 1);

	talloc_free(msgs);
	talloc_unlink(mem_ctx, sam_ctx);

	return NT_STATUS_OK;
}


/*
  samr_Connect2
*/
static NTSTATUS dcesrv_samr_Connect2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Connect2 *r)
{
	struct samr_Connect c;

	c = (struct samr_Connect) {
		.in.system_name = NULL,
		.in.access_mask = r->in.access_mask,
		.out.connect_handle = r->out.connect_handle,
	};

	return dcesrv_samr_Connect(dce_call, mem_ctx, &c);
}


/*
  samr_SetUserInfo2

  just an alias for samr_SetUserInfo
*/
static NTSTATUS dcesrv_samr_SetUserInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_SetUserInfo2 *r)
{
	struct samr_SetUserInfo r2;

	r2 = (struct samr_SetUserInfo) {
		.in.user_handle = r->in.user_handle,
		.in.level = r->in.level,
		.in.info = r->in.info,
	};

	return dcesrv_samr_SetUserInfo(dce_call, mem_ctx, &r2);
}


/*
  samr_SetBootKeyInformation
*/
static NTSTATUS dcesrv_samr_SetBootKeyInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetBootKeyInformation *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_GetBootKeyInformation
*/
static NTSTATUS dcesrv_samr_GetBootKeyInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetBootKeyInformation *r)
{
	/* Windows Server 2008 returns this */
	return NT_STATUS_NOT_SUPPORTED;
}


/*
  samr_Connect3
*/
static NTSTATUS dcesrv_samr_Connect3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_Connect3 *r)
{
	struct samr_Connect c;

	c = (struct samr_Connect) {
		.in.system_name = NULL,
		.in.access_mask = r->in.access_mask,
		.out.connect_handle = r->out.connect_handle,
	};

	return dcesrv_samr_Connect(dce_call, mem_ctx, &c);
}


/*
  samr_Connect4
*/
static NTSTATUS dcesrv_samr_Connect4(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_Connect4 *r)
{
	struct samr_Connect c;

	c = (struct samr_Connect) {
		.in.system_name = NULL,
		.in.access_mask = r->in.access_mask,
		.out.connect_handle = r->out.connect_handle,
	};

	return dcesrv_samr_Connect(dce_call, mem_ctx, &c);
}


/*
  samr_Connect5
*/
static NTSTATUS dcesrv_samr_Connect5(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Connect5 *r)
{
	struct samr_Connect c;
	NTSTATUS status;

	c = (struct samr_Connect) {
		.in.system_name = NULL,
		.in.access_mask = r->in.access_mask,
		.out.connect_handle = r->out.connect_handle,
	};

	status = dcesrv_samr_Connect(dce_call, mem_ctx, &c);

	r->out.info_out->info1.client_version = SAMR_CONNECT_AFTER_W2K;
	r->out.info_out->info1.supported_features = 0;
	*r->out.level_out = r->in.level_in;

	return status;
}


/*
  samr_RidToSid
*/
static NTSTATUS dcesrv_samr_RidToSid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_RidToSid *r)
{
	struct samr_domain_state *d_state;
	struct dcesrv_handle *h;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the users SID */
	*r->out.sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (!*r->out.sid) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}


/*
  samr_SetDsrmPassword
*/
static NTSTATUS dcesrv_samr_SetDsrmPassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetDsrmPassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  samr_ValidatePassword

  For now the call checks the password complexity (if active) and the minimum
  password length on level 2 and 3. Level 1 is ignored for now.
*/
static NTSTATUS dcesrv_samr_ValidatePassword(struct dcesrv_call_state *dce_call,
					     TALLOC_CTX *mem_ctx,
					     struct samr_ValidatePassword *r)
{
	struct samr_GetDomPwInfo r2 = {};
	struct samr_PwInfo pwInfo = {};
	const char *account = NULL;
	DATA_BLOB password;
	enum samr_ValidationStatus res;
	NTSTATUS status;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;

	if (transport != NCACN_IP_TCP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	dcesrv_call_auth_info(dce_call, NULL, &auth_level);
	if (auth_level != DCERPC_AUTH_LEVEL_PRIVACY) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	(*r->out.rep) = talloc_zero(mem_ctx, union samr_ValidatePasswordRep);

	r2 = (struct samr_GetDomPwInfo) {
		.in.domain_name = NULL,
		.out.info = &pwInfo,
	};

	status = dcesrv_samr_GetDomPwInfo(dce_call, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (r->in.level) {
	case NetValidateAuthentication:
		/* we don't support this yet */
		return NT_STATUS_NOT_SUPPORTED;
	break;
	case NetValidatePasswordChange:
		account = r->in.req->req2.account.string;
		password = data_blob_const(r->in.req->req2.password.string,
					   r->in.req->req2.password.length);
		res = samdb_check_password(mem_ctx,
					   dce_call->conn->dce_ctx->lp_ctx,
					   account,
					   NULL, /* userPrincipalName */
					   NULL, /* displayName/full_name */
					   &password,
					   pwInfo.password_properties,
					   pwInfo.min_password_length);
		(*r->out.rep)->ctr2.status = res;
	break;
	case NetValidatePasswordReset:
		account = r->in.req->req3.account.string;
		password = data_blob_const(r->in.req->req3.password.string,
					   r->in.req->req3.password.length);
		res = samdb_check_password(mem_ctx,
					   dce_call->conn->dce_ctx->lp_ctx,
					   account,
					   NULL, /* userPrincipalName */
					   NULL, /* displayName/full_name */
					   &password,
					   pwInfo.password_properties,
					   pwInfo.min_password_length);
		(*r->out.rep)->ctr3.status = res;
	break;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	break;
	}

	return NT_STATUS_OK;
}

static void dcesrv_samr_Opnum68NotUsedOnWire(struct dcesrv_call_state *dce_call,
					     TALLOC_CTX *mem_ctx,
					     struct samr_Opnum68NotUsedOnWire *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}

static void dcesrv_samr_Opnum69NotUsedOnWire(struct dcesrv_call_state *dce_call,
					     TALLOC_CTX *mem_ctx,
					     struct samr_Opnum69NotUsedOnWire *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}

static void dcesrv_samr_Opnum70NotUsedOnWire(struct dcesrv_call_state *dce_call,
					     TALLOC_CTX *mem_ctx,
					     struct samr_Opnum70NotUsedOnWire *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}

static void dcesrv_samr_Opnum71NotUsedOnWire(struct dcesrv_call_state *dce_call,
					     TALLOC_CTX *mem_ctx,
					     struct samr_Opnum71NotUsedOnWire *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}

static void dcesrv_samr_Opnum72NotUsedOnWire(struct dcesrv_call_state *dce_call,
					     TALLOC_CTX *mem_ctx,
					     struct samr_Opnum72NotUsedOnWire *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_samr_s.c"
