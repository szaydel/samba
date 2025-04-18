/*
   Unix SMB/CIFS implementation.

   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2006

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
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/credentials/credentials.h"
#include "auth/common_auth.h"
#include "../lib/util/asn1.h"
#include "param/param.h"
#include "libds/common/roles.h"
#include "lib/util/util_net.h"

#undef strcasecmp

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

NTSTATUS gensec_generate_session_info_pac(TALLOC_CTX *mem_ctx,
					  struct gensec_security *gensec_security,
					  struct smb_krb5_context *smb_krb5_context,
					  DATA_BLOB *pac_blob,
					  const char *principal_string,
					  const struct tsocket_address *remote_address,
					  struct auth_session_info **session_info)
{
	uint32_t session_info_flags = 0;
	struct auth4_context *auth_context = NULL;
	NTSTATUS status;

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_DEFAULT_GROUPS;

	if (!pac_blob) {
		enum server_role server_role =
			lpcfg_server_role(gensec_security->settings->lp_ctx);

		/*
		 * For any domain setup (DC or member) we require having
		 * a PAC, as the service ticket comes from an AD DC,
		 * which will always provide a PAC, unless
		 * UF_NO_AUTH_DATA_REQUIRED is configured for our
		 * account, but that's just an invalid configuration,
		 * the admin configured for us!
		 *
		 * As a legacy case, we still allow kerberos tickets from an MIT
		 * realm, but only in standalone mode. In that mode we'll only
		 * ever accept a kerberos authentication with a keytab file
		 * being explicitly configured via the 'keytab method' option.
		 */
		if (server_role != ROLE_STANDALONE) {
			DBG_WARNING("Unable to find PAC in ticket from %s, "
				    "failing to allow access\n",
				    principal_string);
			return NT_STATUS_NO_IMPERSONATION_TOKEN;
		}
		DBG_NOTICE("Unable to find PAC for %s, resorting to local "
			   "user lookup\n", principal_string);
	}

	auth_context = gensec_security->auth_context;

	if ((auth_context == NULL) ||
	    (auth_context->generate_session_info_pac == NULL)) {
		DBG_ERR("Cannot generate a session_info without "
			"the auth_context\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = auth_context->generate_session_info_pac(
		auth_context,
		mem_ctx,
		smb_krb5_context,
		pac_blob,
		principal_string,
		remote_address,
		session_info_flags,
		session_info);
	return status;
}

/*
  magic check a GSS-API wrapper packet for an Kerberos OID
*/
static bool gensec_gssapi_check_oid(const DATA_BLOB *blob, const char *oid)
{
	bool ret = false;
	struct asn1_data *data = asn1_init(NULL, ASN1_MAX_TREE_DEPTH);

	if (!data) return false;

	if (!asn1_load(data, *blob)) goto err;
	if (!asn1_start_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_check_OID(data, oid)) goto err;

	ret = !asn1_has_error(data);

  err:

	asn1_free(data);
	return ret;
}

/**
 * Check if the packet is one for the KRB5 mechanism
 *
 * NOTE: This is a helper that can be employed by multiple mechanisms, do
 * not make assumptions about the private_data
 *
 * @param gensec_security GENSEC state, unused
 * @param in The request, as a DATA_BLOB
 * @return Error, INVALID_PARAMETER if it's not a packet for us
 *                or NT_STATUS_OK if the packet is ok.
 */

NTSTATUS gensec_magic_check_krb5_oid(struct gensec_security *unused,
					const DATA_BLOB *blob)
{
	if (gensec_gssapi_check_oid(blob, GENSEC_OID_KERBEROS5)) {
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

void gensec_child_want_feature(struct gensec_security *gensec_security,
			       uint32_t feature)
{
	struct gensec_security *child_security = gensec_security->child_security;

	gensec_security->want_features |= feature;
	if (child_security == NULL) {
		return;
	}
	gensec_want_feature(child_security, feature);
}

bool gensec_child_have_feature(struct gensec_security *gensec_security,
			       uint32_t feature)
{
	struct gensec_security *child_security = gensec_security->child_security;

	if (feature & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		/*
		 * All mechs with sub (child) mechs need to provide DCERPC
		 * header signing! This is required because the negotiation
		 * of header signing is done before the authentication
		 * is completed.
		 */
		return true;
	}

	if (child_security == NULL) {
		return false;
	}

	return gensec_have_feature(child_security, feature);
}

NTSTATUS gensec_child_unseal_packet(struct gensec_security *gensec_security,
				    uint8_t *data, size_t length,
				    const uint8_t *whole_pdu, size_t pdu_length,
				    const DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_unseal_packet(gensec_security->child_security,
				    data, length,
				    whole_pdu, pdu_length,
				    sig);
}

NTSTATUS gensec_child_check_packet(struct gensec_security *gensec_security,
				   const uint8_t *data, size_t length,
				   const uint8_t *whole_pdu, size_t pdu_length,
				   const DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_check_packet(gensec_security->child_security,
				   data, length,
				   whole_pdu, pdu_length,
				   sig);
}

NTSTATUS gensec_child_seal_packet(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  uint8_t *data, size_t length,
				  const uint8_t *whole_pdu, size_t pdu_length,
				  DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_seal_packet(gensec_security->child_security,
				  mem_ctx,
				  data, length,
				  whole_pdu, pdu_length,
				  sig);
}

NTSTATUS gensec_child_sign_packet(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  const uint8_t *data, size_t length,
				  const uint8_t *whole_pdu, size_t pdu_length,
				  DATA_BLOB *sig)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_sign_packet(gensec_security->child_security,
				  mem_ctx,
				  data, length,
				  whole_pdu, pdu_length,
				  sig);
}

NTSTATUS gensec_child_wrap(struct gensec_security *gensec_security,
			   TALLOC_CTX *mem_ctx,
			   const DATA_BLOB *in,
			   DATA_BLOB *out)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_wrap(gensec_security->child_security,
			   mem_ctx, in, out);
}

NTSTATUS gensec_child_unwrap(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx,
			     const DATA_BLOB *in,
			     DATA_BLOB *out)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_unwrap(gensec_security->child_security,
			     mem_ctx, in, out);
}

size_t gensec_child_sig_size(struct gensec_security *gensec_security,
			     size_t data_size)
{
	if (gensec_security->child_security == NULL) {
		return 0;
	}

	return gensec_sig_size(gensec_security->child_security, data_size);
}

size_t gensec_child_max_input_size(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return 0;
	}

	return gensec_max_input_size(gensec_security->child_security);
}

size_t gensec_child_max_wrapped_size(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return 0;
	}

	return gensec_max_wrapped_size(gensec_security->child_security);
}

NTSTATUS gensec_child_session_key(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *session_key)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_session_key(gensec_security->child_security,
				  mem_ctx,
				  session_key);
}

NTSTATUS gensec_child_session_info(struct gensec_security *gensec_security,
				   TALLOC_CTX *mem_ctx,
				   struct auth_session_info **session_info)
{
	if (gensec_security->child_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_session_info(gensec_security->child_security,
				   mem_ctx,
				   session_info);
}

NTTIME gensec_child_expire_time(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return GENSEC_EXPIRE_TIME_INFINITY;
	}

	return gensec_expire_time(gensec_security->child_security);
}

const char *gensec_child_final_auth_type(struct gensec_security *gensec_security)
{
	if (gensec_security->child_security == NULL) {
		return "NONE";
	}

	return gensec_final_auth_type(gensec_security->child_security);
}

char *gensec_get_unparsed_target_principal(struct gensec_security *gensec_security,
					   TALLOC_CTX *mem_ctx)
{
	const char *target_principal = gensec_get_target_principal(gensec_security);
	const char *service = gensec_get_target_service(gensec_security);
	const char *hostname = gensec_get_target_hostname(gensec_security);

	if (target_principal != NULL) {
		return talloc_strdup(mem_ctx, target_principal);
	} else if (service != NULL && hostname != NULL) {
		return talloc_asprintf(mem_ctx, "%s/%s", service, hostname);
	} else if (hostname != NULL) {
		return talloc_strdup(mem_ctx, target_principal);
	}

	return NULL;
}

NTSTATUS gensec_kerberos_possible(struct gensec_security *gensec_security)
{
	struct cli_credentials *creds = gensec_get_credentials(gensec_security);
	bool auth_requested = cli_credentials_authentication_requested(creds);
	enum credentials_use_kerberos krb5_state =
		cli_credentials_get_kerberos_state(creds);
	char *user_principal = NULL;
	const char *client_realm = cli_credentials_get_realm(creds);
	const char *target_principal = gensec_get_target_principal(gensec_security);
	const char *hostname = gensec_get_target_hostname(gensec_security);

	if (!auth_requested) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (krb5_state == CRED_USE_KERBEROS_DISABLED) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	errno = 0;
	user_principal = cli_credentials_get_principal(creds, gensec_security);
	if (errno != 0) {
		TALLOC_FREE(user_principal);
		return NT_STATUS_NO_MEMORY;
	}

	if (user_principal == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	TALLOC_FREE(user_principal);

	if (target_principal != NULL) {
		return NT_STATUS_OK;
	}

	if (client_realm == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (hostname == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strcasecmp(hostname, "localhost") == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

#define STAR_SMBSERVER "*SMBSERVER"
	if (strcmp(hostname, STAR_SMBSERVER) == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (is_ipaddress(hostname)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}
