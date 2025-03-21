/*
   Unix SMB/CIFS implementation.

   Extract the user/system database from a remote SamSync server

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Guenther Deschner <gd@samba.org> 2008

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
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/samsync/samsync.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "lib/crypto/gnutls_helpers.h"

#undef netlogon_creds_arcfour_crypt

/**
 * Decrypt and extract the user's passwords.
 *
 * The writes decrypted (no longer 'RID encrypted' or arcfour encrypted)
 * passwords back into the structure
 */

static NTSTATUS fix_user(TALLOC_CTX *mem_ctx,
			 struct netlogon_creds_CredentialState *creds,
			 enum netr_SamDatabaseID database_id,
			 struct netr_DELTA_ENUM *delta)
{

	uint32_t rid = delta->delta_id_union.rid;
	struct netr_DELTA_USER *user = delta->delta_union.user;
	struct samr_Password lm_hash;
	struct samr_Password nt_hash;
	int rc;

	/* Note that win2000 may send us all zeros
	 * for the hashes if it doesn't
	 * think this channel is secure enough. */
	if (user->lm_password_present) {
		if (!all_zero(user->lmpassword.hash, 16)) {
			rc = sam_rid_crypt(rid, user->lmpassword.hash,
					    lm_hash.hash, SAMBA_GNUTLS_DECRYPT);
			if (rc != 0) {
				return gnutls_error_to_ntstatus(rc,
								NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
			}
		} else {
			memset(lm_hash.hash, '\0', sizeof(lm_hash.hash));
		}
		user->lmpassword = lm_hash;
	}

	if (user->nt_password_present) {
		if (!all_zero(user->ntpassword.hash, 16)) {
			rc = sam_rid_crypt(rid, user->ntpassword.hash,
					    nt_hash.hash, SAMBA_GNUTLS_DECRYPT);
			if (rc != 0) {
				return gnutls_error_to_ntstatus(rc,
								NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
			}
		} else {
			memset(nt_hash.hash, '\0', sizeof(nt_hash.hash));
		}
		user->ntpassword = nt_hash;
	}

	if (user->user_private_info.SensitiveData) {
		DATA_BLOB data;
		struct netr_USER_KEYS keys;
		enum ndr_err_code ndr_err;
		NTSTATUS status;

		data.data = user->user_private_info.SensitiveData;
		data.length = user->user_private_info.DataLength;

		status = netlogon_creds_arcfour_crypt(creds,
						      data.data,
						      data.length);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		user->user_private_info.SensitiveData = data.data;
		user->user_private_info.DataLength = data.length;

		ndr_err = ndr_pull_struct_blob(&data, mem_ctx, &keys,
			(ndr_pull_flags_fn_t)ndr_pull_netr_USER_KEYS);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			dump_data(10, data.data, data.length);
			return ndr_map_error2ntstatus(ndr_err);
		}

		/* Note that win2000 may send us all zeros
		 * for the hashes if it doesn't
		 * think this channel is secure enough. */
		if (keys.keys.keys2.lmpassword.length == 16) {
			if (!all_zero(keys.keys.keys2.lmpassword.pwd.hash,
				      16)) {
				rc = sam_rid_crypt(rid,
					           keys.keys.keys2.lmpassword.pwd.hash,
					           lm_hash.hash, SAMBA_GNUTLS_DECRYPT);
				if (rc != 0) {
					return gnutls_error_to_ntstatus(rc,
									NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
				}
			} else {
				memset(lm_hash.hash, '\0', sizeof(lm_hash.hash));
			}
			user->lmpassword = lm_hash;
			user->lm_password_present = true;
		}
		if (keys.keys.keys2.ntpassword.length == 16) {
			if (!all_zero(keys.keys.keys2.ntpassword.pwd.hash,
				      16)) {
				rc = sam_rid_crypt(rid,
						   keys.keys.keys2.ntpassword.pwd.hash,
						   nt_hash.hash, SAMBA_GNUTLS_DECRYPT);
				if (rc != 0) {
					return gnutls_error_to_ntstatus(rc,
									NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
				}
			} else {
				memset(nt_hash.hash, '\0', sizeof(nt_hash.hash));
			}
			user->ntpassword = nt_hash;
			user->nt_password_present = true;
		}
		/* TODO: rid decrypt history fields */
	}
	return NT_STATUS_OK;
}

/**
 * Decrypt and extract the secrets
 * 
 * The writes decrypted secrets back into the structure
 */
static NTSTATUS fix_secret(TALLOC_CTX *mem_ctx,
			   struct netlogon_creds_CredentialState *creds,
			   enum netr_SamDatabaseID database,
			   struct netr_DELTA_ENUM *delta) 
{
	struct netr_DELTA_SECRET *secret = delta->delta_union.secret;
	NTSTATUS status;

	status = netlogon_creds_arcfour_crypt(creds,
					      secret->current_cipher.cipher_data,
					      secret->current_cipher.maxlen);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = netlogon_creds_arcfour_crypt(creds,
					      secret->old_cipher.cipher_data,
					      secret->old_cipher.maxlen);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/**
 * Fix up the delta, dealing with encryption issues so that the final
 * callback need only do the printing or application logic
 */

NTSTATUS samsync_fix_delta(TALLOC_CTX *mem_ctx,
			   struct netlogon_creds_CredentialState *creds,
			   enum netr_SamDatabaseID database_id,
			   struct netr_DELTA_ENUM *delta)
{
	NTSTATUS status = NT_STATUS_OK;

	switch (delta->delta_type) {
		case NETR_DELTA_USER:

			status = fix_user(mem_ctx,
					  creds,
					  database_id,
					  delta);
			break;
		case NETR_DELTA_SECRET:

			status = fix_secret(mem_ctx,
					    creds,
					    database_id,
					    delta);
			break;
		default:
			break;
	}

	return status;
}

