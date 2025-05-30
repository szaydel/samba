/*
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Guenther Deschner 2005-2009

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

#ifndef _KRB5_SAMBA_H
#define _KRB5_SAMBA_H

#include "lib/util/data_blob.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/debug.h"

#ifdef HAVE_KRB5

#define KRB5_PRIVATE    1       /* this file uses PRIVATE interfaces! */
/* this file uses DEPRECATED interfaces! */

#ifdef KRB5_DEPRECATED
#undef KRB5_DEPRECATED
#endif

#if defined(HAVE_KRB5_DEPRECATED_WITH_IDENTIFIER)
#define KRB5_DEPRECATED 1
#else
#define KRB5_DEPRECATED
#endif

#include "system/kerberos.h"
#include "system/network.h"

#ifndef KRB5_ADDR_NETBIOS
#define KRB5_ADDR_NETBIOS 0x14
#endif

#ifndef KRB5KRB_ERR_RESPONSE_TOO_BIG
#define KRB5KRB_ERR_RESPONSE_TOO_BIG (-1765328332L)
#endif

/* Heimdal uses a slightly different name */
#if defined(HAVE_ENCTYPE_ARCFOUR_HMAC_MD5) && !defined(HAVE_ENCTYPE_ARCFOUR_HMAC)
#define ENCTYPE_ARCFOUR_HMAC ENCTYPE_ARCFOUR_HMAC_MD5
#endif
#if defined(HAVE_ENCTYPE_ARCFOUR_HMAC_MD5_56) && !defined(HAVE_ENCTYPE_ARCFOUR_HMAC_EXP)
#define ENCTYPE_ARCFOUR_HMAC_EXP ENCTYPE_ARCFOUR_HMAC_MD5_56
#endif

/* The older versions of heimdal that don't have this
   define don't seem to use it anyway.  I'm told they
   always use a subkey */
#ifndef HAVE_AP_OPTS_USE_SUBKEY
#define AP_OPTS_USE_SUBKEY 0
#endif

#ifndef KRB5_PW_SALT
#define KRB5_PW_SALT 3
#endif

/* CKSUMTYPE_HMAC_MD5 in Heimdal
   CKSUMTYPE_HMAC_MD5_ARCFOUR in MIT */
#if defined(CKSUMTYPE_HMAC_MD5_ARCFOUR) && !defined(CKSUMTYPE_HMAC_MD5)
#define CKSUMTYPE_HMAC_MD5 CKSUMTYPE_HMAC_MD5_ARCFOUR
#endif

/*
 * CKSUMTYPE_HMAC_SHA1_96_AES_* in Heimdal
 * CKSUMTYPE_HMAC_SHA1_96_AES* in MIT
 */
#if defined(CKSUMTYPE_HMAC_SHA1_96_AES128) && !defined(CKSUMTYPE_HMAC_SHA1_96_AES_128)
#define CKSUMTYPE_HMAC_SHA1_96_AES_128 CKSUMTYPE_HMAC_SHA1_96_AES128
#endif
#if defined(CKSUMTYPE_HMAC_SHA1_96_AES256) && !defined(CKSUMTYPE_HMAC_SHA1_96_AES_256)
#define CKSUMTYPE_HMAC_SHA1_96_AES_256 CKSUMTYPE_HMAC_SHA1_96_AES256
#endif

/*
 * RFC8009 encryption types' defines have different names:
 *
 * KRB5_ENCTYPE_AES128_CTS_HMAC_SHA256_128 in Heimdal
 * ENCTYPE_AES128_CTS_HMAC_SHA256_128 in MIT
 *
 * and
 *
 * KRB5_ENCTYPE_AES256_CTS_HMAC_SHA384_192 in Heimdal
 * ENCTYPE_AES256_CTS_HMAC_SHA384_192 in MIT
 */
#if !defined(ENCTYPE_AES128_CTS_HMAC_SHA256_128)
#define ENCTYPE_AES128_CTS_HMAC_SHA256_128 KRB5_ENCTYPE_AES128_CTS_HMAC_SHA256_128
#endif
#if !defined(ENCTYPE_AES256_CTS_HMAC_SHA384_192)
#define ENCTYPE_AES256_CTS_HMAC_SHA384_192 KRB5_ENCTYPE_AES256_CTS_HMAC_SHA384_192
#endif

/*
 * Same for older encryption types, rename to have the same defines
 */
#if !defined(ENCTYPE_AES128_CTS_HMAC_SHA1_96)
#define ENCTYPE_AES128_CTS_HMAC_SHA1_96 KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96
#endif
#if !defined(ENCTYPE_AES256_CTS_HMAC_SHA1_96)
#define ENCTYPE_AES256_CTS_HMAC_SHA1_96 KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96
#endif

/*
 * KRB5_KU_OTHER_ENCRYPTED in Heimdal
 * KRB5_KEYUSAGE_APP_DATA_ENCRYPT in MIT
 */
#if defined(KRB5_KEYUSAGE_APP_DATA_ENCRYPT) && !defined(KRB5_KU_OTHER_ENCRYPTED)
#define KRB5_KU_OTHER_ENCRYPTED KRB5_KEYUSAGE_APP_DATA_ENCRYPT
#endif

typedef struct {
#if defined(HAVE_MAGIC_IN_KRB5_ADDRESS) && defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS) /* MIT */
	krb5_address **addrs;
#elif defined(HAVE_KRB5_ADDRESSES) /* Heimdal */
	krb5_addresses *addrs;
#else
#error UNKNOWN_KRB5_ADDRESS_TYPE
#endif /* defined(HAVE_MAGIC_IN_KRB5_ADDRESS) && defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS) */
} smb_krb5_addresses;

#ifdef HAVE_KRB5_KEYTAB_ENTRY_KEY               /* MIT */
#define KRB5_KT_KEY(k)		(&(k)->key)
#elif defined(HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK)  /* Heimdal */
#define KRB5_KT_KEY(k)		(&(k)->keyblock)
#else
#error krb5_keytab_entry has no key or keyblock member
#endif /* HAVE_KRB5_KEYTAB_ENTRY_KEY */

/* work around broken krb5.h on sles9 */
#ifdef SIZEOF_LONG
#undef SIZEOF_LONG
#endif

#ifdef HAVE_KRB5_KEYBLOCK_KEYVALUE /* Heimdal */
#define KRB5_KEY_TYPE(k)	((k)->keytype)
#define KRB5_KEY_LENGTH(k)	((k)->keyvalue.length)
#define KRB5_KEY_DATA(k)	((k)->keyvalue.data)
#define KRB5_KEY_DATA_CAST	void
#else /* MIT */
#define KRB5_KEY_TYPE(k)	((k)->enctype)
#define KRB5_KEY_LENGTH(k)	((k)->length)
#define KRB5_KEY_DATA(k)	((k)->contents)
#define KRB5_KEY_DATA_CAST	krb5_octet
#endif /* HAVE_KRB5_KEYBLOCK_KEYVALUE */

#ifdef HAVE_E_DATA_POINTER_IN_KRB5_ERROR /* Heimdal */
#define KRB5_ERROR_CODE(k)	((k)->error_code)
#else /* MIT */
#define KRB5_ERROR_CODE(k)	((k)->error)
#endif /* HAVE_E_DATA_POINTER_IN_KRB5_ERROR */

#ifndef HAVE_KRB5_CONST_PAC
#ifdef KRB5_CONST_PAC_GET_BUFFER
typedef const struct krb5_pac_data *krb5_const_pac;
#else
/*
 * Certain Heimdal versions include a version of krb5_pac_get_buffer() that is
 * unusable in certain cases, taking a krb5_pac when a krb5_const_pac may be all
 * that we can supply. Furthermore, MIT Kerberos doesn't declare krb5_const_pac
 * at all. In such cases, we must declare krb5_const_pac as a non-const typedef
 * so that the build can succeed.
 */
typedef struct krb5_pac_data *krb5_const_pac;
#endif
#endif

krb5_error_code smb_krb5_parse_name(krb5_context context,
				const char *name, /* in unix charset */
                                krb5_principal *principal);

krb5_error_code smb_krb5_parse_name_flags(krb5_context context,
					  const char *name, /* unix charset */
					  int flags,
					  krb5_principal *principal);

krb5_error_code smb_krb5_unparse_name(TALLOC_CTX *mem_ctx,
				      krb5_context context,
				      krb5_const_principal principal,
				      char **unix_name);

static inline void samba_trace_keytab_entry(krb5_context context,
			      krb5_keytab_entry kt_entry,
			      const char *func,
			      int line,
			      const char *op)
{
	char *princ_s = NULL;
#define MAX_KEYLEN 64
	char tmp[2 * MAX_KEYLEN + 1] = { 0, };
	krb5_enctype enctype = 0;
	krb5_keyblock *key = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	krb5_error_code code;
	const uint8_t *ptr = NULL;
	unsigned len, i;

	code = smb_krb5_unparse_name(frame,
				     context,
				     kt_entry.principal,
				     &princ_s);
	if (code != 0) {
		goto out;
	}
	enctype = KRB5_KEY_TYPE(KRB5_KT_KEY(&kt_entry));
	key = KRB5_KT_KEY(&kt_entry);
#ifdef DEBUG_PASSWORD
	ptr = (const uint8_t *) KRB5_KEY_DATA(key);
	len = KRB5_KEY_LENGTH(key);

	for (i = 0; i < len && i < MAX_KEYLEN; i++) {
		snprintf(&tmp[2 * i], 3, "%02X", ptr[i]);
	}
#else
	tmp[0] = 0;
#endif
	DEBUG(10,("KEYTAB_TRACE %36s:%-4d %3s %78s %3d %2d %s\n",
		  func,
		  line,
		  op,
		  princ_s,
		  kt_entry.vno,
		  enctype,
		  tmp));
out:
	TALLOC_FREE(frame);
}

#if defined(__GNUC__) && defined(DEVELOPER)
/* http://gcc.gnu.org/onlinedocs/gcc/Statement-Exprs.html */

#define samba_krb5_kt_add_entry(context, id, entry)                          \
	({                                                                   \
		krb5_error_code _code;                                       \
		_code = krb5_kt_add_entry((context), (id), (entry));         \
		if (CHECK_DEBUGLVL(10)) {                                    \
			samba_trace_keytab_entry((context),                  \
						 *(entry),                   \
						 __func__,                   \
						 __LINE__,                   \
						 _code == 0 ? "add"          \
							    : "add FAILED"); \
		}                                                            \
		_code;                                                       \
	})

#define samba_krb5_kt_remove_entry(context, id, entry)                       \
	({                                                                   \
		krb5_error_code _code;                                       \
		_code = krb5_kt_remove_entry((context), (id), (entry));      \
		if (CHECK_DEBUGLVL(10)) {                                    \
			samba_trace_keytab_entry((context),                  \
						 *(entry),                   \
						 __func__,                   \
						 __LINE__,                   \
						 _code == 0 ? "rem"          \
							    : "rem FAILED"); \
		}                                                            \
		_code;                                                       \
	})

#define samba_krb5_kt_next_entry(context, id, entry, cursor) \
	({                                                   \
		krb5_error_code _code;                       \
		_code = krb5_kt_next_entry((context),        \
					   (id),             \
					   (entry),          \
					   (cursor));        \
		if (_code == 0 && CHECK_DEBUGLVL(10)) {      \
			samba_trace_keytab_entry((context),  \
						 *(entry),   \
						 __func__,   \
						 __LINE__,   \
						 "nxt");     \
		}                                            \
		_code;                                       \
	})

#else

#define samba_krb5_kt_add_entry(context, id, entry) \
	krb5_kt_add_entry((context), (id), (entry))
#define samba_krb5_kt_remove_entry(context, id, entry) \
	krb5_kt_remove_entry((context), (id), (entry))
#define samba_krb5_kt_next_entry(context, id, entry, cursor) \
	krb5_kt_next_entry((context), (id), (entry), (cursor))

#endif

krb5_error_code smb_krb5_init_context_common(krb5_context *_krb5_context);

/*
 * This should only be used in code that
 * really wants to touch the global default ccache!
 */
krb5_error_code smb_force_krb5_cc_default(krb5_context ctx, krb5_ccache *id);
/*
 * This should only be used in code that
 * really wants to touch the global default ccache!
 */
const char *smb_force_krb5_cc_default_name(krb5_context ctx);

krb5_error_code krb5_set_default_tgs_ktypes(krb5_context ctx, const krb5_enctype *enc);

#if defined(HAVE_KRB5_AUTH_CON_SETKEY) && !defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY)
krb5_error_code krb5_auth_con_setuseruserkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock *keyblock);
#endif

#ifndef HAVE_KRB5_FREE_UNPARSED_NAME
void krb5_free_unparsed_name(krb5_context ctx, char *val);
#endif

#if !defined(HAVE_KRB5_FREE_ENCTYPES)
void krb5_free_enctypes(krb5_context context, krb5_enctype *val);
#endif

#if !defined(HAVE_KRB5_FREE_STRING)
void krb5_free_string(krb5_context context, char *val);
#endif

/* Stub out initialize_krb5_error_table since it is not present in all
 * Kerberos implementations. If it's not present, it's not necessary to
 * call it.
 */
#ifndef HAVE_INITIALIZE_KRB5_ERROR_TABLE
#define initialize_krb5_error_table()
#endif

/* Samba wrapper functions for krb5 functionality. */
bool smb_krb5_sockaddr_to_kaddr(struct sockaddr_storage *paddr,
				krb5_address *pkaddr);

krb5_error_code smb_krb5_mk_error(krb5_context context,
				  krb5_error_code error_code,
				  const char *e_text,
				  krb5_data *e_data,
				  const krb5_principal client,
				  const krb5_principal server,
				  krb5_data *enc_err);

krb5_error_code smb_krb5_get_allowed_etypes(krb5_context context,
					    krb5_enctype **enctypes);

bool smb_krb5_get_smb_session_key(TALLOC_CTX *mem_ctx,
				  krb5_context context,
				  krb5_auth_context auth_context,
				  DATA_BLOB *session_key,
				  bool remote);

krb5_error_code smb_krb5_kt_free_entry(krb5_context context, krb5_keytab_entry *kt_entry);
void smb_krb5_free_data_contents(krb5_context context, krb5_data *pdata);
krb5_error_code smb_krb5_renew_ticket(const char *ccache_string, const char *client_string, const char *service_string, time_t *expire_time);
krb5_error_code smb_krb5_gen_netbios_krb5_address(smb_krb5_addresses **kerb_addr,
						  const char *netbios_name);
krb5_error_code smb_krb5_free_addresses(krb5_context context, smb_krb5_addresses *addr);
krb5_enctype smb_krb5_kt_get_enctype_from_entry(krb5_keytab_entry *kt_entry);

krb5_error_code smb_krb5_enctype_to_string(krb5_context context,
					    krb5_enctype enctype,
					    char **etype_s);
krb5_error_code smb_krb5_kt_open_relative(krb5_context context,
					  const char *keytab_name_req,
					  bool write_access,
					  krb5_keytab *keytab);
krb5_error_code smb_krb5_kt_open(krb5_context context,
				 const char *keytab_name,
				 bool write_access,
				 krb5_keytab *keytab);
krb5_error_code smb_krb5_kt_get_name(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     krb5_keytab keytab,
				     const char **keytab_name);
krb5_error_code smb_krb5_kt_seek_and_delete_old_entries(krb5_context context,
							krb5_keytab keytab,
							bool keep_old_kvno,
							krb5_kvno kvno,
							bool enctype_only,
							krb5_enctype enctype,
							const char *princ_s,
							krb5_principal princ,
							bool flush);

krb5_error_code smb_krb5_get_credentials(krb5_context context,
					 krb5_ccache ccache,
					 krb5_principal me,
					 krb5_principal server,
					 krb5_principal impersonate_princ,
					 krb5_creds **out_creds);
krb5_error_code smb_krb5_keyblock_init_contents(krb5_context context,
						krb5_enctype enctype,
						const void *data,
						size_t length,
						krb5_keyblock *key);
krb5_error_code smb_krb5_kinit_keyblock_ccache(krb5_context ctx,
					       krb5_ccache cc,
					       krb5_principal principal,
					       krb5_keyblock *keyblock,
					       const char *target_service,
					       krb5_get_init_creds_opt *krb_options,
					       time_t *expire_time,
					       time_t *kdc_time);
krb5_error_code smb_krb5_kinit_password_ccache(krb5_context ctx,
					       krb5_ccache cc,
					       krb5_principal principal,
					       const char *password,
					       const char *target_service,
					       krb5_get_init_creds_opt *krb_options,
					       time_t *expire_time,
					       time_t *kdc_time);
krb5_error_code smb_krb5_kinit_s4u2_ccache(krb5_context ctx,
					   krb5_ccache store_cc,
					   krb5_principal init_principal,
					   const char *init_password,
					   krb5_principal impersonate_principal,
					   const char *self_service,
					   const char *target_service,
					   krb5_get_init_creds_opt *krb_options,
					   time_t *expire_time,
					   time_t *kdc_time);

#if defined(HAVE_KRB5_MAKE_PRINCIPAL)
#define smb_krb5_make_principal krb5_make_principal
#elif defined(HAVE_KRB5_BUILD_PRINCIPAL_ALLOC_VA)
krb5_error_code smb_krb5_make_principal(krb5_context context,
					krb5_principal *principal,
					const char *realm, ...);
#else
#error krb5_make_principal not available
#endif

#if defined(HAVE_KRB5_CC_GET_LIFETIME)
#define smb_krb5_cc_get_lifetime krb5_cc_get_lifetime
#elif defined(HAVE_KRB5_CC_RETRIEVE_CRED)
krb5_error_code smb_krb5_cc_get_lifetime(krb5_context context,
					 krb5_ccache id,
					 time_t *t);
#else
#error krb5_cc_get_lifetime not available
#endif

#if defined(HAVE_KRB5_FREE_CHECKSUM_CONTENTS)
#define smb_krb5_free_checksum_contents krb5_free_checksum_contents
#elif defined (HAVE_FREE_CHECKSUM)
void smb_krb5_free_checksum_contents(krb5_context ctx, krb5_checksum *cksum);
#else
#error krb5_free_checksum_contents/free_Checksum is not available
#endif

krb5_error_code smb_krb5_make_pac_checksum(TALLOC_CTX *mem_ctx,
					   DATA_BLOB *pac_data,
					   krb5_context context,
					   const krb5_keyblock *keyblock,
					   uint32_t *sig_type,
					   DATA_BLOB *sig_blob);

char *smb_krb5_principal_get_realm(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   krb5_const_principal principal);

void smb_krb5_principal_set_type(krb5_context context,
				 krb5_principal principal,
				 int type);

int smb_krb5_principal_is_tgs(krb5_context context,
			      krb5_const_principal principal);

krb5_error_code smb_krb5_principal_set_realm(krb5_context context,
					     krb5_principal principal,
					     const char *realm);

char *smb_krb5_get_realm_from_hostname(TALLOC_CTX *mem_ctx,
				       const char *hostname,
				       const char *client_realm);

char *smb_get_krb5_error_message(krb5_context context,
				 krb5_error_code code,
				 TALLOC_CTX *mem_ctx);

#if defined(HAVE_KRB5_KT_COMPARE)
#define smb_krb5_kt_compare krb5_kt_compare
#else
krb5_boolean smb_krb5_kt_compare(krb5_context context,
				 krb5_keytab_entry *entry,
				 krb5_const_principal principal,
				 krb5_kvno vno,
				 krb5_enctype enctype);
#endif

const krb5_enctype *samba_all_enctypes(void);

uint32_t kerberos_enctype_to_bitmap(krb5_enctype enc_type_enum);
krb5_enctype ms_suptype_to_ietf_enctype(uint32_t enctype_bitmap);
krb5_error_code ms_suptypes_to_ietf_enctypes(TALLOC_CTX *mem_ctx,
					     uint32_t enctype_bitmap,
					     krb5_enctype **enctypes);
int smb_krb5_get_pw_salt(krb5_context context,
			 krb5_const_principal host_princ,
			 krb5_data *psalt);
int smb_krb5_salt_principal(krb5_context krb5_ctx,
			    const char *realm,
			    const char *sAMAccountName,
			    const char *userPrincipalName,
			    uint32_t uac_flags,
			    krb5_principal *salt_princ);

int smb_krb5_salt_principal_str(const char *realm,
				const char *sAMAccountName,
				const char *userPrincipalName,
				uint32_t uac_flags,
				TALLOC_CTX *mem_ctx,
				char **_salt_principal);
int smb_krb5_salt_principal2data(krb5_context context,
				 const char *salt_principal,
				 TALLOC_CTX *mem_ctx,
				 char **_salt_data);

int smb_krb5_create_key_from_string(krb5_context context,
				    krb5_const_principal host_princ,
				    const krb5_data *salt,
				    const krb5_data *password,
				    krb5_enctype enctype,
				    krb5_keyblock *key);

#ifndef krb5_princ_size
#if defined(HAVE_KRB5_PRINCIPAL_GET_NUM_COMP)
#define krb5_princ_size krb5_principal_get_num_comp
#else
#error krb5_princ_size unavailable
#endif
#endif

krb5_error_code smb_krb5_principal_get_comp_string(TALLOC_CTX *mem_ctx,
						   krb5_context context,
						   krb5_const_principal principal,
						   unsigned int component,
						   char **out);

krb5_error_code smb_krb5_copy_data_contents(krb5_data *p,
					    const void *data,
					    size_t len);

krb5_data smb_krb5_make_data(void *data,
			     size_t len);

krb5_data smb_krb5_data_from_blob(DATA_BLOB blob);

int smb_krb5_principal_get_type(krb5_context context,
				krb5_const_principal principal);

#if !defined(HAVE_KRB5_WARNX)
krb5_error_code krb5_warnx(krb5_context context, const char *fmt, ...)
	PRINTF_ATTRIBUTE(2, 0);
#endif

krb5_error_code smb_krb5_cc_new_unique_memory(krb5_context context,
					      TALLOC_CTX *mem_ctx,
					      char **ccache_name,
					      krb5_ccache *id);

krb5_error_code smb_krb5_cc_copy_creds(krb5_context context,
				       krb5_ccache incc, krb5_ccache outcc);

#endif /* HAVE_KRB5 */

int ads_krb5_cli_get_ticket(TALLOC_CTX *mem_ctx,
			    const char *principal,
			    time_t time_offset,
			    DATA_BLOB *ticket,
			    DATA_BLOB *session_key_krb5,
			    uint32_t extra_ap_opts, const char *ccname,
			    time_t *tgs_expire,
			    const char *impersonate_princ_s);

NTSTATUS krb5_to_nt_status(krb5_error_code kerberos_error);
krb5_error_code nt_status_to_krb5(NTSTATUS nt_status);

#endif /* _KRB5_SAMBA_H */
