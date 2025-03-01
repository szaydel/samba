/*
 *  Unix SMB/CIFS implementation.
 *  kerberos utility library
 *
 *  Copyright (C) Andrew Tridgell			2001
 *  Copyright (C) Remus Koos (remuskoos@yahoo.com)	2001
 *  Copyright (C) Luke Howard				2002-2003
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>	2003
 *  Copyright (C) Guenther Deschner			2003-2008
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org>	2004-2005
 *  Copyright (C) Jeremy Allison			2004,2007
 *  Copyright (C) Stefan Metzmacher			2004-2005
 *  Copyright (C) Nalin Dahyabhai <nalin@redhat.com>	2004
 *  Copyright (C) Gerald Carter				2006
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LIBADS_KERBEROS_PROTO_H_
#define _LIBADS_KERBEROS_PROTO_H_

#include "system/kerberos.h"

struct PAC_DATA_CTR;
struct samr_Password;

#define DEFAULT_KRB5_PORT 88

#include "libads/ads_status.h"

/* The following definitions come from libads/kerberos.c  */

int kerberos_kinit_password_ext(const char *given_principal,
				const char *password,
				int time_offset,
				time_t *expire_time,
				time_t *renew_till_time,
				const char *cache_name,
				bool request_pac,
				bool add_netbios_addr,
				time_t renewable_time,
				TALLOC_CTX *mem_ctx,
				char **_canon_principal,
				char **_canon_realm,
				NTSTATUS *ntstatus);
int kerberos_kinit_passwords_ext(const char *given_principal,
				 uint8_t num_passwords,
				 const char * const *passwords,
				 const struct samr_Password * const *nt_hashes,
				 uint8_t *used_idx,
				 const char *explicit_kdc,
				 const char *cache_name,
				 TALLOC_CTX *mem_ctx,
				 char **_canon_principal,
				 char **_canon_realm,
				 NTSTATUS *ntstatus);
int ads_kdestroy(const char *cc_name);

int kerberos_kinit_password(const char *principal,
			    const char *password,
			    const char *cache_name);
bool create_local_private_krb5_conf_for_domain(const char *realm,
						const char *domain,
						const char *sitename,
					        const struct sockaddr_storage *pss);

/* The following definitions come from libads/authdata.c  */

NTSTATUS kerberos_return_pac(TALLOC_CTX *mem_ctx,
			     const char *name,
			     const char *pass,
			     time_t time_offset,
			     time_t *expire_time,
			     time_t *renew_till_time,
			     const char *cache_name,
			     bool request_pac,
			     bool add_netbios_addr,
			     time_t renewable_time,
			     const char *impersonate_princ_s,
			     const char *local_service,
			     char **_canon_principal,
			     char **_canon_realm,
			     struct PAC_DATA_CTR **pac_data_ctr);

/* The following definitions come from libads/krb5_setpw.c  */

ADS_STATUS ads_krb5_set_password(const char *princ,
				 const char *newpw,
				 const char *ccname);
ADS_STATUS kerberos_set_password(const char *auth_principal,
				 const char *auth_password,
				 const char *target_principal,
				 const char *new_password);

#ifdef HAVE_KRB5
int create_kerberos_key_from_string(krb5_context context,
					krb5_principal host_princ,
					krb5_principal salt_princ,
					krb5_data *password,
					krb5_keyblock *key,
					krb5_enctype enctype,
					bool no_salt);
#endif

#endif /* _LIBADS_KERBEROS_PROTO_H_ */
