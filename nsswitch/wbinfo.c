/*
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2003
   Copyright (C) Andrew Bartlett 2002-2007
   Copyright (C) Volker Lendecke 2009

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
#include "libwbclient/wbclient.h"
#include "winbind_struct_protocol.h"
#include "libwbclient/wbclient_internal.h"
#include "../libcli/auth/libcli_auth.h"
#include "lib/cmdline/cmdline.h"
#include "lib/afs/afs_settoken.h"
#include "lib/util/smb_strtox.h"
#include "lib/util/string_wrappers.h"

#ifdef DBGC_CLASS
#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND
#endif

static struct wbcInterfaceDetails *init_interface_details(void)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	static struct wbcInterfaceDetails *details;

	if (details) {
		return details;
	}

	wbc_status = wbcInterfaceDetails(&details);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "could not obtain winbind interface "
				  "details: %s\n", wbcErrorString(wbc_status));
	}

	return details;
}

static char winbind_separator(void)
{
	struct wbcInterfaceDetails *details;
	static bool got_sep;
	static char sep;

	if (got_sep)
		return sep;

	details = init_interface_details();

	if (!details) {
		d_fprintf(stderr, "could not obtain winbind separator!\n");
		return 0;
	}

	sep = details->winbind_separator;
	got_sep = true;

	if (!sep) {
		d_fprintf(stderr, "winbind separator was NULL!\n");
		return 0;
	}

	return sep;
}

static const char *get_winbind_domain(void)
{
	static struct wbcInterfaceDetails *details;

	details = init_interface_details();

	if (!details) {
		d_fprintf(stderr, "could not obtain winbind domain name!\n");
		return 0;
	}

	return details->netbios_domain;
}

static const char *get_winbind_netbios_name(void)
{
	static struct wbcInterfaceDetails *details;

	details = init_interface_details();

	if (!details) {
		d_fprintf(stderr, "could not obtain winbind netbios name!\n");
		return 0;
	}

	return details->netbios_name;
}

/* Copy of parse_domain_user from winbindd_util.c.  Parse a string of the
   form DOMAIN/user into a domain and a user */

static bool parse_wbinfo_domain_user(const char *domuser, fstring domain,
				     fstring user)
{

	char *p = strchr(domuser,winbind_separator());

	if (!p) {
		/* Maybe it was a UPN? */
		p = strchr(domuser, '@');
		if (p != NULL) {
			fstrcpy(domain, "");
			fstrcpy(user, domuser);
			return true;
		}

		fstrcpy(user, domuser);
		fstrcpy(domain, get_winbind_domain());
		return true;
	}

	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;

	return true;
}

/* Parse string of "uid,sid" or "gid,sid" into separate int and string values.
 * Return true if input was valid, false otherwise. */
static bool parse_mapping_arg(char *arg, int *id, char **sid)
{
	char *tmp;
	int error = 0;

	if (!arg || !*arg)
		return false;

	tmp = strtok(arg, ",");
	*sid = strtok(NULL, ",");

	if (!tmp || !*tmp || !*sid || !**sid)
		return false;

	/* Because atoi() can return 0 on invalid input, which would be a valid
	 * UID/GID we must use strtoul() and do error checking */
	*id = smb_strtoul(tmp, NULL, 10, &error, SMB_STR_FULL_STR_CONV);
	if (error != 0)
		return false;

	return true;
}

/* pull pwent info for a given user */

static bool wbinfo_get_userinfo(char *user)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct passwd *pwd = NULL;

	wbc_status = wbcGetpwnam(user, &pwd);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGetpwnam: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	d_printf("%s:%s:%u:%u:%s:%s:%s\n",
		 pwd->pw_name,
		 pwd->pw_passwd,
		 (unsigned int)pwd->pw_uid,
		 (unsigned int)pwd->pw_gid,
		 pwd->pw_gecos,
		 pwd->pw_dir,
		 pwd->pw_shell);

	wbcFreeMemory(pwd);

	return true;
}

/* pull pwent info for a given uid */
static bool wbinfo_get_uidinfo(int uid)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct passwd *pwd = NULL;

	wbc_status = wbcGetpwuid(uid, &pwd);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGetpwuid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	d_printf("%s:%s:%u:%u:%s:%s:%s\n",
		 pwd->pw_name,
		 pwd->pw_passwd,
		 (unsigned int)pwd->pw_uid,
		 (unsigned int)pwd->pw_gid,
		 pwd->pw_gecos,
		 pwd->pw_dir,
		 pwd->pw_shell);

	wbcFreeMemory(pwd);

	return true;
}

static bool wbinfo_get_user_sidinfo(const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct passwd *pwd = NULL;
	struct wbcDomainSid sid;

	wbc_status = wbcStringToSid(sid_str, &sid);
	wbc_status = wbcGetpwsid(&sid, &pwd);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGetpwsid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	d_printf("%s:%s:%u:%u:%s:%s:%s\n",
		 pwd->pw_name,
		 pwd->pw_passwd,
		 (unsigned int)pwd->pw_uid,
		 (unsigned int)pwd->pw_gid,
		 pwd->pw_gecos,
		 pwd->pw_dir,
		 pwd->pw_shell);

	wbcFreeMemory(pwd);

	return true;
}


/* pull grent for a given group */
static bool wbinfo_get_groupinfo(const char *group)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct group *grp;
	char **mem;

	wbc_status = wbcGetgrnam(group, &grp);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGetgrnam: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	d_printf("%s:%s:%u:",
		 grp->gr_name,
		 grp->gr_passwd,
		 (unsigned int)grp->gr_gid);

	mem = grp->gr_mem;
	while (*mem != NULL) {
		d_printf("%s%s", *mem, *(mem+1) != NULL ? "," : "");
		mem += 1;
	}
	d_printf("\n");

	wbcFreeMemory(grp);

	return true;
}

/* pull grent for a given gid */
static bool wbinfo_get_gidinfo(int gid)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct group *grp;
	char **mem;

	wbc_status = wbcGetgrgid(gid, &grp);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGetgrgid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	d_printf("%s:%s:%u:",
		 grp->gr_name,
		 grp->gr_passwd,
		 (unsigned int)grp->gr_gid);

	mem = grp->gr_mem;
	while (*mem != NULL) {
		d_printf("%s%s", *mem, *(mem+1) != NULL ? "," : "");
		mem += 1;
	}
	d_printf("\n");

	wbcFreeMemory(grp);

	return true;
}

/* List groups a user is a member of */

static bool wbinfo_get_usergroups(const char *user)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t num_groups;
	uint32_t i;
	gid_t *groups = NULL;

	/* Send request */

	wbc_status = wbcGetGroups(user, &num_groups, &groups);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGetGroups: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	for (i = 0; i < num_groups; i++) {
		d_printf("%d\n", (int)groups[i]);
	}

	wbcFreeMemory(groups);

	return true;
}


/* List group SIDs a user SID is a member of */
static bool wbinfo_get_usersids(const char *user_sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t num_sids;
	uint32_t i;
	struct wbcDomainSid user_sid, *sids = NULL;

	/* Send request */

	wbc_status = wbcStringToSid(user_sid_str, &user_sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcLookupUserSids(&user_sid, false, &num_sids, &sids);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcLookupUserSids: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	for (i = 0; i < num_sids; i++) {
		char str[WBC_SID_STRING_BUFLEN];
		wbcSidToStringBuf(&sids[i], str, sizeof(str));
		d_printf("%s\n", str);
	}

	wbcFreeMemory(sids);

	return true;
}

static bool wbinfo_get_userdomgroups(const char *user_sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t num_sids;
	uint32_t i;
	struct wbcDomainSid user_sid, *sids = NULL;

	/* Send request */

	wbc_status = wbcStringToSid(user_sid_str, &user_sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcLookupUserSids(&user_sid, true, &num_sids, &sids);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcLookupUserSids: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	for (i = 0; i < num_sids; i++) {
		char str[WBC_SID_STRING_BUFLEN];
		wbcSidToStringBuf(&sids[i], str, sizeof(str));
		d_printf("%s\n", str);
	}

	wbcFreeMemory(sids);

	return true;
}

static bool wbinfo_get_sidaliases(const char *domain,
				  const char *user_sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainInfo *dinfo = NULL;
	uint32_t i;
	struct wbcDomainSid user_sid;
	uint32_t *alias_rids = NULL;
	uint32_t num_alias_rids;
	char domain_sid_str[WBC_SID_STRING_BUFLEN];

	/* Send request */
	if ((domain == NULL) || (strequal(domain, ".")) ||
           (domain[0] == '\0')) {
		domain = get_winbind_domain();
	}

	/* Send request */

	wbc_status = wbcDomainInfo(domain, &dinfo);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "wbcDomainInfo(%s) failed: %s\n", domain,
			  wbcErrorString(wbc_status));
		goto done;
	}
	wbc_status = wbcStringToSid(user_sid_str, &user_sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		goto done;
	}

	wbc_status = wbcGetSidAliases(&dinfo->sid, &user_sid, 1,
	    &alias_rids, &num_alias_rids);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		goto done;
	}

	wbcSidToStringBuf(&dinfo->sid, domain_sid_str, sizeof(domain_sid_str));

	for (i = 0; i < num_alias_rids; i++) {
		d_printf("%s-%d\n", domain_sid_str, alias_rids[i]);
	}

	wbcFreeMemory(alias_rids);

done:
	wbcFreeMemory(dinfo);
	return (WBC_ERR_SUCCESS == wbc_status);
}


/* Convert NetBIOS name to IP */

static bool wbinfo_wins_byname(const char *name)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *ip = NULL;

	wbc_status = wbcResolveWinsByName(name, &ip);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcResolveWinsByName: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("%s\n", ip);

	wbcFreeMemory(ip);

	return true;
}

/* Convert IP to NetBIOS name */

static bool wbinfo_wins_byip(const char *ip)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *name = NULL;

	wbc_status = wbcResolveWinsByIP(ip, &name);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcResolveWinsByIP: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("%s\n", name);

	wbcFreeMemory(name);

	return true;
}

/* List all/trusted domains */

static bool wbinfo_list_domains(bool list_all_domains, bool verbose)
{
	struct wbcDomainInfo *domain_list = NULL;
	size_t i, num_domains;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	bool print_all = !list_all_domains && verbose;

	wbc_status = wbcListTrusts(&domain_list, &num_domains);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcListTrusts: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	if (print_all) {
		d_printf("%-16s%-65s%-12s%-12s%-5s%-5s\n",
			 "Domain Name", "DNS Domain", "Trust Type",
			 "Transitive", "In", "Out");
	}

	for (i=0; i<num_domains; i++) {
		if (print_all) {
			d_printf("%-16s", domain_list[i].short_name);
		} else {
			d_printf("%s", domain_list[i].short_name);
			d_printf("\n");
			continue;
		}

		d_printf("%-65s", domain_list[i].dns_name);

		switch(domain_list[i].trust_type) {
		case WBC_DOMINFO_TRUSTTYPE_NONE:
			if (domain_list[i].trust_routing != NULL) {
				d_printf("%s\n", domain_list[i].trust_routing);
			} else {
				d_printf("None\n");
			}
			continue;
		case WBC_DOMINFO_TRUSTTYPE_LOCAL:
			d_printf("Local\n");
			continue;
		case WBC_DOMINFO_TRUSTTYPE_RWDC:
			d_printf("RWDC\n");
			continue;
		case WBC_DOMINFO_TRUSTTYPE_RODC:
			d_printf("RODC\n");
			continue;
		case WBC_DOMINFO_TRUSTTYPE_PDC:
			d_printf("PDC\n");
			continue;
		case WBC_DOMINFO_TRUSTTYPE_WKSTA:
			d_printf("Workstation ");
			break;
		case WBC_DOMINFO_TRUSTTYPE_FOREST:
			d_printf("Forest      ");
			break;
		case WBC_DOMINFO_TRUSTTYPE_EXTERNAL:
			d_printf("External    ");
			break;
		case WBC_DOMINFO_TRUSTTYPE_IN_FOREST:
			d_printf("In-Forest   ");
			break;
		}

		if (domain_list[i].trust_flags & WBC_DOMINFO_TRUST_TRANSITIVE) {
			d_printf("Yes         ");
		} else {
			d_printf("No          ");
		}

		if (domain_list[i].trust_flags & WBC_DOMINFO_TRUST_INCOMING) {
			d_printf("Yes  ");
		} else {
			d_printf("No   ");
		}

		if (domain_list[i].trust_flags & WBC_DOMINFO_TRUST_OUTGOING) {
			d_printf("Yes  ");
		} else {
			d_printf("No   ");
		}

		d_printf("\n");
	}

	wbcFreeMemory(domain_list);

	return true;
}

/* List own domain */

static bool wbinfo_list_own_domain(void)
{
	d_printf("%s\n", get_winbind_domain());

	return true;
}

/* show sequence numbers */
static bool wbinfo_show_onlinestatus(const char *domain)
{
	struct wbcDomainInfo *domain_list = NULL;
	size_t i, num_domains;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	wbc_status = wbcListTrusts(&domain_list, &num_domains);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcListTrusts: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	for (i=0; i<num_domains; i++) {
		bool is_offline;

		if (domain) {
			if (!strequal(domain_list[i].short_name, domain)) {
				continue;
			}
		}

		is_offline = (domain_list[i].domain_flags &
			      WBC_DOMINFO_DOMAIN_OFFLINE);

		d_printf("%s : %s\n",
			 domain_list[i].short_name,
			 is_offline ? "no active connection" : "active connection" );
	}

	wbcFreeMemory(domain_list);

	return true;
}


/* Show domain info */

static bool wbinfo_domain_info(const char *domain)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainInfo *dinfo = NULL;
	char sid_str[WBC_SID_STRING_BUFLEN];

	if ((domain == NULL) || (strequal(domain, ".")) || (domain[0] == '\0')){
		domain = get_winbind_domain();
	}

	/* Send request */

	wbc_status = wbcDomainInfo(domain, &dinfo);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcDomainInfo: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbcSidToStringBuf(&dinfo->sid, sid_str, sizeof(sid_str));

	/* Display response */

	d_printf("Name              : %s\n", dinfo->short_name);
	d_printf("Alt_Name          : %s\n", dinfo->dns_name);

	d_printf("SID               : %s\n", sid_str);

	d_printf("Active Directory  : %s\n",
		 (dinfo->domain_flags & WBC_DOMINFO_DOMAIN_AD) ? "Yes" : "No");
	d_printf("Native            : %s\n",
		 (dinfo->domain_flags & WBC_DOMINFO_DOMAIN_NATIVE) ?
		 "Yes" : "No");

	d_printf("Primary           : %s\n",
		 (dinfo->domain_flags & WBC_DOMINFO_DOMAIN_PRIMARY) ?
		 "Yes" : "No");

	wbcFreeMemory(dinfo);

	return true;
}

/* Get a foreign DC's name */
static bool wbinfo_getdcname(const char *domain_name)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.domain_name, domain_name);

	/* Send request */

	wbc_status = wbcRequestResponse(NULL, WINBINDD_GETDCNAME,
					&request, &response);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "Could not get dc name for %s\n",domain_name);
		return false;
	}

	/* Display response */

	d_printf("%s\n", response.data.dc_name);

	return true;
}

/* Find a DC */
static bool wbinfo_dsgetdcname(const char *domain_name, uint32_t flags)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainControllerInfoEx *dc_info;
	char *str = NULL;

	wbc_status = wbcLookupDomainControllerEx(domain_name, NULL, NULL,
						 flags | DS_DIRECTORY_SERVICE_REQUIRED,
						 &dc_info);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		printf("Could not find dc for %s\n", domain_name);
		return false;
	}

	wbcGuidToString(dc_info->domain_guid, &str);

	d_printf("%s\n", dc_info->dc_unc);
	d_printf("%s\n", dc_info->dc_address);
	d_printf("%d\n", dc_info->dc_address_type);
	d_printf("%s\n", str);
	d_printf("%s\n", dc_info->domain_name);
	d_printf("%s\n", dc_info->forest_name);
	d_printf("0x%08x\n", dc_info->dc_flags);
	d_printf("%s\n", dc_info->dc_site_name);
	d_printf("%s\n", dc_info->client_site_name);

	wbcFreeMemory(str);
	wbcFreeMemory(dc_info);

	return true;
}

/* Check trust account password */

static bool wbinfo_check_secret(const char *domain)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcAuthErrorInfo *error = NULL;
	const char *domain_name;

	if (domain) {
		domain_name = domain;
	} else {
		domain_name = get_winbind_domain();
	}

	wbc_status = wbcCheckTrustCredentials(domain_name, &error);

	d_printf("checking the trust secret for domain %s via RPC calls %s\n",
		domain_name,
		WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		d_fprintf(stderr, "wbcCheckTrustCredentials(%s): error code was %s (0x%x)\n",
			  domain_name, error->nt_string, error->nt_status);
		wbcFreeMemory(error);
	}
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcCheckTrustCredentials: "
			  "%s\n", wbcErrorString(wbc_status));
		return false;
	}

	return true;
}

/* Find the currently connected DCs */

static bool wbinfo_dc_info(const char *domain_name)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	size_t i, num_dcs;
	const char **dc_names, **dc_ips;

	wbc_status = wbcDcInfo(domain_name, &num_dcs,
			       &dc_names, &dc_ips);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		printf("Could not find dc info %s\n",
		       domain_name ? domain_name : "our domain");
		return false;
	}

	for (i=0; i<num_dcs; i++) {
		printf("%s (%s)\n", dc_names[i], dc_ips[i]);
	}
	wbcFreeMemory(dc_names);
	wbcFreeMemory(dc_ips);

	return true;
}

/* Change trust account password */

static bool wbinfo_change_secret(const char *domain)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcAuthErrorInfo *error = NULL;
	const char *domain_name;

	if (domain) {
		domain_name = domain;
	} else {
		domain_name = get_winbind_domain();
	}

	wbc_status = wbcChangeTrustCredentials(domain_name, &error);

	d_printf("changing the trust secret for domain %s via RPC calls %s\n",
		domain_name,
		WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		d_fprintf(stderr, "wbcChangeTrustCredentials(%s): error code was %s (0x%x)\n",
			  domain_name, error->nt_string, error->nt_status);
		wbcFreeMemory(error);
	}
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcChangeTrustCredentials: "
			  "%s\n", wbcErrorString(wbc_status));
		return false;
	}

	return true;
}

/* Change trust account password chose Domain Controller */

static bool wbinfo_change_secret_at(const char *domain,
				    const char *domain_controller)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcAuthErrorInfo *error = NULL;
	const char *domain_name;

	if (domain) {
		domain_name = domain;
	} else {
		domain_name = get_winbind_domain();
	}

	wbc_status = wbcChangeTrustCredentialsAt(
		domain_name, domain_controller,  &error);

	d_printf("changing the trust secret for domain %s via RPC calls %s\n",
		domain_name,
		WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		d_fprintf(stderr, "wbcChangeTrustCredentials(%s): "
			  "error code was %s (0x%x)\n",
			  domain_name, error->nt_string, error->nt_status);
		wbcFreeMemory(error);
	}
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcChangeTrustCredentials: "
			  "%s\n", wbcErrorString(wbc_status));
		return false;
	}

	return true;
}

/* Check DC connection */

static bool wbinfo_ping_dc(const char *domain)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcAuthErrorInfo *error = NULL;
	char *dcname = NULL;

	const char *domain_name;

	if (domain) {
		domain_name = domain;
	} else {
		domain_name = get_winbind_domain();
	}

	wbc_status = wbcPingDc2(domain_name, &error, &dcname);

	d_printf("checking the NETLOGON for domain[%s] dc connection to \"%s\" %s\n",
		 domain_name ? domain_name : "",
		 dcname ? dcname : "",
		 WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	wbcFreeMemory(dcname);
	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		d_fprintf(stderr, "wbcPingDc2(%s): error code was %s (0x%x)\n",
			  domain_name, error->nt_string, error->nt_status);
		wbcFreeMemory(error);
		return false;
	}
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcPingDc: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	return true;
}

/* Convert uid to sid */

static bool wbinfo_uid_to_sid(uid_t uid)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	char sid_str[WBC_SID_STRING_BUFLEN];

	/* Send request */

	wbc_status = wbcUidToSid(uid, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcUidToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbcSidToStringBuf(&sid, sid_str, sizeof(sid_str));

	/* Display response */

	d_printf("%s\n", sid_str);

	return true;
}

/* Convert gid to sid */

static bool wbinfo_gid_to_sid(gid_t gid)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	char sid_str[WBC_SID_STRING_BUFLEN];

	/* Send request */

	wbc_status = wbcGidToSid(gid, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGidToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbcSidToStringBuf(&sid, sid_str, sizeof(sid_str));

	/* Display response */

	d_printf("%s\n", sid_str);

	return true;
}

/* Convert sid to uid */

static bool wbinfo_sid_to_uid(const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	uid_t uid;

	/* Send request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcSidToUid(&sid, &uid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcSidToUid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("%d\n", (int)uid);

	return true;
}

static bool wbinfo_sid_to_gid(const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	gid_t gid;

	/* Send request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcSidToGid(&sid, &gid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcSidToGid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("%d\n", (int)gid);

	return true;
}

static bool wbinfo_sids_to_unix_ids(const char *arg)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *sidstr = NULL;
	struct wbcDomainSid *sids;
	struct wbcUnixId *unix_ids;
	int i, num_sids;
	const char *p;
	wbcErr wbc_status;
	bool ret = false;

	num_sids = 0;
	sids = NULL;
	p = arg;

	while (next_token_talloc(frame, &p, &sidstr, LIST_SEP)) {
		sids = talloc_realloc(frame,
				      sids,
				      struct wbcDomainSid,
				      num_sids + 1);
		if (sids == NULL) {
			d_fprintf(stderr, "talloc failed\n");
			goto fail;
		}
		wbc_status = wbcStringToSid(sidstr, &sids[num_sids]);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			d_fprintf(stderr, "wbcSidToString(%s) failed: %s\n",
				  sidstr, wbcErrorString(wbc_status));
			goto fail;
		}
		TALLOC_FREE(sidstr);
		num_sids += 1;
	}

	unix_ids = talloc_array(frame, struct wbcUnixId, num_sids);
	if (unix_ids == NULL) {
		goto fail;
	}

	wbc_status = wbcSidsToUnixIds(sids, num_sids, unix_ids);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "wbcSidsToUnixIds failed: %s\n",
			  wbcErrorString(wbc_status));
		goto fail;
	}

	for (i=0; i<num_sids; i++) {
		fstring sidbuf;

		wbcSidToStringBuf(&sids[i], sidbuf, sizeof(sidbuf));

		switch(unix_ids[i].type) {
		case WBC_ID_TYPE_UID:
			d_printf("%s -> uid %d\n", sidbuf, unix_ids[i].id.uid);
			break;
		case WBC_ID_TYPE_GID:
			d_printf("%s -> gid %d\n", sidbuf, unix_ids[i].id.gid);
			break;
		case WBC_ID_TYPE_BOTH:
			d_printf("%s -> uid/gid %d\n",
				 sidbuf,
				 unix_ids[i].id.uid);
			break;
		default:
			d_printf("%s -> unmapped\n", sidbuf);
			break;
		}
	}

	ret = true;
fail:
	TALLOC_FREE(frame);
	return ret;
}

static bool wbinfo_xids_to_sids(const char *arg)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *idstr = NULL;
	struct wbcUnixId *xids = NULL;
	struct wbcDomainSid *sids;
	wbcErr wbc_status;
	int num_xids = 0;
	const char *p;
	int i;
	bool ret = false;

	p = arg;

	while (next_token_talloc(frame, &p, &idstr, LIST_SEP)) {
		xids = talloc_realloc(xids,
				      xids,
				      struct wbcUnixId,
				      num_xids + 1);
		if (xids == NULL) {
			d_fprintf(stderr, "talloc failed\n");
			goto fail;
		}

		switch (idstr[0]) {
		case 'u':
			xids[num_xids] = (struct wbcUnixId) {
				.type = WBC_ID_TYPE_UID,
				.id.uid = atoi(&idstr[1])
			};
			break;
		case 'g':
			xids[num_xids] = (struct wbcUnixId) {
				.type = WBC_ID_TYPE_GID,
				.id.gid = atoi(&idstr[1])
			};
			break;
		default:
			d_fprintf(stderr, "%s is an invalid id\n", idstr);
			goto fail;
		}
		TALLOC_FREE(idstr);
		num_xids += 1;
	}

	sids = talloc_array(frame, struct wbcDomainSid, num_xids);
	if (sids == NULL) {
		d_fprintf(stderr, "talloc failed\n");
		goto fail;
	}

	wbc_status = wbcUnixIdsToSids(xids, num_xids, sids);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "wbcUnixIdsToSids failed: %s\n",
			  wbcErrorString(wbc_status));
		goto fail;
	}

	for (i=0; i<num_xids; i++) {
		char str[WBC_SID_STRING_BUFLEN];
		struct wbcDomainSid null_sid = { 0 };

		if (memcmp(&null_sid, &sids[i], sizeof(struct wbcDomainSid)) == 0) {
			d_printf("NOT MAPPED\n");
			continue;
		}
		wbcSidToStringBuf(&sids[i], str, sizeof(str));
		d_printf("%s\n", str);
	}

	ret = true;
fail:
	TALLOC_FREE(frame);
	return ret;
}

static bool wbinfo_allocate_uid(void)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uid_t uid;

	/* Send request */

	wbc_status = wbcAllocateUid(&uid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcAllocateUid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("New uid: %u\n", (unsigned int)uid);

	return true;
}

static bool wbinfo_allocate_gid(void)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	gid_t gid;

	/* Send request */

	wbc_status = wbcAllocateGid(&gid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcAllocateGid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("New gid: %u\n", (unsigned int)gid);

	return true;
}

static bool wbinfo_set_uid_mapping(uid_t uid, const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;

	/* Send request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcSetUidMapping(uid, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcSetUidMapping: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("uid %u now mapped to sid %s\n",
		(unsigned int)uid, sid_str);

	return true;
}

static bool wbinfo_set_gid_mapping(gid_t gid, const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;

	/* Send request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcSetGidMapping(gid, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcSetGidMapping: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("gid %u now mapped to sid %s\n",
		(unsigned int)gid, sid_str);

	return true;
}

static bool wbinfo_remove_uid_mapping(uid_t uid, const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;

	/* Send request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcRemoveUidMapping(uid, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcRemoveUidMapping: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("Removed uid %u to sid %s mapping\n",
		(unsigned int)uid, sid_str);

	return true;
}

static bool wbinfo_remove_gid_mapping(gid_t gid, const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;

	/* Send request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcRemoveGidMapping(gid, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcRemoveGidMapping: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("Removed gid %u to sid %s mapping\n",
		(unsigned int)gid, sid_str);

	return true;
}

/* Convert sid to string */

static bool wbinfo_lookupsid(const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	char *domain;
	char *name;
	enum wbcSidType type;

	/* Send off request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcLookupSid(&sid, &domain, &name, &type);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcLookupSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	if (type == WBC_SID_NAME_DOMAIN) {
		d_printf("%s %d\n", domain, type);
	} else {
		d_printf("%s%c%s %d\n",
			 domain, winbind_separator(), name, type);
	}

	wbcFreeMemory(domain);
	wbcFreeMemory(name);

	return true;
}

/* Convert sid to fullname */

static bool wbinfo_lookupsid_fullname(const char *sid_str)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	char *domain;
	char *name;
	enum wbcSidType type;

	/* Send off request */

	wbc_status = wbcStringToSid(sid_str, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcStringToSid: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcGetDisplayName(&sid, &domain, &name, &type);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcGetDisplayName: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	/* Display response */

	d_printf("%s%c%s %d\n",
		 domain, winbind_separator(), name, type);

	wbcFreeMemory(domain);
	wbcFreeMemory(name);

	return true;
}

/* Lookup a list of RIDs */

static bool wbinfo_lookuprids(const char *domain, const char *arg)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid dsid;
	char *domain_name = NULL;
	const char **names = NULL;
	enum wbcSidType *types = NULL;
	size_t i, num_rids;
	uint32_t *rids = NULL;
	const char *p;
	char *ridstr;
	TALLOC_CTX *mem_ctx = NULL;
	bool ret = false;

	if ((domain == NULL) || (strequal(domain, ".")) || (domain[0] == '\0')){
		domain = get_winbind_domain();
	}

	wbc_status = wbcStringToSid(domain, &dsid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		struct wbcDomainInfo *dinfo = NULL;

		wbc_status = wbcDomainInfo(domain, &dinfo);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			d_printf("wbcDomainInfo(%s) failed: %s\n", domain,
				 wbcErrorString(wbc_status));
			goto done;
		}

		dsid = dinfo->sid;
		wbcFreeMemory(dinfo);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		d_printf("talloc_new failed\n");
		goto done;
	}

	num_rids = 0;
	rids = NULL;
	p = arg;

	while (next_token_talloc(mem_ctx, &p, &ridstr, " ,\n")) {
		int error = 0;
		uint32_t rid;

		rid = smb_strtoul(ridstr, NULL, 10, &error, SMB_STR_STANDARD);
		if (error != 0) {
			d_printf("failed to convert rid\n");
			goto done;
		}
		rids = talloc_realloc(mem_ctx, rids, uint32_t, num_rids + 1);
		if (rids == NULL) {
			d_printf("talloc_realloc failed\n");
		}
		rids[num_rids] = rid;
		num_rids += 1;
	}

	if (rids == NULL) {
		d_printf("no rids\n");
		goto done;
	}

	wbc_status = wbcLookupRids(
		&dsid, num_rids, rids, &p, &names, &types);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_printf("winbind_lookup_rids failed: %s\n",
			 wbcErrorString(wbc_status));
		goto done;
	}

	domain_name = discard_const_p(char, p);
	d_printf("Domain: %s\n", domain_name);

	for (i=0; i<num_rids; i++) {
		d_printf("%8d: %s (%s)\n", rids[i], names[i],
			 wbcSidTypeString(types[i]));
	}

	ret = true;
done:
	wbcFreeMemory(domain_name);
	wbcFreeMemory(names);
	wbcFreeMemory(types);
	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool wbinfo_lookup_sids(const char *arg)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *sidstr = NULL;
	struct wbcDomainSid *sids;
	struct wbcDomainInfo *domains;
	struct wbcTranslatedName *names;
	int num_domains;
	int i, num_sids;
	const char *p;
	wbcErr wbc_status;
	bool ret = false;

	num_sids = 0;
	sids = NULL;
	p = arg;

	while (next_token_talloc(frame, &p, &sidstr, LIST_SEP)) {
		sids = talloc_realloc(frame,
				      sids,
				      struct wbcDomainSid,
				      num_sids + 1);
		if (sids == NULL) {
			d_fprintf(stderr, "talloc failed\n");
			goto fail;
		}
		wbc_status = wbcStringToSid(sidstr, &sids[num_sids]);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			d_fprintf(stderr, "wbcSidToString(%s) failed: %s\n",
				  sidstr, wbcErrorString(wbc_status));
			goto fail;
		}
		TALLOC_FREE(sidstr);
		num_sids += 1;
	}

	wbc_status = wbcLookupSids(sids, num_sids, &domains, &num_domains,
				   &names);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "wbcLookupSids failed: %s\n",
			  wbcErrorString(wbc_status));
		goto fail;
	}

	for (i=0; i<num_sids; i++) {
		const char *domain = NULL;

		wbcSidToStringBuf(&sids[i], sidstr, sizeof(sidstr));

		if (names[i].domain_index >= num_domains) {
			domain = "<none>";
		} else if (names[i].domain_index < 0) {
			domain = "<none>";
		} else {
			domain = domains[names[i].domain_index].short_name;
		}

		if (names[i].type == WBC_SID_NAME_DOMAIN) {
			d_printf("%s -> %s %d\n", sidstr,
				 domain,
				 names[i].type);
		} else {
			d_printf("%s -> %s%c%s %d\n", sidstr,
				 domain,
				 winbind_separator(),
				 names[i].name, names[i].type);
		}
	}
	wbcFreeMemory(names);
	wbcFreeMemory(domains);

	ret = true;
fail:
	TALLOC_FREE(frame);
	return ret;
}

/* Convert string to sid */

static bool wbinfo_lookupname(const char *full_name)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainSid sid;
	char sid_str[WBC_SID_STRING_BUFLEN];
	enum wbcSidType type;
	fstring domain_name;
	fstring account_name;

	/* Send off request */

	parse_wbinfo_domain_user(full_name, domain_name,
				 account_name);

	wbc_status = wbcLookupName(domain_name, account_name,
				   &sid, &type);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcLookupName: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	wbcSidToStringBuf(&sid, sid_str, sizeof(sid_str));

	/* Display response */

	d_printf("%s %s (%d)\n", sid_str, wbcSidTypeString(type), type);

	return true;
}

static char *wbinfo_prompt_pass(TALLOC_CTX *mem_ctx,
				const char *prefix,
				const char *username)
{
	char *prompt;
	char buf[1024] = {0};
	int rc;

	prompt = talloc_asprintf(mem_ctx, "Enter %s's ", username);
	if (!prompt) {
		return NULL;
	}
	if (prefix) {
		prompt = talloc_asprintf_append(prompt, "%s ", prefix);
		if (!prompt) {
			return NULL;
		}
	}
	prompt = talloc_asprintf_append(prompt, "password: ");
	if (!prompt) {
		return NULL;
	}

	rc = samba_getpass(prompt, buf, sizeof(buf), false, false);
	TALLOC_FREE(prompt);
	if (rc < 0) {
		return NULL;
	}

	return talloc_strdup(mem_ctx, buf);
}

/* Authenticate a user with a plaintext password */

static bool wbinfo_auth_krb5(char *username, const char *cctype, uint32_t flags)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *s = NULL;
	char *p = NULL;
	char *password = NULL;
	char *name = NULL;
	char *local_cctype = NULL;
	uid_t uid;
	struct wbcLogonUserParams params;
	struct wbcLogonUserInfo *info = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	struct wbcUserPasswordPolicyInfo *policy = NULL;
	TALLOC_CTX *frame = talloc_tos();

	if ((s = talloc_strdup(frame, username)) == NULL) {
		return false;
	}

	if ((p = strchr(s, '%')) != NULL) {
		*p = 0;
		p++;
		password = talloc_strdup(frame, p);
	} else {
		password = wbinfo_prompt_pass(frame, NULL, username);
	}

	local_cctype = talloc_strdup(frame, cctype);

	name = s;

	uid = geteuid();

	params.username = name;
	params.password = password;
	params.num_blobs = 0;
	params.blobs = NULL;

	wbc_status = wbcAddNamedBlob(&params.num_blobs,
				     &params.blobs,
				     "flags",
				     0,
				     (uint8_t *)&flags,
				     sizeof(flags));
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcAddNamedBlob: %s\n",
			  wbcErrorString(wbc_status));
		goto done;
	}

	wbc_status = wbcAddNamedBlob(&params.num_blobs,
				     &params.blobs,
				     "user_uid",
				     0,
				     (uint8_t *)&uid,
				     sizeof(uid));
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcAddNamedBlob: %s\n",
			  wbcErrorString(wbc_status));
		goto done;
	}

	wbc_status = wbcAddNamedBlob(&params.num_blobs,
				     &params.blobs,
				     "krb5_cc_type",
				     0,
				     (uint8_t *)local_cctype,
				     strlen(cctype)+1);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcAddNamedBlob: %s\n",
			  wbcErrorString(wbc_status));
		goto done;
	}

	wbc_status = wbcLogonUser(&params, &info, &error, &policy);

	d_printf("plaintext kerberos password authentication for [%s] %s "
		 "(requesting cctype: %s)\n",
		 name, WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed",
		 cctype);

	if (error) {
		d_fprintf(stderr,
			 "wbcLogonUser(%s): error code was %s (0x%x)\n"
			 "error message was: %s\n",
			 params.username, error->nt_string,
			 error->nt_status,
			 error->display_string);
	}

	if (WBC_ERROR_IS_OK(wbc_status)) {
		if (flags & WBFLAG_PAM_INFO3_TEXT) {
			if (info && info->info && info->info->user_flags &
			    NETLOGON_CACHED_ACCOUNT) {
				d_printf("user_flgs: "
					 "NETLOGON_CACHED_ACCOUNT\n");
			}
		}

		if (info) {
			size_t i;
			for (i=0; i < info->num_blobs; i++) {
				if (strequal(info->blobs[i].name,
					     "krb5ccname")) {
					d_printf("credentials were put "
						 "in: %s\n",
						(const char *)
						      info->blobs[i].blob.data);
					break;
				}
			}
		} else {
			d_printf("no credentials cached\n");
		}
	}
 done:
	wbcFreeMemory(error);
	wbcFreeMemory(policy);
	wbcFreeMemory(info);
	wbcFreeMemory(params.blobs);

	return WBC_ERROR_IS_OK(wbc_status);
}

/* Authenticate a user with a plaintext password */

static bool wbinfo_auth(char *username)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *s = NULL;
	char *p = NULL;
	char *password = NULL;
	char *name = NULL;
	TALLOC_CTX *frame = talloc_tos();

	if ((s = talloc_strdup(frame, username)) == NULL) {
		return false;
	}

	if ((p = strchr(s, '%')) != NULL) {
		*p = 0;
		p++;
		password = talloc_strdup(frame, p);
	} else {
		password = wbinfo_prompt_pass(frame, NULL, username);
	}

	name = s;

	wbc_status = wbcAuthenticateUser(name, password);

	d_printf("plaintext password authentication %s\n",
		 WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

#if 0
	if (response.data.auth.nt_status)
		d_fprintf(stderr,
			 "error code was %s (0x%x)\nerror message was: %s\n",
			 response.data.auth.nt_status_string,
			 response.data.auth.nt_status,
			 response.data.auth.error_string);
#endif

	return WBC_ERROR_IS_OK(wbc_status);
}

/* Authenticate a user with a challenge/response */

static bool wbinfo_auth_crap(char *username, bool use_ntlmv2, bool use_lanman)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcAuthUserParams params;
	struct wbcAuthUserInfo *info = NULL;
	struct wbcAuthErrorInfo *err = NULL;
	DATA_BLOB lm = data_blob_null;
	DATA_BLOB nt = data_blob_null;
	fstring name_user;
	fstring name_domain;
	char *pass;
	char *p;
	TALLOC_CTX *frame = talloc_tos();

	p = strchr(username, '%');

	if (p) {
		*p = 0;
		pass = talloc_strdup(frame, p + 1);
	} else {
		pass = wbinfo_prompt_pass(frame, NULL, username);
	}

	parse_wbinfo_domain_user(username, name_domain, name_user);

	params.account_name	= name_user;
	params.domain_name	= name_domain;
	params.workstation_name	= NULL;

	params.flags		= 0;
	params.parameter_control= WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
				  WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

	params.level		= WBC_AUTH_USER_LEVEL_RESPONSE;

	generate_random_buffer(params.password.response.challenge, 8);

	if (use_ntlmv2) {
		DATA_BLOB server_chal;
		DATA_BLOB names_blob;
		const char *netbios_name = NULL;
		const char *domain = NULL;

		netbios_name = get_winbind_netbios_name(),
		domain = get_winbind_domain();
		if (domain == NULL) {
			d_fprintf(stderr, "Failed to get domain from winbindd\n");
			return false;
		}

		server_chal = data_blob(params.password.response.challenge, 8);

		/* Pretend this is a login to 'us', for blob purposes */
		names_blob = NTLMv2_generate_names_blob(NULL,
							netbios_name,
							domain);

		if (pass != NULL &&
		    !SMBNTLMv2encrypt(NULL, name_user, name_domain, pass,
				      &server_chal,
				      &names_blob,
				      &lm, &nt, NULL, NULL)) {
			data_blob_free(&names_blob);
			data_blob_free(&server_chal);
			TALLOC_FREE(pass);
			return false;
		}
		data_blob_free(&names_blob);
		data_blob_free(&server_chal);

	} else {
		if (use_lanman) {
			bool ok;
			lm = data_blob(NULL, 24);
			ok = SMBencrypt(pass,
					params.password.response.challenge,
					lm.data);
			if (!ok) {
				data_blob_free(&lm);
			}
		}
		nt = data_blob(NULL, 24);
		SMBNTencrypt(pass, params.password.response.challenge,
			     nt.data);
	}

	params.password.response.nt_length	= nt.length;
	params.password.response.nt_data	= nt.data;
	params.password.response.lm_length	= lm.length;
	params.password.response.lm_data	= lm.data;

	wbc_status = wbcAuthenticateUserEx(&params, &info, &err);

	/* Display response */

	d_printf("challenge/response password authentication %s\n",
		 WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		d_fprintf(stderr,
			 "wbcAuthenticateUserEx(%s%c%s): error code was "
			  "%s (0x%x, authoritative=%"PRIu8")\n"
			 "error message was: %s\n",
			 name_domain,
			 winbind_separator(),
			 name_user,
			 err->nt_string,
			 err->nt_status,
			 err->authoritative,
			 err->display_string);
		wbcFreeMemory(err);
	} else if (WBC_ERROR_IS_OK(wbc_status)) {
		wbcFreeMemory(info);
	}

	data_blob_free(&nt);
	data_blob_free(&lm);

	return WBC_ERROR_IS_OK(wbc_status);
}

/* Authenticate a user with a plaintext password */

static bool wbinfo_pam_logon(char *username, bool verbose)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcLogonUserParams params;
	struct wbcLogonUserInfo *info = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	char *s = NULL;
	char *p = NULL;
	TALLOC_CTX *frame = talloc_tos();
	uint32_t flags;
	uint32_t uid;

	ZERO_STRUCT(params);

	if ((s = talloc_strdup(frame, username)) == NULL) {
		return false;
	}

	if ((p = strchr(s, '%')) != NULL) {
		*p = 0;
		p++;
		params.password = talloc_strdup(frame, p);
	} else {
		params.password = wbinfo_prompt_pass(frame, NULL, username);
	}
	params.username = s;

	flags = WBFLAG_PAM_CACHED_LOGIN;

	wbc_status = wbcAddNamedBlob(&params.num_blobs, &params.blobs,
				     "flags", 0,
				     (uint8_t *)&flags, sizeof(flags));
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_printf("wbcAddNamedBlob failed: %s\n",
			 wbcErrorString(wbc_status));
		return false;
	}

	uid = getuid();

	wbc_status = wbcAddNamedBlob(&params.num_blobs, &params.blobs,
				     "user_uid", 0,
				     (uint8_t *)&uid, sizeof(uid));
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_printf("wbcAddNamedBlob failed: %s\n",
			 wbcErrorString(wbc_status));
		return false;
	}

	wbc_status = wbcLogonUser(&params, &info, &error, NULL);

	if (verbose && (info != NULL)) {
		struct wbcAuthUserInfo *i = info->info;
		uint32_t j;

		if (i->account_name != NULL) {
			d_printf("account_name: %s\n", i->account_name);
		}
		if (i->user_principal != NULL) {
			d_printf("user_principal: %s\n", i->user_principal);
		}
		if (i->full_name != NULL) {
			d_printf("full_name: %s\n", i->full_name);
		}
		if (i->domain_name != NULL) {
			d_printf("domain_name: %s\n", i->domain_name);
		}
		if (i->dns_domain_name != NULL) {
			d_printf("dns_domain_name: %s\n", i->dns_domain_name);
		}
		if (i->logon_server != NULL) {
			d_printf("logon_server: %s\n", i->logon_server);
		}
		if (i->logon_script != NULL) {
			d_printf("logon_script: %s\n", i->logon_script);
		}
		if (i->profile_path != NULL) {
			d_printf("profile_path: %s\n", i->profile_path);
		}
		if (i->home_directory != NULL) {
			d_printf("home_directory: %s\n", i->home_directory);
		}
		if (i->home_drive != NULL) {
			d_printf("home_drive: %s\n", i->home_drive);
		}

		d_printf("sids:");

		for (j=0; j<i->num_sids; j++) {
			char buf[WBC_SID_STRING_BUFLEN];
			wbcSidToStringBuf(&i->sids[j].sid, buf, sizeof(buf));
			d_printf(" %s", buf);
		}
		d_printf("\n");

		wbcFreeMemory(info);
		info = NULL;
	}

	wbcFreeMemory(params.blobs);

	d_printf("plaintext password authentication %s\n",
		 WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	if (!WBC_ERROR_IS_OK(wbc_status) && (error != NULL)) {
		d_fprintf(stderr,
			  "wbcLogonUser(%s): error code was %s (0x%x)\n"
			  "error message was: %s\n",
			  params.username,
			  error->nt_string,
			  (int)error->nt_status,
			  error->display_string);
		wbcFreeMemory(error);
	}
	return WBC_ERROR_IS_OK(wbc_status);
}

/* Save creds with winbind */

static bool wbinfo_ccache_save(char *username)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *s = NULL;
	char *p = NULL;
	char *password = NULL;
	char *name = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	s = talloc_strdup(frame, username);
	if (s == NULL) {
		return false;
	}

	p = strchr(s, '%');
	if (p != NULL) {
		*p = 0;
		p++;
		password = talloc_strdup(frame, p);
	} else {
		password = wbinfo_prompt_pass(frame, NULL, username);
	}

	name = s;

	wbc_status = wbcCredentialSave(name, password);

	d_printf("saving creds %s\n",
		 WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	TALLOC_FREE(frame);

	return WBC_ERROR_IS_OK(wbc_status);
}

#ifdef WITH_FAKE_KASERVER
/* Authenticate a user with a plaintext password and set a token */

static bool wbinfo_klog(char *username)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;
	char *p;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	p = strchr(username, '%');

	if (p) {
		*p = 0;
		fstrcpy(request.data.auth.user, username);
		fstrcpy(request.data.auth.pass, p + 1);
		*p = '%';
	} else {
		fstrcpy(request.data.auth.user, username);
		(void) samba_getpass("Password: ",
				     request.data.auth.pass,
				     sizeof(request.data.auth.pass),
				     false, false);
	}

	request.flags |= WBFLAG_PAM_AFS_TOKEN;

	wbc_status = wbcRequestResponse(NULL, WINBINDD_PAM_AUTH,
					&request, &response);

	/* Display response */

	d_printf("plaintext password authentication %s\n",
		 WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	if (response.data.auth.nt_status)
		d_fprintf(stderr,
			 "error code was %s (0x%x)\nerror message was: %s\n",
			 response.data.auth.nt_status_string,
			 response.data.auth.nt_status,
			 response.data.auth.error_string);

	if (!WBC_ERROR_IS_OK(wbc_status))
		return false;

	if (response.extra_data.data == NULL) {
		d_fprintf(stderr, "Did not get token data\n");
		return false;
	}

	if (!afs_settoken_str((char *)response.extra_data.data)) {
		winbindd_free_response(&response);
		d_fprintf(stderr, "Could not set token\n");
		return false;
	}

	winbindd_free_response(&response);
	d_printf("Successfully created AFS token\n");
	return true;
}
#else
static bool wbinfo_klog(char *username)
{
	d_fprintf(stderr, "No AFS support compiled in.\n");
	return false;
}
#endif

/* Print domain users */

static bool print_domain_users(const char *domain)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t i;
	uint32_t num_users = 0;
	const char **users = NULL;

	/* Send request to winbind daemon */

	if (domain == NULL) {
		domain = get_winbind_domain();
	} else {
		/* '.' is the special sign for our own domain */
		if ((domain[0] == '\0') || strcmp(domain, ".") == 0) {
			domain = get_winbind_domain();
		/* '*' is the special sign for all domains */
		} else if (strcmp(domain, "*") == 0) {
			domain = NULL;
		}
	}

	wbc_status = wbcListUsers(domain, &num_users, &users);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		return false;
	}

	for (i=0; i < num_users; i++) {
		d_printf("%s\n", users[i]);
	}

	wbcFreeMemory(users);

	return true;
}

/* Print domain groups */

static bool print_domain_groups(const char *domain)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t i;
	uint32_t num_groups = 0;
	const char **groups = NULL;

	/* Send request to winbind daemon */

	if (domain == NULL) {
		domain = get_winbind_domain();
	} else {
		/* '.' is the special sign for our own domain */
		if ((domain[0] == '\0') || strcmp(domain, ".") == 0) {
			domain = get_winbind_domain();
		/* '*' is the special sign for all domains */
		} else if (strcmp(domain, "*") == 0) {
			domain = NULL;
		}
	}

	wbc_status = wbcListGroups(domain, &num_groups, &groups);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "failed to call wbcListGroups: %s\n",
			  wbcErrorString(wbc_status));
		return false;
	}

	for (i=0; i < num_groups; i++) {
		d_printf("%s\n", groups[i]);
	}

	wbcFreeMemory(groups);

	return true;
}

/* Set the authorised user for winbindd access in secrets.tdb */

static bool wbinfo_set_auth_user(char *username)
{
	d_fprintf(stderr, "This functionality was moved to the 'net' utility.\n"
			  "See 'net help setauthuser' for details.\n");
	return false;
}

static void wbinfo_get_auth_user(void)
{
	d_fprintf(stderr, "This functionality was moved to the 'net' utility.\n"
			  "See 'net help getauthuser' for details.\n");
}

static bool wbinfo_ping(void)
{
	wbcErr wbc_status;

	wbc_status = wbcPing();

	/* Display response */

	d_printf("Ping to winbindd %s\n",
		 WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	return WBC_ERROR_IS_OK(wbc_status);
}

static bool wbinfo_change_user_password(const char *username)
{
	wbcErr wbc_status;
	char *old_password = NULL;
	char *new_password = NULL;
	TALLOC_CTX *frame = talloc_tos();

	old_password = wbinfo_prompt_pass(frame, "old", username);
	new_password = wbinfo_prompt_pass(frame, "new", username);

	wbc_status = wbcChangeUserPassword(username, old_password,new_password);

	/* Display response */

	d_printf("Password change for user %s %s\n", username,
		WBC_ERROR_IS_OK(wbc_status) ? "succeeded" : "failed");

	return WBC_ERROR_IS_OK(wbc_status);
}

/* Main program */

enum {
	OPT_SET_AUTH_USER = 1000,
	OPT_GET_AUTH_USER,
	OPT_DOMAIN_NAME,
	OPT_GETDCNAME,
	OPT_DSGETDCNAME,
	OPT_DC_INFO,
	OPT_USERDOMGROUPS,
	OPT_SIDALIASES,
	OPT_USERSIDS,
	OPT_LOOKUP_SIDS,
	OPT_ALLOCATE_UID,
	OPT_ALLOCATE_GID,
	OPT_SET_UID_MAPPING,
	OPT_SET_GID_MAPPING,
	OPT_REMOVE_UID_MAPPING,
	OPT_REMOVE_GID_MAPPING,
	OPT_SIDS_TO_XIDS,
	OPT_XIDS_TO_SIDS,
	OPT_SEPARATOR,
	OPT_LIST_ALL_DOMAINS,
	OPT_LIST_OWN_DOMAIN,
	OPT_UID_INFO,
	OPT_USER_SIDINFO,
	OPT_GROUP_INFO,
	OPT_GID_INFO,
	OPT_VERBOSE,
	OPT_ONLINESTATUS,
	OPT_CHANGE_USER_PASSWORD,
	OPT_CCACHE_SAVE,
	OPT_SID_TO_FULLNAME,
	OPT_NTLMV1,
	OPT_NTLMV2,
	OPT_PAM_LOGON,
	OPT_LOGOFF,
	OPT_LOGOFF_USER,
	OPT_LOGOFF_UID,
	OPT_LANMAN,
	OPT_KRB5CCNAME,
	OPT_CHANGE_SECRET_AT
};

int main(int argc, const char **argv, char **envp)
{
	int opt;
	TALLOC_CTX *frame = talloc_stackframe();
	poptContext pc;
	static char *string_arg;
	char *string_subarg = NULL;
	static char *opt_domain_name;
	static int int_arg;
	int int_subarg = -1;
	int result = 1;
	bool verbose = false;
	bool use_ntlmv2 = true;
	bool use_lanman = false;
	char *logoff_user = getenv("USER");
	int logoff_uid = geteuid();
	const char *opt_krb5ccname = "FILE";

	struct poptOption long_options[] = {
		POPT_AUTOHELP

		/* longName, shortName, argInfo, argPtr, value, descrip,
		   argDesc */

		{
			.longName   = "domain-users",
			.shortName  = 'u',
			.argInfo    = POPT_ARG_NONE,
			.val        = 'u',
			.descrip    = "Lists all domain users",
			.argDescrip = "domain"
		},
		{
			.longName   = "domain-groups",
			.shortName  = 'g',
			.argInfo    = POPT_ARG_NONE,
			.val        = 'g',
			.descrip    = "Lists all domain groups",
			.argDescrip = "domain"
		},
		{
			.longName   = "WINS-by-name",
			.shortName  = 'N',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'N',
			.descrip    = "Converts NetBIOS name to IP",
			.argDescrip = "NETBIOS-NAME"
		},
		{
			.longName   = "WINS-by-ip",
			.shortName  = 'I',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'I',
			.descrip    = "Converts IP address to NetBIOS name",
			.argDescrip = "IP"
		},
		{
			.longName   = "name-to-sid",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'n',
			.descrip    = "Converts name to sid",
			.argDescrip = "NAME"
		},
		{
			.longName   = "sid-to-name",
			.shortName  = 's',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 's',
			.descrip    = "Converts sid to name",
			.argDescrip = "SID"
		},
		{
			.longName   = "sid-to-fullname",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_SID_TO_FULLNAME,
			.descrip    = "Converts sid to fullname",
			.argDescrip = "SID"
		},
		{
			.longName   = "lookup-rids",
			.shortName  = 'R',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'R',
			.descrip    = "Converts RIDs to names",
			.argDescrip = "RIDs"
		},
		{
			.longName   = "lookup-sids",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_LOOKUP_SIDS,
			.descrip    = "Converts SIDs to types and names",
			.argDescrip = "Sid-List"
		},
		{
			.longName   = "uid-to-sid",
			.shortName  = 'U',
			.argInfo    = POPT_ARG_INT,
			.arg        = &int_arg,
			.val        = 'U',
			.descrip    = "Converts uid to sid",
			.argDescrip = "UID"
		},
		{
			.longName   = "gid-to-sid",
			.shortName  = 'G',
			.argInfo    = POPT_ARG_INT,
			.arg        = &int_arg,
			.val        = 'G',
			.descrip    = "Converts gid to sid",
			.argDescrip = "GID"
		},
		{
			.longName   = "sid-to-uid",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'S',
			.descrip    = "Converts sid to uid",
			.argDescrip = "SID"
		},
		{
			.longName   = "sid-to-gid",
			.shortName  = 'Y',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'Y',
			.descrip    = "Converts sid to gid",
			.argDescrip = "SID"
		},
		{
			.longName   = "allocate-uid",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_ALLOCATE_UID,
			.descrip    = "Get a new UID out of idmap"
		},
		{
			.longName   = "allocate-gid",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_ALLOCATE_GID,
			.descrip    = "Get a new GID out of idmap"
		},
		{
			.longName   = "set-uid-mapping",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_SET_UID_MAPPING,
			.descrip    = "Create or modify uid to sid mapping in "
				      "idmap",
			.argDescrip = "UID,SID"
		},
		{
			.longName   = "set-gid-mapping",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_SET_GID_MAPPING,
			.descrip    = "Create or modify gid to sid mapping in "
				      "idmap",
			.argDescrip = "GID,SID"
		},
		{
			.longName   = "remove-uid-mapping",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_REMOVE_UID_MAPPING,
			.descrip    = "Remove uid to sid mapping in idmap",
			.argDescrip = "UID,SID"
		},
		{
			.longName   = "remove-gid-mapping",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_REMOVE_GID_MAPPING,
			.descrip    = "Remove gid to sid mapping in idmap",
			.argDescrip = "GID,SID",
		},
		{
			.longName   = "sids-to-unix-ids",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_SIDS_TO_XIDS,
			.descrip    = "Translate SIDs to Unix IDs",
			.argDescrip = "Sid-List",
		},
		{
			.longName   = "unix-ids-to-sids",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_XIDS_TO_SIDS,
			.descrip    = "Translate Unix IDs to SIDs",
			.argDescrip = "ID-List (u<num> g<num>)",
		},
		{
			.longName   = "check-secret",
			.shortName  = 't',
			.argInfo    = POPT_ARG_NONE,
			.val        = 't',
			.descrip    = "Check shared secret",
		},
		{
			.longName   = "change-secret",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_NONE,
			.val        = 'c',
			.descrip    = "Change shared secret",
		},
		{
			.longName   = "change-secret-at",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_CHANGE_SECRET_AT,
			.descrip    = "Change shared secret at Domain Controller" },
		{
			.longName   = "ping-dc",
			.shortName  = 'P',
			.argInfo    = POPT_ARG_NONE,
			.val        = 'P',
			.descrip    = "Check the NETLOGON connection",
		},
		{
			.longName   = "trusted-domains",
			.shortName  = 'm',
			.argInfo    = POPT_ARG_NONE,
			.val        = 'm',
			.descrip    = "List trusted domains",
		},
		{
			.longName   = "all-domains",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_LIST_ALL_DOMAINS,
			.descrip    = "List all domains (trusted and own "
				      "domain)",
		},
		{
			.longName   = "own-domain",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_LIST_OWN_DOMAIN,
			.descrip    = "List own domain",
		},
		{
			.longName   = "online-status",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_ONLINESTATUS,
			.descrip    = "Show whether domains maintain an active "
				      "connection",
		},
		{
			.longName   = "domain-info",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'D',
			.descrip    = "Show most of the info we have about the "
				      "domain",
		},
		{
			.longName   = "user-info",
			.shortName  = 'i',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'i',
			.descrip    = "Get user info",
			.argDescrip = "USER",
		},
		{
			.longName   = "uid-info",
			.argInfo    = POPT_ARG_INT,
			.arg        = &int_arg,
			.val        = OPT_UID_INFO,
			.descrip    = "Get user info from uid",
			.argDescrip = "UID",
		},
		{
			.longName   = "group-info",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_GROUP_INFO,
			.descrip    = "Get group info",
			.argDescrip = "GROUP",
		},
		{
			.longName   = "user-sidinfo",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_USER_SIDINFO,
			.descrip    = "Get user info from sid",
			.argDescrip = "SID",
		},
		{
			.longName   = "gid-info",
			.argInfo    = POPT_ARG_INT,
			.arg        = &int_arg,
			.val        = OPT_GID_INFO,
			.descrip    = "Get group info from gid",
			.argDescrip = "GID",
		},
		{
			.longName   = "user-groups",
			.shortName  = 'r',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'r',
			.descrip    = "Get user groups",
			.argDescrip = "USER",
		},
		{
			.longName   = "user-domgroups",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_USERDOMGROUPS,
			.descrip    = "Get user domain groups",
			.argDescrip = "SID",
		},
		{
			.longName   = "sid-aliases",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_SIDALIASES,
			.descrip    = "Get sid aliases",
			.argDescrip = "SID",
		},
		{
			.longName   = "user-sids",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_USERSIDS,
			.descrip    = "Get user group sids for user SID",
			.argDescrip = "SID",
		},
		{
			.longName   = "authenticate",
			.shortName  = 'a',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'a',
			.descrip    = "authenticate user",
			.argDescrip = "user%password",
		},
		{
			.longName   = "pam-logon",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_PAM_LOGON,
			.descrip    = "do a pam logon equivalent",
			.argDescrip = "user%password",
		},
		{
			.longName   = "logoff",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_LOGOFF,
			.descrip    = "log off user",
			.argDescrip = "uid",
		},
		{
			.longName   = "logoff-user",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &logoff_user,
			.val        = OPT_LOGOFF_USER,
			.descrip    = "username to log off"
		},
		{
			.longName   = "logoff-uid",
			.argInfo    = POPT_ARG_INT,
			.arg        = &logoff_uid,
			.val        = OPT_LOGOFF_UID,
			.descrip    = "uid to log off",
		},
		{
			.longName   = "set-auth-user",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_SET_AUTH_USER,
			.descrip    = "Store user and password used by "
				      "winbindd (root only)",
			.argDescrip = "user%password",
		},
		{
			.longName   = "ccache-save",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_CCACHE_SAVE,
			.descrip    = "Store user and password for ccache "
			              "operation",
			.argDescrip = "user%password",
		},
		{
			.longName   = "getdcname",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_GETDCNAME,
			.descrip    = "Get a DC name for a foreign domain",
			.argDescrip = "domainname",
		},
		{
			.longName   = "dsgetdcname",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_DSGETDCNAME,
			.descrip    = "Find a DC for a domain",
			.argDescrip = "domainname",
		},
		{
			.longName   = "dc-info",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_DC_INFO,
			.descrip    = "Find the currently known DCs",
			.argDescrip = "domainname",
		},
		{
			.longName   = "get-auth-user",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_GET_AUTH_USER,
			.descrip    = "Retrieve user and password used by "
				      "winbindd (root only)",
		},
		{
			.longName   = "ping",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_NONE,
			.arg        = 0,
			.val        = 'p',
			.descrip    = "Ping winbindd to see if it is alive",
		},
		{
			.longName   = "domain",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_domain_name,
			.val        = OPT_DOMAIN_NAME,
			.descrip    = "Define to the domain to restrict "
				      "operation",
			.argDescrip = "domain",
		},
#ifdef WITH_FAKE_KASERVER
		{
			.longName   = "klog",
			.shortName  = 'k',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'k',
			.descrip    = "set an AFS token from winbind",
			.argDescrip = "user%password",
		},
#endif
#ifdef HAVE_KRB5
		{
			.longName   = "krb5auth",
			.shortName  = 'K',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = 'K',
			.descrip    = "authenticate user using Kerberos",
			.argDescrip = "user%password",
		},
			/* destroys wbinfo --help output */
			/* "user%password,DOM\\user%password,user@EXAMPLE.COM,EXAMPLE.COM\\user%password" },
			*/
		{
			.longName   = "krb5ccname",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt_krb5ccname,
			.val        = OPT_KRB5CCNAME,
			.descrip    = "authenticate user using Kerberos and "
				      "specific credential cache type",
			.argDescrip = "krb5ccname",
		},
#endif
		{
			.longName   = "separator",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_SEPARATOR,
			.descrip    = "Get the active winbind separator",
		},
		{
			.longName   = "verbose",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_VERBOSE,
			.descrip    = "Print additional information per command",
		},
		{
			.longName   = "change-user-password",
			.argInfo    = POPT_ARG_STRING,
			.arg        = &string_arg,
			.val        = OPT_CHANGE_USER_PASSWORD,
			.descrip    = "Change the password for a user",
		},
		{
			.longName   = "ntlmv1",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_NTLMV1,
			.descrip    = "Use NTLMv1 cryptography for user authentication",
		},
		{
			.longName   = "ntlmv2",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_NTLMV2,
			.descrip    = "Use NTLMv2 cryptography for user authentication",
		},
		{
			.longName   = "lanman",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_LANMAN,
			.descrip    = "Use lanman cryptography for user authentication",
		},
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	/* Samba client initialisation */
	smb_init_locale();


	/* Parse options */

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		exit(1);
	}

	/* Parse command line options */

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		return 1;
	}

	while((opt = poptGetNextOpt(pc)) != -1) {
		/* get the generic configuration parameters like --domain */
		switch (opt) {
		case OPT_VERBOSE:
			verbose = true;
			break;
		case OPT_NTLMV1:
			use_ntlmv2 = false;
			break;
		case OPT_LANMAN:
			use_lanman = true;
			break;
		}
	}

	poptFreeContext(pc);

	pc = poptGetContext(NULL, argc, (const char **)argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'u':
			if (!print_domain_users(opt_domain_name)) {
				d_fprintf(stderr,
					  "Error looking up domain users\n");
				goto done;
			}
			break;
		case 'g':
			if (!print_domain_groups(opt_domain_name)) {
				d_fprintf(stderr,
					  "Error looking up domain groups\n");
				goto done;
			}
			break;
		case 's':
			if (!wbinfo_lookupsid(string_arg)) {
				d_fprintf(stderr,
					  "Could not lookup sid %s\n",
					  string_arg);
				goto done;
			}
			break;
		case OPT_SID_TO_FULLNAME:
			if (!wbinfo_lookupsid_fullname(string_arg)) {
				d_fprintf(stderr, "Could not lookup sid %s\n",
					  string_arg);
				goto done;
			}
			break;
		case 'R':
			if (!wbinfo_lookuprids(opt_domain_name, string_arg)) {
				d_fprintf(stderr, "Could not lookup RIDs %s\n",
					  string_arg);
				goto done;
			}
			break;
		case OPT_LOOKUP_SIDS:
			if (!wbinfo_lookup_sids(string_arg)) {
				d_fprintf(stderr, "Could not lookup SIDs %s\n",
					  string_arg);
				goto done;
			}
			break;
		case 'n':
			if (!wbinfo_lookupname(string_arg)) {
				d_fprintf(stderr, "Could not lookup name %s\n",
					  string_arg);
				goto done;
			}
			break;
		case 'N':
			if (!wbinfo_wins_byname(string_arg)) {
				d_fprintf(stderr,
					  "Could not lookup WINS by name %s\n",
					  string_arg);
				goto done;
			}
			break;
		case 'I':
			if (!wbinfo_wins_byip(string_arg)) {
				d_fprintf(stderr,
					  "Could not lookup WINS by IP %s\n",
					  string_arg);
				goto done;
			}
			break;
		case 'U':
			if (!wbinfo_uid_to_sid(int_arg)) {
				d_fprintf(stderr,
					  "Could not convert uid %d to sid\n",
					  int_arg);
				goto done;
			}
			break;
		case 'G':
			if (!wbinfo_gid_to_sid(int_arg)) {
				d_fprintf(stderr,
					  "Could not convert gid %d to sid\n",
					  int_arg);
				goto done;
			}
			break;
		case 'S':
			if (!wbinfo_sid_to_uid(string_arg)) {
				d_fprintf(stderr,
					  "Could not convert sid %s to uid\n",
					  string_arg);
				goto done;
			}
			break;
		case 'Y':
			if (!wbinfo_sid_to_gid(string_arg)) {
				d_fprintf(stderr,
					  "Could not convert sid %s to gid\n",
					  string_arg);
				goto done;
			}
			break;
		case OPT_ALLOCATE_UID:
			if (!wbinfo_allocate_uid()) {
				d_fprintf(stderr, "Could not allocate a uid\n");
				goto done;
			}
			break;
		case OPT_ALLOCATE_GID:
			if (!wbinfo_allocate_gid()) {
				d_fprintf(stderr, "Could not allocate a gid\n");
				goto done;
			}
			break;
		case OPT_SET_UID_MAPPING:
			if (!parse_mapping_arg(string_arg, &int_subarg,
				&string_subarg) ||
			    !wbinfo_set_uid_mapping(int_subarg, string_subarg))
			{
				d_fprintf(stderr, "Could not create or modify "
					  "uid to sid mapping\n");
				goto done;
			}
			break;
		case OPT_SET_GID_MAPPING:
			if (!parse_mapping_arg(string_arg, &int_subarg,
			        &string_subarg) ||
			    !wbinfo_set_gid_mapping(int_subarg, string_subarg))
			{
				d_fprintf(stderr, "Could not create or modify "
					  "gid to sid mapping\n");
				goto done;
			}
			break;
		case OPT_REMOVE_UID_MAPPING:
			if (!parse_mapping_arg(string_arg, &int_subarg,
				&string_subarg) ||
			    !wbinfo_remove_uid_mapping(int_subarg,
				string_subarg))
			{
				d_fprintf(stderr, "Could not remove uid to sid "
				    "mapping\n");
				goto done;
			}
			break;
		case OPT_REMOVE_GID_MAPPING:
			if (!parse_mapping_arg(string_arg, &int_subarg,
			        &string_subarg) ||
			    !wbinfo_remove_gid_mapping(int_subarg,
			        string_subarg))
			{
				d_fprintf(stderr, "Could not remove gid to sid "
				    "mapping\n");
				goto done;
			}
			break;
		case OPT_SIDS_TO_XIDS:
			if (!wbinfo_sids_to_unix_ids(string_arg)) {
				d_fprintf(stderr, "wbinfo_sids_to_unix_ids "
					  "failed\n");
				goto done;
			}
			break;
		case OPT_XIDS_TO_SIDS:
			if (!wbinfo_xids_to_sids(string_arg)) {
				d_fprintf(stderr, "wbinfo_xids_to_sids "
					  "failed\n");
				goto done;
			}
			break;
		case 't':
			if (!wbinfo_check_secret(opt_domain_name)) {
				d_fprintf(stderr, "Could not check secret\n");
				goto done;
			}
			break;
		case 'c':
			if (!wbinfo_change_secret(opt_domain_name)) {
				d_fprintf(stderr, "Could not change secret\n");
				goto done;
			}
			break;
		case OPT_CHANGE_SECRET_AT:
			if (!wbinfo_change_secret_at(opt_domain_name, string_arg)) {
				d_fprintf(stderr, "Could not change secret\n");
				goto done;
			}
			break;
		case 'P':
			if (!wbinfo_ping_dc(opt_domain_name)) {
				goto done;
			}
			break;
		case 'm':
			if (!wbinfo_list_domains(false, verbose)) {
				d_fprintf(stderr,
					  "Could not list trusted domains\n");
				goto done;
			}
			break;
		case OPT_ONLINESTATUS:
			if (!wbinfo_show_onlinestatus(opt_domain_name)) {
				d_fprintf(stderr,
					  "Could not show online-status\n");
				goto done;
			}
			break;
		case 'D':
			if (!wbinfo_domain_info(string_arg)) {
				d_fprintf(stderr,
					  "Could not get domain info\n");
				goto done;
			}
			break;
		case 'i':
			if (!wbinfo_get_userinfo(string_arg)) {
				d_fprintf(stderr,
					  "Could not get info for user %s\n",
					  string_arg);
				goto done;
			}
			break;
		case OPT_USER_SIDINFO:
			if ( !wbinfo_get_user_sidinfo(string_arg)) {
				d_fprintf(stderr,
					  "Could not get info for user "
					  "sid %s\n", string_arg);
				goto done;
			}
			break;
		case OPT_UID_INFO:
			if ( !wbinfo_get_uidinfo(int_arg)) {
				d_fprintf(stderr, "Could not get info for uid "
						"%d\n", int_arg);
				goto done;
			}
			break;
		case OPT_GROUP_INFO:
			if ( !wbinfo_get_groupinfo(string_arg)) {
				d_fprintf(stderr, "Could not get info for "
					  "group %s\n", string_arg);
				goto done;
			}
			break;
		case OPT_GID_INFO:
			if ( !wbinfo_get_gidinfo(int_arg)) {
				d_fprintf(stderr, "Could not get info for gid "
						"%d\n", int_arg);
				goto done;
			}
			break;
		case 'r':
			if (!wbinfo_get_usergroups(string_arg)) {
				d_fprintf(stderr,
					  "Could not get groups for user %s\n",
					  string_arg);
				goto done;
			}
			break;
		case OPT_USERSIDS:
			if (!wbinfo_get_usersids(string_arg)) {
				d_fprintf(stderr, "Could not get group SIDs "
					  "for user SID %s\n",
					  string_arg);
				goto done;
			}
			break;
		case OPT_USERDOMGROUPS:
			if (!wbinfo_get_userdomgroups(string_arg)) {
				d_fprintf(stderr, "Could not get user's domain "
					 "groups for user SID %s\n",
					 string_arg);
				goto done;
			}
			break;
		case OPT_SIDALIASES:
			if (!wbinfo_get_sidaliases(opt_domain_name,
						   string_arg)) {
				d_fprintf(stderr, "Could not get sid aliases "
					 "for user SID %s\n", string_arg);
				goto done;
			}
			break;
		case 'a': {
				bool got_error = false;

				if (!wbinfo_auth(string_arg)) {
					d_fprintf(stderr,
						  "Could not authenticate user "
						  "%s with plaintext "
						  "password\n", string_arg);
					got_error = true;
				}

				if (!wbinfo_auth_crap(string_arg, use_ntlmv2,
						      use_lanman)) {
					d_fprintf(stderr,
						"Could not authenticate user "
						"%s with challenge/response\n",
						string_arg);
					got_error = true;
				}

				if (got_error)
					goto done;
				break;
			}
		case OPT_PAM_LOGON:
			if (!wbinfo_pam_logon(string_arg, verbose)) {
				d_fprintf(stderr, "pam_logon failed for %s\n",
					  string_arg);
				goto done;
			}
			break;
		case OPT_LOGOFF:
		{
			wbcErr wbc_status;

			wbc_status = wbcLogoffUser(logoff_user, logoff_uid,
						   "");
			d_printf("Logoff %s (%d): %s\n", logoff_user,
				 logoff_uid, wbcErrorString(wbc_status));
			break;
		}
		case 'K': {
				uint32_t flags = WBFLAG_PAM_KRB5 |
						 WBFLAG_PAM_CACHED_LOGIN |
						WBFLAG_PAM_FALLBACK_AFTER_KRB5 |
						 WBFLAG_PAM_INFO3_TEXT |
						 WBFLAG_PAM_CONTACT_TRUSTDOM;

				if (!wbinfo_auth_krb5(string_arg, opt_krb5ccname,
						      flags)) {
					d_fprintf(stderr,
						"Could not authenticate user "
						"[%s] with Kerberos "
						"(ccache: %s)\n", string_arg,
						opt_krb5ccname);
					goto done;
				}
				break;
			}
		case 'k':
			if (!wbinfo_klog(string_arg)) {
				d_fprintf(stderr, "Could not klog user\n");
				goto done;
			}
			break;
		case 'p':
			if (!wbinfo_ping()) {
				d_fprintf(stderr, "could not ping winbindd!\n");
				goto done;
			}
			break;
		case OPT_SET_AUTH_USER:
			if (!wbinfo_set_auth_user(string_arg)) {
				goto done;
			}
			break;
		case OPT_GET_AUTH_USER:
			wbinfo_get_auth_user();
			goto done;
			break;
		case OPT_CCACHE_SAVE:
			if (!wbinfo_ccache_save(string_arg)) {
				goto done;
			}
			break;
		case OPT_GETDCNAME:
			if (!wbinfo_getdcname(string_arg)) {
				goto done;
			}
			break;
		case OPT_DSGETDCNAME:
			if (!wbinfo_dsgetdcname(string_arg, 0)) {
				goto done;
			}
			break;
		case OPT_DC_INFO:
			if (!wbinfo_dc_info(string_arg)) {
				goto done;
			}
			break;
		case OPT_SEPARATOR: {
			const char sep = winbind_separator();
			if ( !sep ) {
				goto done;
			}
			d_printf("%c\n", sep);
			break;
		}
		case OPT_LIST_ALL_DOMAINS:
			if (!wbinfo_list_domains(true, verbose)) {
				goto done;
			}
			break;
		case OPT_LIST_OWN_DOMAIN:
			if (!wbinfo_list_own_domain()) {
				goto done;
			}
			break;
		case OPT_CHANGE_USER_PASSWORD:
			if (!wbinfo_change_user_password(string_arg)) {
				d_fprintf(stderr,
					"Could not change user password "
					 "for user %s\n", string_arg);
				goto done;
			}
			break;

		/* generic configuration options */
		case OPT_DOMAIN_NAME:
		case OPT_VERBOSE:
		case OPT_NTLMV1:
		case OPT_NTLMV2:
		case OPT_LANMAN:
		case OPT_LOGOFF_USER:
		case OPT_LOGOFF_UID:
		case OPT_KRB5CCNAME:
			break;
		default:
			d_fprintf(stderr, "Invalid option\n");
			poptPrintHelp(pc, stderr, 0);
			goto done;
		}
	}

	result = 0;

	/* Exit code */

 done:
	talloc_free(frame);

	poptFreeContext(pc);
	return result;
}
