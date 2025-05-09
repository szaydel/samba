/*
   Samba Unix/Linux SMB client library
   net ads cldap functions
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2003 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2008 Guenther Deschner (gd@samba.org)
   Copyright (C) 2009 Stefan Metzmacher (metze@samba.org)

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

#ifndef _LIBADS_CLDAP_H_
#define _LIBADS_CLDAP_H_

#include "../libcli/netlogon/netlogon.h"

/* The following definitions come from libads/cldap.c  */

bool ads_cldap_netlogon_5(TALLOC_CTX *mem_ctx,
			  struct sockaddr_storage *ss,
			  const char *realm,
			  uint32_t required_flags,
			  struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply5);

#endif /* _LIBADS_CLDAP_H_ */
