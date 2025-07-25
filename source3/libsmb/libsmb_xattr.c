/*
   Unix SMB/Netbios implementation.
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000, 2002
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002
   Copyright (C) Derrell Lipman 2003-2008
   Copyright (C) Jeremy Allison 2007, 2008

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
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "source3/libsmb/cli_smb2_fnum.h"
#include "libsmbclient.h"
#include "libsmb_internal.h"
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "rpc_client/rpc_client.h"
#include "rpc_client/cli_lsarpc.h"
#include "../libcli/security/security.h"
#include "lib/util/string_wrappers.h"
#include "source3/include/trans2.h"

/*
 * Find an lsa pipe handle associated with a cli struct.
 */
static struct rpc_pipe_client *
find_lsa_pipe_hnd(struct cli_state *ipc_cli)
{
	struct rpc_pipe_client *pipe_hnd;

	for (pipe_hnd = ipc_cli->pipe_list;
             pipe_hnd;
             pipe_hnd = pipe_hnd->next) {
		struct dcerpc_binding_handle *bh = NULL;
		const struct dcerpc_binding *bd = NULL;
		struct ndr_syntax_id syntax;

		bh = pipe_hnd->binding_handle;
		bd = dcerpc_binding_handle_get_binding(bh);
		syntax = dcerpc_binding_get_abstract_syntax(bd);

		if (ndr_syntax_id_equal(&syntax,
					&ndr_table_lsarpc.syntax_id)) {
			return pipe_hnd;
		}
	}
	return NULL;
}

/*
 * Sort ACEs according to the documentation at
 * http://support.microsoft.com/kb/269175, at least as far as it defines the
 * order.
 */

static int
ace_compare(struct security_ace *ace1,
            struct security_ace *ace2)
{
        bool b1;
        bool b2;

        /* If the ACEs are equal, we have nothing more to do. */
        if (security_ace_equal(ace1, ace2)) {
		return 0;
        }

        /* Inherited follow non-inherited */
        b1 = ((ace1->flags & SEC_ACE_FLAG_INHERITED_ACE) != 0);
        b2 = ((ace2->flags & SEC_ACE_FLAG_INHERITED_ACE) != 0);
        if (b1 != b2) {
                return (b1 ? 1 : -1);
        }

        /*
         * What shall we do with AUDITs and ALARMs?  It's undefined.  We'll
         * sort them after DENY and ALLOW.
         */
        b1 = (ace1->type != SEC_ACE_TYPE_ACCESS_ALLOWED &&
              ace1->type != SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT &&
              ace1->type != SEC_ACE_TYPE_ACCESS_DENIED &&
              ace1->type != SEC_ACE_TYPE_ACCESS_DENIED_OBJECT);
        b2 = (ace2->type != SEC_ACE_TYPE_ACCESS_ALLOWED &&
              ace2->type != SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT &&
              ace2->type != SEC_ACE_TYPE_ACCESS_DENIED &&
              ace2->type != SEC_ACE_TYPE_ACCESS_DENIED_OBJECT);
        if (b1 != b2) {
                return (b1 ? 1 : -1);
        }

        /* Allowed ACEs follow denied ACEs */
        b1 = (ace1->type == SEC_ACE_TYPE_ACCESS_ALLOWED ||
              ace1->type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT);
        b2 = (ace2->type == SEC_ACE_TYPE_ACCESS_ALLOWED ||
              ace2->type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT);
        if (b1 != b2) {
                return (b1 ? 1 : -1);
        }

        /*
         * ACEs applying to an entity's object follow those applying to the
         * entity itself
         */
        b1 = (ace1->type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT ||
              ace1->type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT);
        b2 = (ace2->type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT ||
              ace2->type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT);
        if (b1 != b2) {
                return (b1 ? 1 : -1);
        }

        /*
         * If we get this far, the ACEs are similar as far as the
         * characteristics we typically care about (those defined by the
         * referenced MS document).  We'll now sort by characteristics that
         * just seems reasonable.
         */

	if (ace1->type != ace2->type) {
		/*
		 * ace2 and ace1 are reversed here, so that
		 * ACCESS_DENIED_ACE_TYPE (1) sorts before
		 * ACCESS_ALLOWED_ACE_TYPE (0), which is the order you
		 * usually want.
		 */
		return NUMERIC_CMP(ace2->type, ace1->type);
        }

	if (dom_sid_compare(&ace1->trustee, &ace2->trustee)) {
		return dom_sid_compare(&ace1->trustee, &ace2->trustee);
        }

	if (ace1->flags != ace2->flags) {
		return NUMERIC_CMP(ace1->flags, ace2->flags);
        }

	if (ace1->access_mask != ace2->access_mask) {
		return NUMERIC_CMP(ace1->access_mask, ace2->access_mask);
        }

	if (ace1->size != ace2->size) {
		return NUMERIC_CMP(ace1->size, ace2->size);
        }

	return memcmp(ace1, ace2, sizeof(struct security_ace));
}


static void
sort_acl(struct security_acl *the_acl)
{
	uint32_t i;
	if (!the_acl) return;

	TYPESAFE_QSORT(the_acl->aces, the_acl->num_aces, ace_compare);

	for (i=1;i<the_acl->num_aces;) {
		if (security_ace_equal(&the_acl->aces[i-1],
				       &the_acl->aces[i])) {
			ARRAY_DEL_ELEMENT(
				the_acl->aces, i, the_acl->num_aces);
			the_acl->num_aces--;
		} else {
			i++;
		}
	}
}

/* convert a SID to a string, either numeric or username/group */
static void
convert_sid_to_string(struct cli_state *ipc_cli,
                      struct policy_handle *pol,
                      fstring str,
                      bool numeric,
                      struct dom_sid *sid)
{
	char **domains = NULL;
	char **names = NULL;
	enum lsa_SidType *types = NULL;
	struct rpc_pipe_client *pipe_hnd = find_lsa_pipe_hnd(ipc_cli);
	TALLOC_CTX *ctx;

	sid_to_fstring(str, sid);

	if (numeric) {
		return;     /* no lookup desired */
	}

	if (!pipe_hnd) {
		return;
	}

	/* Ask LSA to convert the sid to a name */

	ctx = talloc_stackframe();

	if (!NT_STATUS_IS_OK(rpccli_lsa_lookup_sids(pipe_hnd, ctx,
                                                    pol, 1, sid, &domains,
                                                    &names, &types)) ||
	    !domains || !domains[0] || !names || !names[0]) {
		TALLOC_FREE(ctx);
		return;
	}

	/* Converted OK */

	fstr_sprintf(str, "%s%s%s",
		     domains[0], lp_winbind_separator(), names[0]);

	TALLOC_FREE(ctx);
}

/* convert a string to a SID, either numeric or username/group */
static bool
convert_string_to_sid(struct cli_state *ipc_cli,
                      struct policy_handle *pol,
                      bool numeric,
                      struct dom_sid *sid,
                      const char *str)
{
	enum lsa_SidType *types = NULL;
	struct dom_sid *sids = NULL;
	bool result = True;
	TALLOC_CTX *ctx = NULL;
	struct rpc_pipe_client *pipe_hnd = find_lsa_pipe_hnd(ipc_cli);

	if (!pipe_hnd) {
		return False;
	}

        if (numeric) {
                if (strncmp(str, "S-", 2) == 0) {
                        return string_to_sid(sid, str);
                }

                result = False;
                goto done;
        }

	ctx = talloc_stackframe();
	if (!NT_STATUS_IS_OK(rpccli_lsa_lookup_names(pipe_hnd, ctx,
                                                     pol, 1, &str,
                                                     NULL, 1, &sids,
                                                     &types))) {
		result = False;
		goto done;
	}

	sid_copy(sid, &sids[0]);
done:
	TALLOC_FREE(ctx);
	return result;
}


/* parse an struct security_ace in the same format as print_ace() */
static bool
parse_ace(struct cli_state *ipc_cli,
          struct policy_handle *pol,
          struct security_ace *ace,
          bool numeric,
          char *str)
{
	char *p;
	const char *cp;
	char *tok;
	unsigned int atype;
        unsigned int aflags;
        unsigned int amask;
	struct dom_sid sid;
	uint32_t mask;
        struct perm_value {
                const char perm[7];
                uint32_t mask;
        };
	size_t i;
	TALLOC_CTX *frame = talloc_stackframe();

        /* These values discovered by inspection */
        static const struct perm_value special_values[] = {
                { "R", 0x00120089 },
                { "W", 0x00120116 },
                { "X", 0x001200a0 },
                { "D", 0x00010000 },
                { "P", 0x00040000 },
                { "O", 0x00080000 },
        };

        static const struct perm_value standard_values[] = {
                { "READ",   0x001200a9 },
                { "CHANGE", 0x001301bf },
                { "FULL",   0x001f01ff },
        };

	ZERO_STRUCTP(ace);
	p = strchr_m(str,':');
	if (!p) {
		TALLOC_FREE(frame);
		return False;
	}
	*p = '\0';
	p++;
	/* Try to parse numeric form */

	if (sscanf(p, "%u/%u/%u", &atype, &aflags, &amask) == 3 &&
	    convert_string_to_sid(ipc_cli, pol, numeric, &sid, str)) {
		goto done;
	}

	/* Try to parse text form */

	if (!convert_string_to_sid(ipc_cli, pol, numeric, &sid, str)) {
		TALLOC_FREE(frame);
		return false;
	}

	cp = p;
	if (!next_token_talloc(frame, &cp, &tok, "/")) {
		TALLOC_FREE(frame);
		return false;
	}

	if (strnequal(tok, "ALLOWED", strlen("ALLOWED"))) {
		atype = SEC_ACE_TYPE_ACCESS_ALLOWED;
	} else if (strnequal(tok, "DENIED", strlen("DENIED"))) {
		atype = SEC_ACE_TYPE_ACCESS_DENIED;
	} else {
		TALLOC_FREE(frame);
		return false;
	}

	/* Only numeric form accepted for flags at present */

	if (!(next_token_talloc(frame, &cp, &tok, "/") &&
	      sscanf(tok, "%u", &aflags))) {
		TALLOC_FREE(frame);
		return false;
	}

	if (!next_token_talloc(frame, &cp, &tok, "/")) {
		TALLOC_FREE(frame);
		return false;
	}

	if (strncmp(tok, "0x", 2) == 0) {
		if (sscanf(tok, "%u", &amask) != 1) {
			TALLOC_FREE(frame);
			return false;
		}
		goto done;
	}

	for (i = 0; i < ARRAY_SIZE(standard_values); i++) {
		const struct perm_value *v = &standard_values[i];
		if (strcmp(tok, v->perm) == 0) {
			amask = v->mask;
			goto done;
		}
	}

	p = tok;

	while(*p) {
		bool found = False;

		for (i = 0; i < ARRAY_SIZE(special_values); i++) {
			const struct perm_value *v = &special_values[i];
			if (v->perm[0] == *p) {
				amask |= v->mask;
				found = True;
			}
		}

		if (!found) {
			TALLOC_FREE(frame);
		 	return false;
		}
		p++;
	}

	if (*p) {
		TALLOC_FREE(frame);
		return false;
	}

done:
	mask = amask;
	init_sec_ace(ace, &sid, atype, mask, aflags);
	TALLOC_FREE(frame);
	return true;
}

/* add an struct security_ace to a list of struct security_aces in a struct security_acl */
static bool
add_ace(struct security_acl **the_acl,
        const struct security_ace *ace,
        TALLOC_CTX *ctx)
{
	struct security_acl *acl = *the_acl;

	if (acl == NULL) {
		acl = make_sec_acl(ctx, 3, 0, NULL);
		if (acl == NULL) {
			return false;
		}
	}

	if (acl->num_aces == UINT32_MAX) {
		return false;
	}
	ADD_TO_ARRAY(
		acl, struct security_ace, *ace, &acl->aces, &acl->num_aces);
	*the_acl = acl;
	return True;
}


/* parse a ascii version of a security descriptor */
static struct security_descriptor *
sec_desc_parse(TALLOC_CTX *ctx,
               struct cli_state *ipc_cli,
               struct policy_handle *pol,
               bool numeric,
               const char *str)
{
	const char *p = str;
	char *tok;
	struct security_descriptor *ret = NULL;
	size_t sd_size;
	struct dom_sid owner_sid = { .num_auths = 0 };
	struct dom_sid group_sid = { .num_auths = 0 };
	bool have_owner = false, have_group = false;
	struct security_acl *dacl=NULL;
	int revision=1;

	while (next_token_talloc(ctx, &p, &tok, "\t,\r\n")) {

		if (strnequal(tok, "REVISION:", 9)) {
			revision = strtol(tok+9, NULL, 16);
			continue;
		}

		if (strnequal(tok, "OWNER:", 6)) {
			if (have_owner) {
				DEBUG(5,("OWNER specified more than once!\n"));
				goto done;
			}
			if (!convert_string_to_sid(ipc_cli, pol,
                                                   numeric,
                                                   &owner_sid, tok+6)) {
				DEBUG(5, ("Failed to parse owner sid\n"));
				goto done;
			}
			have_owner = true;
			continue;
		}

		if (strnequal(tok, "OWNER+:", 7)) {
			if (have_owner) {
				DEBUG(5,("OWNER specified more than once!\n"));
				goto done;
			}
			if (!convert_string_to_sid(ipc_cli, pol,
                                                   False,
                                                   &owner_sid, tok+7)) {
				DEBUG(5, ("Failed to parse owner sid\n"));
				goto done;
			}
			have_owner = true;
			continue;
		}

		if (strnequal(tok, "GROUP:", 6)) {
			if (have_group) {
				DEBUG(5,("GROUP specified more than once!\n"));
				goto done;
			}
			if (!convert_string_to_sid(ipc_cli, pol,
                                                   numeric,
                                                   &group_sid, tok+6)) {
				DEBUG(5, ("Failed to parse group sid\n"));
				goto done;
			}
			have_group = true;
			continue;
		}

		if (strnequal(tok, "GROUP+:", 7)) {
			if (have_group) {
				DEBUG(5,("GROUP specified more than once!\n"));
				goto done;
			}
			if (!convert_string_to_sid(ipc_cli, pol,
                                                   False,
                                                   &group_sid, tok+6)) {
				DEBUG(5, ("Failed to parse group sid\n"));
				goto done;
			}
			have_group = true;
			continue;
		}

		if (strnequal(tok, "ACL:", 4)) {
			struct security_ace ace;
			if (!parse_ace(ipc_cli, pol, &ace, numeric, tok+4)) {
				DEBUG(5, ("Failed to parse ACL %s\n", tok));
				goto done;
			}
			if(!add_ace(&dacl, &ace, ctx)) {
				DEBUG(5, ("Failed to add ACL %s\n", tok));
				goto done;
			}
			continue;
		}

		if (strnequal(tok, "ACL+:", 5)) {
			struct security_ace ace;
			if (!parse_ace(ipc_cli, pol, &ace, False, tok+5)) {
				DEBUG(5, ("Failed to parse ACL %s\n", tok));
				goto done;
			}
			if(!add_ace(&dacl, &ace, ctx)) {
				DEBUG(5, ("Failed to add ACL %s\n", tok));
				goto done;
			}
			continue;
		}

		DEBUG(5, ("Failed to parse security descriptor\n"));
		goto done;
	}

	ret = make_sec_desc(
		ctx,
		revision,
		SEC_DESC_SELF_RELATIVE,
		have_owner ? &owner_sid : NULL,
		have_group ? &group_sid : NULL,
		NULL,
		dacl,
		&sd_size);

done:
	return ret;
}


/* Obtain the current dos attributes */
static struct DOS_ATTR_DESC *
dos_attr_query(SMBCCTX *context,
               TALLOC_CTX *ctx,
               const char *filename,
               SMBCSRV *srv)
{
	struct stat sb = {0};
        struct DOS_ATTR_DESC *ret = NULL;
	NTSTATUS status;

        ret = talloc(ctx, struct DOS_ATTR_DESC);
        if (!ret) {
                errno = ENOMEM;
                return NULL;
        }

        /* Obtain the DOS attributes */
	status = SMBC_getatr(context, srv, filename, &sb);
	if (!NT_STATUS_IS_OK(status)) {
                DEBUG(5, ("dos_attr_query Failed to query old attributes\n"));
		TALLOC_FREE(ret);
                errno = cli_status_to_errno(status);
                return NULL;
        }

        ret->mode = sb.st_mode;
        ret->size = sb.st_size;
        ret->create_time = sb.st_ctime;
        ret->access_time = sb.st_atime;
        ret->write_time = sb.st_mtime;
        ret->change_time = sb.st_mtime;
        ret->inode = sb.st_ino;

        return ret;
}


/* parse a ascii version of a security descriptor */
static void
dos_attr_parse(SMBCCTX *context,
               struct DOS_ATTR_DESC *dad,
               SMBCSRV *srv,
               char *str)
{
        int n;
        const char *p = str;
	char *tok = NULL;
	TALLOC_CTX *frame = NULL;
        struct {
                const char * create_time_attr;
                const char * access_time_attr;
                const char * write_time_attr;
                const char * change_time_attr;
        } attr_strings;

        /* Determine whether to use old-style or new-style attribute names */
        if (context->internal->full_time_names) {
                /* new-style names */
                attr_strings.create_time_attr = "CREATE_TIME";
                attr_strings.access_time_attr = "ACCESS_TIME";
                attr_strings.write_time_attr = "WRITE_TIME";
                attr_strings.change_time_attr = "CHANGE_TIME";
        } else {
                /* old-style names */
                attr_strings.create_time_attr = NULL;
                attr_strings.access_time_attr = "A_TIME";
                attr_strings.write_time_attr = "M_TIME";
                attr_strings.change_time_attr = "C_TIME";
        }

        /* if this is to set the entire ACL... */
        if (*str == '*') {
                /* ... then increment past the first colon if there is one */
                if ((p = strchr(str, ':')) != NULL) {
                        ++p;
                } else {
                        p = str;
                }
        }

	frame = talloc_stackframe();
	while (next_token_talloc(frame, &p, &tok, "\t,\r\n")) {
		if (strnequal(tok, "MODE:", 5)) {
                        long request = strtol(tok+5, NULL, 16);
                        if (request == 0) {
				dad->mode =
					(dad->mode & FILE_ATTRIBUTE_DIRECTORY)
						? FILE_ATTRIBUTE_DIRECTORY
						: FILE_ATTRIBUTE_NORMAL;
			} else {
                                dad->mode = request;
                        }
			continue;
		}

		if (strnequal(tok, "SIZE:", 5)) {
                        dad->size = (off_t)atof(tok+5);
			continue;
		}

                n = strlen(attr_strings.access_time_attr);
                if (strnequal(tok, attr_strings.access_time_attr, n)) {
                        dad->access_time = (time_t)strtol(tok+n+1, NULL, 10);
			continue;
		}

                n = strlen(attr_strings.change_time_attr);
                if (strnequal(tok, attr_strings.change_time_attr, n)) {
                        dad->change_time = (time_t)strtol(tok+n+1, NULL, 10);
			continue;
		}

                n = strlen(attr_strings.write_time_attr);
                if (strnequal(tok, attr_strings.write_time_attr, n)) {
                        dad->write_time = (time_t)strtol(tok+n+1, NULL, 10);
			continue;
		}

		if (attr_strings.create_time_attr != NULL) {
			n = strlen(attr_strings.create_time_attr);
			if (strnequal(tok, attr_strings.create_time_attr, n)) {
				dad->create_time = (time_t)strtol(tok+n+1,
								  NULL, 10);
				continue;
			}
		}

		if (strnequal(tok, "INODE:", 6)) {
                        dad->inode = (SMB_INO_T)atof(tok+6);
			continue;
		}
	}
	TALLOC_FREE(frame);
}

/*****************************************************
 Retrieve the acls for a file.
*******************************************************/

static int
cacl_get(SMBCCTX *context,
         TALLOC_CTX *ctx,
         SMBCSRV *srv,
         struct cli_state *ipc_cli,
         struct policy_handle *pol,
         const char *filename,
         const char *attr_name,
         char *buf,
         int bufsize)
{
	uint32_t i;
        int n = 0;
        int n_used;
        bool all;
        bool all_nt;
        bool all_nt_acls;
        bool all_dos;
        bool some_nt;
        bool some_dos;
        bool exclude_nt_revision = False;
        bool exclude_nt_owner = False;
        bool exclude_nt_group = False;
        bool exclude_nt_acl = False;
        bool exclude_dos_mode = False;
        bool exclude_dos_size = False;
        bool exclude_dos_create_time = False;
        bool exclude_dos_access_time = False;
        bool exclude_dos_write_time = False;
        bool exclude_dos_change_time = False;
        bool exclude_dos_inode = False;
        bool numeric = True;
        bool determine_size = (bufsize == 0);
	uint16_t fnum;
	struct security_descriptor *sd;
	fstring sidstr;
        fstring name_sandbox;
        char *name;
        char *pExclude;
        char *p;
	struct cli_state *cli = srv->cli;
        struct {
                const char * create_time_attr;
                const char * access_time_attr;
                const char * write_time_attr;
                const char * change_time_attr;
        } attr_strings;
        struct {
                const char * create_time_attr;
                const char * access_time_attr;
                const char * write_time_attr;
                const char * change_time_attr;
        } excl_attr_strings;

        /* Determine whether to use old-style or new-style attribute names */
        if (context->internal->full_time_names) {
                /* new-style names */
                attr_strings.create_time_attr = "CREATE_TIME";
                attr_strings.access_time_attr = "ACCESS_TIME";
                attr_strings.write_time_attr = "WRITE_TIME";
                attr_strings.change_time_attr = "CHANGE_TIME";

                excl_attr_strings.create_time_attr = "CREATE_TIME";
                excl_attr_strings.access_time_attr = "ACCESS_TIME";
                excl_attr_strings.write_time_attr = "WRITE_TIME";
                excl_attr_strings.change_time_attr = "CHANGE_TIME";
        } else {
                /* old-style names */
                attr_strings.create_time_attr = NULL;
                attr_strings.access_time_attr = "A_TIME";
                attr_strings.write_time_attr = "M_TIME";
                attr_strings.change_time_attr = "C_TIME";

                excl_attr_strings.create_time_attr = NULL;
                excl_attr_strings.access_time_attr = "dos_attr.A_TIME";
                excl_attr_strings.write_time_attr = "dos_attr.M_TIME";
                excl_attr_strings.change_time_attr = "dos_attr.C_TIME";
        }

        /* Copy name so we can strip off exclusions (if any are specified) */
        fstrcpy(name_sandbox, attr_name);

        /* Ensure name is null terminated */
        name_sandbox[sizeof(name_sandbox) - 1] = '\0';

        /* Play in the sandbox */
        name = name_sandbox;

        /* If there are any exclusions, point to them and mask them from name */
        if ((pExclude = strchr(name, '!')) != NULL)
        {
                *pExclude++ = '\0';
        }

        all = (strnequal(name, "system.*", 8));
        all_nt = (strnequal(name, "system.nt_sec_desc.*", 20));
        all_nt_acls = (strnequal(name, "system.nt_sec_desc.acl.*", 24));
        all_dos = (strnequal(name, "system.dos_attr.*", 17));
        some_nt = (strnequal(name, "system.nt_sec_desc.", 19));
        some_dos = (strnequal(name, "system.dos_attr.", 16));
        numeric = (* (name + strlen(name) - 1) != '+');

        /* Look for exclusions from "all" requests */
        if (all || all_nt || all_dos) {
                /* Exclusions are delimited by '!' */
                for (;
                     pExclude != NULL;
                     pExclude = (p == NULL ? NULL : p + 1)) {

                        /* Find end of this exclusion name */
                        if ((p = strchr(pExclude, '!')) != NULL)
                        {
                                *p = '\0';
                        }

                        /* Which exclusion name is this? */
			if (strequal(pExclude, "nt_sec_desc.revision")) {
				exclude_nt_revision = True;
			} else if (strequal(pExclude, "nt_sec_desc.owner")) {
				exclude_nt_owner = True;
			} else if (strequal(pExclude, "nt_sec_desc.group")) {
				exclude_nt_group = True;
			} else if (strequal(pExclude, "nt_sec_desc.acl")) {
				exclude_nt_acl = True;
			} else if (strequal(pExclude, "dos_attr.mode")) {
				exclude_dos_mode = True;
			} else if (strequal(pExclude, "dos_attr.size")) {
				exclude_dos_size = True;
			} else if (excl_attr_strings.create_time_attr != NULL &&
				   strequal(pExclude,
					    excl_attr_strings.change_time_attr))
			{
				exclude_dos_create_time = True;
			} else if (strequal(pExclude,
					    excl_attr_strings.access_time_attr))
			{
				exclude_dos_access_time = True;
			} else if (strequal(pExclude,
					    excl_attr_strings.write_time_attr))
			{
				exclude_dos_write_time = True;
			} else if (strequal(pExclude,
					    excl_attr_strings.change_time_attr))
			{
				exclude_dos_change_time = True;
			} else if (strequal(pExclude, "dos_attr.inode")) {
				exclude_dos_inode = True;
			} else {
				DEBUG(5, ("cacl_get received unknown exclusion: %s\n",
                                          pExclude));
                                errno = ENOATTR;
                                return -1;
                        }
                }
        }

        n_used = 0;

        /*
         * If we are (possibly) talking to an NT or new system and some NT
         * attributes have been requested...
         */
        if (ipc_cli && (all || some_nt || all_nt_acls)) {
		char *targetpath = NULL;
	        struct cli_state *targetcli = NULL;
		struct cli_credentials *creds = NULL;
		NTSTATUS status;

                /* Point to the portion after "system.nt_sec_desc." */
                name += 19;     /* if (all) this will be invalid but unused */

		creds = context->internal->creds;

		status = cli_resolve_path(
			ctx, "",
			creds,
			cli, filename, &targetcli, &targetpath);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("cacl_get Could not resolve %s\n",
				filename));
                        errno = ENOENT;
                        return -1;
		}

                /* ... then obtain any NT attributes which were requested */
		status = cli_ntcreate(
			targetcli,		/* cli */
			targetpath,		/* fname */
			0,			/* CreatFlags */
			READ_CONTROL_ACCESS,	/* DesiredAccess */
			0,			/* FileAttributes */
			FILE_SHARE_READ|
			FILE_SHARE_WRITE,	/* ShareAccess */
			FILE_OPEN,		/* CreateDisposition */
			0x0,			/* CreateOptions */
			0x0,			/* SecurityFlags */
			&fnum,			/* pfid */
			NULL);			/* cr */
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("cacl_get failed to open %s: %s\n",
				  targetpath, nt_errstr(status)));
			errno = cli_status_to_errno(status);
			return -1;
		}

		status = cli_query_secdesc(targetcli, fnum, ctx, &sd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5,("cacl_get Failed to query old descriptor "
				 "of %s: %s\n",
				  targetpath, nt_errstr(status)));
			errno = cli_status_to_errno(status);
			return -1;
		}

                cli_close(targetcli, fnum);

                if (! exclude_nt_revision) {
                        if (all || all_nt) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx,
                                                            "REVISION:%d",
                                                            sd->revision);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "REVISION:%d",
                                                     sd->revision);
                                }
                        } else if (strequal(name, "revision")) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "%d",
                                                            sd->revision);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize, "%d",
                                                     sd->revision);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_nt_owner) {
                        /* Get owner and group sid */
                        if (sd->owner_sid) {
                                convert_sid_to_string(ipc_cli, pol,
                                                      sidstr,
                                                      numeric,
                                                      sd->owner_sid);
                        } else {
                                fstrcpy(sidstr, "");
                        }

                        if (all || all_nt) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, ",OWNER:%s",
                                                            sidstr);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else if (sidstr[0] != '\0') {
                                        n = snprintf(buf, bufsize,
                                                     ",OWNER:%s", sidstr);
                                }
                        } else if (strnequal(name, "owner", 5)) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "%s", sidstr);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize, "%s",
                                                     sidstr);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_nt_group) {
                        if (sd->group_sid) {
                                convert_sid_to_string(ipc_cli, pol,
                                                      sidstr, numeric,
                                                      sd->group_sid);
                        } else {
                                fstrcpy(sidstr, "");
                        }

                        if (all || all_nt) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, ",GROUP:%s",
                                                            sidstr);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else if (sidstr[0] != '\0') {
                                        n = snprintf(buf, bufsize,
                                                     ",GROUP:%s", sidstr);
                                }
                        } else if (strnequal(name, "group", 5)) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "%s", sidstr);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%s", sidstr);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_nt_acl) {
                        /* Add aces to value buffer  */
                        for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {

                                struct security_ace *ace = &sd->dacl->aces[i];
                                convert_sid_to_string(ipc_cli, pol,
                                                      sidstr, numeric,
                                                      &ace->trustee);

                                if (all || all_nt) {
                                        if (determine_size) {
                                                p = talloc_asprintf(
                                                        ctx,
                                                        ",ACL:"
                                                        "%s:%d/%d/0x%08x",
                                                        sidstr,
                                                        ace->type,
                                                        ace->flags,
                                                        ace->access_mask);
                                                if (!p) {
                                                        errno = ENOMEM;
                                                        return -1;
                                                }
                                                n = strlen(p);
                                        } else {
                                                n = snprintf(
                                                        buf, bufsize,
                                                        ",ACL:%s:%d/%d/0x%08x",
                                                        sidstr,
                                                        ace->type,
                                                        ace->flags,
                                                        ace->access_mask);
                                        }
                                } else if ((strnequal(name, "acl", 3) &&
                                            strequal(name+3, sidstr)) ||
                                           (strnequal(name, "acl+", 4) &&
                                            strequal(name+4, sidstr))) {
                                        if (determine_size) {
                                                p = talloc_asprintf(
                                                        ctx,
                                                        "%d/%d/0x%08x",
                                                        ace->type,
                                                        ace->flags,
                                                        ace->access_mask);
                                                if (!p) {
                                                        errno = ENOMEM;
                                                        return -1;
                                                }
                                                n = strlen(p);
                                        } else {
                                                n = snprintf(buf, bufsize,
                                                             "%d/%d/0x%08x",
                                                             ace->type,
                                                             ace->flags,
                                                             ace->access_mask);
                                        }
                                } else if (all_nt_acls) {
                                        if (determine_size) {
                                                p = talloc_asprintf(
                                                        ctx,
                                                        "%s%s:%d/%d/0x%08x",
                                                        i ? "," : "",
                                                        sidstr,
                                                        ace->type,
                                                        ace->flags,
                                                        ace->access_mask);
                                                if (!p) {
                                                        errno = ENOMEM;
                                                        return -1;
                                                }
                                                n = strlen(p);
                                        } else {
                                                n = snprintf(buf, bufsize,
                                                             "%s%s:%d/%d/0x%08x",
                                                             i ? "," : "",
                                                             sidstr,
                                                             ace->type,
                                                             ace->flags,
                                                             ace->access_mask);
                                        }
                                }
                                if (!determine_size && n > bufsize) {
                                        errno = ERANGE;
                                        return -1;
                                }
                                buf += n;
                                n_used += n;
                                bufsize -= n;
                                n = 0;
                        }
                }

                /* Restore name pointer to its original value */
                name -= 19;
        }

        if (all || some_dos) {
		struct stat sb = {0};
		time_t create_time = (time_t)0;
		time_t write_time = (time_t)0;
		time_t access_time = (time_t)0;
		time_t change_time = (time_t)0;
		off_t size = 0;
		uint16_t mode = 0;
		SMB_INO_T ino = 0;
		NTSTATUS status;

                /* Point to the portion after "system.dos_attr." */
                name += 16;     /* if (all) this will be invalid but unused */

                /* Obtain the DOS attributes */
		status = SMBC_getatr(context, srv, filename, &sb);
		if (!NT_STATUS_IS_OK(status)) {
                        errno = cli_status_to_errno(status);
                        return -1;
                }

		create_time = sb.st_ctime;
		access_time = sb.st_atime;
		write_time  = sb.st_mtime;
		change_time = sb.st_mtime;
		size        = sb.st_size;
		mode        = sb.st_mode;
		ino         = sb.st_ino;

                if (! exclude_dos_mode) {
                        if (all || all_dos) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx,
                                                            "%sMODE:0x%x",
                                                            (ipc_cli &&
                                                             (all || some_nt)
                                                             ? ","
                                                             : ""),
                                                            mode);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%sMODE:0x%x",
                                                     (ipc_cli &&
                                                      (all || some_nt)
                                                      ? ","
                                                      : ""),
                                                     mode);
                                }
                        } else if (strequal(name, "mode")) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "0x%x", mode);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "0x%x", mode);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_dos_size) {
                        if (all || all_dos) {
                                if (determine_size) {
                                        p = talloc_asprintf(
                                                ctx,
                                                ",SIZE:%.0f",
                                                (double)size);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     ",SIZE:%.0f",
                                                     (double)size);
                                }
                        } else if (strequal(name, "size")) {
                                if (determine_size) {
                                        p = talloc_asprintf(
                                                ctx,
                                                "%.0f",
                                                (double)size);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%.0f",
                                                     (double)size);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_dos_create_time &&
                    attr_strings.create_time_attr != NULL) {
                        if (all || all_dos) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx,
                                                            ",%s:%lu",
                                                            attr_strings.create_time_attr,
                                                            (unsigned long) create_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     ",%s:%lu",
                                                     attr_strings.create_time_attr,
                                                     (unsigned long) create_time);
                                }
			} else if (strequal(name,
					    attr_strings.create_time_attr))
			{
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "%lu", (unsigned long) create_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%lu", (unsigned long) create_time);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_dos_access_time) {
                        if (all || all_dos) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx,
                                                            ",%s:%lu",
                                                            attr_strings.access_time_attr,
                                                            (unsigned long) access_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     ",%s:%lu",
                                                     attr_strings.access_time_attr,
                                                     (unsigned long) access_time);
                                }
			} else if (strequal(name,
					    attr_strings.access_time_attr))
			{
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "%lu", (unsigned long) access_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%lu", (unsigned long) access_time);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_dos_write_time) {
                        if (all || all_dos) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx,
                                                            ",%s:%lu",
                                                            attr_strings.write_time_attr,
                                                            (unsigned long) write_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     ",%s:%lu",
                                                     attr_strings.write_time_attr,
                                                     (unsigned long) write_time);
                                }
			} else if (strequal(name, attr_strings.write_time_attr))
			{
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "%lu", (unsigned long) write_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%lu", (unsigned long) write_time);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_dos_change_time) {
                        if (all || all_dos) {
                                if (determine_size) {
                                        p = talloc_asprintf(ctx,
                                                            ",%s:%lu",
                                                            attr_strings.change_time_attr,
                                                            (unsigned long) change_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     ",%s:%lu",
                                                     attr_strings.change_time_attr,
                                                     (unsigned long) change_time);
                                }
			} else if (strequal(name,
					    attr_strings.change_time_attr))
			{
                                if (determine_size) {
                                        p = talloc_asprintf(ctx, "%lu", (unsigned long) change_time);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%lu", (unsigned long) change_time);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                if (! exclude_dos_inode) {
                        if (all || all_dos) {
                                if (determine_size) {
                                        p = talloc_asprintf(
                                                ctx,
                                                ",INODE:%.0f",
                                                (double)ino);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     ",INODE:%.0f",
                                                     (double) ino);
                                }
                        } else if (strequal(name, "inode")) {
                                if (determine_size) {
                                        p = talloc_asprintf(
                                                ctx,
                                                "%.0f",
                                                (double) ino);
                                        if (!p) {
                                                errno = ENOMEM;
                                                return -1;
                                        }
                                        n = strlen(p);
                                } else {
                                        n = snprintf(buf, bufsize,
                                                     "%.0f",
                                                     (double) ino);
                                }
                        }

                        if (!determine_size && n > bufsize) {
                                errno = ERANGE;
                                return -1;
                        }
                        buf += n;
                        n_used += n;
                        bufsize -= n;
                        n = 0;
                }

                /* Restore name pointer to its original value */
                name -= 16;
        }

        if (n_used == 0) {
                errno = ENOATTR;
                return -1;
        }

	return n_used;
}

/*****************************************************
set the ACLs on a file given an ascii description
*******************************************************/
static int
cacl_set(SMBCCTX *context,
	TALLOC_CTX *ctx,
	struct cli_state *cli,
	struct cli_state *ipc_cli,
	struct policy_handle *pol,
	const char *filename,
	char *the_acl,
	int mode,
	int flags)
{
	uint16_t fnum = (uint16_t)-1;
        int err = 0;
	struct security_descriptor *sd = NULL, *old;
        struct security_acl *dacl = NULL;
	struct dom_sid *owner_sid = NULL;
	struct dom_sid *group_sid = NULL;
	uint32_t i, j;
	size_t sd_size;
	int ret = 0;
        char *p;
        bool numeric = True;
	char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	struct cli_credentials *creds = NULL;
	NTSTATUS status;

        /* the_acl will be null for REMOVE_ALL operations */
        if (the_acl) {
                numeric = ((p = strchr(the_acl, ':')) != NULL &&
                           p > the_acl &&
                           p[-1] != '+');

                /* if this is to set the entire ACL... */
                if (*the_acl == '*') {
                        /* ... then increment past the first colon */
                        the_acl = p + 1;
                }

                sd = sec_desc_parse(ctx, ipc_cli, pol, numeric, the_acl);
                if (!sd) {
			errno = EINVAL;
			return -1;
                }
        }

	/* SMBC_XATTR_MODE_REMOVE_ALL is the only caller
	   that doesn't deref sd */

	if (!sd && (mode != SMBC_XATTR_MODE_REMOVE_ALL)) {
		errno = EINVAL;
		return -1;
	}

	creds = context->internal->creds;

	status = cli_resolve_path(ctx, "",
				  creds,
				  cli, filename, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("cacl_set: Could not resolve %s\n", filename));
		errno = ENOENT;
		return -1;
	}

	/* The desired access below is the only one I could find that works
	   with NT4, W2KP and Samba */

	status = cli_ntcreate(
		targetcli,		/* cli */
		targetpath,		/* fname */
		0,			/* CreatFlags */
		READ_CONTROL_ACCESS,	/* DesiredAccess */
		0,			/* FileAttributes */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE,	/* ShareAccess */
		FILE_OPEN,		/* CreateDisposition */
		0x0,			/* CreateOptions */
		0x0,			/* SecurityFlags */
		&fnum,			/* pfid */
		NULL);			/* cr */
	if (!NT_STATUS_IS_OK(status)) {
                DEBUG(5, ("cacl_set failed to open %s: %s\n",
                          targetpath, nt_errstr(status)));
                errno = 0;
		return -1;
	}

	status = cli_query_secdesc(targetcli, fnum, ctx, &old);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("cacl_set Failed to query old descriptor of %s: %s\n",
			 targetpath, nt_errstr(status)));
		errno = 0;
		return -1;
	}

	cli_close(targetcli, fnum);

	switch (mode) {
	case SMBC_XATTR_MODE_REMOVE_ALL:
                old->dacl->num_aces = 0;
                dacl = old->dacl;
                break;

        case SMBC_XATTR_MODE_REMOVE:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			bool found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
                                if (security_ace_equal(&sd->dacl->aces[i],
						       &old->dacl->aces[j])) {
					uint32_t k;
					for (k=j; k<old->dacl->num_aces-1;k++) {
						old->dacl->aces[k] =
                                                        old->dacl->aces[k+1];
					}
					old->dacl->num_aces--;
					found = True;
                                        dacl = old->dacl;
					break;
				}
			}

			if (!found) {
                                err = ENOATTR;
                                ret = -1;
                                goto failed;
			}
		}
		break;

	case SMBC_XATTR_MODE_ADD:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			bool found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (dom_sid_equal(&sd->dacl->aces[i].trustee,
					      &old->dacl->aces[j].trustee)) {
                                        if (!(flags & SMBC_XATTR_FLAG_CREATE)) {
                                                err = EEXIST;
                                                ret = -1;
                                                goto failed;
                                        }
                                        old->dacl->aces[j] = sd->dacl->aces[i];
                                        ret = -1;
					found = True;
				}
			}

			if (!found && (flags & SMBC_XATTR_FLAG_REPLACE)) {
                                err = ENOATTR;
                                ret = -1;
                                goto failed;
			}

                        for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
                                add_ace(&old->dacl, &sd->dacl->aces[i], ctx);
                        }
		}
                dacl = old->dacl;
		break;

	case SMBC_XATTR_MODE_SET:
 		old = sd;
                owner_sid = old->owner_sid;
                group_sid = old->group_sid;
                dacl = old->dacl;
		break;

        case SMBC_XATTR_MODE_CHOWN:
                owner_sid = sd->owner_sid;
                break;

        case SMBC_XATTR_MODE_CHGRP:
                group_sid = sd->group_sid;
                break;
	}

	/* Denied ACE entries must come before allowed ones */
	sort_acl(old->dacl);

	/* Create new security descriptor and set it */
	sd = make_sec_desc(ctx, old->revision, SEC_DESC_SELF_RELATIVE,
			   owner_sid, group_sid, NULL, dacl, &sd_size);

	status = cli_ntcreate(targetcli, targetpath, 0,
			      WRITE_DAC_ACCESS | WRITE_OWNER_ACCESS, 0,
			      FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN,
			      0x0, 0x0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("cacl_set failed to open %s: %s\n",
                          targetpath, nt_errstr(status)));
                errno = 0;
		return -1;
	}

	status = cli_set_secdesc(targetcli, fnum, sd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("ERROR: secdesc set failed: %s\n",
			  nt_errstr(status)));
		ret = -1;
	}

	/* Clean up */

failed:
	cli_close(targetcli, fnum);

        if (err != 0) {
                errno = err;
        }

	return ret;
}


int
SMBC_setxattr_ctx(SMBCCTX *context,
                  const char *fname,
                  const char *name,
                  const void *value,
                  size_t size,
                  int flags)
{
        int ret;
        int ret2;
        SMBCSRV *srv = NULL;
        SMBCSRV *ipc_srv = NULL;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *workgroup = NULL;
	char *path = NULL;
        struct DOS_ATTR_DESC *dad = NULL;
        struct {
                const char * create_time_attr;
                const char * access_time_attr;
                const char * write_time_attr;
                const char * change_time_attr;
        } attr_strings;
	uint16_t port = 0;
        TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		TALLOC_FREE(frame);
		errno = EINVAL;  /* Best I can think of ... */
		return -1;
	}

	if (!fname) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}

	DEBUG(4, ("smbc_setxattr(%s, %s, %.*s)\n",
                  fname, name, (int) size, (const char*)value));

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return -1;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);
	if (!srv) {
		TALLOC_FREE(frame);
		return -1;  /* errno set by SMBC_server */
	}

        if (! srv->no_nt_session) {
                ipc_srv = SMBC_attr_server(frame, context, server, port, share,
                                           &workgroup, &user, &password);
                if (! ipc_srv) {
                        srv->no_nt_session = True;
                }
        } else {
                ipc_srv = NULL;
        }

        /*
         * Are they asking to set the entire set of known attributes?
         */
	if (strequal(name, "system.*") || strequal(name, "system.*+")) {
                /* Yup. */
                char *namevalue =
                        talloc_asprintf(talloc_tos(), "%s:%s",
                                        name+7, (const char *) value);
                if (! namevalue) {
                        ret = -1;
			TALLOC_FREE(frame);
                        errno = ENOMEM;
                        return -1;
                }

                if (ipc_srv) {
                        ret = cacl_set(context, talloc_tos(), srv->cli,
                                       ipc_srv->cli, &ipc_srv->pol, path,
                                       namevalue,
                                       (*namevalue == '*'
                                        ? SMBC_XATTR_MODE_SET
                                        : SMBC_XATTR_MODE_ADD),
                                       flags);
                } else {
                        ret = 0;
                }

                /* get a DOS Attribute Descriptor with current attributes */
                dad = dos_attr_query(context, talloc_tos(), path, srv);
                if (dad) {
			bool ok;

                        /* Overwrite old with new, using what was provided */
                        dos_attr_parse(context, dad, srv, namevalue);

                        /* Set the new DOS attributes */
			ok = SMBC_setatr(
				context,
				srv,
				path,
				(struct timespec) {
					.tv_sec = dad->create_time },
				(struct timespec) {
					.tv_sec = dad->access_time },
				(struct timespec) {
					.tv_sec = dad->write_time },
				(struct timespec) {
					.tv_sec = dad->change_time },
				dad->mode);
			if (!ok) {
                                /* cause failure if NT failed too */
                                dad = NULL;
                        }
                }

                /* we only fail if both NT and DOS sets failed */
                if (ret < 0 && ! dad) {
                        ret = -1; /* in case dad was null */
                }
                else {
                        ret = 0;
                }

		TALLOC_FREE(frame);
                return ret;
        }

        /*
         * Are they asking to set an access control element or to set
         * the entire access control list?
         */
	if (strequal(name, "system.nt_sec_desc.*") ||
	    strequal(name, "system.nt_sec_desc.*+") ||
	    strequal(name, "system.nt_sec_desc.revision") ||
	    strnequal(name, "system.nt_sec_desc.acl", 22) ||
	    strnequal(name, "system.nt_sec_desc.acl+", 23))
	{

                /* Yup. */
                char *namevalue =
                        talloc_asprintf(talloc_tos(), "%s:%s",
                                        name+19, (const char *) value);

                if (! ipc_srv) {
                        ret = -1; /* errno set by SMBC_server() */
                }
                else if (! namevalue) {
                        errno = ENOMEM;
                        ret = -1;
                } else {
                        ret = cacl_set(context, talloc_tos(), srv->cli,
                                       ipc_srv->cli, &ipc_srv->pol, path,
                                       namevalue,
                                       (*namevalue == '*'
                                        ? SMBC_XATTR_MODE_SET
                                        : SMBC_XATTR_MODE_ADD),
                                       flags);
                }
		TALLOC_FREE(frame);
                return ret;
        }

        /*
         * Are they asking to set the owner?
         */
	if (strequal(name, "system.nt_sec_desc.owner") ||
	    strequal(name, "system.nt_sec_desc.owner+"))
	{

                /* Yup. */
                char *namevalue =
                        talloc_asprintf(talloc_tos(), "%s:%s",
                                        name+19, (const char *) value);

                if (! ipc_srv) {
                        ret = -1; /* errno set by SMBC_server() */
                }
                else if (! namevalue) {
                        errno = ENOMEM;
                        ret = -1;
                } else {
                        ret = cacl_set(context, talloc_tos(), srv->cli,
                                       ipc_srv->cli, &ipc_srv->pol, path,
                                       namevalue, SMBC_XATTR_MODE_CHOWN, 0);
                }
		TALLOC_FREE(frame);
                return ret;
        }

        /*
         * Are they asking to set the group?
         */
	if (strequal(name, "system.nt_sec_desc.group") ||
	    strequal(name, "system.nt_sec_desc.group+"))
	{

                /* Yup. */
                char *namevalue =
                        talloc_asprintf(talloc_tos(), "%s:%s",
                                        name+19, (const char *) value);

                if (! ipc_srv) {
                        /* errno set by SMBC_server() */
                        ret = -1;
                }
                else if (! namevalue) {
                        errno = ENOMEM;
                        ret = -1;
                } else {
                        ret = cacl_set(context, talloc_tos(), srv->cli,
                                       ipc_srv->cli, &ipc_srv->pol, path,
                                       namevalue, SMBC_XATTR_MODE_CHGRP, 0);
                }
		TALLOC_FREE(frame);
                return ret;
        }

        /* Determine whether to use old-style or new-style attribute names */
        if (context->internal->full_time_names) {
                /* new-style names */
                attr_strings.create_time_attr = "system.dos_attr.CREATE_TIME";
                attr_strings.access_time_attr = "system.dos_attr.ACCESS_TIME";
                attr_strings.write_time_attr = "system.dos_attr.WRITE_TIME";
                attr_strings.change_time_attr = "system.dos_attr.CHANGE_TIME";
        } else {
                /* old-style names */
                attr_strings.create_time_attr = NULL;
                attr_strings.access_time_attr = "system.dos_attr.A_TIME";
                attr_strings.write_time_attr = "system.dos_attr.M_TIME";
                attr_strings.change_time_attr = "system.dos_attr.C_TIME";
        }

        /*
         * Are they asking to set a DOS attribute?
         */
	if (strequal(name, "system.dos_attr.*") ||
	    strequal(name, "system.dos_attr.mode") ||
	    (attr_strings.create_time_attr != NULL &&
	     strequal(name, attr_strings.create_time_attr)) ||
	    strequal(name, attr_strings.access_time_attr) ||
	    strequal(name, attr_strings.write_time_attr) ||
	    strequal(name, attr_strings.change_time_attr))
	{

                /* get a DOS Attribute Descriptor with current attributes */
                dad = dos_attr_query(context, talloc_tos(), path, srv);
                if (dad) {
                        char *namevalue =
                                talloc_asprintf(talloc_tos(), "%s:%s",
                                                name+16, (const char *) value);
                        if (! namevalue) {
                                errno = ENOMEM;
                                ret = -1;
                        } else {
                                /* Overwrite old with provided new params */
                                dos_attr_parse(context, dad, srv, namevalue);

                                /* Set the new DOS attributes */
				ret2 = SMBC_setatr(
					context,
					srv,
					path,
					(struct timespec) {
						.tv_sec = dad->create_time },
					(struct timespec) {
						.tv_sec = dad->access_time },
					(struct timespec) {
						.tv_sec = dad->write_time },
					(struct timespec) {
						.tv_sec = dad->change_time },
					dad->mode);

                                /* ret2 has True (success) / False (failure) */
                                if (ret2) {
                                        ret = 0;
                                } else {
                                        ret = -1;
                                }
                        }
                } else {
                        ret = -1;
                }

		TALLOC_FREE(frame);
                return ret;
        }

        /* Unsupported attribute name */
	TALLOC_FREE(frame);
        errno = EINVAL;
        return -1;
}

int
SMBC_getxattr_ctx(SMBCCTX *context,
                  const char *fname,
                  const char *name,
                  const void *value,
                  size_t size)
{
        int ret;
        SMBCSRV *srv = NULL;
        SMBCSRV *ipc_srv = NULL;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *workgroup = NULL;
	char *path = NULL;
        struct {
                const char * create_time_attr;
                const char * access_time_attr;
                const char * write_time_attr;
                const char * change_time_attr;
        } attr_strings;
	uint16_t port = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		TALLOC_FREE(frame);
                errno = EINVAL;  /* Best I can think of ... */
                return -1;
        }

        if (!fname) {
		TALLOC_FREE(frame);
                errno = EINVAL;
                return -1;
        }

        DEBUG(4, ("smbc_getxattr(%s, %s)\n", fname, name));

        if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
        }

        if (!user || user[0] == '\0') {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return -1;
		}
	}

        srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);
        if (!srv) {
		TALLOC_FREE(frame);
                return -1;  /* errno set by SMBC_server */
        }

        if (! srv->no_nt_session) {
                ipc_srv = SMBC_attr_server(frame, context, server, port, share,
                                           &workgroup, &user, &password);
		/*
		 * SMBC_attr_server() can cause the original
		 * server to be removed from the cache.
		 * If so we must error out here as the srv
		 * pointer has been freed.
		 */
		if (smbc_getFunctionGetCachedServer(context)(context,
				server,
				share,
				workgroup,
				user) != srv) {
#if defined(ECONNRESET)
			errno = ECONNRESET;
#else
			errno = ETIMEDOUT;
#endif
			TALLOC_FREE(frame);
			return -1;
		}
                if (! ipc_srv) {
                        srv->no_nt_session = True;
                }
        } else {
                ipc_srv = NULL;
        }

        /* Determine whether to use old-style or new-style attribute names */
        if (context->internal->full_time_names) {
                /* new-style names */
                attr_strings.create_time_attr = "system.dos_attr.CREATE_TIME";
                attr_strings.access_time_attr = "system.dos_attr.ACCESS_TIME";
                attr_strings.write_time_attr = "system.dos_attr.WRITE_TIME";
                attr_strings.change_time_attr = "system.dos_attr.CHANGE_TIME";
        } else {
                /* old-style names */
                attr_strings.create_time_attr = NULL;
                attr_strings.access_time_attr = "system.dos_attr.A_TIME";
                attr_strings.write_time_attr = "system.dos_attr.M_TIME";
                attr_strings.change_time_attr = "system.dos_attr.C_TIME";
        }

        /* Are they requesting a supported attribute? */
	if (strequal(name, "system.*") || strnequal(name, "system.*!", 9) ||
	    strequal(name, "system.*+") || strnequal(name, "system.*+!", 10) ||
	    strequal(name, "system.nt_sec_desc.*") ||
	    strnequal(name, "system.nt_sec_desc.*!", 21) ||
	    strequal(name, "system.nt_sec_desc.*+") ||
	    strnequal(name, "system.nt_sec_desc.*+!", 22) ||
	    strequal(name, "system.nt_sec_desc.revision") ||
	    strequal(name, "system.nt_sec_desc.owner") ||
	    strequal(name, "system.nt_sec_desc.owner+") ||
	    strequal(name, "system.nt_sec_desc.group") ||
	    strequal(name, "system.nt_sec_desc.group+") ||
	    strnequal(name, "system.nt_sec_desc.acl", 22) ||
	    strnequal(name, "system.nt_sec_desc.acl+", 23) ||
	    strequal(name, "system.dos_attr.*") ||
	    strnequal(name, "system.dos_attr.*!", 18) ||
	    strequal(name, "system.dos_attr.mode") ||
	    strequal(name, "system.dos_attr.size") ||
	    (attr_strings.create_time_attr != NULL &&
	     strequal(name, attr_strings.create_time_attr)) ||
	    strequal(name, attr_strings.access_time_attr) ||
	    strequal(name, attr_strings.write_time_attr) ||
	    strequal(name, attr_strings.change_time_attr) ||
	    strequal(name, "system.dos_attr.inode"))
	{

                /* Yup. */
                const char *filename = name;
                ret = cacl_get(context, talloc_tos(), srv,
                               ipc_srv == NULL ? NULL : ipc_srv->cli,
                               &ipc_srv->pol, path,
                               filename,
                               discard_const_p(char, value),
                               size);
		TALLOC_FREE(frame);
		/*
		 * static function cacl_get returns a value greater than zero
		 * which is needed buffer size needed when size_t is 0.
		 */
                return ret;
        }

        /* Unsupported attribute name */
        errno = EINVAL;
	TALLOC_FREE(frame);
        return -1;
}

int
SMBC_fgetxattr_ctx(SMBCCTX *context,
		   SMBCFILE *file,
		   const char *name,
		   const void *value,
		   size_t size)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int ret;

	if (!context || !context->internal->initialized) {
		TALLOC_FREE(frame);
		errno = EINVAL; /* Best I can think of ... */
		return -1;
	}

	if (!file) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}

	DEBUG(4, ("smbc_fgetxattr(%s, %s)\n", file->fname, name));

	if (strequal(name, "posix.attr.enabled")) {
		bool is_posix;
		int len;

		is_posix = cli_smb2_fnum_is_posix(file->targetcli,
						  file->cli_fd);
		len = snprintf(discard_const_p(char, value),
			       size,
			       "%d",
			       is_posix ? 1 : 0);
		if (len < 0) {
			TALLOC_FREE(frame);
			errno = EINVAL;
			return -1;
		}

		if ((size_t)len > size) {
			TALLOC_FREE(frame);
			errno = ERANGE;
			return -1;
		}

		TALLOC_FREE(frame);
		return len;
	}

	if (strequal(name, "smb311_posix.statinfo")) {
		struct stat st = {};
		struct timespec t = {};
		DATA_BLOB out = {};
		uint32_t *_attrs = NULL;
		NTSTATUS status;

		if (size != (sizeof(struct stat) + 4)) {
			TALLOC_FREE(frame);
			errno = EINVAL;
			return -1;
		}

		status = cli_smb2_query_info_fnum(file->targetcli,
						  file->cli_fd,
						  SMB2_0_INFO_FILE,
						  FSCC_FILE_POSIX_INFORMATION,
						  65536,
						  NULL,
						  0,
						  0,
						  frame,
						  &out);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			errno = map_errno_from_nt_status(status);
			return -1;
		}

		if (out.length < 80) {
			TALLOC_FREE(frame);
			errno = EIO;
			return -1;
		}

		t = nt_time_to_unix_timespec(PULL_LE_U64(out.data, 8));
		st.st_atime = t.tv_sec;
		set_atimensec(&st, t.tv_nsec);

		t = nt_time_to_unix_timespec(PULL_LE_U64(out.data, 16));
		st.st_mtime = t.tv_sec;
		set_mtimensec(&st, t.tv_nsec);

		t = nt_time_to_unix_timespec(PULL_LE_U64(out.data, 24));
		st.st_ctime = t.tv_sec;
		set_ctimensec(&st, t.tv_nsec);

		st.st_size = PULL_LE_U64(out.data, 32);
		st.st_ino = PULL_LE_U64(out.data, 52);
		st.st_dev = PULL_LE_U32(out.data, 60);
		st.st_nlink = PULL_LE_U32(out.data, 68);
		st.st_mode = PULL_LE_U32(out.data, 76);

		memcpy(discard_const_p(char, value), &st, sizeof(struct stat));

		_attrs = (uint32_t *)(discard_const_p(char, value) +
				      sizeof(struct stat));
		*_attrs = PULL_LE_U32(out.data, 48);

		TALLOC_FREE(frame);

		return sizeof(struct stat);
	}

	ret = SMBC_getxattr_ctx(context, file->fname, name, value, size);

	{
		int errno_saved = errno;
		TALLOC_FREE(frame);
		errno = errno_saved;
	}

	return ret;
}

int
SMBC_removexattr_ctx(SMBCCTX *context,
                     const char *fname,
                     const char *name)
{
        int ret;
        SMBCSRV *srv = NULL;
        SMBCSRV *ipc_srv = NULL;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *workgroup = NULL;
	char *path = NULL;
	uint16_t port = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
                errno = EINVAL;  /* Best I can think of ... */
		TALLOC_FREE(frame);
                return -1;
        }

        if (!fname) {
                errno = EINVAL;
		TALLOC_FREE(frame);
                return -1;
        }

        DEBUG(4, ("smbc_removexattr(%s, %s)\n", fname, name));

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
        }

        if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return -1;
		}
	}

        srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);
        if (!srv) {
		TALLOC_FREE(frame);
                return -1;  /* errno set by SMBC_server */
        }

        if (! srv->no_nt_session) {
		int saved_errno;
                ipc_srv = SMBC_attr_server(frame, context, server, port, share,
                                           &workgroup, &user, &password);
		saved_errno = errno;
		/*
		 * SMBC_attr_server() can cause the original
		 * server to be removed from the cache.
		 * If so we must error out here as the srv
		 * pointer has been freed.
		 */
		if (smbc_getFunctionGetCachedServer(context)(context,
				server,
				share,
				workgroup,
				user) != srv) {
#if defined(ECONNRESET)
			errno = ECONNRESET;
#else
			errno = ETIMEDOUT;
#endif
			TALLOC_FREE(frame);
			return -1;
		}
                if (! ipc_srv) {
			errno = saved_errno;
                        srv->no_nt_session = True;
                }
        } else {
                ipc_srv = NULL;
        }

        if (! ipc_srv) {
		TALLOC_FREE(frame);
                return -1; /* errno set by SMBC_attr_server */
        }

        /* Are they asking to set the entire ACL? */
	if (strequal(name, "system.nt_sec_desc.*") ||
	    strequal(name, "system.nt_sec_desc.*+"))
	{

                /* Yup. */
                ret = cacl_set(context, talloc_tos(), srv->cli,
                               ipc_srv->cli, &ipc_srv->pol, path,
                               NULL, SMBC_XATTR_MODE_REMOVE_ALL, 0);
		TALLOC_FREE(frame);
                return ret;
        }

        /*
         * Are they asking to remove one or more specific security descriptor
         * attributes?
         */
	if (strequal(name, "system.nt_sec_desc.revision") ||
	    strequal(name, "system.nt_sec_desc.owner") ||
	    strequal(name, "system.nt_sec_desc.owner+") ||
	    strequal(name, "system.nt_sec_desc.group") ||
	    strequal(name, "system.nt_sec_desc.group+") ||
	    strnequal(name, "system.nt_sec_desc.acl", 22) ||
	    strnequal(name, "system.nt_sec_desc.acl+", 23))
	{

                /* Yup. */
                ret = cacl_set(context, talloc_tos(), srv->cli,
                               ipc_srv->cli, &ipc_srv->pol, path,
                               discard_const_p(char, name) + 19,
                               SMBC_XATTR_MODE_REMOVE, 0);
		TALLOC_FREE(frame);
                return ret;
        }

        /* Unsupported attribute name */
        errno = EINVAL;
	TALLOC_FREE(frame);
        return -1;
}

int
SMBC_listxattr_ctx(SMBCCTX *context,
                   const char *fname,
                   char *list,
                   size_t size)
{
        /*
         * This isn't quite what listxattr() is supposed to do.  This returns
         * the complete set of attribute names, always, rather than only those
         * attribute names which actually exist for a file.  Hmmm...
         */
        size_t retsize;
        static const char supported_old[] =
                "system.*\0"
                "system.*+\0"
                "system.nt_sec_desc.revision\0"
                "system.nt_sec_desc.owner\0"
                "system.nt_sec_desc.owner+\0"
                "system.nt_sec_desc.group\0"
                "system.nt_sec_desc.group+\0"
                "system.nt_sec_desc.acl.*\0"
                "system.nt_sec_desc.acl\0"
                "system.nt_sec_desc.acl+\0"
                "system.nt_sec_desc.*\0"
                "system.nt_sec_desc.*+\0"
                "system.dos_attr.*\0"
                "system.dos_attr.mode\0"
                "system.dos_attr.c_time\0"
                "system.dos_attr.a_time\0"
                "system.dos_attr.m_time\0"
                ;
        static const char supported_new[] =
                "system.*\0"
                "system.*+\0"
                "system.nt_sec_desc.revision\0"
                "system.nt_sec_desc.owner\0"
                "system.nt_sec_desc.owner+\0"
                "system.nt_sec_desc.group\0"
                "system.nt_sec_desc.group+\0"
                "system.nt_sec_desc.acl.*\0"
                "system.nt_sec_desc.acl\0"
                "system.nt_sec_desc.acl+\0"
                "system.nt_sec_desc.*\0"
                "system.nt_sec_desc.*+\0"
                "system.dos_attr.*\0"
                "system.dos_attr.mode\0"
                "system.dos_attr.create_time\0"
                "system.dos_attr.access_time\0"
                "system.dos_attr.write_time\0"
                "system.dos_attr.change_time\0"
                ;
        const char * supported;

        if (context->internal->full_time_names) {
                supported = supported_new;
                retsize = sizeof(supported_new);
        } else {
                supported = supported_old;
                retsize = sizeof(supported_old);
        }

        if (size == 0) {
                return retsize;
        }

        if (retsize > size) {
                errno = ERANGE;
                return -1;
        }

        /* this can't be strcpy() because there are embedded null characters */
        memcpy(list, supported, retsize);
        return retsize;
}
