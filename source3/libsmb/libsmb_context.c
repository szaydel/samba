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
#include "libsmbclient.h"
#include "libsmb_internal.h"
#include "libsmb/smbsock_connect.h"
#include "secrets.h"
#include "../libcli/smb/smbXcli_base.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "lib/param/param.h"
#include "../lib/util/smb_threads.h"
#include "../lib/util/smb_threads_internal.h"

/*
 * Is the logging working / configfile read ?
 */
static bool SMBC_initialized = false;
static unsigned int initialized_ctx_count = 0;
static void *initialized_ctx_count_mutex = NULL;

/*
 * Do some module- and library-wide initializations
 */
static void
SMBC_module_init(void * punused)
{
	bool conf_loaded = False;
	char *home = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	/*
	 * We can't rely on periodic connection
	 * monitoring, so we can't use
	 * the ngtcp2 over udp quic support.
	 */
	smbsock_connect_require_bsd_socket = true;

	setup_logging("libsmbclient", DEBUG_STDOUT);

	/* Here we would open the smb.conf file if needed ... */

	home = getenv("HOME");
	if (home) {
		char *conf = NULL;
		if (asprintf(&conf, "%s/.smb/smb.conf", home) > 0) {
			if (lp_load_client(conf)) {
				conf_loaded = True;
			} else {
				DEBUG(5, ("Could not load config file: %s\n",
					  conf));
			}
			SAFE_FREE(conf);
		}
	}

	if (!conf_loaded) {
		/*
		 * Well, if that failed, try the get_dyn_CONFIGFILE
		 * Which points to the standard locn, and if that
		 * fails, silently ignore it and use the internal
		 * defaults ...
		 */

		if (!lp_load_client(get_dyn_CONFIGFILE())) {
			DEBUG(5, ("Could not load config file: %s\n",
				  get_dyn_CONFIGFILE()));
		} else if (home) {
			char *conf;
			/*
			 * We loaded the global config file.  Now lets
			 * load user-specific modifications to the
			 * global config.
			 */
			if (asprintf(&conf,
				     "%s/.smb/smb.conf.append",
				     home) > 0) {
				if (!lp_load_client_no_reinit(conf)) {
					DEBUG(10,
					      ("Could not append config file: "
					       "%s\n",
					       conf));
				}
				SAFE_FREE(conf);
			}
		}
	}

	load_interfaces();  /* Load the list of interfaces ... */

	reopen_logs();  /* Get logging working ... */

	/*
	 * Block SIGPIPE (from lib/util_sock.c: write())
	 * It is not needed and should not stop execution
	 */
	BlockSignals(True, SIGPIPE);

	/* Create the mutex we'll use to protect initialized_ctx_count */
	if (SMB_THREAD_CREATE_MUTEX("initialized_ctx_count_mutex",
				    initialized_ctx_count_mutex) != 0) {
		smb_panic("SMBC_module_init: "
			  "failed to create 'initialized_ctx_count' mutex");
	}

	TALLOC_FREE(frame);
}


static void
SMBC_module_terminate(void)
{
	TALLOC_CTX *frame = talloc_stackframe();
	secrets_shutdown();
	gfree_all();
	SMBC_initialized = false;
	TALLOC_FREE(frame);
}


/*
 * Get a new empty handle to fill in with your own info
 */
SMBCCTX *
smbc_new_context(void)
{
        SMBCCTX *context;
	TALLOC_CTX *frame = talloc_stackframe();

        /* The first call to this function should initialize the module */
        SMB_THREAD_ONCE(&SMBC_initialized, SMBC_module_init, NULL);

        /*
         * All newly added context fields should be placed in
         * SMBC_internal_data, not directly in SMBCCTX.
         */
        context = SMB_CALLOC_ARRAY(SMBCCTX, 1);
        if (!context) {
		TALLOC_FREE(frame);
                errno = ENOMEM;
                return NULL;
        }

        context->internal = SMB_CALLOC_ARRAY(struct SMBC_internal_data, 1);
        if (!context->internal) {
		TALLOC_FREE(frame);
                SAFE_FREE(context);
                errno = ENOMEM;
                return NULL;
        }

	context->internal->lp_ctx = loadparm_init_s3(NULL,
						     loadparm_s3_helpers());
	if (context->internal->lp_ctx == NULL) {
		SAFE_FREE(context->internal);
		SAFE_FREE(context);
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return NULL;
	}

        smbc_setDebug(context, 0);
        smbc_setTimeout(context, 20000);
        smbc_setPort(context, 0);

        smbc_setOptionFullTimeNames(context, False);
        smbc_setOptionOpenShareMode(context, SMBC_SHAREMODE_DENY_NONE);
        smbc_setOptionSmbEncryptionLevel(context, SMBC_ENCRYPTLEVEL_DEFAULT);
	{
		bool no_ccache = (getenv("LIBSMBCLIENT_NO_CCACHE") == NULL);
		smbc_setOptionUseCCache(context, !no_ccache);
	}
        smbc_setOptionCaseSensitive(context, False);
        smbc_setOptionBrowseMaxLmbCount(context, 3);    /* # LMBs to query */
        smbc_setOptionUrlEncodeReaddirEntries(context, False);
        smbc_setOptionOneSharePerServer(context, False);
        smbc_setOptionPosixExtensions(context, false);

        smbc_setFunctionAuthData(context, SMBC_get_auth_data);
        smbc_setFunctionCheckServer(context, SMBC_check_server);
        smbc_setFunctionRemoveUnusedServer(context, SMBC_remove_unused_server);

        smbc_setOptionUserData(context, NULL);
        smbc_setFunctionAddCachedServer(context, SMBC_add_cached_server);
        smbc_setFunctionGetCachedServer(context, SMBC_get_cached_server);
        smbc_setFunctionRemoveCachedServer(context, SMBC_remove_cached_server);
        smbc_setFunctionPurgeCachedServers(context, SMBC_purge_cached_servers);

        smbc_setFunctionOpen(context, SMBC_open_ctx);
        smbc_setFunctionCreat(context, SMBC_creat_ctx);
        smbc_setFunctionRead(context, SMBC_read_ctx);
        smbc_setFunctionSplice(context, SMBC_splice_ctx);
        smbc_setFunctionWrite(context, SMBC_write_ctx);
        smbc_setFunctionClose(context, SMBC_close_ctx);
        smbc_setFunctionUnlink(context, SMBC_unlink_ctx);
        smbc_setFunctionRename(context, SMBC_rename_ctx);
        smbc_setFunctionLseek(context, SMBC_lseek_ctx);
        smbc_setFunctionFtruncate(context, SMBC_ftruncate_ctx);
        smbc_setFunctionStat(context, SMBC_stat_ctx);
        smbc_setFunctionStatVFS(context, SMBC_statvfs_ctx);
        smbc_setFunctionFstatVFS(context, SMBC_fstatvfs_ctx);
        smbc_setFunctionFstat(context, SMBC_fstat_ctx);
        smbc_setFunctionOpendir(context, SMBC_opendir_ctx);
        smbc_setFunctionClosedir(context, SMBC_closedir_ctx);
        smbc_setFunctionReaddir(context, SMBC_readdir_ctx);
        smbc_setFunctionReaddirPlus(context, SMBC_readdirplus_ctx);
	smbc_setFunctionReaddirPlus2(context, SMBC_readdirplus2_ctx);
        smbc_setFunctionGetdents(context, SMBC_getdents_ctx);
        smbc_setFunctionMkdir(context, SMBC_mkdir_ctx);
        smbc_setFunctionRmdir(context, SMBC_rmdir_ctx);
        smbc_setFunctionTelldir(context, SMBC_telldir_ctx);
        smbc_setFunctionLseekdir(context, SMBC_lseekdir_ctx);
        smbc_setFunctionFstatdir(context, SMBC_fstatdir_ctx);
        smbc_setFunctionNotify(context, SMBC_notify_ctx);
        smbc_setFunctionChmod(context, SMBC_chmod_ctx);
        smbc_setFunctionUtimes(context, SMBC_utimes_ctx);
        smbc_setFunctionSetxattr(context, SMBC_setxattr_ctx);
        smbc_setFunctionGetxattr(context, SMBC_getxattr_ctx);
        smbc_setFunctionFGetxattr(context, SMBC_fgetxattr_ctx);
        smbc_setFunctionRemovexattr(context, SMBC_removexattr_ctx);
        smbc_setFunctionListxattr(context, SMBC_listxattr_ctx);

        smbc_setFunctionOpenPrintJob(context, SMBC_open_print_job_ctx);
        smbc_setFunctionPrintFile(context, SMBC_print_file_ctx);
        smbc_setFunctionListPrintJobs(context, SMBC_list_print_jobs_ctx);
        smbc_setFunctionUnlinkPrintJob(context, SMBC_unlink_print_job_ctx);

	TALLOC_FREE(frame);
        return context;
}

/*
 * Free a context
 *
 * Returns 0 on success. Otherwise returns 1, the SMBCCTX is _not_ freed
 * and thus you'll be leaking memory if not handled properly.
 *
 */
int
smbc_free_context(SMBCCTX *context,
                  int shutdown_ctx)
{
	TALLOC_CTX *frame;
        if (!context) {
                errno = EBADF;
                return 1;
        }

	frame = talloc_stackframe();

        if (shutdown_ctx) {
                SMBCFILE * f;
                DEBUG(1,("Performing aggressive shutdown.\n"));

                f = context->internal->files;
                while (f) {
			SMBCFILE *next = f->next;
                        smbc_getFunctionClose(context)(context, f);
			f = next;
                }
                context->internal->files = NULL;

                /* First try to remove the servers the nice way. */
                if (smbc_getFunctionPurgeCachedServers(context)(context)) {
                        SMBCSRV * s;
                        SMBCSRV * next;
                        DEBUG(1, ("Could not purge all servers, "
                                  "Nice way shutdown failed.\n"));
                        s = context->internal->servers;
                        while (s) {
                                DEBUG(1, ("Forced shutdown: %p (cli=%p)\n",
                                          s, s->cli));
                                cli_shutdown(s->cli);
                                smbc_getFunctionRemoveCachedServer(context)(context,
                                                                         s);
                                next = s->next;
                                DLIST_REMOVE(context->internal->servers, s);
                                SAFE_FREE(s);
                                s = next;
                        }
                        context->internal->servers = NULL;
                }
        }
        else {
                /* This is the polite way */
                if (smbc_getFunctionPurgeCachedServers(context)(context)) {
                        DEBUG(1, ("Could not purge all servers, "
                                  "free_context failed.\n"));
                        errno = EBUSY;
			TALLOC_FREE(frame);
                        return 1;
                }
                if (context->internal->servers) {
                        DEBUG(1, ("Active servers in context, "
                                  "free_context failed.\n"));
                        errno = EBUSY;
			TALLOC_FREE(frame);
                        return 1;
                }
                if (context->internal->files) {
                        DEBUG(1, ("Active files in context, "
                                  "free_context failed.\n"));
                        errno = EBUSY;
			TALLOC_FREE(frame);
                        return 1;
                }
        }

        /* Things we have to clean up */
        smbc_setWorkgroup(context, NULL);
        smbc_setNetbiosName(context, NULL);
        smbc_setUser(context, NULL);

        DEBUG(3, ("Context %p successfully freed\n", context));

	/* Free any DFS auth context. */
	TALLOC_FREE(context->internal->creds);

	TALLOC_FREE(context->internal->lp_ctx);
	SAFE_FREE(context->internal);
        SAFE_FREE(context);

        /* Protect access to the count of contexts in use */
	if (SMB_THREAD_LOCK(initialized_ctx_count_mutex) != 0) {
                smb_panic("error locking 'initialized_ctx_count'");
	}

	if (initialized_ctx_count) {
		initialized_ctx_count--;
	}

	if (initialized_ctx_count == 0) {
            SMBC_module_terminate();
	}

        /* Unlock the mutex */
	if (SMB_THREAD_UNLOCK(initialized_ctx_count_mutex) != 0) {
                smb_panic("error unlocking 'initialized_ctx_count'");
	}

	TALLOC_FREE(frame);
        return 0;
}


/**
 * Deprecated interface.  Do not use.  Instead, use the various
 * smbc_setOption*() functions or smbc_setFunctionAuthDataWithContext().
 */
void
smbc_option_set(SMBCCTX *context,
                char *option_name,
                ... /* option_value */)
{
        va_list ap;
        union {
                int i;
                bool b;
                smbc_get_auth_data_with_context_fn auth_fn;
                void *v;
                const char *s;
        } option_value;

	TALLOC_CTX *frame = talloc_stackframe();

        va_start(ap, option_name);

        if (strcmp(option_name, "debug_to_stderr") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionDebugToStderr(context, option_value.b);

        } else if (strcmp(option_name, "full_time_names") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionFullTimeNames(context, option_value.b);

        } else if (strcmp(option_name, "open_share_mode") == 0) {
                option_value.i = va_arg(ap, int);
                smbc_setOptionOpenShareMode(context, option_value.i);

        } else if (strcmp(option_name, "auth_function") == 0) {
                option_value.auth_fn =
                        va_arg(ap, smbc_get_auth_data_with_context_fn);
                smbc_setFunctionAuthDataWithContext(context, option_value.auth_fn);

        } else if (strcmp(option_name, "user_data") == 0) {
                option_value.v = va_arg(ap, void *);
                smbc_setOptionUserData(context, option_value.v);

        } else if (strcmp(option_name, "smb_encrypt_level") == 0) {
                option_value.s = va_arg(ap, const char *);
                if (strcmp(option_value.s, "none") == 0) {
                        smbc_setOptionSmbEncryptionLevel(context,
                                                         SMBC_ENCRYPTLEVEL_NONE);
                } else if (strcmp(option_value.s, "request") == 0) {
                        smbc_setOptionSmbEncryptionLevel(context,
                                                         SMBC_ENCRYPTLEVEL_REQUEST);
                } else if (strcmp(option_value.s, "require") == 0) {
                        smbc_setOptionSmbEncryptionLevel(context,
                                                         SMBC_ENCRYPTLEVEL_REQUIRE);
                }

        } else if (strcmp(option_name, "browse_max_lmb_count") == 0) {
                option_value.i = va_arg(ap, int);
                smbc_setOptionBrowseMaxLmbCount(context, option_value.i);

        } else if (strcmp(option_name, "urlencode_readdir_entries") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionUrlEncodeReaddirEntries(context, option_value.b);

        } else if (strcmp(option_name, "one_share_per_server") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionOneSharePerServer(context, option_value.b);

        } else if (strcmp(option_name, "use_kerberos") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionUseKerberos(context, option_value.b);

        } else if (strcmp(option_name, "fallback_after_kerberos") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionFallbackAfterKerberos(context, option_value.b);

        } else if (strcmp(option_name, "use_ccache") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionUseCCache(context, option_value.b);

        } else if (strcmp(option_name, "no_auto_anonymous_login") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionNoAutoAnonymousLogin(context, option_value.b);
        }

        va_end(ap);
	TALLOC_FREE(frame);
}


/*
 * Deprecated interface.  Do not use.  Instead, use the various
 * smbc_getOption*() functions.
 */
void *
smbc_option_get(SMBCCTX *context,
                char *option_name)
{
        if (strcmp(option_name, "debug_stderr") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionDebugToStderr(context);
#else
                return (void *) smbc_getOptionDebugToStderr(context);
#endif

        } else if (strcmp(option_name, "full_time_names") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionFullTimeNames(context);
#else
                return (void *) smbc_getOptionFullTimeNames(context);
#endif

        } else if (strcmp(option_name, "open_share_mode") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionOpenShareMode(context);
#else
                return (void *) smbc_getOptionOpenShareMode(context);
#endif

        } else if (strcmp(option_name, "auth_function") == 0) {
                return (void *) smbc_getFunctionAuthDataWithContext(context);

        } else if (strcmp(option_name, "user_data") == 0) {
                return smbc_getOptionUserData(context);

        } else if (strcmp(option_name, "smb_encrypt_level") == 0) {
                switch(smbc_getOptionSmbEncryptionLevel(context))
                {
                case SMBC_ENCRYPTLEVEL_DEFAULT:
                        return discard_const_p(void, "default");
                case 0:
                        return discard_const_p(void, "none");
                case 1:
                        return discard_const_p(void, "request");
                case 2:
                        return discard_const_p(void, "require");
                }

        } else if (strcmp(option_name, "smb_encrypt_on") == 0) {
                SMBCSRV *s;
                unsigned int num_servers = 0;

                for (s = context->internal->servers; s; s = s->next) {
                        num_servers++;
                        if (!cli_state_is_encryption_on(s->cli)) {
                                return (void *)false;
                        }
                }
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) (bool) (num_servers > 0);
#else
                return (void *) (bool) (num_servers > 0);
#endif

        } else if (strcmp(option_name, "browse_max_lmb_count") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionBrowseMaxLmbCount(context);
#else
                return (void *) smbc_getOptionBrowseMaxLmbCount(context);
#endif

        } else if (strcmp(option_name, "urlencode_readdir_entries") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *)(intptr_t) smbc_getOptionUrlEncodeReaddirEntries(context);
#else
                return (void *) (bool) smbc_getOptionUrlEncodeReaddirEntries(context);
#endif

        } else if (strcmp(option_name, "one_share_per_server") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionOneSharePerServer(context);
#else
                return (void *) (bool) smbc_getOptionOneSharePerServer(context);
#endif

        } else if (strcmp(option_name, "use_kerberos") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionUseKerberos(context);
#else
                return (void *) (bool) smbc_getOptionUseKerberos(context);
#endif

        } else if (strcmp(option_name, "fallback_after_kerberos") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *)(intptr_t) smbc_getOptionFallbackAfterKerberos(context);
#else
                return (void *) (bool) smbc_getOptionFallbackAfterKerberos(context);
#endif

        } else if (strcmp(option_name, "use_ccache") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionUseCCache(context);
#else
                return (void *) (bool) smbc_getOptionUseCCache(context);
#endif

        } else if (strcmp(option_name, "no_auto_anonymous_login") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionNoAutoAnonymousLogin(context);
#else
                return (void *) (bool) smbc_getOptionNoAutoAnonymousLogin(context);
#endif
        }

        return NULL;
}


/*
 * Initialize the library, etc.
 *
 * We accept a struct containing handle information.
 * valid values for info->debug from 0 to 100,
 * and insist that info->fn must be non-null.
 */
SMBCCTX *
smbc_init_context(SMBCCTX *context)
{
        int pid;
        TALLOC_CTX *frame;

        if (!context) {
                errno = EBADF;
                return NULL;
        }

        /* Do not initialise the same client twice */
        if (context->internal->initialized) {
                return NULL;
        }

        frame = talloc_stackframe();

        if ((!smbc_getFunctionAuthData(context) &&
             !smbc_getFunctionAuthDataWithContext(context)) ||
            smbc_getDebug(context) < 0 ||
            smbc_getDebug(context) > 100) {

                TALLOC_FREE(frame);
                errno = EINVAL;
                return NULL;

        }

        if (!smbc_getUser(context)) {
                /*
                 * FIXME: Is this the best way to get the user info?
                 */
        	char *user = getenv("USER");
                /* walk around as "guest" if no username can be found */
                if (!user) {
                        user = SMB_STRDUP("guest");
                } else {
                        user = SMB_STRDUP(user);
                }

                if (!user) {
                        TALLOC_FREE(frame);
                        errno = ENOMEM;
                        return NULL;
                }

                smbc_setUser(context, user);
		SAFE_FREE(user);

        	if (!smbc_getUser(context)) {
                        TALLOC_FREE(frame);
                        errno = ENOMEM;
                        return NULL;
                }
        }

        if (!smbc_getNetbiosName(context)) {
                /*
                 * We try to get our netbios name from the config. If that
                 * fails we fall back on constructing our netbios name from
                 * our hostname etc
                 */
                char *netbios_name;
                if (lp_netbios_name()) {
                        netbios_name = SMB_STRDUP(lp_netbios_name());
                } else {
                        /*
                         * Hmmm, I want to get hostname as well, but I am too
                         * lazy for the moment
                         */
                        pid = getpid();
                        netbios_name = (char *)SMB_MALLOC(17);
                        if (!netbios_name) {
                                TALLOC_FREE(frame);
                                errno = ENOMEM;
                                return NULL;
                        }
                        slprintf(netbios_name, 16,
                                 "smbc%s%d", smbc_getUser(context), pid);
                }

                if (!netbios_name) {
                        TALLOC_FREE(frame);
                        errno = ENOMEM;
                        return NULL;
                }

                smbc_setNetbiosName(context, netbios_name);
		SAFE_FREE(netbios_name);

                if (!smbc_getNetbiosName(context)) {
                        TALLOC_FREE(frame);
                        errno = ENOMEM;
                        return NULL;
                }
        }

        DEBUG(1, ("Using netbios name %s.\n", smbc_getNetbiosName(context)));

        if (!smbc_getWorkgroup(context)) {
                const char *workgroup;

                if (lp_workgroup()) {
                        workgroup = lp_workgroup();
                } else {
                        /* TODO: Think about a decent default workgroup */
                        workgroup = "samba";
                }

                smbc_setWorkgroup(context, workgroup);

		if (!smbc_getWorkgroup(context)) {
                        TALLOC_FREE(frame);
			errno = ENOMEM;
			return NULL;
		}
        }

        DEBUG(1, ("Using workgroup %s.\n", smbc_getWorkgroup(context)));

        /* shortest timeout is 1 second */
        if (smbc_getTimeout(context) > 0 && smbc_getTimeout(context) < 1000)
                smbc_setTimeout(context, 1000);

        context->internal->initialized = True;

        /* Protect access to the count of contexts in use */
	if (SMB_THREAD_LOCK(initialized_ctx_count_mutex) != 0) {
                smb_panic("error locking 'initialized_ctx_count'");
	}

	initialized_ctx_count++;

        /* Unlock the mutex */
	if (SMB_THREAD_UNLOCK(initialized_ctx_count_mutex) != 0) {
                smb_panic("error unlocking 'initialized_ctx_count'");
	}

        TALLOC_FREE(frame);
        return context;
}


/* Return the version of samba, and thus libsmbclient */
const char *
smbc_version(void)
{
        return samba_version_string();
}

/*
 * Set the credentials so DFS will work when following referrals.
 * This function is broken and must be removed. No SMBCCTX arg...
 * JRA.
 */

void
smbc_set_credentials(const char *workgroup,
			const char *user,
			const char *password,
			smbc_bool use_kerberos,
			const char *signing_state)
{
	d_printf("smbc_set_credentials is obsolete. Replace with smbc_set_credentials_with_fallback().\n");
}

void smbc_set_credentials_with_fallback(SMBCCTX *context,
					const char *workgroup,
					const char *user,
					const char *password)
{
	struct cli_credentials *creds = NULL;
	enum credentials_use_kerberos kerberos_state =
		CRED_USE_KERBEROS_DISABLED;

	if (! context) {

		return;
	}

	if (! workgroup || ! *workgroup) {
		workgroup = smbc_getWorkgroup(context);
	}

	if (! user) {
		user = smbc_getUser(context);
	}

	if (! password) {
		password = "";
	}

	creds = cli_credentials_init(NULL);
	if (creds == NULL) {
		DEBUG(0, ("smbc_set_credentials_with_fallback: allocation fail\n"));
		return;
	}

	cli_credentials_set_conf(creds, context->internal->lp_ctx);

	if (smbc_getOptionUseKerberos(context)) {
		kerberos_state = CRED_USE_KERBEROS_REQUIRED;

		if (smbc_getOptionFallbackAfterKerberos(context)) {
			kerberos_state = CRED_USE_KERBEROS_DESIRED;
		}
	}

	cli_credentials_set_username(creds, user, CRED_SPECIFIED);
	cli_credentials_set_password(creds, password, CRED_SPECIFIED);
	cli_credentials_set_domain(creds, workgroup, CRED_SPECIFIED);
	cli_credentials_set_kerberos_state(creds,
					   kerberos_state,
					   CRED_SPECIFIED);
	if (smbc_getOptionUseCCache(context)) {
		cli_credentials_add_gensec_features(creds,
						    GENSEC_FEATURE_NTLM_CCACHE,
						    CRED_SPECIFIED);
	}

	TALLOC_FREE(context->internal->creds);
	context->internal->creds = creds;
}
