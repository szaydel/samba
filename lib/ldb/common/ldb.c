/*
   ldb database library

   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Simo Sorce  2005-2008

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb core API
 *
 *  Description: core API routines interfacing to ldb backends
 *
 *  Author: Andrew Tridgell
 */

#define TEVENT_DEPRECATED 1
#include "ldb_private.h"
#include "ldb.h"

static int ldb_context_destructor(void *ptr)
{
	struct ldb_context *ldb = talloc_get_type(ptr, struct ldb_context);

	if (ldb->transaction_active) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "A transaction is still active in ldb context [%p] on %s",
			  ldb, (const char *)ldb_get_opaque(ldb, "ldb_url"));
	}

	return 0;
}

/*
  this is used to catch debug messages from events
*/
static void ldb_tevent_debug(void *context, enum tevent_debug_level level,
			     const char *fmt, va_list ap)  PRINTF_ATTRIBUTE(3,0);

static void ldb_tevent_debug(void *context, enum tevent_debug_level level,
			     const char *fmt, va_list ap)
{
	struct ldb_context *ldb = talloc_get_type(context, struct ldb_context);
	enum ldb_debug_level ldb_level = LDB_DEBUG_FATAL;

	switch (level) {
	case TEVENT_DEBUG_FATAL:
		ldb_level = LDB_DEBUG_FATAL;
		break;
	case TEVENT_DEBUG_ERROR:
		ldb_level = LDB_DEBUG_ERROR;
		break;
	case TEVENT_DEBUG_WARNING:
		ldb_level = LDB_DEBUG_WARNING;
		break;
	case TEVENT_DEBUG_TRACE:
		ldb_level = LDB_DEBUG_TRACE;
		break;
	};

	/* There isn't a tevent: prefix here because to add it means
	 * actually printing the string, and most of the time we don't
	 * want to show it */
	ldb_vdebug(ldb, ldb_level, fmt, ap);
}

/*
   initialise a ldb context
   The mem_ctx is required
   The event_ctx is required
*/
struct ldb_context *ldb_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev_ctx)
{
	struct ldb_context *ldb;
	int ret;
	const char *modules_path = getenv("LDB_MODULES_PATH");

	if (modules_path == NULL) {
		modules_path = LDB_MODULESDIR;
	}

	ret = ldb_modules_load(modules_path, LDB_VERSION);
	if (ret != LDB_SUCCESS) {
		return NULL;
	}

	ldb = talloc_zero(mem_ctx, struct ldb_context);
	if (ldb == NULL) {
		return NULL;
	}

	/* A new event context so that callers who don't want ldb
	 * operating on their global event context can work without
	 * having to provide their own private one explicitly */
	if (ev_ctx == NULL) {
		ev_ctx = tevent_context_init(ldb);
		if (ev_ctx == NULL) {
			talloc_free(ldb);
			return NULL;
		}
		tevent_set_debug(ev_ctx, ldb_tevent_debug, ldb);
		tevent_set_max_debug_level(ev_ctx, TEVENT_DEBUG_TRACE);
		tevent_loop_allow_nesting(ev_ctx);
	}

	ret = ldb_setup_wellknown_attributes(ldb);
	if (ret != LDB_SUCCESS) {
		talloc_free(ldb);
		return NULL;
	}

	ldb_set_utf8_default(ldb);
	ldb_set_create_perms(ldb, 0666);
	ldb_set_modules_dir(ldb, LDB_MODULESDIR);
	ldb_set_event_context(ldb, ev_ctx);
	ret = ldb_register_extended_match_rules(ldb);
	if (ret != LDB_SUCCESS) {
		talloc_free(ldb);
		return NULL;
	}

	/* TODO: get timeout from options if available there */
	ldb->default_timeout = 300; /* set default to 5 minutes */

	talloc_set_destructor((TALLOC_CTX *)ldb, ldb_context_destructor);

	return ldb;
}

/*
  try to autodetect a basedn if none specified. This fixes one of my
  pet hates about ldapsearch, which is that you have to get a long,
  complex basedn right to make any use of it.
*/
void ldb_set_default_dns(struct ldb_context *ldb)
{
	TALLOC_CTX *tmp_ctx;
	int ret;
	struct ldb_result *res;
	struct ldb_dn *tmp_dn=NULL;
	static const char *attrs[] = {
		"rootDomainNamingContext",
		"configurationNamingContext",
		"schemaNamingContext",
		"defaultNamingContext",
		NULL
	};

	tmp_ctx = talloc_new(ldb);
	ret = ldb_search(ldb, tmp_ctx, &res, ldb_dn_new(tmp_ctx, ldb, NULL),
			 LDB_SCOPE_BASE, attrs, "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return;
	}

	if (res->count != 1) {
		talloc_free(tmp_ctx);
		return;
	}

	if (!ldb_get_opaque(ldb, "rootDomainNamingContext")) {
		tmp_dn = ldb_msg_find_attr_as_dn(ldb, ldb, res->msgs[0],
						 "rootDomainNamingContext");
		ldb_set_opaque(ldb, "rootDomainNamingContext", tmp_dn);
	}

	if (!ldb_get_opaque(ldb, "configurationNamingContext")) {
		tmp_dn = ldb_msg_find_attr_as_dn(ldb, ldb, res->msgs[0],
						 "configurationNamingContext");
		ldb_set_opaque(ldb, "configurationNamingContext", tmp_dn);
	}

	if (!ldb_get_opaque(ldb, "schemaNamingContext")) {
		tmp_dn = ldb_msg_find_attr_as_dn(ldb, ldb, res->msgs[0],
						 "schemaNamingContext");
		ldb_set_opaque(ldb, "schemaNamingContext", tmp_dn);
	}

	if (!ldb_get_opaque(ldb, "defaultNamingContext")) {
		tmp_dn = ldb_msg_find_attr_as_dn(ldb, ldb, res->msgs[0],
						 "defaultNamingContext");
		ldb_set_opaque(ldb, "defaultNamingContext", tmp_dn);
	}

	talloc_free(tmp_ctx);
}

struct ldb_dn *ldb_get_root_basedn(struct ldb_context *ldb)
{
	void *opaque = ldb_get_opaque(ldb, "rootDomainNamingContext");
	return talloc_get_type(opaque, struct ldb_dn);
}

struct ldb_dn *ldb_get_config_basedn(struct ldb_context *ldb)
{
	void *opaque = ldb_get_opaque(ldb, "configurationNamingContext");
	return talloc_get_type(opaque, struct ldb_dn);
}

struct ldb_dn *ldb_get_schema_basedn(struct ldb_context *ldb)
{
	void *opaque = ldb_get_opaque(ldb, "schemaNamingContext");
	return talloc_get_type(opaque, struct ldb_dn);
}

struct ldb_dn *ldb_get_default_basedn(struct ldb_context *ldb)
{
	void *opaque = ldb_get_opaque(ldb, "defaultNamingContext");
	return talloc_get_type(opaque, struct ldb_dn);
}

/*
   connect to a database. The URL can either be one of the following forms
   ldb://path
   ldapi://path

   flags is made up of LDB_FLG_*

   the options are passed uninterpreted to the backend, and are
   backend specific
*/
int ldb_connect(struct ldb_context *ldb, const char *url,
		unsigned int flags, const char *options[])
{
	int ret;
	char *url2;

	const char *existing_url = ldb_get_opaque(ldb, "ldb_url");
	if (existing_url != NULL) {
		ldb_asprintf_errstring(
			ldb,
			"This LDB has already connected to '%s', and "
			"cannot also connect to '%s'",
			existing_url, url);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* We seem to need to do this here, or else some utilities don't
	 * get ldb backends */

	ldb->flags = flags;

	url2 = talloc_strdup(ldb, url);
	if (!url2) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_set_opaque(ldb, "ldb_url", url2);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/*
	 * Take a copy of the options.
	 */
	ldb->options = ldb_options_copy(ldb, options);
	if (ldb->options == NULL && options != NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_module_connect_backend(ldb, url, options, &ldb->modules);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_load_modules(ldb, options);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "Unable to load modules for %s: %s",
			  url, ldb_errstring(ldb));
		return ret;
	}

	/* set the default base dn */
	ldb_set_default_dns(ldb);

	return LDB_SUCCESS;
}

void ldb_set_errstring(struct ldb_context *ldb, const char *err_string)
{
	ldb_asprintf_errstring(ldb, "%s", err_string);
}

void ldb_asprintf_errstring(struct ldb_context *ldb, const char *format, ...)
{
	va_list ap;
	char *old_err_string = NULL;
	if (ldb->err_string) {
		old_err_string = ldb->err_string;
	}

	va_start(ap, format);
	ldb->err_string = talloc_vasprintf(ldb, format, ap);
	va_end(ap);

	TALLOC_FREE(old_err_string);

	if (ldb->flags & LDB_FLG_ENABLE_TRACING) {
		ldb_debug(ldb, LDB_DEBUG_TRACE, "ldb_asprintf/set_errstring: %s",
			  ldb->err_string);
	}
}

void ldb_reset_err_string(struct ldb_context *ldb)
{
	TALLOC_FREE(ldb->err_string);
}



/*
  set an ldb error based on file:line
*/
int ldb_error_at(struct ldb_context *ldb, int ecode,
		 const char *reason, const char *file, int line)
{
	if (reason == NULL) {
		reason = ldb_strerror(ecode);
	}
	ldb_asprintf_errstring(ldb, "%s at %s:%d", reason, file, line);
	return ecode;
}


#define FIRST_OP_NOERR(ldb, op) do { \
	next_module = ldb->modules;					\
	while (next_module && next_module->ops->op == NULL) {		\
		next_module = next_module->next;			    \
	};							    \
	if ((ldb->flags & LDB_FLG_ENABLE_TRACING) && next_module) { \
		ldb_debug(ldb, LDB_DEBUG_TRACE, "ldb_trace_request: (%s)->" #op, \
			  next_module->ops->name);				\
	}								\
} while (0)

#define FIRST_OP(ldb, op) do { \
	FIRST_OP_NOERR(ldb, op); \
	if (next_module == NULL) {	       				\
		ldb_asprintf_errstring(ldb, "unable to find module or backend to handle operation: " #op); \
		return LDB_ERR_OPERATIONS_ERROR;			\
	} \
} while (0)


/*
  start a transaction
*/
int ldb_transaction_start(struct ldb_context *ldb)
{
	struct ldb_module *next_module;
	int status;

	ldb_debug(ldb, LDB_DEBUG_TRACE,
		  "start ldb transaction (nesting: %d)",
		  ldb->transaction_active);

	/* explicit transaction active, count nested requests */
	if (ldb->transaction_active) {
		ldb->transaction_active++;
		return LDB_SUCCESS;
	}

	/* start a new transaction */
	ldb->transaction_active++;
	ldb->prepare_commit_done = false;

	FIRST_OP(ldb, start_transaction);

	ldb_reset_err_string(ldb);

	status = next_module->ops->start_transaction(next_module);
	if (status != LDB_SUCCESS) {
		if (ldb->err_string == NULL) {
			/* no error string was setup by the backend */
			ldb_asprintf_errstring(ldb,
				"ldb transaction start: %s (%d)",
				ldb_strerror(status),
				status);
		ldb->transaction_active--;
		}
		if ((next_module && next_module->ldb->flags & LDB_FLG_ENABLE_TRACING)) {
			ldb_debug(next_module->ldb, LDB_DEBUG_TRACE, "start ldb transaction error: %s",
				  ldb_errstring(next_module->ldb));
		}
	} else {
		if ((next_module && next_module->ldb->flags & LDB_FLG_ENABLE_TRACING)) {
			ldb_debug(next_module->ldb, LDB_DEBUG_TRACE, "start ldb transaction success");
		}
	}
	return status;
}

/*
  prepare for transaction commit (first phase of two phase commit)
*/
int ldb_transaction_prepare_commit(struct ldb_context *ldb)
{
	struct ldb_module *next_module;
	int status;

	if (ldb->prepare_commit_done) {
		return LDB_SUCCESS;
	}

	/* commit only when all nested transactions are complete */
	if (ldb->transaction_active > 1) {
		return LDB_SUCCESS;
	}

	ldb->prepare_commit_done = true;

	if (ldb->transaction_active < 0) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "prepare commit called but no ldb transactions are active!");
		ldb->transaction_active = 0;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* call prepare transaction if available */
	FIRST_OP_NOERR(ldb, prepare_commit);
	if (next_module == NULL) {
		return LDB_SUCCESS;
	}

	ldb_reset_err_string(ldb);

	status = next_module->ops->prepare_commit(next_module);
	if (status != LDB_SUCCESS) {
		ldb->transaction_active--;
		/* if a next_module fails the prepare then we need
		   to call the end transaction for everyone */
		FIRST_OP(ldb, del_transaction);
		next_module->ops->del_transaction(next_module);
		if (ldb->err_string == NULL) {
			/* no error string was setup by the backend */
			ldb_asprintf_errstring(ldb,
					       "ldb transaction prepare commit: %s (%d)",
					       ldb_strerror(status),
					       status);
		}
		if ((next_module && next_module->ldb->flags & LDB_FLG_ENABLE_TRACING)) {
			ldb_debug(next_module->ldb, LDB_DEBUG_TRACE, "prepare commit transaction error: %s",
				  ldb_errstring(next_module->ldb));
		}
	}

	return status;
}


/*
  commit a transaction
*/
int ldb_transaction_commit(struct ldb_context *ldb)
{
	struct ldb_module *next_module;
	int status;

	status = ldb_transaction_prepare_commit(ldb);
	if (status != LDB_SUCCESS) {
		return status;
	}

	ldb->transaction_active--;

	ldb_debug(ldb, LDB_DEBUG_TRACE,
		  "commit ldb transaction (nesting: %d)",
		  ldb->transaction_active);

	/* commit only when all nested transactions are complete */
	if (ldb->transaction_active > 0) {
		return LDB_SUCCESS;
	}

	if (ldb->transaction_active < 0) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "commit called but no ldb transactions are active!");
		ldb->transaction_active = 0;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_reset_err_string(ldb);

	FIRST_OP(ldb, end_transaction);
	status = next_module->ops->end_transaction(next_module);
	if (status != LDB_SUCCESS) {
		if (ldb->err_string == NULL) {
			/* no error string was setup by the backend */
			ldb_asprintf_errstring(ldb,
				"ldb transaction commit: %s (%d)",
				ldb_strerror(status),
				status);
		}
		if ((next_module && next_module->ldb->flags & LDB_FLG_ENABLE_TRACING)) {
			ldb_debug(next_module->ldb, LDB_DEBUG_TRACE, "commit ldb transaction error: %s",
				  ldb_errstring(next_module->ldb));
		}
	}
	return status;
}


/*
  cancel a transaction
*/
int ldb_transaction_cancel(struct ldb_context *ldb)
{
	struct ldb_module *next_module;
	int status;

	ldb->transaction_active--;

	ldb_debug(ldb, LDB_DEBUG_TRACE,
		  "cancel ldb transaction (nesting: %d)",
		  ldb->transaction_active);

	/* really cancel only if all nested transactions are complete */
	if (ldb->transaction_active > 0) {
		return LDB_SUCCESS;
	}

	if (ldb->transaction_active < 0) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "cancel called but no ldb transactions are active!");
		ldb->transaction_active = 0;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	FIRST_OP(ldb, del_transaction);

	status = next_module->ops->del_transaction(next_module);
	if (status != LDB_SUCCESS) {
		if (ldb->err_string == NULL) {
			/* no error string was setup by the backend */
			ldb_asprintf_errstring(ldb,
				"ldb transaction cancel: %s (%d)",
				ldb_strerror(status),
				status);
		}
		if ((next_module && next_module->ldb->flags & LDB_FLG_ENABLE_TRACING)) {
			ldb_debug(next_module->ldb, LDB_DEBUG_TRACE, "cancel ldb transaction error: %s",
				  ldb_errstring(next_module->ldb));
		}
	}
	return status;
}

/*
  cancel a transaction with no error if no transaction is pending
  used when we fork() to clear any parent transactions
*/
int ldb_transaction_cancel_noerr(struct ldb_context *ldb)
{
	if (ldb->transaction_active > 0) {
		return ldb_transaction_cancel(ldb);
	}
	return LDB_SUCCESS;
}


/* autostarts a transaction if none active */
static int ldb_autotransaction_request(struct ldb_context *ldb,
				       struct ldb_request *req)
{
	int ret;

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_request(ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_SUCCESS) {
		return ldb_transaction_commit(ldb);
	}
	ldb_transaction_cancel(ldb);

	return ret;
}

int ldb_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	struct tevent_context *ev;
	int ret;

	if (handle == NULL) {
		return LDB_ERR_UNAVAILABLE;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		if ((handle->status != LDB_SUCCESS) &&
		    (handle->ldb->err_string == NULL)) {
			/* if no error string was setup by the backend */
			ldb_asprintf_errstring(handle->ldb,
					       "ldb_wait from %s with LDB_ASYNC_DONE: %s (%d)",
					       handle->location,
					       ldb_strerror(handle->status),
					       handle->status);
		}
		return handle->status;
	}

	ev = ldb_handle_get_event_context(handle);
	if (NULL == ev) {
		return ldb_oom(handle->ldb);
	}

	switch (type) {
	case LDB_WAIT_NONE:
		ret = tevent_loop_once(ev);
		if (ret != 0) {
			return ldb_operr(handle->ldb);
		}
		if (handle->status == LDB_SUCCESS) {
			return LDB_SUCCESS;
		}
		if (handle->ldb->err_string != NULL) {
			return handle->status;
		}
		/*
		 * if no error string was setup by the backend
		 */
		ldb_asprintf_errstring(handle->ldb,
				       "ldb_wait from %s with LDB_WAIT_NONE: %s (%d)",
				       handle->location,
				       ldb_strerror(handle->status),
				       handle->status);
		return handle->status;

	case LDB_WAIT_ALL:
		while (handle->state != LDB_ASYNC_DONE) {
			ret = tevent_loop_once(ev);
			if (ret != 0) {
				return ldb_operr(handle->ldb);
			}
			if (handle->status != LDB_SUCCESS) {
				if (handle->ldb->err_string != NULL) {
					return handle->status;
				}
				/*
				 * if no error string was setup by the
				 * backend
				 */
				ldb_asprintf_errstring(handle->ldb,
						       "ldb_wait from %s with "
						       "LDB_WAIT_ALL: %s (%d)",
						       handle->location,
						       ldb_strerror(handle->status),
						       handle->status);
				return handle->status;
			}
		}
		if (handle->status == LDB_SUCCESS) {
			return LDB_SUCCESS;
		}
		if (handle->ldb->err_string != NULL) {
			return handle->status;
		}
		/*
		 * if no error string was setup by the backend
		 */
		ldb_asprintf_errstring(handle->ldb,
				       "ldb_wait from %s with LDB_WAIT_ALL,"
				       " LDB_ASYNC_DONE: %s (%d)",
				       handle->location,
				       ldb_strerror(handle->status),
				       handle->status);
		return handle->status;
	}

	return LDB_SUCCESS;
}

/* set the specified timeout or, if timeout is 0 set the default timeout */
int ldb_set_timeout(struct ldb_context *ldb,
		    struct ldb_request *req,
		    int timeout)
{
	if (req == NULL) return LDB_ERR_OPERATIONS_ERROR;

	if (timeout != 0) {
		req->timeout = timeout;
	} else {
		req->timeout = ldb->default_timeout;
	}
	req->starttime = time(NULL);

	return LDB_SUCCESS;
}

/* calculates the new timeout based on the previous starttime and timeout */
int ldb_set_timeout_from_prev_req(struct ldb_context *ldb,
				  struct ldb_request *oldreq,
				  struct ldb_request *newreq)
{
	if (newreq == NULL) return LDB_ERR_OPERATIONS_ERROR;

	if (oldreq == NULL) {
		return ldb_set_timeout(ldb, newreq, 0);
	}

	newreq->starttime = oldreq->starttime;
	newreq->timeout = oldreq->timeout;

	return LDB_SUCCESS;
}


struct ldb_handle *ldb_handle_new(TALLOC_CTX *mem_ctx, struct ldb_context *ldb)
{
	struct ldb_handle *h;

	h = talloc_zero(mem_ctx, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return NULL;
	}

	h->status = LDB_SUCCESS;
	h->state = LDB_ASYNC_INIT;
	h->ldb = ldb;
	h->flags = 0;
	h->location = NULL;
	h->parent = NULL;

	if (h->ldb->require_private_event_context == true) {
		h->event_context = tevent_context_init(h);
		if (h->event_context == NULL) {
			ldb_set_errstring(ldb,
					  "Out of Memory allocating "
					  "event context for new handle");
			return NULL;
		}
		tevent_set_debug(h->event_context, ldb_tevent_debug, ldb);
		tevent_set_max_debug_level(h->event_context, TEVENT_DEBUG_TRACE);
		tevent_loop_allow_nesting(h->event_context);
	}

	return h;
}

static struct ldb_handle *ldb_handle_new_child(TALLOC_CTX *mem_ctx,
					       struct ldb_request *parent_req)
{
	struct ldb_handle *h;

	h = talloc_zero(mem_ctx, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(parent_req->handle->ldb,
				  "Out of Memory");
		return NULL;
	}

	h->status = LDB_SUCCESS;
	h->state = LDB_ASYNC_INIT;
	h->ldb = parent_req->handle->ldb;
	h->parent = parent_req;
	h->nesting = parent_req->handle->nesting + 1;
	h->flags = parent_req->handle->flags;
	h->custom_flags = parent_req->handle->custom_flags;
	h->event_context = parent_req->handle->event_context;

	return h;
}

/*
   set the permissions for new files to be passed to open() in
   backends that use local files
 */
void ldb_set_create_perms(struct ldb_context *ldb, unsigned int perms)
{
	ldb->create_perms = perms;
}

unsigned int ldb_get_create_perms(struct ldb_context *ldb)
{
	return ldb->create_perms;
}

void ldb_set_event_context(struct ldb_context *ldb, struct tevent_context *ev)
{
	ldb->ev_ctx = ev;
}

struct tevent_context * ldb_get_event_context(struct ldb_context *ldb)
{
	return ldb->ev_ctx;
}

void ldb_request_set_state(struct ldb_request *req, int state)
{
	req->handle->state = state;
}

int ldb_request_get_status(struct ldb_request *req)
{
	return req->handle->status;
}

/*
 * This function obtains the private event context for the handle,
 * which may have been created to avoid nested event loops during
 * ldb_tdb with the locks held
 */
struct tevent_context *ldb_handle_get_event_context(struct ldb_handle *handle)
{
	if (handle->event_context != NULL) {
		return handle->event_context;
	}
	return ldb_get_event_context(handle->ldb);
}

/*
 * This function forces a specific ldb handle to use the global event
 * context.  This allows a nested event loop to operate, so any open
 * transaction also needs to be aborted.
 *
 * Any events on this event context will be lost
 *
 * This is used in Samba when sending an IRPC to another part of the
 * same process instead of making a local DB modification.
 */
void ldb_handle_use_global_event_context(struct ldb_handle *handle)
{
	TALLOC_FREE(handle->event_context);
}

void ldb_set_require_private_event_context(struct ldb_context *ldb)
{
	ldb->require_private_event_context = true;
}

/*
  trace a ldb request
*/
static void ldb_trace_request(struct ldb_context *ldb, struct ldb_request *req)
{
	TALLOC_CTX *tmp_ctx = talloc_new(req);
	unsigned int i;
	struct ldb_ldif ldif;

	switch (req->operation) {
	case LDB_SEARCH:
		ldb_debug_add(ldb, "ldb_trace_request: SEARCH\n");
		ldb_debug_add(ldb, " dn: %s\n",
			      ldb_dn_is_null(req->op.search.base)?"<rootDSE>":
			      ldb_dn_get_linearized(req->op.search.base));
		ldb_debug_add(ldb, " scope: %s\n",
			  req->op.search.scope==LDB_SCOPE_BASE?"base":
			  req->op.search.scope==LDB_SCOPE_ONELEVEL?"one":
			  req->op.search.scope==LDB_SCOPE_SUBTREE?"sub":"UNKNOWN");
		ldb_debug_add(ldb, " expr: %s\n",
			  ldb_filter_from_tree(tmp_ctx, req->op.search.tree));
		if (req->op.search.attrs == NULL) {
			ldb_debug_add(ldb, " attr: <ALL>\n");
		} else {
			for (i=0; req->op.search.attrs[i]; i++) {
				ldb_debug_add(ldb, " attr: %s\n", req->op.search.attrs[i]);
			}
		}
		break;
	case LDB_DELETE:
		ldb_debug_add(ldb, "ldb_trace_request: DELETE\n");
		ldb_debug_add(ldb, " dn: %s\n",
			      ldb_dn_get_linearized(req->op.del.dn));
		break;
	case LDB_RENAME:
		ldb_debug_add(ldb, "ldb_trace_request: RENAME\n");
		ldb_debug_add(ldb, " olddn: %s\n",
			      ldb_dn_get_linearized(req->op.rename.olddn));
		ldb_debug_add(ldb, " newdn: %s\n",
			      ldb_dn_get_linearized(req->op.rename.newdn));
		break;
	case LDB_EXTENDED:
		ldb_debug_add(ldb, "ldb_trace_request: EXTENDED\n");
		ldb_debug_add(ldb, " oid: %s\n", req->op.extended.oid);
		ldb_debug_add(ldb, " data: %s\n", req->op.extended.data?"yes":"no");
		break;
	case LDB_ADD:
		ldif.changetype = LDB_CHANGETYPE_ADD;
		ldif.msg = discard_const_p(struct ldb_message, req->op.add.message);

		ldb_debug_add(ldb, "ldb_trace_request: ADD\n");

		/*
		 * The choice to call
		 * ldb_ldif_write_redacted_trace_string() is CRITICAL
		 * for security.  It ensures that we do not output
		 * passwords into debug logs
		 */

		ldb_debug_add(req->handle->ldb, "%s\n",
			      ldb_ldif_write_redacted_trace_string(req->handle->ldb, tmp_ctx, &ldif));
		break;
	case LDB_MODIFY:
		ldif.changetype = LDB_CHANGETYPE_MODIFY;
		ldif.msg = discard_const_p(struct ldb_message, req->op.mod.message);

		ldb_debug_add(ldb, "ldb_trace_request: MODIFY\n");

		/*
		 * The choice to call
		 * ldb_ldif_write_redacted_trace_string() is CRITICAL
		 * for security.  It ensures that we do not output
		 * passwords into debug logs
		 */

		ldb_debug_add(req->handle->ldb, "%s\n",
			      ldb_ldif_write_redacted_trace_string(req->handle->ldb, tmp_ctx, &ldif));
		break;
	case LDB_REQ_REGISTER_CONTROL:
		ldb_debug_add(ldb, "ldb_trace_request: REGISTER_CONTROL\n");
		ldb_debug_add(req->handle->ldb, "%s\n",
			      req->op.reg_control.oid);
		break;
	case LDB_REQ_REGISTER_PARTITION:
		ldb_debug_add(ldb, "ldb_trace_request: REGISTER_PARTITION\n");
		ldb_debug_add(req->handle->ldb, "%s\n",
			      ldb_dn_get_linearized(req->op.reg_partition.dn));
		break;
	default:
		ldb_debug_add(ldb, "ldb_trace_request: UNKNOWN(%u)\n",
			      req->operation);
		break;
	}

	if (req->controls == NULL) {
		ldb_debug_add(ldb, " control: <NONE>\n");
	} else {
		for (i=0; req->controls && req->controls[i]; i++) {
			if (req->controls[i]->oid) {
				ldb_debug_add(ldb, " control: %s  crit:%u  data:%s\n",
					      req->controls[i]->oid,
					      req->controls[i]->critical,
					      req->controls[i]->data?"yes":"no");
			}
		}
	}

	ldb_debug_end(ldb, LDB_DEBUG_TRACE);

	talloc_free(tmp_ctx);
}

/*
  check that the element flags don't have any internal bits set
 */
static int ldb_msg_check_element_flags(struct ldb_context *ldb,
				       const struct ldb_message *message)
{
	unsigned i;
	for (i=0; i<message->num_elements; i++) {
		if (message->elements[i].flags & LDB_FLAG_INTERNAL_MASK) {
			ldb_asprintf_errstring(ldb, "Invalid element flags 0x%08x on element %s in %s\n",
					       message->elements[i].flags, message->elements[i].name,
					       ldb_dn_get_linearized(message->dn));
			return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
		}
	}
	return LDB_SUCCESS;
}

/*
 * This context allows us to make the unlock be a talloc destructor
 *
 * This ensures that a request started, but not waited on, will still
 * unlock.
 */
struct ldb_db_lock_context {
	struct ldb_request *req;
	struct ldb_context *ldb;
};

/*
 * We have to have the unlock on a destructor so that we unlock the
 * DB if a caller calls talloc_free(req).  We trust that the ldb
 * context has not already gone away.
 */
static int ldb_db_lock_destructor(struct ldb_db_lock_context *lock_context)
{
	int ret;
	struct ldb_module *next_module;
	FIRST_OP_NOERR(lock_context->ldb, read_unlock);
	if (next_module != NULL) {
		ret = next_module->ops->read_unlock(next_module);
	} else {
		ret = LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		ldb_debug(lock_context->ldb,
			  LDB_DEBUG_FATAL,
			  "Failed to unlock db: %s / %s",
			  ldb_errstring(lock_context->ldb),
			  ldb_strerror(ret));
	}
	return 0;
}

static int ldb_lock_backend_callback(struct ldb_request *req,
				     struct ldb_reply *ares)
{
	struct ldb_db_lock_context *lock_context;
	int ret;

	if (req->context == NULL) {
		/*
		 * The usual way to get here is to ignore the return codes
		 * and continuing processing after an error.
		 */
		abort();
	}
	lock_context = talloc_get_type(req->context,
				       struct ldb_db_lock_context);

	if (!ares) {
		return ldb_module_done(lock_context->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS || ares->type == LDB_REPLY_DONE) {
		ret = ldb_module_done(lock_context->req, ares->controls,
				      ares->response, ares->error);
		/*
		 * If this is a LDB_REPLY_DONE or an error, unlock the
		 * DB by calling the destructor on this context
		 */
		TALLOC_FREE(req->context);
		return ret;
	}

	/* Otherwise pass on the callback */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		return ldb_module_send_entry(lock_context->req, ares->message,
					     ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(lock_context->req,
						ares->referral);
	default:
		/* Can't happen */
		return LDB_ERR_OPERATIONS_ERROR;
	}
}

/*
 * Do an ldb_search() with a lock held, but release it if the request
 * is freed with talloc_free()
 */
static int lock_search(struct ldb_module *lock_module, struct ldb_request *req)
{
	/* Used in FIRST_OP_NOERR to find where to send the lock request */
	struct ldb_module *next_module = NULL;
	struct ldb_request *down_req = NULL;
	struct ldb_db_lock_context *lock_context;
	struct ldb_context *ldb = ldb_module_get_ctx(lock_module);
	int ret;

	lock_context = talloc(req, struct ldb_db_lock_context);
	if (lock_context == NULL) {
		return ldb_oom(ldb);
	}

	lock_context->ldb = ldb;
	lock_context->req = req;

	ret = ldb_build_search_req_ex(&down_req, ldb, req,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      req->op.search.attrs,
				      req->controls,
				      lock_context,
				      ldb_lock_backend_callback,
				      req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* call DB lock */
	FIRST_OP_NOERR(ldb, read_lock);
	if (next_module != NULL) {
		ret = next_module->ops->read_lock(next_module);
	} else {
		ret = LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
	}

	if (ret == LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION) {
		/* We might be talking LDAP */
		ldb_reset_err_string(ldb);
		TALLOC_FREE(lock_context);

		return ldb_next_request(lock_module, req);
	} else if ((ret != LDB_SUCCESS) && (ldb->err_string == NULL)) {
		/* if no error string was setup by the backend */
		ldb_asprintf_errstring(ldb, "Failed to get DB lock: %s (%d)",
				       ldb_strerror(ret), ret);
	} else {
		talloc_set_destructor(lock_context, ldb_db_lock_destructor);
	}

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(lock_module, down_req);
}

/*
  start an ldb request
  NOTE: the request must be a talloc context.
  returns LDB_ERR_* on errors.
*/
int ldb_request(struct ldb_context *ldb, struct ldb_request *req)
{
	struct ldb_module *next_module;
	int ret;

	if (req->callback == NULL) {
		ldb_set_errstring(ldb, "Requests MUST define callbacks");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ldb_reset_err_string(ldb);

	if (ldb->flags & LDB_FLG_ENABLE_TRACING) {
		ldb_trace_request(ldb, req);
	}

	/* call the first module in the chain */
	switch (req->operation) {
	case LDB_SEARCH:
	{
		/*
		 * A fake module to allow ldb_next_request() to be
		 * re-used and to keep the locking out of this function.
		 */
		static const struct ldb_module_ops lock_module_ops = {
			.name = "lock_searches",
			.search = lock_search
		};
		struct ldb_module lock_module = {
			.ldb = ldb,
			.next = ldb->modules,
			.ops = &lock_module_ops
		};
		next_module = &lock_module;

		/* due to "ldb_build_search_req" base DN always != NULL */
		if (!ldb_dn_validate(req->op.search.base)) {
			ldb_asprintf_errstring(ldb, "ldb_search: invalid basedn '%s'",
					       ldb_dn_get_linearized(req->op.search.base));
			return LDB_ERR_INVALID_DN_SYNTAX;
		}

		ret = next_module->ops->search(next_module, req);
		break;
	}
	case LDB_ADD:
		if (!ldb_dn_validate(req->op.add.message->dn)) {
			ldb_asprintf_errstring(ldb, "ldb_add: invalid dn '%s'",
					       ldb_dn_get_linearized(req->op.add.message->dn));
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
		/*
		 * we have to normalize here, as so many places
		 * in modules and backends assume we don't have two
		 * elements with the same name
		 */
		ret = ldb_msg_normalize(ldb, req, req->op.add.message,
		                        discard_const(&req->op.add.message));
		if (ret != LDB_SUCCESS) {
			ldb_oom(ldb);
			return ret;
		}
		FIRST_OP(ldb, add);
		ret = ldb_msg_check_element_flags(ldb, req->op.add.message);
		if (ret != LDB_SUCCESS) {
			/*
			 * "ldb_msg_check_element_flags" generates an error
			 * string
			 */
			return ret;
		}
		ret = next_module->ops->add(next_module, req);
		break;
	case LDB_MODIFY:
		if (!ldb_dn_validate(req->op.mod.message->dn)) {
			ldb_asprintf_errstring(ldb, "ldb_modify: invalid dn '%s'",
					       ldb_dn_get_linearized(req->op.mod.message->dn));
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
		FIRST_OP(ldb, modify);
		ret = ldb_msg_check_element_flags(ldb, req->op.mod.message);
		if (ret != LDB_SUCCESS) {
			/*
			 * "ldb_msg_check_element_flags" generates an error
			 * string
			 */
			return ret;
		}
		ret = next_module->ops->modify(next_module, req);
		break;
	case LDB_DELETE:
		if (!ldb_dn_validate(req->op.del.dn)) {
			ldb_asprintf_errstring(ldb, "ldb_delete: invalid dn '%s'",
					       ldb_dn_get_linearized(req->op.del.dn));
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
		FIRST_OP(ldb, del);
		ret = next_module->ops->del(next_module, req);
		break;
	case LDB_RENAME:
		if (!ldb_dn_validate(req->op.rename.olddn)) {
			ldb_asprintf_errstring(ldb, "ldb_rename: invalid olddn '%s'",
					       ldb_dn_get_linearized(req->op.rename.olddn));
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
		if (!ldb_dn_validate(req->op.rename.newdn)) {
			ldb_asprintf_errstring(ldb, "ldb_rename: invalid newdn '%s'",
					       ldb_dn_get_linearized(req->op.rename.newdn));
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
		FIRST_OP(ldb, rename);
		ret = next_module->ops->rename(next_module, req);
		break;
	case LDB_EXTENDED:
		FIRST_OP(ldb, extended);
		ret = next_module->ops->extended(next_module, req);
		break;
	default:
		FIRST_OP(ldb, request);
		ret = next_module->ops->request(next_module, req);
		break;
	}

	if ((ret != LDB_SUCCESS) && (ldb->err_string == NULL)) {
		/* if no error string was setup by the backend */
		ldb_asprintf_errstring(ldb, "ldb_request: %s (%d)",
				       ldb_strerror(ret), ret);
	}

	return ret;
}

int ldb_request_done(struct ldb_request *req, int status)
{
	req->handle->state = LDB_ASYNC_DONE;
	req->handle->status = status;
	return status;
}

/*
  search the database given a LDAP-like search expression

  returns an LDB error code

  Use talloc_free to free the ldb_message returned in 'res', if successful

*/
int ldb_search_default_callback(struct ldb_request *req,
				struct ldb_reply *ares)
{
	struct ldb_result *res;
	unsigned int n;

	res = talloc_get_type(req->context, struct ldb_result);

	if (!ares) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_request_done(req, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		res->msgs = talloc_realloc(res, res->msgs,
					struct ldb_message *, res->count + 2);
		if (! res->msgs) {
			return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
		}

		res->msgs[res->count + 1] = NULL;

		res->msgs[res->count] = talloc_move(res->msgs, &ares->message);
		res->count++;
		break;

	case LDB_REPLY_REFERRAL:
		if (res->refs) {
			for (n = 0; res->refs[n]; n++) /*noop*/ ;
		} else {
			n = 0;
		}

		res->refs = talloc_realloc(res, res->refs, char *, n + 2);
		if (! res->refs) {
			return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
		}

		res->refs[n] = talloc_move(res->refs, &ares->referral);
		res->refs[n + 1] = NULL;
		break;

	case LDB_REPLY_DONE:
		/* TODO: we should really support controls on entries
		 * and referrals too! */
		res->controls = talloc_move(res, &ares->controls);

		/* this is the last message, and means the request is done */
		/* we have to signal and eventual ldb_wait() waiting that the
		 * async request operation was completed */
		talloc_free(ares);
		return ldb_request_done(req, LDB_SUCCESS);
	}

	talloc_free(ares);

	return LDB_SUCCESS;
}

int ldb_modify_default_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_result *res;
	unsigned int n;
	int ret;

	res = talloc_get_type(req->context, struct ldb_result);

	if (!ares) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->error != LDB_SUCCESS) {
		ret = ares->error;
		talloc_free(ares);
		return ldb_request_done(req, ret);
	}

	switch (ares->type) {
	case LDB_REPLY_REFERRAL:
		if (res->refs) {
			for (n = 0; res->refs[n]; n++) /*noop*/ ;
		} else {
			n = 0;
		}

		res->refs = talloc_realloc(res, res->refs, char *, n + 2);
		if (! res->refs) {
			return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
		}

		res->refs[n] = talloc_move(res->refs, &ares->referral);
		res->refs[n + 1] = NULL;
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);
		return ldb_request_done(req, LDB_SUCCESS);
	default:
		talloc_free(ares);
		ldb_asprintf_errstring(req->handle->ldb, "Invalid LDB reply type %d", ares->type);
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);
	return ldb_request_done(req, LDB_SUCCESS);
}

int ldb_op_default_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	int ret;

	if (!ares) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->error != LDB_SUCCESS) {
		ret = ares->error;
		talloc_free(ares);
		return ldb_request_done(req, ret);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_asprintf_errstring(req->handle->ldb, "Invalid LDB reply type %d", ares->type);
		TALLOC_FREE(ares);
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);
	return ldb_request_done(req, LDB_SUCCESS);
}

static struct ldb_request *ldb_build_req_common(TALLOC_CTX *mem_ctx,
				struct ldb_context *ldb,
				struct ldb_control **controls,
				void *context,
				ldb_request_callback_t callback,
				struct ldb_request *parent)
{
	struct ldb_request *req = NULL;

	req = talloc_zero(mem_ctx, struct ldb_request);
	if (req == NULL) {
		return NULL;
	}
	req->controls = controls;
	req->context = context;
	req->callback = callback;

	ldb_set_timeout_from_prev_req(ldb, parent, req);

	if (parent != NULL) {
		req->handle = ldb_handle_new_child(req, parent);
		if (req->handle == NULL) {
			TALLOC_FREE(req);
			return NULL;
		}
	} else {
		req->handle = ldb_handle_new(req, ldb);
		if (req->handle == NULL) {
			TALLOC_FREE(req);
			return NULL;
		}
	}

	return req;
}

int ldb_build_search_req_ex(struct ldb_request **ret_req,
			struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			struct ldb_dn *base,
	       		enum ldb_scope scope,
			struct ldb_parse_tree *tree,
			const char * const *attrs,
			struct ldb_control **controls,
			void *context,
			ldb_request_callback_t callback,
			struct ldb_request *parent)
{
	struct ldb_request *req;

	*ret_req = NULL;

	req = ldb_build_req_common(mem_ctx, ldb, controls,
				   context, callback, parent);
	if (req == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_SEARCH;
	if (base == NULL) {
		req->op.search.base = ldb_dn_new(req, ldb, NULL);
		if (req->op.search.base == NULL) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		req->op.search.base = base;
	}
	req->op.search.scope = scope;

	req->op.search.tree = tree;
	if (req->op.search.tree == NULL) {
		ldb_set_errstring(ldb, "'tree' can't be NULL");
		talloc_free(req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->op.search.attrs = attrs;
	*ret_req = req;
	return LDB_SUCCESS;
}

int ldb_build_search_req(struct ldb_request **ret_req,
			struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			struct ldb_dn *base,
			enum ldb_scope scope,
			const char *expression,
			const char * const *attrs,
			struct ldb_control **controls,
			void *context,
			ldb_request_callback_t callback,
			struct ldb_request *parent)
{
	struct ldb_parse_tree *tree;
	int ret;

	tree = ldb_parse_tree(mem_ctx, expression);
	if (tree == NULL) {
		ldb_set_errstring(ldb, "Unable to parse search expression");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req_ex(ret_req, ldb, mem_ctx, base,
				      scope, tree, attrs, controls,
				      context, callback, parent);
	if (ret == LDB_SUCCESS) {
		talloc_steal(*ret_req, tree);
	}
	return ret;
}

int ldb_build_add_req(struct ldb_request **ret_req,
			struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			const struct ldb_message *message,
			struct ldb_control **controls,
			void *context,
			ldb_request_callback_t callback,
			struct ldb_request *parent)
{
	struct ldb_request *req;

	*ret_req = NULL;

	req = ldb_build_req_common(mem_ctx, ldb, controls,
				   context, callback, parent);
	if (req == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_ADD;
	req->op.add.message = message;
	*ret_req = req;
	return LDB_SUCCESS;
}

int ldb_build_mod_req(struct ldb_request **ret_req,
			struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			const struct ldb_message *message,
			struct ldb_control **controls,
			void *context,
			ldb_request_callback_t callback,
			struct ldb_request *parent)
{
	struct ldb_request *req;

	*ret_req = NULL;

	req = ldb_build_req_common(mem_ctx, ldb, controls,
				   context, callback, parent);
	if (req == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_MODIFY;
	req->op.mod.message = message;

	*ret_req = req;
	return LDB_SUCCESS;
}

int ldb_build_del_req(struct ldb_request **ret_req,
			struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			struct ldb_dn *dn,
			struct ldb_control **controls,
			void *context,
			ldb_request_callback_t callback,
			struct ldb_request *parent)
{
	struct ldb_request *req;

	*ret_req = NULL;

	req = ldb_build_req_common(mem_ctx, ldb, controls,
				   context, callback, parent);
	if (req == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_DELETE;
	req->op.del.dn = dn;
	*ret_req = req;
	return LDB_SUCCESS;
}

int ldb_build_rename_req(struct ldb_request **ret_req,
			struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			struct ldb_dn *olddn,
			struct ldb_dn *newdn,
			struct ldb_control **controls,
			void *context,
			ldb_request_callback_t callback,
			struct ldb_request *parent)
{
	struct ldb_request *req;

	*ret_req = NULL;

	req = ldb_build_req_common(mem_ctx, ldb, controls,
				   context, callback, parent);
	if (req == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_RENAME;
	req->op.rename.olddn = olddn;
	req->op.rename.newdn = newdn;
	*ret_req = req;
	return LDB_SUCCESS;
}

int ldb_extended_default_callback(struct ldb_request *req,
				  struct ldb_reply *ares)
{
	struct ldb_result *res;

	res = talloc_get_type(req->context, struct ldb_result);

	if (!ares) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_request_done(req, ares->error);
	}

	if (ares->type == LDB_REPLY_DONE) {

		/* TODO: we should really support controls on entries and referrals too! */
		res->extended = talloc_move(res, &ares->response);
		res->controls = talloc_move(res, &ares->controls);

		talloc_free(ares);
		return ldb_request_done(req, LDB_SUCCESS);
	}

	talloc_free(ares);
	ldb_asprintf_errstring(req->handle->ldb, "Invalid LDB reply type %d", ares->type);
	return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
}

int ldb_build_extended_req(struct ldb_request **ret_req,
			   struct ldb_context *ldb,
			   TALLOC_CTX *mem_ctx,
			   const char *oid,
			   void *data,
			   struct ldb_control **controls,
			   void *context,
			   ldb_request_callback_t callback,
			   struct ldb_request *parent)
{
	struct ldb_request *req;

	*ret_req = NULL;

	req = ldb_build_req_common(mem_ctx, ldb, controls,
				   context, callback, parent);
	if (req == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_EXTENDED;
	req->op.extended.oid = oid;
	req->op.extended.data = data;
	*ret_req = req;
	return LDB_SUCCESS;
}

int ldb_extended(struct ldb_context *ldb,
		 const char *oid,
		 void *data,
		 struct ldb_result **_res)
{
	struct ldb_request *req;
	int ret;
	struct ldb_result *res;

	*_res = NULL;
	req = NULL;

	res = talloc_zero(ldb, struct ldb_result);
	if (!res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_extended_req(&req, ldb, ldb,
				     oid, data, NULL,
				     res, ldb_extended_default_callback,
				     NULL);
	ldb_req_set_location(req, "ldb_extended");

	if (ret != LDB_SUCCESS) goto done;

	ldb_set_timeout(ldb, req, 0); /* use default timeout */

	ret = ldb_request(ldb, req);

	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

done:
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		res = NULL;
	}

	talloc_free(req);

	*_res = res;
	return ret;
}

/*
  note that ldb_search() will automatically replace a NULL 'base' value
  with the defaultNamingContext from the rootDSE if available.
*/
int ldb_search(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
		struct ldb_result **result, struct ldb_dn *base,
		enum ldb_scope scope, const char * const *attrs,
		const char *exp_fmt, ...)
{
	struct ldb_request *req;
	struct ldb_result *res;
	char *expression;
	va_list ap;
	int ret;

	expression = NULL;
	*result = NULL;
	req = NULL;

	res = talloc_zero(mem_ctx, struct ldb_result);
	if (!res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (exp_fmt) {
		va_start(ap, exp_fmt);
		expression = talloc_vasprintf(mem_ctx, exp_fmt, ap);
		va_end(ap);

		if (!expression) {
			talloc_free(res);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	ret = ldb_build_search_req(&req, ldb, mem_ctx,
					base?base:ldb_get_default_basedn(ldb),
	       				scope,
					expression,
					attrs,
					NULL,
					res,
					ldb_search_default_callback,
					NULL);
	ldb_req_set_location(req, "ldb_search");

	if (ret != LDB_SUCCESS) goto done;

	ret = ldb_request(ldb, req);

	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

done:
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		res = NULL;
	}

	talloc_free(expression);
	talloc_free(req);

	*result = res;
	return ret;
}

/*
  add a record to the database. Will fail if a record with the given class
  and key already exists
*/
int ldb_add(struct ldb_context *ldb,
	    const struct ldb_message *message)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_msg_sanity_check(ldb, message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_add_req(&req, ldb, ldb,
					message,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
	ldb_req_set_location(req, "ldb_add");

	if (ret != LDB_SUCCESS) return ret;

	/* do request and autostart a transaction */
	ret = ldb_autotransaction_request(ldb, req);

	talloc_free(req);
	return ret;
}

/*
  modify the specified attributes of a record
*/
int ldb_modify(struct ldb_context *ldb,
	       const struct ldb_message *message)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_msg_sanity_check(ldb, message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_mod_req(&req, ldb, ldb,
					message,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
	ldb_req_set_location(req, "ldb_modify");

	if (ret != LDB_SUCCESS) return ret;

	/* do request and autostart a transaction */
	ret = ldb_autotransaction_request(ldb, req);

	talloc_free(req);
	return ret;
}


/*
  delete a record from the database
*/
int ldb_delete(struct ldb_context *ldb, struct ldb_dn *dn)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_build_del_req(&req, ldb, ldb,
					dn,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
	ldb_req_set_location(req, "ldb_delete");

	if (ret != LDB_SUCCESS) return ret;

	/* do request and autostart a transaction */
	ret = ldb_autotransaction_request(ldb, req);

	talloc_free(req);
	return ret;
}

/*
  rename a record in the database
*/
int ldb_rename(struct ldb_context *ldb,
		struct ldb_dn *olddn, struct ldb_dn *newdn)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_build_rename_req(&req, ldb, ldb,
					olddn,
					newdn,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
	ldb_req_set_location(req, "ldb_rename");

	if (ret != LDB_SUCCESS) return ret;

	/* do request and autostart a transaction */
	ret = ldb_autotransaction_request(ldb, req);

	talloc_free(req);
	return ret;
}


/*
  return the global sequence number
*/
int ldb_sequence_number(struct ldb_context *ldb,
			enum ldb_sequence_type type, uint64_t *seq_num)
{
	struct ldb_seqnum_request *seq;
	struct ldb_seqnum_result *seqr;
	struct ldb_result *res;
	TALLOC_CTX *tmp_ctx;
	int ret;

	*seq_num = 0;

	tmp_ctx = talloc_zero(ldb, struct ldb_request);
	if (tmp_ctx == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	seq = talloc_zero(tmp_ctx, struct ldb_seqnum_request);
	if (seq == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	seq->type = type;

	ret = ldb_extended(ldb, LDB_EXTENDED_SEQUENCE_NUMBER, seq, &res);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	talloc_steal(tmp_ctx, res);

	if (strcmp(LDB_EXTENDED_SEQUENCE_NUMBER, res->extended->oid) != 0) {
		ldb_set_errstring(ldb, "Invalid OID in reply");
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	seqr = talloc_get_type(res->extended->data,
				struct ldb_seqnum_result);
	*seq_num = seqr->seq_num;

done:
	talloc_free(tmp_ctx);
	return ret;
}

/*
  return extended error information
*/
const char *ldb_errstring(struct ldb_context *ldb)
{
	return ldb->err_string;
}

/*
  return a string explaining what a ldb error constant means
*/
const char *ldb_strerror(int ldb_err)
{
	switch (ldb_err) {
	case LDB_SUCCESS:
		return "Success";
	case LDB_ERR_OPERATIONS_ERROR:
		return "Operations error";
	case LDB_ERR_PROTOCOL_ERROR:
		return "Protocol error";
	case LDB_ERR_TIME_LIMIT_EXCEEDED:
		return "Time limit exceeded";
	case LDB_ERR_SIZE_LIMIT_EXCEEDED:
		return "Size limit exceeded";
	case LDB_ERR_COMPARE_FALSE:
		return "Compare false";
	case LDB_ERR_COMPARE_TRUE:
		return "Compare true";
	case LDB_ERR_AUTH_METHOD_NOT_SUPPORTED:
		return "Auth method not supported";
	case LDB_ERR_STRONG_AUTH_REQUIRED:
		return "Strong auth required";
/* 9 RESERVED */
	case LDB_ERR_REFERRAL:
		return "Referral error";
	case LDB_ERR_ADMIN_LIMIT_EXCEEDED:
		return "Admin limit exceeded";
	case LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION:
		return "Unsupported critical extension";
	case LDB_ERR_CONFIDENTIALITY_REQUIRED:
		return "Confidentiality required";
	case LDB_ERR_SASL_BIND_IN_PROGRESS:
		return "SASL bind in progress";
	case LDB_ERR_NO_SUCH_ATTRIBUTE:
		return "No such attribute";
	case LDB_ERR_UNDEFINED_ATTRIBUTE_TYPE:
		return "Undefined attribute type";
	case LDB_ERR_INAPPROPRIATE_MATCHING:
		return "Inappropriate matching";
	case LDB_ERR_CONSTRAINT_VIOLATION:
		return "Constraint violation";
	case LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS:
		return "Attribute or value exists";
	case LDB_ERR_INVALID_ATTRIBUTE_SYNTAX:
		return "Invalid attribute syntax";
/* 22-31 unused */
	case LDB_ERR_NO_SUCH_OBJECT:
		return "No such object";
	case LDB_ERR_ALIAS_PROBLEM:
		return "Alias problem";
	case LDB_ERR_INVALID_DN_SYNTAX:
		return "Invalid DN syntax";
/* 35 RESERVED */
	case LDB_ERR_ALIAS_DEREFERENCING_PROBLEM:
		return "Alias dereferencing problem";
/* 37-47 unused */
	case LDB_ERR_INAPPROPRIATE_AUTHENTICATION:
		return "Inappropriate authentication";
	case LDB_ERR_INVALID_CREDENTIALS:
		return "Invalid credentials";
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return "insufficient access rights";
	case LDB_ERR_BUSY:
		return "Busy";
	case LDB_ERR_UNAVAILABLE:
		return "Unavailable";
	case LDB_ERR_UNWILLING_TO_PERFORM:
		return "Unwilling to perform";
	case LDB_ERR_LOOP_DETECT:
		return "Loop detect";
/* 55-63 unused */
	case LDB_ERR_NAMING_VIOLATION:
		return "Naming violation";
	case LDB_ERR_OBJECT_CLASS_VIOLATION:
		return "Object class violation";
	case LDB_ERR_NOT_ALLOWED_ON_NON_LEAF:
		return "Not allowed on non-leaf";
	case LDB_ERR_NOT_ALLOWED_ON_RDN:
		return "Not allowed on RDN";
	case LDB_ERR_ENTRY_ALREADY_EXISTS:
		return "Entry already exists";
	case LDB_ERR_OBJECT_CLASS_MODS_PROHIBITED:
		return "Object class mods prohibited";
/* 70 RESERVED FOR CLDAP */
	case LDB_ERR_AFFECTS_MULTIPLE_DSAS:
		return "Affects multiple DSAs";
/* 72-79 unused */
	case LDB_ERR_OTHER:
		return "Other";
	}

	return "Unknown error";
}

/*
  set backend specific opaque parameters
*/
int ldb_set_opaque(struct ldb_context *ldb, const char *name, void *value)
{
	struct ldb_opaque *o;

	/* allow updating an existing value */
	for (o=ldb->opaque;o;o=o->next) {
		if (strcmp(o->name, name) == 0) {
			o->value = value;
			return LDB_SUCCESS;
		}
	}

	o = talloc(ldb, struct ldb_opaque);
	if (o == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OTHER;
	}
	o->next = ldb->opaque;
	o->name = name;
	o->value = value;
	ldb->opaque = o;
	return LDB_SUCCESS;
}

/*
  get a previously set opaque value
*/
void *ldb_get_opaque(struct ldb_context *ldb, const char *name)
{
	struct ldb_opaque *o;
	for (o=ldb->opaque;o;o=o->next) {
		if (strcmp(o->name, name) == 0) {
			return o->value;
		}
	}
	return NULL;
}

int ldb_global_init(void)
{
	/* Provided for compatibility with some older versions of ldb */
	return 0;
}

/* return the ldb flags */
unsigned int ldb_get_flags(struct ldb_context *ldb)
{
	return ldb->flags;
}

/* set the ldb flags */
void ldb_set_flags(struct ldb_context *ldb, unsigned flags)
{
	ldb->flags = flags;
}


/*
  set the location in a ldb request. Used for debugging
 */
void ldb_req_set_location(struct ldb_request *req, const char *location)
{
	if (req && req->handle) {
		req->handle->location = location;
	}
}

/*
  return the location set with dsdb_req_set_location
 */
const char *ldb_req_location(struct ldb_request *req)
{
	return req->handle->location;
}

/**
  mark a request as untrusted. This tells the rootdse module to remove
  unregistered controls
 */
void ldb_req_mark_untrusted(struct ldb_request *req)
{
	req->handle->flags |= LDB_HANDLE_FLAG_UNTRUSTED;
}

/**
  mark a request as trusted.
 */
void ldb_req_mark_trusted(struct ldb_request *req)
{
	req->handle->flags &= ~LDB_HANDLE_FLAG_UNTRUSTED;
}

/**
  set custom flags. Those flags are set by applications using ldb,
  they are application dependent and the same bit can have different
  meaning in different application.
 */
void ldb_req_set_custom_flags(struct ldb_request *req, uint32_t flags)
{
	if (req != NULL && req->handle != NULL) {
		req->handle->custom_flags = flags;
	}
}


/**
  get custom flags. Those flags are set by applications using ldb,
  they are application dependent and the same bit can have different
  meaning in different application.
 */
uint32_t ldb_req_get_custom_flags(struct ldb_request *req)
{
	if (req != NULL && req->handle != NULL) {
		return req->handle->custom_flags;
	}

	/*
	 * 0 is not something any better or worse than
	 * anything else as req or the handle is NULL
	 */
	return 0;
}


/**
 * return true if a request is untrusted
 */
bool ldb_req_is_untrusted(struct ldb_request *req)
{
	return (req->handle->flags & LDB_HANDLE_FLAG_UNTRUSTED) != 0;
}
