/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2005

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

#include "ldb_tdb.h"
#include "dlinklist.h"

static void ltdb_log_fn(struct tdb_context *tdb, enum tdb_debug_level level, const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);
static void ltdb_log_fn(struct tdb_context *tdb, enum tdb_debug_level level, const char *fmt, ...)
{
	va_list ap;
	const char *name = tdb_name(tdb);
	struct ldb_context *ldb = talloc_get_type(tdb_get_logging_private(tdb), struct ldb_context);
	enum ldb_debug_level ldb_level;
	char *message; 

	if (ldb == NULL)
		return;

	va_start(ap, fmt);
	message = talloc_vasprintf(ldb, fmt, ap);
	va_end(ap);

	switch (level) {
	case TDB_DEBUG_FATAL:
		ldb_level = LDB_DEBUG_FATAL;
		break;
	case TDB_DEBUG_ERROR:
		ldb_level = LDB_DEBUG_ERROR;
		break;
	case TDB_DEBUG_WARNING:
		ldb_level = LDB_DEBUG_WARNING;
		break;
	case TDB_DEBUG_TRACE:
		ldb_level = LDB_DEBUG_TRACE;
		break;
	default:
		ldb_level = LDB_DEBUG_FATAL;
	}

	ldb_debug(ldb, ldb_level, "ltdb: tdb(%s): %s", name, message);
	talloc_free(message);
}

/*
  the purpose of this code is to work around the braindead posix locking
  rules, to allow us to have a ldb open more than once while allowing
  locking to work

  TDB2 handles multiple opens, so we don't have this problem there.
*/

struct ltdb_wrap {
	struct ltdb_wrap *next, *prev;
	struct tdb_context *tdb;
	dev_t device;
	ino_t inode;
	pid_t pid;
};

static struct ltdb_wrap *tdb_list;

/* destroy the last connection to a tdb */
static int ltdb_wrap_destructor(struct ltdb_wrap *w)
{
	tdb_close(w->tdb);
	DLIST_REMOVE(tdb_list, w);
	return 0;
}

/*
  wrapped connection to a tdb database. The caller should _not_ free
  this as it is not a talloc structure (as tdb does not use talloc
  yet). It will auto-close when the caller frees the mem_ctx that is
  passed to this call
 */
struct tdb_context *ltdb_wrap_open(TALLOC_CTX *mem_ctx,
				   const char *path, int hash_size, 
				   int tdb_flags,
				   int open_flags, mode_t mode, 
				   struct ldb_context *ldb)
{
	struct ltdb_wrap *w;
	struct tdb_logging_context lctx;
	struct stat st;

	if (path != NULL && stat(path, &st) == 0) {
		for (w=tdb_list;w;w=w->next) {
			if (st.st_dev == w->device && st.st_ino == w->inode) {
				pid_t pid = getpid();
				int ret;
				if (!talloc_reference(mem_ctx, w)) {
					return NULL;
				}
				if (w->pid != pid) {
					ret = tdb_reopen(w->tdb);
					if (ret != 0) {
						/*
						 * Avoid use-after-free:
						 * on fail the TDB
						 * is closed!
						 */
						DLIST_REMOVE(tdb_list,
							     w);
						return NULL;
					}
					w->pid = pid;
				}
				return w->tdb;
			}
		}
	}

	w = talloc(mem_ctx, struct ltdb_wrap);
	if (w == NULL) {
		return NULL;
	}

	lctx.log_fn = ltdb_log_fn;
	lctx.log_private = ldb;
	w->tdb = tdb_open_ex(path, hash_size, tdb_flags, open_flags, mode,
			     &lctx, NULL);
	if (w->tdb == NULL) {
		talloc_free(w);
		return NULL;
	}

	if (fstat(tdb_fd(w->tdb), &st) != 0) {
		tdb_close(w->tdb);
		talloc_free(w);
		return NULL;
	}

	w->device = st.st_dev;
	w->inode  = st.st_ino;
	w->pid    = getpid();

	talloc_set_destructor(w, ltdb_wrap_destructor);

	DLIST_ADD(tdb_list, w);
	
	return w->tdb;
}
