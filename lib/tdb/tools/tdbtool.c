/*
   Unix SMB/CIFS implementation.
   Samba database functions
   Copyright (C) Andrew Tridgell              1999-2000
   Copyright (C) Paul `Rusty' Russell		   2000
   Copyright (C) Jeremy Allison			   2000
   Copyright (C) Andrew Esh                        2001

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

#include "replace.h"
#include "system/locale.h"
#include "system/time.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "tdb.h"

static int do_command(void);
const char *cmdname;
char *arg1, *arg2;
size_t arg1len, arg2len;
int bIterate = 0;
char *line;
TDB_DATA iterate_kbuf;
char cmdline[1024];
static int disable_mmap;
static int _disable_lock;

enum commands {
	CMD_CREATE_TDB,
	CMD_OPEN_TDB,
	CMD_TRANSACTION_START,
	CMD_TRANSACTION_COMMIT,
	CMD_TRANSACTION_CANCEL,
	CMD_ERASE,
	CMD_DUMP,
	CMD_INSERT,
	CMD_MOVE,
	CMD_STOREHEX,
	CMD_STORE,
	CMD_SHOW,
	CMD_KEYS,
	CMD_HEXKEYS,
	CMD_DELETE,
	CMD_LIST_HASH_FREE,
	CMD_LIST_FREE,
	CMD_FREELIST_SIZE,
	CMD_INFO,
	CMD_MMAP,
	CMD_SPEED,
	CMD_FIRST,
	CMD_NEXT,
	CMD_SYSTEM,
	CMD_CHECK,
	CMD_REPACK,
	CMD_QUIT,
	CMD_HELP
};

typedef struct {
	const char *name;
	enum commands cmd;
} COMMAND_TABLE;

COMMAND_TABLE cmd_table[] = {
	{"create",	CMD_CREATE_TDB},
	{"open",	CMD_OPEN_TDB},
	{"transaction_start",	CMD_TRANSACTION_START},
	{"transaction_commit",	CMD_TRANSACTION_COMMIT},
	{"transaction_cancel",	CMD_TRANSACTION_CANCEL},
	{"erase",	CMD_ERASE},
	{"dump",	CMD_DUMP},
	{"insert",	CMD_INSERT},
	{"move",	CMD_MOVE},
	{"storehex",	CMD_STOREHEX},
	{"store",	CMD_STORE},
	{"show",	CMD_SHOW},
	{"keys",	CMD_KEYS},
	{"hexkeys",	CMD_HEXKEYS},
	{"delete",	CMD_DELETE},
	{"list",	CMD_LIST_HASH_FREE},
	{"free",	CMD_LIST_FREE},
	{"freelist_size",	CMD_FREELIST_SIZE},
	{"info",	CMD_INFO},
	{"speed",	CMD_SPEED},
	{"mmap",	CMD_MMAP},
	{"first",	CMD_FIRST},
	{"1",		CMD_FIRST},
	{"next",	CMD_NEXT},
	{"n",		CMD_NEXT},
	{"check",	CMD_CHECK},
	{"quit",	CMD_QUIT},
	{"q",		CMD_QUIT},
	{"!",		CMD_SYSTEM},
	{"repack",	CMD_REPACK},
	{NULL,		CMD_HELP}
};

struct timeval tp1,tp2;

static void _start_timer(void)
{
	gettimeofday(&tp1,NULL);
}

static double _end_timer(void)
{
	gettimeofday(&tp2,NULL);
	return((tp2.tv_sec - tp1.tv_sec) +
	       (tp2.tv_usec - tp1.tv_usec)*1.0e-6);
}

#ifdef PRINTF_ATTRIBUTE
static void tdb_log_open(struct tdb_context *tdb, enum tdb_debug_level level,
			 const char *format, ...) PRINTF_ATTRIBUTE(3,4);
#endif
static void tdb_log_open(struct tdb_context *tdb, enum tdb_debug_level level,
			 const char *format, ...)
{
	const char *mutex_msg =
		"Can use mutexes only with MUTEX_LOCKING or NOLOCK\n";
	char *p;
	va_list ap;

	p = strstr(format, mutex_msg);
	if (p != NULL) {
		/*
		 * Yes, this is a hack, but we don't want to see this
		 * message on first open, but we want to see
		 * everything else.
		 */
		return;
	}

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

#ifdef PRINTF_ATTRIBUTE
static void tdb_log(struct tdb_context *tdb, enum tdb_debug_level level, const char *format, ...) PRINTF_ATTRIBUTE(3,4);
#endif
static void tdb_log(struct tdb_context *tdb, enum tdb_debug_level level, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

/* a tdb tool for manipulating a tdb database */

static TDB_CONTEXT *tdb;

static int print_rec(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state);
static int print_key(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state);
static int print_hexkey(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state);

static void print_asc(const char *buf,int len)
{
	int i;

	/* We're probably printing ASCII strings so don't try to display
	   the trailing NULL character. */

	if (buf[len - 1] == 0)
	        len--;

	for (i=0;i<len;i++)
		printf("%c",isprint(buf[i])?buf[i]:'.');
}

static void print_data(const char *buf,int len)
{
	int i=0;
	if (len<=0) return;
	printf("[%03X] ",i);
	for (i=0;i<len;) {
		printf("%02X ",(int)((unsigned char)buf[i]));
		i++;
		if (i%8 == 0) printf(" ");
		if (i%16 == 0) {
			print_asc(&buf[i-16],8); printf(" ");
			print_asc(&buf[i-8],8); printf("\n");
			if (i<len) printf("[%03X] ",i);
		}
	}
	if (i%16) {
		int n;

		n = 16 - (i%16);
		printf(" ");
		if (n>8) printf(" ");
		while (n--) printf("   ");

		n = i%16;
		if (n > 8) n = 8;
		print_asc(&buf[i-(i%16)],n); printf(" ");
		n = (i%16) - n;
		if (n>0) print_asc(&buf[i-n],n);
		printf("\n");
	}
}

static void help(void)
{
	printf("\n"
"tdbtool: \n"
"  create    dbname     : create a database\n"
"  open      dbname     : open an existing database\n"
"  transaction_start    : start a transaction\n"
"  transaction_commit   : commit a transaction\n"
"  transaction_cancel   : cancel a transaction\n"
"  erase                : erase the database\n"
"  dump                 : dump the database as strings\n"
"  keys                 : dump the database keys as strings\n"
"  hexkeys              : dump the database keys as hex values\n"
"  info                 : print summary info about the database\n"
"  insert    key  data  : insert a record\n"
"  move      key  file  : move a record to a destination tdb\n"
"  storehex  key  data  : store a record (replace), key/value in hex format\n"
"  store     key  data  : store a record (replace)\n"
"  show      key        : show a record by key\n"
"  delete    key        : delete a record by key\n"
"  list                 : print the database hash table and freelist\n"
"  free                 : print the database freelist\n"
"  freelist_size        : print the number of records in the freelist\n"
"  check                : check the integrity of an opened database\n"
"  repack               : repack the database\n"
"  speed                : perform speed tests on the database\n"
"  ! command            : execute system command\n"
"  1 | first            : print the first record\n"
"  n | next             : print the next record\n"
"  q | quit             : terminate\n"
"  \\n                   : repeat 'next' command\n"
"\n");
}

static void terror(const char *why)
{
	printf("%s\n", why);
}

static int create_tdb(const char *tdbname)
{
	struct tdb_logging_context log_ctx = { NULL, NULL};
	log_ctx.log_fn = tdb_log;

	if (tdb) tdb_close(tdb);
	tdb = tdb_open_ex(tdbname, 0,
			  TDB_CLEAR_IF_FIRST |
			  (disable_mmap?TDB_NOMMAP:0) |
			  (_disable_lock?TDB_NOLOCK:0),
			  O_RDWR | O_CREAT | O_TRUNC, 0600, &log_ctx, NULL);
	if (!tdb) {
		printf("Could not create %s: %s\n", tdbname, strerror(errno));
		return -1;
	}

	return 0;
}

static int open_tdb(const char *tdbname)
{
	struct tdb_logging_context log_ctx = { NULL, NULL };
	log_ctx.log_fn = tdb_log_open;

	if (tdb) tdb_close(tdb);
	tdb = tdb_open_ex(tdbname, 0,
			  (disable_mmap?TDB_NOMMAP:0) |
			  (_disable_lock?TDB_NOLOCK:0),
			  O_RDWR, 0600,
			  &log_ctx, NULL);

	log_ctx.log_fn = tdb_log;
	if (tdb != NULL) {
		tdb_set_logging_function(tdb, &log_ctx);
	}

	if ((tdb == NULL) && (errno == EINVAL)) {
		/*
		 * Retry NOLOCK and readonly. There we want to see all
		 * error messages.
		 */
		tdb = tdb_open_ex(tdbname, 0,
				  (disable_mmap?TDB_NOMMAP:0) |TDB_NOLOCK,
				  O_RDONLY, 0600,
				  &log_ctx, NULL);
	}

	if (!tdb) {
		printf("Could not open %s: %s\n", tdbname, strerror(errno));
		return -1;
	}

	return 0;
}

static int insert_tdb(char *keyname, size_t keylen, char* data, size_t datalen)
{
	TDB_DATA key, dbuf;

	if ((keyname == NULL) || (keylen == 0)) {
		terror("need key");
		return -1;
	}

	key.dptr = (unsigned char *)keyname;
	key.dsize = keylen;
	dbuf.dptr = (unsigned char *)data;
	dbuf.dsize = datalen;

	if (tdb_store(tdb, key, dbuf, TDB_INSERT) != 0) {
		terror("insert failed");
		return -1;
	}

	return 0;
}

static int store_tdb(char *keyname, size_t keylen, char* data, size_t datalen)
{
	TDB_DATA key, dbuf;

	if ((keyname == NULL) || (keylen == 0)) {
		terror("need key");
		return -1;
	}

	if ((data == NULL) || (datalen == 0)) {
		terror("need data");
		return -1;
	}

	key.dptr = (unsigned char *)keyname;
	key.dsize = keylen;
	dbuf.dptr = (unsigned char *)data;
	dbuf.dsize = datalen;

	printf("Storing key:\n");
	print_rec(tdb, key, dbuf, NULL);

	if (tdb_store(tdb, key, dbuf, TDB_REPLACE) != 0) {
		terror("store failed");
		return -1;
	}

	return 0;
}

static bool parse_hex(const char *src, size_t srclen, uint8_t *dst)
{
	size_t i=0;

	if ((srclen % 2) != 0) {
		return false;
	}

	while (i<srclen) {
		bool ok = hex_byte(src, dst);
		if (!ok) {
			return false;
		}
		src += 2;
		dst += 1;
	}

	return true;
}

static int store_hex_tdb(char *keystr, size_t keylen,
			  char *datastr, size_t datalen)
{
	if ((keystr == NULL) || (keylen == 0)) {
		terror("need key");
		return -1;
	}
	if ((datastr == NULL) || (datalen == 0)) {
		terror("need data");
		return -1;
	}

	{
		uint8_t keybuf[keylen/2];
		TDB_DATA key = { .dptr = keybuf, .dsize = sizeof(keybuf) };
		uint8_t databuf[datalen/2];
		TDB_DATA data = { .dptr = databuf, .dsize = sizeof(databuf) };
		bool ok;

		ok = parse_hex(keystr, keylen, keybuf);
		if (!ok) {
			terror("need hex key");
			return -1;
		}
		ok = parse_hex(datastr, datalen, databuf);
		if (!ok) {
			terror("need hex data");
			return -1;
		}

		printf("storing key/data:\n");
		print_data((char *)key.dptr, key.dsize);
		print_data((char *)data.dptr, data.dsize);

		if (tdb_store(tdb, key, data, TDB_REPLACE) != 0) {
			terror("store failed");
			return -1;
		}
	}

	return 0;
}

static int show_tdb(char *keyname, size_t keylen)
{
	TDB_DATA key, dbuf;

	if ((keyname == NULL) || (keylen == 0)) {
		terror("need key");
		return -1;
	}

	key.dptr = (unsigned char *)keyname;
	key.dsize = keylen;

	dbuf = tdb_fetch(tdb, key);
	if (!dbuf.dptr) {
	    terror("fetch failed");
	    return -1;
	}

	print_rec(tdb, key, dbuf, NULL);

	free( dbuf.dptr );

	return 0;
}

static int delete_tdb(char *keyname, size_t keylen)
{
	TDB_DATA key;

	if ((keyname == NULL) || (keylen == 0)) {
		terror("need key");
		return -1;
	}

	key.dptr = (unsigned char *)keyname;
	key.dsize = keylen;

	if (tdb_delete(tdb, key) != 0) {
		terror("delete failed");
		return -1;
	}

	return 0;
}

static int move_rec(char *keyname, size_t keylen, char* tdbname)
{
	TDB_DATA key, dbuf;
	TDB_CONTEXT *dst_tdb;

	if ((keyname == NULL) || (keylen == 0)) {
		terror("need key");
		return -1;
	}

	if ( !tdbname ) {
		terror("need destination tdb name");
		return -1;
	}

	key.dptr = (unsigned char *)keyname;
	key.dsize = keylen;

	dbuf = tdb_fetch(tdb, key);
	if (!dbuf.dptr) {
		terror("fetch failed");
		return -1;
	}

	print_rec(tdb, key, dbuf, NULL);

	dst_tdb = tdb_open(tdbname, 0, 0, O_RDWR, 0600);
	if ( !dst_tdb ) {
		terror("unable to open destination tdb");
		return -1;
	}

	if (tdb_store( dst_tdb, key, dbuf, TDB_REPLACE ) != 0) {
		terror("failed to move record");
	}
	else
		printf("record moved\n");

	tdb_close( dst_tdb );

	return 0;
}

static int print_rec(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	printf("\nkey %d bytes\n", (int)key.dsize);
	print_asc((const char *)key.dptr, key.dsize);
	printf("\ndata %d bytes\n", (int)dbuf.dsize);
	print_data((const char *)dbuf.dptr, dbuf.dsize);
	return 0;
}

static int print_key(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	printf("key %d bytes: ", (int)key.dsize);
	print_asc((const char *)key.dptr, key.dsize);
	printf("\n");
	return 0;
}

static int print_hexkey(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	printf("key %d bytes\n", (int)key.dsize);
	print_data((const char *)key.dptr, key.dsize);
	printf("\n");
	return 0;
}

static int total_bytes;

static int traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	total_bytes += dbuf.dsize;
	return 0;
}

static int info_tdb(void)
{
	char *summary = tdb_summary(tdb);

	if (!summary) {
		printf("Error = %s\n", tdb_errorstr(tdb));
		return -1;
	} else {
		printf("%s", summary);
		free(summary);
	}

	return 0;
}

static void speed_tdb(const char *tlimit)
{
	const char *str = "store test", *str2 = "transaction test";
	unsigned timelimit = tlimit?atoi(tlimit):0;
	double t;
	int ops;
	if (timelimit == 0) timelimit = 5;

	ops = 0;
	printf("Testing store speed for %u seconds\n", timelimit);
	_start_timer();
	do {
		long int r = random();
		TDB_DATA key, dbuf;
		key.dptr = discard_const_p(uint8_t, str);
		key.dsize = strlen((char *)key.dptr);
		dbuf.dptr = (uint8_t *) &r;
		dbuf.dsize = sizeof(r);
		tdb_store(tdb, key, dbuf, TDB_REPLACE);
		t = _end_timer();
		ops++;
	} while (t < timelimit);
	printf("%10.3f ops/sec\n", ops/t);

	ops = 0;
	printf("Testing fetch speed for %u seconds\n", timelimit);
	_start_timer();
	do {
		TDB_DATA key;
		key.dptr = discard_const_p(uint8_t, str);
		key.dsize = strlen((char *)key.dptr);
		tdb_fetch(tdb, key);
		t = _end_timer();
		ops++;
	} while (t < timelimit);
	printf("%10.3f ops/sec\n", ops/t);

	ops = 0;
	printf("Testing transaction speed for %u seconds\n", timelimit);
	_start_timer();
	do {
		long int r = random();
		TDB_DATA key, dbuf;
		key.dptr = discard_const_p(uint8_t, str2);
		key.dsize = strlen((char *)key.dptr);
		dbuf.dptr = (uint8_t *) &r;
		dbuf.dsize = sizeof(r);
		tdb_transaction_start(tdb);
		tdb_store(tdb, key, dbuf, TDB_REPLACE);
		tdb_transaction_commit(tdb);
		t = _end_timer();
		ops++;
	} while (t < timelimit);
	printf("%10.3f ops/sec\n", ops/t);

	ops = 0;
	printf("Testing traverse speed for %u seconds\n", timelimit);
	_start_timer();
	do {
		tdb_traverse(tdb, traverse_fn, NULL);
		t = _end_timer();
		ops++;
	} while (t < timelimit);
	printf("%10.3f ops/sec\n", ops/t);
}

static void toggle_mmap(void)
{
	disable_mmap = !disable_mmap;
	if (disable_mmap) {
		printf("mmap is disabled\n");
	} else {
		printf("mmap is enabled\n");
	}
}

static char *tdb_getline(const char *prompt)
{
	static char thisline[1024];
	char *p;
	fputs(prompt, stdout);
	thisline[0] = 0;
	p = fgets(thisline, sizeof(thisline)-1, stdin);
	if (p) p = strchr(p, '\n');
	if (p) *p = 0;
	return p?thisline:NULL;
}

static int first_record(TDB_CONTEXT *the_tdb, TDB_DATA *pkey)
{
	TDB_DATA dbuf;
	*pkey = tdb_firstkey(the_tdb);

	dbuf = tdb_fetch(the_tdb, *pkey);
	if (!dbuf.dptr) {
		terror("fetch failed");
		return -1;
	} else {
		print_rec(the_tdb, *pkey, dbuf, NULL);
		return 0;
	}
}

static int next_record(TDB_CONTEXT *the_tdb, TDB_DATA *pkey)
{
	TDB_DATA dbuf;
	*pkey = tdb_nextkey(the_tdb, *pkey);

	dbuf = tdb_fetch(the_tdb, *pkey);
	if (!dbuf.dptr) {
		terror("fetch failed");
		return -1;
	} else {
		print_rec(the_tdb, *pkey, dbuf, NULL);
		return 0;
	}
}

static int count(TDB_DATA key, TDB_DATA data, void *private_data)
{
	(*(unsigned int *)private_data)++;
	return 0;
}

static int check_db(TDB_CONTEXT *the_tdb)
{
	int tdbcount = 0;
	if (!the_tdb) {
		printf("Error: No database opened!\n");
		return -1;
	} else if (tdb_check(the_tdb, count, &tdbcount) == -1) {
		printf("Integrity check for the opened database failed.\n");
		return -1;
	} else {
		printf("Database integrity is OK and has %d records.\n",
		       tdbcount);
	}
	return 0;
}

static int do_command(void)
{
	COMMAND_TABLE *ctp = cmd_table;
	enum commands mycmd = CMD_HELP;
	int cmd_len;
	int ret;

	if (cmdname != NULL) {
		if (strlen(cmdname) == 0) {
			mycmd = CMD_NEXT;
		} else {
			while (ctp->name) {
				cmd_len = strlen(ctp->name);
				if (strncmp(ctp->name,cmdname,cmd_len) == 0) {
					mycmd = ctp->cmd;
					break;
				}
				ctp++;
			}
		}
	}

	switch (mycmd) {
	case CMD_CREATE_TDB:
		bIterate = 0;
		return create_tdb(arg1);
	case CMD_OPEN_TDB:
		bIterate = 0;
		return open_tdb(arg1);
	case CMD_SYSTEM:
		/* Shell command */
		ret = system(arg1);
		if (ret != 0) {
			terror("system() call failed\n");
			return ret;
		}
		return 0;
	case CMD_QUIT:
		return 1;
	default:
		/* all the rest require a open database */
		if (!tdb) {
			bIterate = 0;
			terror("database not open");
			help();
			return -1;
		}
		switch (mycmd) {
		case CMD_TRANSACTION_START:
			bIterate = 0;
			return tdb_transaction_start(tdb);
		case CMD_TRANSACTION_COMMIT:
			bIterate = 0;
			return tdb_transaction_commit(tdb);
		case CMD_REPACK:
			bIterate = 0;
			return tdb_repack(tdb);
		case CMD_TRANSACTION_CANCEL:
			bIterate = 0;
			return tdb_transaction_cancel(tdb);
		case CMD_ERASE:
			bIterate = 0;
			return tdb_wipe_all(tdb);
		case CMD_DUMP:
			bIterate = 0;
			ret = tdb_traverse(tdb, print_rec, NULL);
			return (ret == -1) ? ret : 0;
		case CMD_INSERT:
			bIterate = 0;
			return insert_tdb(arg1, arg1len,arg2,arg2len);
		case CMD_MOVE:
			bIterate = 0;
			return move_rec(arg1,arg1len,arg2);
		case CMD_STORE:
			bIterate = 0;
			return store_tdb(arg1,arg1len,arg2,arg2len);
		case CMD_STOREHEX:
			bIterate = 0;
			return store_hex_tdb(arg1,arg1len,arg2,arg2len);
		case CMD_SHOW:
			bIterate = 0;
			return show_tdb(arg1, arg1len);
		case CMD_KEYS:
			ret = tdb_traverse(tdb, print_key, NULL);
			return (ret == -1) ? ret : 0;
		case CMD_HEXKEYS:
			ret = tdb_traverse(tdb, print_hexkey, NULL);
			return (ret == -1) ? ret : 0;
		case CMD_DELETE:
			bIterate = 0;
			return delete_tdb(arg1,arg1len);
		case CMD_LIST_HASH_FREE:
			tdb_dump_all(tdb);
			return 0;
		case CMD_LIST_FREE:
			return tdb_printfreelist(tdb);
		case CMD_FREELIST_SIZE: {
			int size;

			size = tdb_freelist_size(tdb);
			if (size < 0) {
				printf("Error getting freelist size.\n");
				return -1;
			} else {
				printf("freelist size: %d\n", size);
			}

			return 0;
		}
		case CMD_INFO:
			return info_tdb();
		case CMD_SPEED:
			speed_tdb(arg1);
			return 0;
		case CMD_MMAP:
			toggle_mmap();
			return 0;
		case CMD_FIRST:
			bIterate = 1;
			return first_record(tdb, &iterate_kbuf);
		case CMD_NEXT:
			if (bIterate)
				return next_record(tdb, &iterate_kbuf);
			return 0;
		case CMD_CHECK:
			return check_db(tdb);
		case CMD_HELP:
			help();
			return 0;
		case CMD_CREATE_TDB:
		case CMD_OPEN_TDB:
		case CMD_SYSTEM:
		case CMD_QUIT:
			/*
			 * unhandled commands.  cases included here to avoid compiler
			 * warnings.
			 */
			return 0;
		}
	}

	return 0;
}

static char *tdb_convert_string(char *instring, size_t *sizep)
{
	size_t length = 0;
	char *outp, *inp;
	char temp[3];

	outp = inp = instring;

	while (*inp) {
		if (*inp == '\\') {
			inp++;
			if (*inp && strchr("0123456789abcdefABCDEF",(int)*inp)) {
				temp[0] = *inp++;
				temp[1] = '\0';
				if (*inp && strchr("0123456789abcdefABCDEF",(int)*inp)) {
					temp[1] = *inp++;
					temp[2] = '\0';
				}
				*outp++ = (char)strtol((const char *)temp,NULL,16);
			} else {
				*outp++ = *inp++;
			}
		} else {
			*outp++ = *inp++;
		}
		length++;
	}
	*sizep = length;
	return instring;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	cmdname = "";
	arg1 = NULL;
	arg1len = 0;
	arg2 = NULL;
	arg2len = 0;

	if (argv[1] && (strcmp(argv[1], "-l") == 0)) {
		_disable_lock = 1;
		argv[1] = argv[0];
		argv += 1;
		argc -= 1;
	}

	if (argv[1]) {
		cmdname = "open";
		arg1 = argv[1];
		do_command();
		cmdname =  "";
		arg1 = NULL;
	}

	switch (argc) {
	case 1:
	case 2:
		/* Interactive mode */
		while ((cmdname = tdb_getline("tdb> "))) {
			arg2 = arg1 = NULL;
			if ((arg1 = strchr((const char *)cmdname,' ')) != NULL) {
				arg1++;
				arg2 = arg1;
				while (*arg2) {
					if (*arg2 == ' ') {
						*arg2++ = '\0';
						break;
					}
					if ((*arg2++ == '\\') && (*arg2 == ' ')) {
						arg2++;
					}
				}
			}
			if (arg1) arg1 = tdb_convert_string(arg1,&arg1len);
			if (arg2) arg2 = tdb_convert_string(arg2,&arg2len);
			if (do_command()) break;
		}
		break;
	case 5:
		arg2 = tdb_convert_string(argv[4],&arg2len);
		FALL_THROUGH;
	case 4:
		arg1 = tdb_convert_string(argv[3],&arg1len);
		FALL_THROUGH;
	case 3:
		cmdname = argv[2];
		FALL_THROUGH;
	default:
		ret = do_command();
		if (ret != 0) {
			ret = 1;
		}
		break;
	}

	if (tdb) tdb_close(tdb);

	return ret;
}
