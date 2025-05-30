/*
   Unix SMB/CIFS implementation.

   test alternate data streams

   Copyright (C) Andrew Tridgell 2004

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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

#include "smb_constants.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"

#include "system/filesys.h"
#include "system/locale.h"
#include "lib/util/tsort.h"
#include "libcli/security/security_descriptor.h"

#define DNAME "teststreams"

#define CHECK_STATUS(status, correct) \
	torture_assert_ntstatus_equal_goto(tctx, status, correct, ret, done, "CHECK_STATUS")

#define CHECK_VALUE(v, correct) \
	torture_assert_u64_equal_goto(tctx, v, correct, ret, done, "CHECK_VALUE")

#define CHECK_NTTIME(v, correct) \
	torture_assert_nttime_equal_goto(tctx, v, correct, ret, done, "CHECK_NTTIME")

#define CHECK_STR(v, correct) \
	torture_assert_str_equal_goto(tctx, v, correct, ret, done, "CHECK_STR")

static int qsort_string(char * const *s1, char * const *s2)
{
	return strcmp(*s1, *s2);
}

static int qsort_stream(const struct stream_struct * s1, const struct stream_struct *s2)
{
	return strcmp(s1->stream_name.s, s2->stream_name.s);
}

static bool check_stream(struct torture_context *tctx,
			 struct smb2_tree *tree,
			 const char *location,
			 TALLOC_CTX *mem_ctx,
			 const char *fname,
			 const char *sname,
			 const char *value)
{
	struct smb2_handle handle;
	struct smb2_create create;
	struct smb2_read r;
	NTSTATUS status;
	const char *full_name;

	full_name = talloc_asprintf(mem_ctx, "%s:%s", fname, sname);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.fname = full_name;

	status = smb2_create(tree, mem_ctx, &create);
	if (!NT_STATUS_IS_OK(status)) {
		if (value == NULL) {
			return true;
		} else {
			torture_comment(tctx, "Unable to open stream %s\n",
			    full_name);
			return false;
		}
	}

	handle = create.out.file.handle;
	if (value == NULL) {
		return true;
	}


	ZERO_STRUCT(r);
	r.in.file.handle = handle;
	r.in.length      = strlen(value)+11;
	r.in.offset      = 0;

	status = smb2_read(tree, tree, &r);

	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "(%s) Failed to read %lu bytes from "
		    "stream '%s'\n", location, (long)strlen(value), full_name);
		return false;
	}

	if (memcmp(r.out.data.data, value, strlen(value)) != 0) {
		torture_comment(tctx, "(%s) Bad data in stream\n", location);
		return false;
	}

	smb2_util_close(tree, handle);
	return true;
}

static bool check_stream_list(struct smb2_tree *tree,
			      struct torture_context *tctx,
			      const char *fname,
			      unsigned int num_exp,
			      const char **exp,
			      struct smb2_handle h)
{
	union smb_fileinfo finfo;
	NTSTATUS status;
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	char **exp_sort;
	struct stream_struct *stream_sort;
	bool ret = false;

	finfo.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	finfo.generic.in.file.handle = h;

	status = smb2_getinfo_file(tree, tctx, &finfo);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "(%s) smb_raw_pathinfo failed: %s\n",
		    __location__, nt_errstr(status));
		goto fail;
	}

	if (finfo.stream_info.out.num_streams != num_exp) {
		torture_comment(tctx, "(%s) expected %d streams, got %d\n",
		    __location__, num_exp, finfo.stream_info.out.num_streams);
		goto fail;
	}

	if (num_exp == 0) {
		ret = true;
		goto fail;
	}

	exp_sort = talloc_memdup(tmp_ctx, exp, num_exp * sizeof(*exp));

	if (exp_sort == NULL) {
		goto fail;
	}

	TYPESAFE_QSORT(exp_sort, num_exp, qsort_string);

	stream_sort = talloc_memdup(tmp_ctx, finfo.stream_info.out.streams,
				    finfo.stream_info.out.num_streams *
				    sizeof(*stream_sort));

	if (stream_sort == NULL) {
		goto fail;
	}

	TYPESAFE_QSORT(stream_sort, finfo.stream_info.out.num_streams, qsort_stream);

	for (i=0; i<num_exp; i++) {
		if (strcmp(exp_sort[i], stream_sort[i].stream_name.s) != 0) {
			torture_comment(tctx,
			    "(%s) expected stream name %s, got %s\n",
			    __location__, exp_sort[i],
			    stream_sort[i].stream_name.s);
			goto fail;
		}
	}

	ret = true;
 fail:
	talloc_free(tmp_ctx);
	return ret;
}


static bool test_stream_dir(struct torture_context *tctx,
			    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream.txt";
	const char *sname1;
	bool ret = true;
	const char *basedir_data;
	struct smb2_handle h;

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	basedir_data = talloc_asprintf(mem_ctx, "%s::$DATA", DNAME);
	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "Stream One");
	torture_comment(tctx, "%s\n", sname1);

	torture_comment(tctx, "(%s) opening non-existent directory stream\n",
	    __location__);
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.desired_access = SEC_FILE_WRITE_DATA;
	io.smb2.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = sname1;
	io.smb2.in.create_flags = 0;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);

	torture_comment(tctx, "(%s) opening basedir  stream\n", __location__);
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = basedir_data;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);

	torture_comment(tctx, "(%s) opening basedir ::$DATA stream\n",
	    __location__);
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0x10;
	io.smb2.in.desired_access = SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = 0;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = basedir_data;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_FILE_IS_A_DIRECTORY);

	torture_comment(tctx, "(%s) list the streams on the basedir\n",
	    __location__);
	ret &= check_stream_list(tree, mem_ctx, DNAME, 0, NULL, h);
done:
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_stream_io(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream.txt";
	const char *sname1, *sname2;
	bool ret = true;
	struct smb2_handle h, h2;

	const char *one[] = { "::$DATA" };
	const char *two[] = { "::$DATA", ":Second Stream:$DATA" };
	const char *three[] = { "::$DATA", ":Stream One:$DATA",
				":Second Stream:$DATA" };

	ZERO_STRUCT(h);
	ZERO_STRUCT(h2);

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "Stream One");
	sname2 = talloc_asprintf(mem_ctx, "%s:%s:$DaTa", fname,
				 "Second Stream");

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "(%s) creating a stream on a non-existent file\n",
		__location__);

	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = sname1;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Stream One", NULL);

	torture_comment(tctx, "(%s) check that open of base file is allowed\n", __location__);
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.fname = fname;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, io.smb2.out.file.handle);

	torture_comment(tctx, "(%s) writing to stream\n", __location__);
	status = smb2_util_write(tree, h2, "test data", 0, 9);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h2);

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Stream One", "test data");

	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.fname = sname1;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;

	torture_comment(tctx, "(%s) modifying stream\n", __location__);
	status = smb2_util_write(tree, h2, "MORE DATA ", 5, 10);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h2);

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Stream One:$FOO", NULL);

	torture_comment(tctx, "(%s) creating a stream2 on a existing file\n",
	    __location__);
	io.smb2.in.fname = sname2;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;

	torture_comment(tctx, "(%s) modifying stream\n", __location__);
	status= smb2_util_write(tree, h2, "SECOND STREAM", 0, 13);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, h2);

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			     "Stream One", "test MORE DATA ");

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Stream One:$DATA", "test MORE DATA ");

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Stream One:", NULL);

	if (!ret) {
		torture_result(tctx, TORTURE_FAIL,
		    "check_stream(\"Stream One:*\") failed\n");
		goto done;
	}

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Second Stream", "SECOND STREAM");

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "SECOND STREAM:$DATA", "SECOND STREAM");
	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Second Stream:$DATA", "SECOND STREAM");

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Second Stream:", NULL);

	ret &= check_stream(tctx, tree, __location__, mem_ctx, fname,
			    "Second Stream:$FOO", NULL);

	if (!ret) {
		torture_result(tctx, TORTURE_FAIL,
		    "check_stream(\"Second Stream:*\") failed\n");
		goto done;
	}

	io.smb2.in.fname = sname2;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;
	check_stream_list(tree, tctx, fname, 3, three, h2);

	smb2_util_close(tree, h2);

	torture_comment(tctx, "(%s) deleting stream\n", __location__);
	status = smb2_util_unlink(tree, sname1);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.smb2.in.fname = sname2;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;
	check_stream_list(tree, tctx, fname, 2, two, h2);
	smb2_util_close(tree, h2);

	torture_comment(tctx, "(%s) delete a stream via delete-on-close\n",
	    __location__);
	io.smb2.in.fname = sname2;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;

	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;

	smb2_util_close(tree, h2);
	status = smb2_util_unlink(tree, sname2);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	io.smb2.in.fname = fname;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	h2 = io.smb2.out.file.handle;
	check_stream_list(tree,tctx, fname, 1, one, h2);
	smb2_util_close(tree, h2);

	if (!torture_setting_bool(tctx, "samba4", false)) {
		io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
		io.smb2.in.fname = sname1;
		status = smb2_create(tree, mem_ctx, &(io.smb2));
		CHECK_STATUS(status, NT_STATUS_OK);
		smb2_util_close(tree, io.ntcreatex.out.file.handle);
		io.smb2.in.fname = sname2;
		status = smb2_create(tree, mem_ctx, &(io.smb2));
		CHECK_STATUS(status, NT_STATUS_OK);
		smb2_util_close(tree, io.ntcreatex.out.file.handle);
		torture_comment(tctx, "(%s) deleting file\n", __location__);
		status = smb2_util_unlink(tree, fname);
		CHECK_STATUS(status, NT_STATUS_OK);
	}


done:
	smb2_util_close(tree, h2);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_zero_byte_stream(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream.txt";
	const char *sname;
	bool ret = true;
	struct smb2_handle h, bh;
	const char *streams[] = { "::$DATA", ":foo:$DATA" };

	sname = talloc_asprintf(mem_ctx, "%s:%s", fname, "foo");

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "testdir");
	smb2_util_close(tree, h);

	torture_comment(tctx, "(%s) Check 0 byte named stream\n",
	    __location__);

	/* Create basefile */
	ZERO_STRUCT(io);
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.fname = fname;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
		SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	smb2_util_close(tree, io.smb2.out.file.handle);

	/* Create named stream and close it */
	ZERO_STRUCT(io);
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.fname = sname;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
		SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	smb2_util_close(tree, io.smb2.out.file.handle);

	/*
	 * Check stream list, the 0 byte stream MUST be returned by
	 * the server.
	 */
	ZERO_STRUCT(io);
	io.smb2.in.fname = fname;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
		SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	bh = io.smb2.out.file.handle;

	ret = check_stream_list(tree,tctx, fname, 2, streams, bh);
	torture_assert_goto(tctx, ret == true, ret, done, "smb2_create");
	smb2_util_close(tree, bh);

done:
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

/*
  test stream sharemodes
*/
static bool test_stream_sharemodes(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream_share.txt";
	const char *sname1, *sname2;
	bool ret = true;
	struct smb2_handle h, h1, h2;

	ZERO_STRUCT(h);
	ZERO_STRUCT(h1);
	ZERO_STRUCT(h2);

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "Stream One");
	sname2 = talloc_asprintf(mem_ctx, "%s:%s:$DaTa", fname,
				 "Second Stream");

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "(%s) Testing stream share mode conflicts\n",
	    __location__);
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = sname1;

	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	/*
	 * A different stream does not give a sharing violation
	 */

	io.smb2.in.fname = sname2;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;

	/*
	 * ... whereas the same stream does with unchanged access/share_access
	 * flags
	 */

	io.smb2.in.fname = sname1;
	io.smb2.in.create_disposition = 0;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	io.smb2.in.fname = sname2;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);
	status = smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

/*
 *  Test FILE_SHARE_DELETE on streams
 *
 * A stream opened with !FILE_SHARE_DELETE prevents the main file to be opened
 * with SEC_STD_DELETE.
 *
 * The main file opened with !FILE_SHARE_DELETE does *not* prevent a stream to
 * be opened with SEC_STD_DELETE.
 *
 * A stream held open with FILE_SHARE_DELETE allows the file to be
 * deleted. After the main file is deleted, access to the open file descriptor
 * still works, but all name-based access to both the main file as well as the
 * stream is denied with DELETE pending.
 *
 * This means, an open of the main file with SEC_STD_DELETE should walk all
 * streams and also open them with SEC_STD_DELETE. If any of these opens gives
 * SHARING_VIOLATION, the main open fails.
 *
 * Closing the main file after delete_on_close has been set does not really
 * unlink it but leaves the corresponding share mode entry with
 * delete_on_close being set around until all streams are closed.
 *
 * Opening a stream must also look at the main file's share mode entry, look
 * at the delete_on_close bit and potentially return DELETE_PENDING.
 */

static bool test_stream_delete(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream_delete.txt";
	const char *sname1;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct smb2_handle h1 = {{0}};
	struct smb2_read r;

	if (torture_setting_bool(tctx, "samba4", false)) {
		torture_comment(tctx, "Skipping test as samba4 is enabled\n");
		goto done;
	}

	ZERO_STRUCT(h);
	ZERO_STRUCT(h1);

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "Stream One");

	/* clean slate .. */
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "(%s) opening non-existent file stream\n",
	    __location__);
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = sname1;

	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	status = smb2_util_write(tree, h1, "test data", 0, 9);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * One stream opened without FILE_SHARE_DELETE prevents the main file
	 * to be deleted or even opened with DELETE access
	 */

	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.fname = fname;
	io.smb2.in.desired_access = SEC_STD_DELETE;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	smb2_util_close(tree, h1);

	/*
	 * ... but unlink works if a stream is opened with FILE_SHARE_DELETE
	 */

	io.smb2.in.fname = sname1;
	io.smb2.in.desired_access = SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE |
			NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * file access still works on the stream while the main file is closed
	 */
	ZERO_STRUCT(r);
	r.in.file.handle = h1;
	r.in.length      = 9;
	r.in.offset      = 0;

	status = smb2_read(tree, tree, &r);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * name-based access to both the main file and the stream does not
	 * work anymore but gives DELETE_PENDING
	 */

	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.fname = fname;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_DELETE_PENDING);

	/*
	 * older S3 doesn't do this
	 */

	io.smb2.in.fname = sname1;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_DELETE_PENDING);

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/*
	 * After closing the stream the file is really gone.
	 */

	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.fname = fname;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

/*
  test stream names
*/
static bool test_stream_names(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	union smb_fileinfo finfo;
	union smb_fileinfo stinfo;
	union smb_setfileinfo sinfo;
	const char *fname = DNAME "\\stream_names.txt";
	const char *sname1, *sname1b, *sname1c, *sname1d;
	const char *sname2, *snamew, *snamew2;
	const char *snamer1;
	bool ret = true;
	struct smb2_handle h, h1, h2, h3;
	int i;
	const char *four[4] = {
		"::$DATA",
		":\x05Stream\n One:$DATA",
		":MStream Two:$DATA",
		":?Stream*:$DATA"
	};
	const char *five1[5] = {
		"::$DATA",
		":\x05Stream\n One:$DATA",
		":BeforeRename:$DATA",
		":MStream Two:$DATA",
		":?Stream*:$DATA"
	};
	const char *five2[5] = {
		"::$DATA",
		":\x05Stream\n One:$DATA",
		":AfterRename:$DATA",
		":MStream Two:$DATA",
		":?Stream*:$DATA"
	};

	ZERO_STRUCT(h);
	ZERO_STRUCT(h1);
	ZERO_STRUCT(h2);
	ZERO_STRUCT(h3);

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "\x05Stream\n One");
	sname1b = talloc_asprintf(mem_ctx, "%s:", sname1);
	sname1c = talloc_asprintf(mem_ctx, "%s:$FOO", sname1);
	sname1d = talloc_asprintf(mem_ctx, "%s:?D*a", sname1);
	sname2 = talloc_asprintf(mem_ctx, "%s:%s:$DaTa", fname, "MStream Two");
	snamew = talloc_asprintf(mem_ctx, "%s:%s:$DATA", fname, "?Stream*");
	snamew2 = talloc_asprintf(mem_ctx, "%s\\stream*:%s:$DATA", DNAME,
				  "?Stream*");
	snamer1 = talloc_asprintf(mem_ctx, "%s:%s:$DATA", fname,
				  "BeforeRename");

	/* clean slate ...*/
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "(%s) testing stream names\n", __location__);
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = sname1;

	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	/*
	 * A different stream does not give a sharing violation
	 */

	io.smb2.in.fname = sname2;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.smb2.out.file.handle;

	/*
	 * ... whereas the same stream does with unchanged access/share_access
	 * flags
	 */

	io.smb2.in.fname = sname1;
	io.smb2.in.create_disposition = NTCREATEX_DISP_SUPERSEDE;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	io.smb2.in.fname = sname1b;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

	io.smb2.in.fname = sname1c;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		/* w2k returns INVALID_PARAMETER */
		CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	} else {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	}

	io.smb2.in.fname = sname1d;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		/* w2k returns INVALID_PARAMETER */
		CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	} else {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	}

	io.smb2.in.fname = sname2;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	io.smb2.in.fname = snamew;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io.smb2.out.file.handle;

	io.smb2.in.fname = snamew2;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

	io.smb2.in.fname = fname;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	ret &= check_stream_list(tree, tctx, fname, 4, four,
				 io.smb2.out.file.handle);
	CHECK_VALUE(ret, true);
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);

	if (torture_setting_bool(tctx, "samba4", true)) {
		goto done;
	}

	finfo.generic.level = RAW_FILEINFO_ALL_INFORMATION;
	finfo.generic.in.file.handle = io.smb2.out.file.handle;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	ret &= check_stream_list(tree, tctx, fname, 4, four,
				 io.smb2.out.file.handle);

	CHECK_VALUE(ret, true);
	for (i=0; i < 4; i++) {
		NTTIME write_time;
		uint64_t stream_size;
		char *path = talloc_asprintf(tctx, "%s%s",
					     fname, four[i]);

		char *rpath = talloc_strdup(path, path);
		char *p = strrchr(rpath, ':');
		/* eat :$DATA */
		*p = 0;
		p--;
		if (*p == ':') {
			/* eat ::$DATA */
			*p = 0;
		}
		torture_comment(tctx, "(%s): i[%u][%s]\n",
		    __location__, i,path);
		io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
		io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_RIGHTS_FILE_ALL;
		io.smb2.in.fname = path;
		status = smb2_create(tree, mem_ctx, &(io.smb2));
		CHECK_STATUS(status, NT_STATUS_OK);
		h1 = io.smb2.out.file.handle;

		finfo.generic.level = RAW_FILEINFO_ALL_INFORMATION;
		finfo.generic.in.file.path = fname;
		status = smb2_getinfo_file(tree, mem_ctx, &finfo);
		CHECK_STATUS(status, NT_STATUS_OK);

		stinfo.generic.level = RAW_FILEINFO_ALL_INFORMATION;
		stinfo.generic.in.file.handle = h1;
		status = smb2_getinfo_file(tree, mem_ctx, &stinfo);
		CHECK_STATUS(status, NT_STATUS_OK);
		if (!torture_setting_bool(tctx, "samba3", false)) {
			CHECK_NTTIME(stinfo.all_info.out.create_time,
				     finfo.all_info.out.create_time);
			CHECK_NTTIME(stinfo.all_info.out.access_time,
				     finfo.all_info.out.access_time);
			CHECK_NTTIME(stinfo.all_info.out.write_time,
				     finfo.all_info.out.write_time);
			CHECK_NTTIME(stinfo.all_info.out.change_time,
				     finfo.all_info.out.change_time);
		}
		CHECK_VALUE(stinfo.all_info.out.attrib,
			    finfo.all_info.out.attrib);
		CHECK_VALUE(stinfo.all_info.out.size,
			    finfo.all_info.out.size);
		CHECK_VALUE(stinfo.all_info.out.delete_pending,
			    finfo.all_info.out.delete_pending);
		CHECK_VALUE(stinfo.all_info.out.directory,
			    finfo.all_info.out.directory);
		CHECK_VALUE(stinfo.all_info.out.ea_size,
			    finfo.all_info.out.ea_size);

		stinfo.generic.level = RAW_FILEINFO_NAME_INFORMATION;
		stinfo.generic.in.file.handle = h1;
		status = smb2_getinfo_file(tree, mem_ctx, &stinfo);
		CHECK_STATUS(status, NT_STATUS_OK);
		if (!torture_setting_bool(tctx, "samba3", false)) {
			CHECK_STR(rpath, stinfo.name_info.out.fname.s);
		}

		write_time = finfo.all_info.out.write_time;
		write_time += i*1000000;
		write_time /= 1000000;
		write_time *= 1000000;

		ZERO_STRUCT(sinfo);
		sinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
		sinfo.basic_info.in.file.handle = h1;
		sinfo.basic_info.in.write_time = write_time;
		sinfo.basic_info.in.attrib = stinfo.all_info.out.attrib;
		status = smb2_setinfo_file(tree, &sinfo);
		CHECK_STATUS(status, NT_STATUS_OK);

		stream_size = i*8192;

		ZERO_STRUCT(sinfo);
		sinfo.end_of_file_info.level =
			RAW_SFILEINFO_END_OF_FILE_INFORMATION;
		sinfo.end_of_file_info.in.file.handle = h1;
		sinfo.end_of_file_info.in.size = stream_size;
		status = smb2_setinfo_file(tree, &sinfo);
		CHECK_STATUS(status, NT_STATUS_OK);

		stinfo.generic.level = RAW_FILEINFO_ALL_INFORMATION;
		stinfo.generic.in.file.handle = h1;
		status = smb2_getinfo_file(tree, mem_ctx, &stinfo);
		CHECK_STATUS(status, NT_STATUS_OK);
		if (!torture_setting_bool(tctx, "samba3", false)) {
			CHECK_NTTIME(stinfo.all_info.out.write_time,
				     write_time);
			CHECK_VALUE(stinfo.all_info.out.attrib,
				    finfo.all_info.out.attrib);
		}
		CHECK_VALUE(stinfo.all_info.out.size,
			    stream_size);
		CHECK_VALUE(stinfo.all_info.out.delete_pending,
			    finfo.all_info.out.delete_pending);
		CHECK_VALUE(stinfo.all_info.out.directory,
			    finfo.all_info.out.directory);
		CHECK_VALUE(stinfo.all_info.out.ea_size,
			    finfo.all_info.out.ea_size);

		io.smb2.in.fname = fname;
		io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
		status = smb2_create(tree, mem_ctx, &(io.smb2));
		CHECK_STATUS(status, NT_STATUS_OK);
		ret &= check_stream_list(tree, tctx, fname, 4, four,
					 io.smb2.out.file.handle);

		smb2_util_close(tree, h1);
		talloc_free(path);
	}

	torture_comment(tctx, "(%s): testing stream renames\n", __location__);
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_RIGHTS_FILE_ALL;
	io.smb2.in.fname = snamer1;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;
	ret &= check_stream_list(tree,tctx, fname, 5, five1,
				 io.smb2.out.file.handle);

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name = ":AfterRename:$DATA";
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret &= check_stream_list(tree,tctx, fname, 5, five2,
				 io.smb2.out.file.handle);

	CHECK_VALUE(ret, true);
	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.overwrite = false;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name = ":MStream Two:$DATA";
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_COLLISION);

	ret &= check_stream_list(tree,tctx, fname, 5, five2,
				 io.smb2.out.file.handle);

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name = ":MStream Two:$DATA";
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	ret &= check_stream_list(tree,tctx, fname, 5, five2,
				 io.smb2.out.file.handle);

	CHECK_VALUE(ret, true);
	/* TODO: we need to test more rename combinations */

done:
	smb2_util_close(tree, h1);
	status = smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

/*
  test stream names
*/
static bool test_stream_names2(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream_names2.txt";
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct smb2_handle h1 = {{0}};
	uint8_t i;

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "(%s) testing stream names\n", __location__);
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	for (i=0x01; i < 0x7F; i++) {
		char *path = talloc_asprintf(mem_ctx, "%s:Stream%c0x%02X:$DATA",
					     fname, i, i);
		NTSTATUS expected;

		switch (i) {
		case '/':/*0x2F*/
		case ':':/*0x3A*/
		case '\\':/*0x5C*/
			expected = NT_STATUS_OBJECT_NAME_INVALID;
			break;
		default:
			expected = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			break;
		}


		io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
		io.smb2.in.fname = path;
		status = smb2_create(tree, mem_ctx, &(io.smb2));
		if (!NT_STATUS_EQUAL(status, expected)) {
			torture_comment(tctx,
			    "(%s) %s:Stream%c0x%02X:$DATA%s => expected[%s]\n",
			    __location__, fname, isprint(i)?(char)i:' ', i,
			    isprint(i)?"":" (not printable)",
			    nt_errstr(expected));
		}
		CHECK_STATUS(status, expected);

		talloc_free(path);
	}

done:
	smb2_util_close(tree, h1);
	status = smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

/*
  test case insensitive stream names
*/
static bool test_stream_names3(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_fsinfo info;
	const char *fname = DNAME "\\stream_names3.txt";
	const char *sname = NULL;
	const char *snamel = NULL;
	const char *snameu = NULL;
	const char *sdname = NULL;
	const char *sdnamel = NULL;
	const char *sdnameu = NULL;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct smb2_handle hf = {{0}};
	struct smb2_handle hs = {{0}};
	struct smb2_handle hsl = {{0}};
	struct smb2_handle hsu = {{0}};
	struct smb2_handle hsd = {{0}};
	struct smb2_handle hsdl = {{0}};
	struct smb2_handle hsdu = {{0}};
	const char *streams[] = { "::$DATA", ":StreamName:$DATA", };

	smb2_deltree(tree, DNAME);
	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(info);
	info.generic.level = RAW_QFS_ATTRIBUTE_INFORMATION;
	info.generic.handle = h;
	status = smb2_getinfo_fs(tree, tree, &info);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!(info.attribute_info.out.fs_attr & FILE_CASE_SENSITIVE_SEARCH)) {
		torture_skip(tctx, "No FILE_CASE_SENSITIVE_SEARCH supported");
	}

	/*
	 * We create the following file:
	 *
	 *   teststreams\\stream_names3.txt
	 *
	 * and add a stream named 'StreamName'
	 *
	 * Then we try to open the stream using the following names:
	 *
	 * teststreams\\stream_names3.txt:StreamName
	 * teststreams\\stream_names3.txt:streamname
	 * teststreams\\stream_names3.txt:STREAMNAME
	 * teststreams\\stream_names3.txt:StreamName:$dAtA
	 * teststreams\\stream_names3.txt:streamname:$data
	 * teststreams\\stream_names3.txt:STREAMNAME:$DATA
	 */
	sname = talloc_asprintf(tctx, "%s:StreamName", fname);
	torture_assert_not_null(tctx, sname, __location__);
	snamel = strlower_talloc(tctx, sname);
	torture_assert_not_null(tctx, snamel, __location__);
	snameu = strupper_talloc(tctx, sname);
	torture_assert_not_null(tctx, snameu, __location__);

	sdname = talloc_asprintf(tctx, "%s:$dAtA", sname);
	torture_assert_not_null(tctx, sdname, __location__);
	sdnamel = strlower_talloc(tctx, sdname);
	torture_assert_not_null(tctx, sdnamel, __location__);
	sdnameu = strupper_talloc(tctx, sdname);
	torture_assert_not_null(tctx, sdnameu, __location__);

	torture_comment(tctx, "(%s) testing case insensitive stream names\n",
			__location__);
	status = torture_smb2_testfile(tree, fname, &hf);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = torture_smb2_testfile(tree, sname, &hs);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, hs);

	torture_assert(tctx,
		       check_stream_list(tree, tctx, fname,
					 ARRAY_SIZE(streams),
					 streams,
					 hf),
		       "streams");

	status = torture_smb2_open(tree, sname, SEC_RIGHTS_FILE_ALL, &hs);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = torture_smb2_open(tree, snamel, SEC_RIGHTS_FILE_ALL, &hsl);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = torture_smb2_open(tree, snameu, SEC_RIGHTS_FILE_ALL, &hsu);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = torture_smb2_open(tree, sdname, SEC_RIGHTS_FILE_ALL, &hsd);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = torture_smb2_open(tree, sdnamel, SEC_RIGHTS_FILE_ALL, &hsdl);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = torture_smb2_open(tree, sdnameu, SEC_RIGHTS_FILE_ALL, &hsdu);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smb2_util_close(tree, hsdu);
	smb2_util_close(tree, hsdl);
	smb2_util_close(tree, hsd);
	smb2_util_close(tree, hsu);
	smb2_util_close(tree, hsl);
	smb2_util_close(tree, hs);
	smb2_util_close(tree, hf);
	smb2_util_close(tree, h);
	status = smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

#define CHECK_CALL_HANDLE(call, rightstatus) do { \
	sfinfo.generic.level = RAW_SFILEINFO_ ## call; \
	sfinfo.generic.in.file.handle = h1; \
	status = smb2_setinfo_file(tree, &sfinfo); \
	torture_assert_ntstatus_equal_goto(tctx, status, rightstatus, ret, done, #call); \
	finfo1.generic.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo1.generic.in.file.handle = h1; \
	status2 = smb2_getinfo_file(tree, tctx, &finfo1); \
	torture_assert_ntstatus_ok_goto(tctx, status2, ret, done, "ALL_INFO"); \
} while (0)

/*
  test stream renames
*/
static bool test_stream_rename(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status, status2;
	union smb_open io;
	const char *fname = DNAME "\\stream_rename.txt";
	const char *sname1, *sname2;
	union smb_fileinfo finfo1;
	union smb_setfileinfo sfinfo;
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct smb2_handle h1 = {{0}};

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "Stream One");
	sname2 = talloc_asprintf(mem_ctx, "%s:%s:$DaTa", fname,
				 "Second Stream");

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "(%s) testing stream renames\n", __location__);
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				      SEC_FILE_WRITE_ATTRIBUTE |
				    SEC_RIGHTS_FILE_ALL;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE |
			NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = sname1;

	/* Create two streams. */
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;
	smb2_util_close(tree, h1);

	io.smb2.in.fname = sname2;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	smb2_util_close(tree, h1);

	/*
	 * Open the second stream.
	 */

	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	/*
	 * Now rename the second stream onto the first.
	 */

	ZERO_STRUCT(sfinfo);

	sfinfo.rename_information.in.overwrite = 1;
	sfinfo.rename_information.in.root_fid  = 0;
	sfinfo.rename_information.in.new_name  = ":Stream One";
	CHECK_CALL_HANDLE(RENAME_INFORMATION, NT_STATUS_OK);
done:
	smb2_util_close(tree, h1);
	status = smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_stream_rename2(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname1 = DNAME "\\stream_rename2.txt";
	const char *fname2 = DNAME "\\stream2_rename2.txt";
	const char *stream_name1 = ":Stream One:$DATA";
	const char *stream_name2 = ":Stream Two:$DATA";
	const char *stream_name_default = "::$DATA";
	const char *sname1;
	const char *sname2;
	bool ret = true;
	struct smb2_handle h, h1;
	union smb_setfileinfo sinfo;

	ZERO_STRUCT(h);
	ZERO_STRUCT(h1);

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname1, "Stream One");
	sname2 = talloc_asprintf(mem_ctx, "%s:%s", fname1, "Stream Two");

	smb2_util_unlink(tree, fname1);
	smb2_util_unlink(tree, fname2);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_READ_DATA |
				SEC_FILE_WRITE_DATA |
				SEC_STD_DELETE |
				SEC_FILE_APPEND_DATA |
				SEC_STD_READ_CONTROL;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE |
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = sname1;

	/* Open/create new stream. */
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, io.smb2.out.file.handle);

	/*
	 * Reopen the stream for SMB2 renames.
	 */
	io.smb2.in.fname = sname1;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	/*
	 * Check SMB2 rename of a stream using :<stream>.
	 */
	torture_comment(tctx, "(%s) Checking SMB2 rename of a stream using "
			":<stream>\n", __location__);
	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION_SMB2;
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.overwrite = 1;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name = stream_name1;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Check SMB2 rename of an overwriting stream using :<stream>.
	 */
	torture_comment(tctx, "(%s) Checking SMB2 rename of an overwriting "
			"stream using :<stream>\n", __location__);

	/* Create second stream. */
	io.smb2.in.fname = sname2;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, io.smb2.out.file.handle);

	/* Rename the first stream onto the second. */
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.new_name = stream_name2;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h1);

	/*
	 * Reopen the stream with the new name.
	 */
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.fname = sname2;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	/*
	 * Check SMB2 rename of a stream using <base>:<stream>.
	 */
	torture_comment(tctx, "(%s) Checking SMB2 rename of a stream using "
			"<base>:<stream>\n", __location__);
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.new_name = sname1;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	/*
	 * Check SMB2 rename to the default stream using :<stream>.
	 */
	torture_comment(tctx, "(%s) Checking SMB2 rename to default stream "
			"using :<stream>\n", __location__);
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.new_name = stream_name_default;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h1);

 done:
	smb2_util_close(tree, h1);
	status = smb2_util_unlink(tree, fname1);
	status = smb2_util_unlink(tree, fname2);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

static bool create_file_with_stream(struct torture_context *tctx,
				    struct smb2_tree *tree,
				    TALLOC_CTX *mem_ctx,
				    const char *base_fname,
				    const char *stream)
{
	NTSTATUS status;
	bool ret = true;
	union smb_open io;

	/* Create a file with a stream */
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_READ_DATA |
				SEC_FILE_WRITE_DATA |
				SEC_FILE_APPEND_DATA |
				SEC_STD_READ_CONTROL;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = stream;

	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

 done:
	smb2_util_close(tree, io.smb2.out.file.handle);
	return ret;
}


/* Test how streams interact with create dispositions */
static bool test_stream_create_disposition(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream_create_disp.txt";
	const char *stream = "Stream One:$DATA";
	const char *fname_stream;
	const char *default_stream_name = "::$DATA";
	const char *stream_list[2];
	bool ret = true;
	struct smb2_handle h = {{0}};
	struct smb2_handle h1 = {{0}};

	/* clean slate .. */
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	fname_stream = talloc_asprintf(mem_ctx, "%s:%s", fname, stream);

	stream_list[0] = talloc_asprintf(mem_ctx, ":%s", stream);
	stream_list[1] = default_stream_name;

	if (!create_file_with_stream(tctx, tree, mem_ctx, fname,
				     fname_stream)) {
		goto done;
	}

	/* Open the base file with OPEN */
	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_READ_DATA |
				SEC_FILE_WRITE_DATA |
				SEC_FILE_APPEND_DATA |
				SEC_STD_READ_CONTROL;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	 * check create open: sanity check
	 */
	torture_comment(tctx, "(%s) Checking create disp: open\n",
			__location__);
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!check_stream_list(tree, tctx, fname, 2, stream_list,
			       io.smb2.out.file.handle)) {
		goto done;
	}
	smb2_util_close(tree, io.smb2.out.file.handle);

	/*
	 * check create overwrite
	 */
	torture_comment(tctx, "(%s) Checking create disp: overwrite\n",
			__location__);
	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!check_stream_list(tree, tctx, fname, 1, &default_stream_name,
			       io.smb2.out.file.handle)) {
		goto done;
	}
	smb2_util_close(tree, io.smb2.out.file.handle);

	/*
	 * check create overwrite_if
	 */
	torture_comment(tctx, "(%s) Checking create disp: overwrite_if\n",
			__location__);
	smb2_util_unlink(tree, fname);
	if (!create_file_with_stream(tctx, tree, mem_ctx, fname, fname_stream))
		goto done;

	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!check_stream_list(tree, tctx, fname, 1, &default_stream_name,
			       io.smb2.out.file.handle)) {
		goto done;
	}
	smb2_util_close(tree, io.smb2.out.file.handle);

	/*
	 * check create supersede
	 */
	torture_comment(tctx, "(%s) Checking create disp: supersede\n",
			__location__);
	smb2_util_unlink(tree, fname);
	if (!create_file_with_stream(tctx, tree, mem_ctx, fname,
				     fname_stream)) {
		goto done;
	}

	io.smb2.in.create_disposition = NTCREATEX_DISP_SUPERSEDE;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!check_stream_list(tree, tctx, fname, 1, &default_stream_name,
			       io.smb2.out.file.handle)) {
		goto done;
	}
	smb2_util_close(tree, io.smb2.out.file.handle);

	/*
	 * check create overwrite_if on a stream.
	 */
	torture_comment(tctx, "(%s) Checking create disp: overwrite_if on "
			"stream\n", __location__);
	smb2_util_unlink(tree, fname);
	if (!create_file_with_stream(tctx, tree, mem_ctx, fname,
				     fname_stream)) {
		goto done;
	}

	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.smb2.in.fname = fname_stream;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!check_stream_list(tree, tctx, fname, 2, stream_list,
			       io.smb2.out.file.handle)) {
		goto done;
	}
	smb2_util_close(tree, io.smb2.out.file.handle);
 done:
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

static bool open_stream(struct smb2_tree *tree,
			struct torture_context *mem_ctx,
			const char *fname,
			struct smb2_handle *h_out)
{
	NTSTATUS status;
	union smb_open io;

	ZERO_STRUCT(io.smb2);
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_READ_DATA |
				SEC_FILE_WRITE_DATA |
				SEC_FILE_APPEND_DATA |
				SEC_STD_READ_CONTROL |
				SEC_FILE_WRITE_ATTRIBUTE;
	io.smb2.in.create_options = 0;
	io.smb2.in.file_attributes = 0;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	status = smb2_create(tree, mem_ctx, &(io.smb2));
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	*h_out = io.smb2.out.file.handle;
	return true;
}


/* Test the effect of setting attributes on a stream. */
static bool test_stream_attributes1(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	const char *fname = DNAME "\\stream_attr.txt";
	const char *stream = "Stream One:$DATA";
	const char *fname_stream;
	struct smb2_handle h, h1;
	union smb_fileinfo finfo;
	union smb_setfileinfo sfinfo;
	time_t basetime = (time(NULL) - 86400) & ~1;

	ZERO_STRUCT(h);
	ZERO_STRUCT(h1);

	torture_comment(tctx, "(%s) testing attribute setting on stream\n",
			__location__);

	/* clean slate .. */
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, fname);
	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	fname_stream = talloc_asprintf(mem_ctx, "%s:%s", fname, stream);

	/* Create a file with a stream with attribute FILE_ATTRIBUTE_ARCHIVE. */
	ret = create_file_with_stream(tctx, tree, mem_ctx, fname,
				      fname_stream);
	if (!ret) {
		goto done;
	}

	ZERO_STRUCT(io.smb2);
	io.smb2.in.fname = fname;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				 NTCREATEX_SHARE_ACCESS_WRITE |
				 NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	finfo.generic.in.file.handle = io.smb2.out.file.handle;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (finfo.basic_info.out.attrib != FILE_ATTRIBUTE_ARCHIVE) {
		torture_comment(tctx, "(%s) Incorrect attrib %x - should be "
		    "%x\n", __location__,
		    (unsigned int)finfo.basic_info.out.attrib,
		    (unsigned int)FILE_ATTRIBUTE_ARCHIVE);
		ret = false;
		goto done;
	}

	smb2_util_close(tree, io.smb2.out.file.handle);
	/* Now open the stream name. */

	if (!open_stream(tree, tctx, fname_stream, &h1)) {
		goto done;
	}

	/* Change the time on the stream. */
	ZERO_STRUCT(sfinfo);
	unix_to_nt_time(&sfinfo.basic_info.in.write_time, basetime);
	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	status = smb2_setinfo_file(tree, &sfinfo);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "(%s) %s - %s (should be %s)\n",
		    __location__, "SETATTR",
		    nt_errstr(status), nt_errstr(NT_STATUS_OK));
		ret = false;
		goto done;
	}

	smb2_util_close(tree, h1);

	ZERO_STRUCT(io.smb2);
	io.smb2.in.fname = fname;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	finfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "(%s) %s pathinfo - %s\n",
		    __location__, "SETATTRE", nt_errstr(status));
		ret = false;
		goto done;
	}

	if (nt_time_to_unix(finfo.basic_info.out.write_time) != basetime) {
		torture_comment(tctx, "(%s) time incorrect.\n", __location__);
		ret = false;
		goto done;
	}
	smb2_util_close(tree, h1);

	if (!open_stream(tree, tctx, fname_stream, &h1)) {
		goto done;
	}

	/* Changing attributes on stream */
	ZERO_STRUCT(sfinfo);
	sfinfo.basic_info.in.attrib = FILE_ATTRIBUTE_READONLY;

	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	status = smb2_setinfo_file(tree, &sfinfo);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "(%s) %s - %s (should be %s)\n",
			__location__, "SETATTR",
			nt_errstr(status), nt_errstr(NT_STATUS_OK));
		ret = false;
		goto done;
	}

	smb2_util_close(tree, h1);

	ZERO_STRUCT(io.smb2);
	io.smb2.in.fname = fname;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.desired_access = SEC_FILE_READ_DATA;
	status = smb2_create(tree, mem_ctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	finfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

done:
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);

	return ret;
}

static bool check_metadata(struct torture_context *tctx,
			   struct smb2_tree *tree,
			   const char *path,
			   struct smb2_handle _h,
			   NTTIME expected_btime,
			   uint32_t expected_attribs)
{
	struct smb2_handle h = _h;
	union smb_fileinfo getinfo;
	NTSTATUS status;
	bool ret = true;

	if (smb2_util_handle_empty(h)) {
		struct smb2_create c;

		c = (struct smb2_create) {
			.in.desired_access = SEC_FILE_ALL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.file_attributes = FILE_ATTRIBUTE_HIDDEN,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
			.in.fname = path,
		};
		status = smb2_create(tree, tctx, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");

		h = c.out.file.handle;
	}

	getinfo = (union smb_fileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
		.generic.in.file.handle = h,
	};

	status = smb2_getinfo_file(tree, tctx, &getinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");

	torture_assert_u64_equal_goto(tctx,
				      expected_btime,
				      getinfo.basic_info.out.create_time,
				      ret, done,
				      "btime was updated\n");

	torture_assert_u32_equal_goto(tctx,
				      expected_attribs,
				      getinfo.basic_info.out.attrib,
				      ret, done,
				      "btime was updated\n");

done:
	if (smb2_util_handle_empty(_h)) {
		smb2_util_close(tree, h);
	}

	return ret;
}

static bool test_stream_attributes2(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create c1;
	struct smb2_handle h1 = {{0}};
	const char *fname = DNAME "\\test_stream_btime";
	const char *sname = DNAME "\\test_stream_btime:stream";
	union smb_fileinfo getinfo;
	union smb_setfileinfo setinfo;
	const char *data = "test data";
	struct timespec ts;
	NTTIME btime;
	uint32_t attrib = FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_ARCHIVE;
	bool ret;

	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree, h1);

	torture_comment(tctx, "Let's dance!\n");

	/*
	 * Step 1: create file and get creation date
	 */

	c1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_HIDDEN,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = fname,
	};
	status = smb2_create(tree, tctx, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c1.out.file.handle;

	getinfo = (union smb_fileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tctx, &getinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");

	btime = getinfo.basic_info.out.create_time;

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	/*
	 * Step X: write to file, assert btime was not updated
	 */

	c1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = attrib,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = fname,
	};
	status = smb2_create(tree, tctx, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c1.out.file.handle;

	status = smb2_util_write(tree, h1, data, 0, strlen(data));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_write failed\n");

	ret = check_metadata(tctx, tree, NULL, h1, btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	ret = check_metadata(tctx, tree, fname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	/*
	 * Step X: create stream, assert creation date is the same
	 * as the one on the basefile
	 */

	c1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = attrib,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = sname,
	};
	status = smb2_create(tree, tctx, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c1.out.file.handle;

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	ret = check_metadata(tctx, tree, sname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	/*
	 * Step X: set btime on stream, verify basefile has the same btime.
	 */

	c1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = attrib,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = sname,
	};
	status = smb2_create(tree, tctx, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c1.out.file.handle;

	setinfo = (union smb_setfileinfo) {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h1,
	};
	clock_gettime_mono(&ts);
	btime = setinfo.basic_info.in.create_time = full_timespec_to_nt_time(&ts);

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	ret = check_metadata(tctx, tree, NULL, h1, btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad time on stream\n");

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	ret = check_metadata(tctx, tree, fname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad time on basefile\n");

	ret = check_metadata(tctx, tree, sname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad time on stream\n");

	/*
	 * Step X: write to stream, assert btime was not updated
	 */

	c1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = attrib,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = sname,
	};
	status = smb2_create(tree, tctx, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c1.out.file.handle;

	status = smb2_util_write(tree, h1, data, 0, strlen(data));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_write failed\n");

	ret = check_metadata(tctx, tree, NULL, h1, btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	ret = check_metadata(tctx, tree, fname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	ret = check_metadata(tctx, tree, sname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	/*
	 * Step X: modify attributes via stream, verify it's "also" set on the
	 * basefile.
	 */

	c1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = attrib,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = sname,
	};
	status = smb2_create(tree, tctx, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c1.out.file.handle;

	attrib = FILE_ATTRIBUTE_NORMAL;

	setinfo = (union smb_setfileinfo) {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h1,
		.basic_info.in.attrib = attrib,
	};

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	ret = check_metadata(tctx, tree, fname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	ret = check_metadata(tctx, tree, sname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	/*
	 * Step X: modify attributes via basefile, verify it's "also" set on the
	 * stream.
	 */

	c1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = attrib,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = fname,
	};
	status = smb2_create(tree, tctx, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c1.out.file.handle;

	attrib = FILE_ATTRIBUTE_HIDDEN;

	setinfo = (union smb_setfileinfo) {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h1,
		.basic_info.in.attrib = attrib,
	};

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	ret = check_metadata(tctx, tree, fname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

	ret = check_metadata(tctx, tree, sname, (struct smb2_handle){{0}},
			     btime, attrib);
	torture_assert_goto(tctx, ret, ret, done, "Bad metadata\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}

	smb2_deltree(tree, DNAME);

	return ret;
}

static bool test_basefile_rename_with_open_stream(struct torture_context *tctx,
						  struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_tree *tree2 = NULL;
	struct smb2_create create, create2;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};
	const char *fname = "test_rename_openfile";
	const char *sname = "test_rename_openfile:foo";
	const char *fname_renamed = "test_rename_openfile_renamed";
	union smb_setfileinfo sinfo;
	const char *data = "test data";

	ret = torture_smb2_connection(tctx, &tree2);
	torture_assert_goto(tctx, ret == true, ret, done,
			    "torture_smb2_connection failed\n");

	torture_comment(tctx, "Creating file with stream\n");

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_FILE_ALL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	create.in.fname = sname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	h1 = create.out.file.handle;

	torture_comment(tctx, "Writing to stream\n");

	status = smb2_util_write(tree, h1, data, 0, strlen(data));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_write failed\n");

	torture_comment(tctx, "Renaming base file\n");

	ZERO_STRUCT(create2);
	create2.in.desired_access = SEC_FILE_ALL;
	create2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create2.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create2.in.create_disposition = NTCREATEX_DISP_OPEN;
	create2.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	create2.in.fname = fname;

	status = smb2_create(tree2, tctx, &create2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	h2 = create2.out.file.handle;

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h2;
	sinfo.rename_information.in.new_name = fname_renamed;

	status = smb2_setinfo_file(tree2, &sinfo);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_ACCESS_DENIED, ret, done,
		"smb2_setinfo_file didn't return NT_STATUS_ACCESS_DENIED\n");

	smb2_util_close(tree2, h2);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname_renamed);

	return ret;
}

/*
 * Simple test creating a stream on a share with "inherit permissions"
 * enabled. This tests specifically bug 15695.
 */
bool test_stream_inherit_perms(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_handle h = {};
	union smb_fileinfo q = {};
	union smb_setfileinfo setinfo = {};
	struct security_descriptor *sd = NULL;
	struct security_ace ace = {};
	const char *fname = DNAME "\\test_stream_inherit_perms:stream";
	bool ret = true;

	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");

	torture_comment(tctx, "getting original sd\n");

	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = h;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;

	status = smb2_getinfo_file(tree, tctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");

	sd = q.query_secdesc.out.sd;

	/*
	 * Add one explicit non-inheriting ACE which will be stored
	 * as a non-inheriting POSIX ACE. These are the ACEs that
	 * "inherit permissions" will want to inherit.
	 */
	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.access_mask = SEC_STD_ALL;
	ace.trustee = *(sd->owner_sid);

	status = security_descriptor_dacl_add(sd, &ace);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"security_descriptor_dacl_add failed\n");

	setinfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	setinfo.set_secdesc.in.file.handle = h;
	setinfo.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	setinfo.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed");

	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

	/* This triggers the crash */
	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testfile failed");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, DNAME);
	return ret;
}

/*
   basic testing of streams calls SMB2
*/
struct torture_suite *torture_smb2_streams_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
		torture_suite_create(ctx, "streams");

	torture_suite_add_1smb2_test(suite, "dir", test_stream_dir);
	torture_suite_add_1smb2_test(suite, "io", test_stream_io);
	torture_suite_add_1smb2_test(suite, "sharemodes", test_stream_sharemodes);
	torture_suite_add_1smb2_test(suite, "names", test_stream_names);
	torture_suite_add_1smb2_test(suite, "names2", test_stream_names2);
	torture_suite_add_1smb2_test(suite, "names3", test_stream_names3);
	torture_suite_add_1smb2_test(suite, "rename", test_stream_rename);
	torture_suite_add_1smb2_test(suite, "rename2", test_stream_rename2);
	torture_suite_add_1smb2_test(suite, "create-disposition", test_stream_create_disposition);
	torture_suite_add_1smb2_test(suite, "attributes1", test_stream_attributes1);
	torture_suite_add_1smb2_test(suite, "attributes2", test_stream_attributes2);
	torture_suite_add_1smb2_test(suite, "delete", test_stream_delete);
	torture_suite_add_1smb2_test(suite, "zero-byte", test_zero_byte_stream);
	torture_suite_add_1smb2_test(suite, "basefile-rename-with-open-stream",
					test_basefile_rename_with_open_stream);

	suite->description = talloc_strdup(suite, "SMB2-STREAM tests");
	return suite;
}
