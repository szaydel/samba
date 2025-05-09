/* 
   Unix SMB/CIFS implementation.

   test suite for delayed write update 

   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Jeremy Allison 2004
   
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
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "system/time.h"
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "torture/basic/proto.h"

#define BASEDIR "\\delaywrite"

static bool test_delayed_write_update(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;

	torture_comment(tctx, "\nRunning test_delayed_write_update\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	torture_assert_int_not_equal(tctx, fnum1, -1, talloc_asprintf(tctx,
				     "Failed to open %s", fname));

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_comment(tctx, "Initial write time %s\n",
			nt_time_string(tctx, finfo1.basic_info.out.write_time));

	/* Bypass coarse timesources resolution */
	smb_msleep(10);

	written =  smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	torture_assert_int_equal(tctx, written, 1,
				 "unexpected number of bytes written");

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo2.basic_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo2.basic_info.out.write_time,
				     finfo1.basic_info.out.write_time,
				     "Server did not update write time");

	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

static bool test_delayed_write_update1(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_fileinfo finfo1, finfo2, finfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file1.txt";
	NTSTATUS status;
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;
	char buf[2048];
	bool first;
	bool updated;

	torture_comment(tctx, "\nRunning test_delayed_write_update1\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	torture_assert_int_not_equal(tctx, fnum1, -1, talloc_asprintf(tctx,
				     "Failed to open %s", fname));

	memset(buf, 'x', 2048);
	written =  smbcli_write(cli->tree, fnum1, 0, buf, 0, 2048);

	/* 3 second delay to ensure we get past any 2 second time
	   granularity (older systems may have that) */
	smb_msleep(3 * msec);

	finfo1.all_info.level = RAW_FILEINFO_ALL_INFO;
	finfo1.all_info.in.file.fnum = fnum1;
	finfo2 = finfo1;
	finfo3 = finfo1;
	pinfo4.all_info.level = RAW_FILEINFO_ALL_INFO;
	pinfo4.all_info.in.file.path = fname;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo1.all_info.out.size, 2048,
				 "file size not as expected after write(2048)");

	torture_comment(tctx, "Initial write time %s\n",
			nt_time_string(tctx, finfo1.all_info.out.write_time));

	/* 3 second delay to ensure we get past any 2 second time
	   granularity (older systems may have that) */
	smb_msleep(3 * msec);

	/* Do a zero length SMBwrite call to truncate. */
	written = smbcli_smbwrite(cli->tree, fnum1, "x", 1024, 0);
	torture_assert_int_equal(tctx, written, 0,
				 "unexpected number of bytes written");

	start = timeval_current();
	end = timeval_add(&start, (120 * sec), 0);
	first = true;
	updated = false;
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

		torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

		torture_assert_u64_equal(tctx, finfo2.all_info.out.size, 1024,
					 "file not truncated to expected size "
					 "(1024)");

		torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo2.all_info.out.write_time));

		if (finfo1.all_info.out.write_time !=
		    finfo2.all_info.out.write_time)
		{
			updated = true;
			break;
		}

		fflush(stdout);
		smb_msleep(1 * msec);
		first = false;
	}

	torture_assert(tctx, updated,
		       "Server did not update write time within 120 seconds");

	torture_assert(tctx, first, talloc_asprintf(tctx,
		       "Server did not update write time immediately but only "
		       "after %.2f seconds!", timeval_elapsed(&start)));

	torture_comment(tctx, "Server updated write time immediately. Good!\n");

	fflush(stdout);
	smb_msleep(2 * msec);

	/* Do a non-zero length SMBwrite and make sure it updates the write time. */
	written = smbcli_smbwrite(cli->tree, fnum1, "x", 0, 1);
	torture_assert_int_equal(tctx, written, 1,
				 "unexpected number of bytes written");

	updated = false;
	start = timeval_current();
	end = timeval_add(&start, (10*sec), 0);
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo3);

		torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

		torture_assert_u64_equal(tctx, finfo3.all_info.out.size, 1024,
					 "file not truncated to expected size "
					 "(1024)");

		torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo3.all_info.out.write_time));

		if (finfo3.all_info.out.write_time !=
		    finfo2.all_info.out.write_time)
		{
			updated = true;
			break;
		}
		fflush(stdout);
		smb_msleep(1 * msec);
	}

	torture_assert(tctx, updated,
		       "Server did not update write time within 10 seconds");

	fflush(stdout);
	smb_msleep(2 * msec);

	/* the close should not trigger an write time update */
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	status = smb_raw_pathinfo(cli->tree, tctx, &pinfo4);
	torture_assert_ntstatus_ok(tctx, status, "pathinfo failed");

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 finfo3.all_info.out.write_time,
				 "Server did update write time on "
				     "close (wrong!)");

	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/* Updating with a SMBwrite of zero length
 * changes the write time immediately - even on expand. */

static bool test_delayed_write_update1a(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_fileinfo finfo1, finfo2, finfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file1a.txt";
	NTSTATUS status;
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	char buf[2048];

	torture_comment(tctx, "\nRunning test_delayed_write_update1a\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	torture_assert_int_not_equal(tctx, fnum1, -1, talloc_asprintf(tctx,
				     "Failed to open %s", fname));

	memset(buf, 'x', 2048);
	written =  smbcli_write(cli->tree, fnum1, 0, buf, 0, 2048);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	finfo1.all_info.level = RAW_FILEINFO_ALL_INFO;
	finfo1.all_info.in.file.fnum = fnum1;
	finfo2 = finfo1;
	finfo3 = finfo1;
	pinfo4.all_info.level = RAW_FILEINFO_ALL_INFO;
	pinfo4.all_info.in.file.path = fname;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo1.all_info.out.size, 2048,
				 "file size not as expected after write(2048)");

	torture_comment(tctx, "Initial write time %s\n",
			nt_time_string(tctx, finfo1.all_info.out.write_time));

	/* Do a zero length SMBwrite call to truncate. */
	written = smbcli_smbwrite(cli->tree, fnum1, "x", 10240, 0);

	torture_assert_int_equal(tctx, written, 0,
				 "unexpected number of bytes written");

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo2.all_info.out.size, 10240,
				 "file not truncated to expected size "
				 "(10240)");

	torture_assert_u64_not_equal(tctx,
				     finfo1.all_info.out.write_time,
				     finfo2.all_info.out.write_time,
				     "Server did not update write time immediately");

	torture_comment(tctx, "Server updated write time immediately. Good!\n");

	fflush(stdout);
	smb_msleep(20);

	/* Do a non-zero length SMBwrite and make sure it doesn't update the write time. */
	written = smbcli_smbwrite(cli->tree, fnum1, "x", 0, 1);

	torture_assert_int_equal(tctx, written, 1,
				 "unexpected number of bytes written");

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo3);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo3.all_info.out.size, 10240,
				 "file not truncated to expected size "
				 "(10240)");

	torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo3.all_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo3.all_info.out.write_time,
				     finfo2.all_info.out.write_time,
				     "Server did not update write time immediately");

	/* the close should not trigger a write time update */
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	status = smb_raw_pathinfo(cli->tree, tctx, &pinfo4);
	torture_assert_ntstatus_ok(tctx, status, "pathinfo failed");

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 finfo3.all_info.out.write_time,
				 "Server updated write time on "
				 "close (wrong!)");

	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/* Updating with a SET_FILE_END_OF_FILE_INFO
 * changes the write time immediately - even on expand. */

static bool test_delayed_write_update1b(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_fileinfo finfo1, finfo2, finfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file1b.txt";
	NTSTATUS status;
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	char buf[2048];

	torture_comment(tctx, "\nRunning test_delayed_write_update1b\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	torture_assert_int_not_equal(tctx, fnum1, -1, talloc_asprintf(tctx,
				     "Failed to open %s", fname));

	memset(buf, 'x', 2048);
	written =  smbcli_write(cli->tree, fnum1, 0, buf, 0, 2048);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	finfo1.all_info.level = RAW_FILEINFO_ALL_INFO;
	finfo1.all_info.in.file.fnum = fnum1;
	finfo2 = finfo1;
	finfo3 = finfo1;
	pinfo4.all_info.level = RAW_FILEINFO_ALL_INFO;
	pinfo4.all_info.in.file.path = fname;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo1.all_info.out.size, 2048,
				 "file size not as expected after write(2048)");

	torture_comment(tctx, "Initial write time %s\n",
		nt_time_string(tctx, finfo1.all_info.out.write_time));

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/* Do a SET_END_OF_FILE_INFO call to truncate. */
	status = smbcli_ftruncate(cli->tree, fnum1, (uint64_t)10240);

	torture_assert_ntstatus_ok(tctx, status, "SET_END_OF_FILE failed");

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo2.all_info.out.size, 10240,
				 "file not truncated to expected size "
				 "(10240)");

	torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo2.all_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	fflush(stdout);
	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/* Do a non-zero length SMBwrite and make sure it doesn't update the write time. */
	written = smbcli_smbwrite(cli->tree, fnum1, "x", 0, 1);

	torture_assert_int_equal(tctx, written, 1,
				 "unexpected number of bytes written");

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo3);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo3.all_info.out.size, 10240,
				 "file not truncated to expected size "
				 "(10240)");

	torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo3.all_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo3.all_info.out.write_time,
				     finfo2.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/* the close should not trigger an write time update */
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	status = smb_raw_pathinfo(cli->tree, tctx, &pinfo4);
	torture_assert_ntstatus_ok(tctx, status, "pathinfo failed");

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 finfo3.all_info.out.write_time,
				 "Server updated write time on "
				 "close (wrong!)");

	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/* Updating with a SET_ALLOCATION_INFO (truncate) does so immediately. */

static bool test_delayed_write_update1c(struct torture_context *tctx, struct smbcli_state *cli)
{
        union smb_setfileinfo parms;
	union smb_fileinfo finfo1, finfo2, finfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file1c.txt";
	NTSTATUS status;
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	char buf[2048];

	torture_comment(tctx, "\nRunning test_delayed_write_update1c\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	torture_assert_int_not_equal(tctx, fnum1, -1, talloc_asprintf(tctx,
				     "Failed to open %s", fname));

	memset(buf, 'x', 2048);
	written =  smbcli_write(cli->tree, fnum1, 0, buf, 0, 2048);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	finfo1.all_info.level = RAW_FILEINFO_ALL_INFO;
	finfo1.all_info.in.file.fnum = fnum1;
	finfo2 = finfo1;
	finfo3 = finfo1;
	pinfo4.all_info.level = RAW_FILEINFO_ALL_INFO;
	pinfo4.all_info.in.file.path = fname;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo1.all_info.out.size, 2048,
				 "file size not as expected after write(2048)");

	torture_comment(tctx, "Initial write time %s\n",
		nt_time_string(tctx, finfo1.all_info.out.write_time));

	/* Do a SET_ALLOCATION_SIZE call to truncate. */
	parms.allocation_info.level = RAW_SFILEINFO_ALLOCATION_INFO;
	parms.allocation_info.in.file.fnum = fnum1;
	parms.allocation_info.in.alloc_size = 0;

	status = smb_raw_setfileinfo(cli->tree, &parms);

	torture_assert_ntstatus_ok(tctx, status,
				   "RAW_SFILEINFO_ALLOCATION_INFO failed");

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo2.all_info.out.size, 0,
				 "file not truncated to expected size "
				 "(0)");

	torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo2.all_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/* Do a non-zero length SMBwrite and make sure it doesn't update the write time. */
	written = smbcli_smbwrite(cli->tree, fnum1, "x", 0, 1);
	torture_assert_int_equal(tctx, written, 1,
				 "Unexpected number of bytes written");

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo3);
	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_assert_u64_equal(tctx, finfo3.all_info.out.size, 1,
					 "file not expaneded");

	torture_comment(tctx, "write time %s\n",
			nt_time_string(tctx, finfo3.all_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo3.all_info.out.write_time,
				     finfo2.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/* the close should trigger an write time update */
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	status = smb_raw_pathinfo(cli->tree, tctx, &pinfo4);
	torture_assert_ntstatus_ok(tctx, status, "pathinfo failed");

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 finfo3.all_info.out.write_time,
				 "Server updated write time on "
				 "close (wrong!)");
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Do as above, but using 2 connections.
 */

static bool test_delayed_write_update2(struct torture_context *tctx, struct smbcli_state *cli, 
									   struct smbcli_state *cli2)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	int fnum2 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;
	union smb_flush flsh;

	torture_comment(tctx, "\nRunning test_delayed_write_update2\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		torture_comment(tctx, "Failed to open %s\n", fname);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	torture_comment(tctx, "Initial write time %s\n",
	       nt_time_string(tctx, finfo1.basic_info.out.write_time));

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	{
		/* Try using setfileinfo instead of write to update write time. */
		union smb_setfileinfo sfinfo;
		time_t t_set = time(NULL);
		sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFO;
		sfinfo.basic_info.in.file.fnum = fnum1;
		sfinfo.basic_info.in.create_time = finfo1.basic_info.out.create_time;
		sfinfo.basic_info.in.access_time = finfo1.basic_info.out.access_time;

		/* I tried this with both + and - ve to see if it makes a different.
		   It doesn't - once the filetime is set via setfileinfo it stays that way. */
#if 1
		unix_to_nt_time(&sfinfo.basic_info.in.write_time, t_set - 30000);
#else
		unix_to_nt_time(&sfinfo.basic_info.in.write_time, t_set + 30000);
#endif
		sfinfo.basic_info.in.change_time = finfo1.basic_info.out.change_time;
		sfinfo.basic_info.in.attrib = finfo1.basic_info.out.attrib;

		status = smb_raw_setfileinfo(cli->tree, &sfinfo);

		torture_assert_ntstatus_ok(tctx, status, "sfileinfo failed");
	}

	finfo2.basic_info.in.file.path = fname;

	status = smb_raw_pathinfo(cli2->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n",
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/* Now try a write to see if the write time gets reset. */

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}

	torture_comment(tctx, "Modified write time %s\n",
	       nt_time_string(tctx, finfo1.basic_info.out.write_time));


	torture_comment(tctx, "Doing a 10 byte write to extend the file and see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum1, 0, "0123456789", 1, 10);

	if (written != 10) {
		torture_result(tctx, TORTURE_FAIL, "write failed - wrote %d bytes (%s)\n",
		       (int)written, __location__);
		return false;
	}

	/* Just to prove to tridge that the an smbflush has no effect on
	   the write time :-). The setfileinfo IS STICKY. JRA. */

	torture_comment(tctx, "Doing flush after write\n");

	flsh.flush.level	= RAW_FLUSH_FLUSH;
	flsh.flush.in.file.fnum = fnum1;
	status = smb_raw_flush(cli->tree, &flsh);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smbflush failed: %s\n", nt_errstr(status)));
		return false;
	}

	/* Once the time was set using setfileinfo then it stays set - writes
	   don't have any effect. But make sure. */
	start = timeval_current();
	end = timeval_add(&start, (4*sec), 0);
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = false;
			break;
		}
		torture_comment(tctx, "write time %s\n",
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));

		torture_assert_u64_equal(tctx,
					 finfo2.all_info.out.write_time,
					 finfo1.all_info.out.write_time,
					 "Server updated write time");

		fflush(stdout);
		smb_msleep(1 * msec);
	}

	fflush(stdout);
	smb_msleep(2 * msec);

	fnum2 = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		torture_result(tctx, TORTURE_FAIL, "Failed to open %s\n", fname);
		return false;
	}

	torture_comment(tctx, "Doing a 10 byte write to extend the file via second fd and see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum2, 0, "0123456789", 11, 10);

	if (written != 10) {
		torture_result(tctx, TORTURE_FAIL, "write failed - wrote %d bytes (%s)\n",
		       (int)written, __location__);
		return false;
	}

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n",
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time");

	torture_comment(tctx, "Closing the first fd to see if write time updated.\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	torture_comment(tctx, "Doing a 10 byte write to extend the file via second fd and see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum2, 0, "0123456789", 21, 10);

	if (written != 10) {
		torture_result(tctx, TORTURE_FAIL, "write failed - wrote %d bytes (%s)\n",
		       (int)written, __location__);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum2;
	finfo2 = finfo1;
	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n",
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/*
	 * Sticky write time only applied to the handle
	 * that was used to set the write time.
	 */
	start = timeval_current();
	end = timeval_add(&start, (4*sec), 0);
	while (!timeval_expired(&end)) {
		status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = false;
			break;
		}
		torture_comment(tctx, "write time %s\n",
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));
		if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
			break;
		}
		fflush(stdout);
		smb_msleep(1 * msec);
	}

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	torture_comment(tctx, "Closing second fd to see if write time updated.\n");

	smbcli_close(cli->tree, fnum2);
	fnum2 = -1;

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	if (fnum1 == -1) {
		torture_comment(tctx, "Failed to open %s\n", fname);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}

	torture_comment(tctx, "Second open initial write time %s\n",
	       nt_time_string(tctx, finfo1.basic_info.out.write_time));

	smb_msleep(10 * msec);
	torture_comment(tctx, "Doing a 10 byte write to extend the file to see if this changes the last write time.\n");

	written =  smbcli_write(cli->tree, fnum1, 0, "0123456789", 31, 10);

	if (written != 10) {
		torture_result(tctx, TORTURE_FAIL, "write failed - wrote %d bytes (%s)\n",
		       (int)written, __location__);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;
	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return false;
	}
	torture_comment(tctx, "write time %s\n",
	       nt_time_string(tctx, finfo2.basic_info.out.write_time));

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/* One more test to do. We should read the filetime via findfirst on the
	   second connection to ensure it's the same. This is very easy for a Windows
	   server but a bastard to get right on a POSIX server. JRA. */

	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}


/* Windows does obviously not update the stat info during a write call. I
 * *think* this is the problem causing a spurious Excel 2003 on XP error
 * message when saving a file. Excel does a setfileinfo, writes, and then does
 * a getpath(!)info. Or so... For Samba sometimes it displays an error message
 * that the file might have been changed in between. What i've been able to
 * trace down is that this happens if the getpathinfo after the write shows a
 * different last write time than the setfileinfo showed. This is really
 * nasty....
 */

static bool test_finfo_after_write(struct torture_context *tctx, struct smbcli_state *cli, 
								   struct smbcli_state *cli2)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	int fnum2;
	bool ret = true;
	ssize_t written;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	torture_comment(tctx, "\nRunning test_finfo_after_write\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;

	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", nt_errstr(status));
		goto done;
	}

	smb_msleep(1 * msec);

	written =  smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);

	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	fnum2 = smbcli_open(cli2->tree, fname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		torture_result(tctx, TORTURE_FAIL, __location__": failed to open 2nd time - %s", 
		       smbcli_errstr(cli2->tree));
		ret = false;
		goto done;
	}

	written =  smbcli_write(cli2->tree, fnum2, 0, "x", 0, 1);

	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", 
		       (int)written);
		ret = false;
		goto done;
	}

	finfo2.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo2.basic_info.in.file.path = fname;

	status = smb_raw_pathinfo(cli2->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", 
			  nt_errstr(status));
		ret = false;
		goto done;
	}

	if (finfo1.basic_info.out.create_time !=
	    finfo2.basic_info.out.create_time) {
		torture_result(tctx, TORTURE_FAIL, __location__": create_time changed");
		ret = false;
		goto done;
	}

	if (finfo1.basic_info.out.write_time ==
	    finfo2.basic_info.out.write_time) {
		torture_result(tctx, TORTURE_FAIL, __location__": write_time unchanged:\n"
					   "write time conn 1 = %s, conn 2 = %s", 
		       nt_time_string(tctx, finfo1.basic_info.out.write_time),
		       nt_time_string(tctx, finfo2.basic_info.out.write_time));
		ret = false;
		goto done;
	}

	if (finfo1.basic_info.out.change_time ==
	    finfo2.basic_info.out.change_time) {
		torture_result(tctx, TORTURE_FAIL, __location__": change_time unchanged");
		ret = false;
		goto done;
	}

	/* One of the two following calls updates the qpathinfo. */

	/* If you had skipped the smbcli_write on fnum2, it would
	 * *not* have updated the stat on disk */

	smbcli_close(cli2->tree, fnum2);
	cli2 = NULL;

	/* This call is only for the people looking at ethereal :-) */
	finfo2.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo2.basic_info.in.file.path = fname;

	status = smb_raw_pathinfo(cli->tree, tctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", nt_errstr(status));
		ret = false;
		goto done;
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

#define COMPARE_WRITE_TIME_CMP(given, correct, cmp) do { \
	uint64_t r = 10*1000*1000; \
	NTTIME g = (given).basic_info.out.write_time; \
	NTTIME gr = (g / r) * r; \
	NTTIME c = (correct).basic_info.out.write_time; \
	NTTIME cr = (c / r) * r; \
	bool strict = torture_setting_bool(tctx, "strict mode", false); \
	bool err = false; \
	if (strict && (g cmp c)) { \
		err = true; \
	} else if ((g cmp c) && (gr cmp cr)) { \
		/* handle filesystem without high resolution timestamps */ \
		err = true; \
	} \
	if (err) { \
		torture_result(tctx, TORTURE_FAIL, __location__": wrong write_time (%s)%s(%llu) %s (%s)%s(%llu)", \
				#given, nt_time_string(tctx, g), (unsigned long long)g, \
				#cmp, #correct, nt_time_string(tctx, c), (unsigned long long)c); \
		ret = false; \
		goto done; \
	} \
} while (0)
#define COMPARE_WRITE_TIME_EQUAL(given,correct) \
	COMPARE_WRITE_TIME_CMP(given,correct,!=)
#define COMPARE_WRITE_TIME_GREATER(given,correct) \
	COMPARE_WRITE_TIME_CMP(given,correct,<=)
#define COMPARE_WRITE_TIME_LESS(given,correct) \
	COMPARE_WRITE_TIME_CMP(given,correct,>=)

#define COMPARE_ACCESS_TIME_CMP(given, correct, cmp) do { \
	NTTIME g = (given).basic_info.out.access_time; \
	NTTIME c = (correct).basic_info.out.access_time; \
	if (g cmp c) { \
		torture_result(tctx, TORTURE_FAIL, __location__": wrong access_time (%s)%s %s (%s)%s", \
				#given, nt_time_string(tctx, g), \
				#cmp, #correct, nt_time_string(tctx, c)); \
		ret = false; \
		goto done; \
	} \
} while (0)
#define COMPARE_ACCESS_TIME_EQUAL(given,correct) \
	COMPARE_ACCESS_TIME_CMP(given,correct,!=)

#define COMPARE_BOTH_TIMES_EQUAL(given,correct) do { \
	COMPARE_ACCESS_TIME_EQUAL(given,correct); \
	COMPARE_WRITE_TIME_EQUAL(given,correct); \
} while (0)

#define GET_INFO_FILE(finfo) do { \
	NTSTATUS _status; \
	_status = smb_raw_fileinfo(cli->tree, tctx, &finfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		ret = false; \
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", \
			       nt_errstr(_status)); \
		goto done; \
	} \
	torture_comment(tctx, "fileinfo: Access(%s) Write(%s)\n", \
			nt_time_string(tctx, finfo.basic_info.out.access_time), \
			nt_time_string(tctx, finfo.basic_info.out.write_time)); \
} while (0)
#define GET_INFO_FILE2(finfo) do { \
	NTSTATUS _status; \
	_status = smb_raw_fileinfo(cli2->tree, tctx, &finfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		ret = false; \
		torture_result(tctx, TORTURE_FAIL, __location__": fileinfo failed: %s", \
			       nt_errstr(_status)); \
		goto done; \
	} \
	torture_comment(tctx, "fileinfo: Access(%s) Write(%s)\n", \
			nt_time_string(tctx, finfo.basic_info.out.access_time), \
			nt_time_string(tctx, finfo.basic_info.out.write_time)); \
} while (0)
#define GET_INFO_FILE_EX(cli,_fnum,finfo) do { \
	NTSTATUS _status; \
	finfo.basic_info.in.file.fnum = (_fnum);		   \
	_status = smb_raw_fileinfo((cli)->tree, tctx, &(finfo)); \
	torture_assert_ntstatus_ok_goto(tctx, _status, ret, done,\
					 "smb_raw_fileinfo failed"); \
	torture_comment(tctx, "fileinfo: Access(%s) Write(%s)\n", \
			nt_time_string(tctx, (finfo).basic_info.out.access_time), \
			nt_time_string(tctx, (finfo).basic_info.out.write_time)); \
} while (0)
#define GET_INFO_PATH(pinfo) do { \
	NTSTATUS _status; \
	_status = smb_raw_pathinfo(cli2->tree, tctx, &pinfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": pathinfo failed: %s", \
			       nt_errstr(_status)); \
		ret = false; \
		goto done; \
	} \
	torture_comment(tctx, "pathinfo: Access(%s) Write(%s)\n", \
			nt_time_string(tctx, pinfo.basic_info.out.access_time), \
			nt_time_string(tctx, pinfo.basic_info.out.write_time)); \
} while (0)
#define GET_INFO_PATH_EX(cli, pinfo) do { \
	NTSTATUS _status; \
	_status = smb_raw_pathinfo((cli)->tree, tctx, &pinfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": pathinfo failed: %s", \
			       nt_errstr(_status)); \
		ret = false; \
		goto done; \
	} \
	torture_comment(tctx, "pathinfo: Access(%s) Write(%s)\n", \
			nt_time_string(tctx, pinfo.basic_info.out.access_time), \
			nt_time_string(tctx, pinfo.basic_info.out.write_time)); \
} while (0)
#define GET_INFO_BOTH(finfo,pinfo) do { \
	GET_INFO_FILE(finfo); \
	GET_INFO_PATH(pinfo); \
	COMPARE_BOTH_TIMES_EQUAL(finfo,pinfo); \
} while (0)

#define GET_INFO_BOTH_EX(cli, fnum, finfo, pinfo) do { \
	GET_INFO_FILE_EX(cli, fnum, finfo); \
	GET_INFO_PATH_EX(cli, pinfo); \
	COMPARE_BOTH_TIMES_EQUAL(finfo, pinfo); \
} while (0)

#define SET_INFO_FILE_EX(finfo, wrtime, tree, tfnum) do { \
	NTSTATUS _status; \
	union smb_setfileinfo _sfinfo; \
	_sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFO; \
	_sfinfo.basic_info.in.file.fnum = tfnum; \
	_sfinfo.basic_info.in.create_time = 0; \
	_sfinfo.basic_info.in.access_time = 0; \
	unix_to_nt_time(&_sfinfo.basic_info.in.write_time, (wrtime)); \
	_sfinfo.basic_info.in.change_time = 0; \
	_sfinfo.basic_info.in.attrib = finfo.basic_info.out.attrib; \
	_status = smb_raw_setfileinfo(tree, &_sfinfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": setfileinfo failed: %s", \
			       nt_errstr(_status)); \
		ret = false; \
		goto done; \
	} \
} while (0)
#define SET_INFO_FILE(finfo, wrtime) \
	SET_INFO_FILE_EX(finfo, wrtime, cli->tree, fnum1)

#define SET_INFO_FILE_NS(finfo, wrtime, ns, tree, tfnum) do { \
	NTSTATUS _status; \
	union smb_setfileinfo sfinfo; \
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFO; \
	sfinfo.basic_info.in.file.fnum = tfnum; \
	sfinfo.basic_info.in.create_time = 0; \
	sfinfo.basic_info.in.access_time = 0; \
	unix_to_nt_time(&sfinfo.basic_info.in.write_time, (wrtime)); \
	sfinfo.basic_info.in.write_time += (ns); \
	sfinfo.basic_info.in.change_time = 0; \
	sfinfo.basic_info.in.attrib = finfo.basic_info.out.attrib; \
	_status = smb_raw_setfileinfo(tree, &sfinfo); \
	if (!NT_STATUS_IS_OK(_status)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": setfileinfo failed: %s", \
			       nt_errstr(_status)); \
		ret = false; \
		goto done; \
	} \
} while (0)

static bool test_delayed_write_update3(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file3.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);

	torture_comment(tctx, "\nRunning test_delayed_write_update3\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/*
	 * make sure the write time is updated immediately
	 */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_FILE(finfo1);

		torture_assert_u64_not_equal(tctx,
					     finfo1.all_info.out.write_time,
					     finfo0.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");
		finfo0 = finfo1;
		/* Bypass possible filesystem granularity */
		smb_msleep(20);
	}

	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_GREATER(pinfo1, pinfo0);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/* any further write also updates the write time */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);

		torture_assert_u64_not_equal(tctx,
					     finfo2.all_info.out.write_time,
					     finfo1.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");
		finfo1 = finfo2;
		/* Bypass possible filesystem granularity */
		smb_msleep(20);
	}

	GET_INFO_BOTH(finfo3,pinfo3);

	torture_assert_u64_equal(tctx,
				 finfo3.all_info.out.write_time,
				 finfo2.all_info.out.write_time,
				 "Server unexpectedly updated write time");

	/*
	 * the close doesn't update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo4);

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 pinfo3.all_info.out.write_time,
				 "Server updated write time "
				 "on close");

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Show that a truncate write always updates the write time even
 * if an initial write has already updated the write time.
 */

static bool test_delayed_write_update3a(struct torture_context *tctx,
				        struct smbcli_state *cli,
				        struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file3a.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	int i;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	torture_comment(tctx, "\nRunning test_delayed_write_update3a\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/*
	 * sleep some time, to demonstrate the handling of write times
	 * doesn't depend on the time since the open
	 */
	smb_msleep(5 * msec);

	/* get the initial times */
	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo0);

	/*
	 * make sure the write time is updated immediately
	 */

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}
	/* get the times after the write */
	GET_INFO_FILE(finfo1);

	torture_assert_u64_not_equal(tctx,
				     finfo1.all_info.out.write_time,
				     finfo0.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_GREATER(pinfo1, pinfo0);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/*
	 * demonstrate that a truncate write always
	 * updates the write time immediately
	 */
	for (i=0; i < 3; i++) {
		smb_msleep(2 * msec);
		/* do a write */
		torture_comment(tctx, "Do a truncate SMBwrite [%d] on the file handle\n", i);
		written = smbcli_smbwrite(cli->tree, fnum1, "x", 10240, 0);
		if (written != 0) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 0", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);
		COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);
		finfo1 = finfo2;
	}

	smb_msleep(3 * msec);

	/* Check a further write updates the write time */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}
	/* get the times after the write */
	GET_INFO_BOTH(finfo2,pinfo2);

	torture_assert_u64_not_equal(tctx,
				     finfo2.all_info.out.write_time,
				     finfo1.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	GET_INFO_BOTH(finfo2,pinfo2);

	/* sleep */
	smb_msleep(3 * msec);

	/* get the initial times */
	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo2);

	/*
	 * demonstrate that a truncate write always
	 * updates the write time immediately
	 */
	for (i=0; i < 3; i++) {
		smb_msleep(2 * msec);
		/* do a write */
		torture_comment(tctx, "Do a truncate SMBwrite [%d] on the file handle\n", i);
		written = smbcli_smbwrite(cli->tree, fnum1, "x", 512, 0);
		if (written != 0) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 0", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);
		COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);
		finfo1 = finfo2;
	}

	/* sleep */
	smb_msleep(3 * msec);

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);

	/*
	 * the close doesn't update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo4);
	COMPARE_WRITE_TIME_EQUAL(pinfo4, pinfo3);

	if (pinfo4.basic_info.out.write_time == pinfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update the write_time on close (correct)\n");
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Show a close after write does not update the write timestamp to
 * the close time.
 */

static bool test_delayed_write_update3b(struct torture_context *tctx,
				        struct smbcli_state *cli,
				        struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file3b.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	torture_comment(tctx, "\nRunning test_delayed_write_update3b\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/*
	 * sleep some time, to demonstrate the handling of write times
	 * doesn't depend on the time since the open
	 */
	smb_msleep(2 * msec);

	/* get the initial times */
	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo0);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}
	/* get the times after the write */
	GET_INFO_BOTH(finfo1,pinfo1);

	torture_assert_u64_not_equal(tctx,
				     finfo1.all_info.out.write_time,
				     finfo0.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	torture_assert_u64_not_equal(tctx,
				     pinfo1.all_info.out.write_time,
				     finfo0.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/* Check further writes also update the write time */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);

		torture_assert_u64_not_equal(tctx,
					     finfo2.all_info.out.write_time,
					     finfo1.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");

		torture_assert_u64_not_equal(tctx,
					     pinfo2.all_info.out.write_time,
					     finfo1.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");

		/* Bypass possible filesystem granularity */
		smb_msleep(20);
	}

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);

	/*
	 * the close does not update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo4);

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 finfo3.all_info.out.write_time,
				 "Server updated write time");

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Check that a write after a truncate write updates
 * the timestamp and a truncate write after a write does.
 * Also prove that a close after a truncate write does not update the
 * timestamp.
 */

static bool test_delayed_write_update3c(struct torture_context *tctx,
				        struct smbcli_state *cli,
				        struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file3c.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	int i;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	torture_comment(tctx, "\nRunning test_delayed_write_update3c\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/*
	 * sleep some time, to demonstrate the handling of write times
	 * doesn't depend on the time since the open
	 */
	smb_msleep(2 * msec);

	/* get the initial times */
	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo0);

	/*
	 * demonstrate that a truncate write always
	 * updates the write time immediately
	 */
	for (i=0; i < 3; i++) {
		/* Bypass possible filesystem granularity */
		smb_msleep(20);
		/* do a write */
		torture_comment(tctx, "Do a truncate SMBwrite [%d] on the file handle\n", i);
		written = smbcli_smbwrite(cli->tree, fnum1, "x", 512, 0);
		if (written != 0) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 0", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);
		COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);
		finfo1 = finfo2;
	}

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	start = timeval_current();
	end = timeval_add(&start, 7 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_FILE(finfo2);

		torture_assert_u64_not_equal(tctx,
					     finfo2.all_info.out.write_time,
					     finfo1.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");
		/* Bypass possible filesystem granularity */
		smb_msleep(20);
	}

	/* sleep */
	smb_msleep(20);

	/* get the initial times */
	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo2);

	/*
	 * demonstrate that a truncate write always
	 * updates the write time immediately
	 */
	for (i=0; i < 3; i++) {
		smb_msleep(2 * msec);
		/* do a write */
		torture_comment(tctx, "Do a truncate write [%d] on the file handle\n", i);
		written = smbcli_smbwrite(cli->tree, fnum1, "x", 512, 0);
		if (written != 0) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 0", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);
		COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);
		finfo1 = finfo2;
	}

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_EQUAL(finfo2, finfo1);

	/*  check further writes also update the write time */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);

		torture_assert_u64_not_equal(tctx,
					     finfo2.all_info.out.write_time,
					     finfo1.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");
		smb_msleep(20);
	}

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);

	/*
	 * the close must not update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo4);

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 finfo3.all_info.out.write_time,
				 "Server did not update write time "
				 "immediately");

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Show only the first write updates the timestamp, and a close
 * after writes updates to current (I think this is the same
 * as test 3b. JRA).
 */

static bool test_delayed_write_update4(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4;
	const char *fname = BASEDIR "\\torture_file4.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);

	torture_comment(tctx, "\nRunning test_delayed_write_update4\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	GET_INFO_BOTH(finfo1,pinfo1);

	torture_assert_u64_not_equal(tctx,
				     finfo1.all_info.out.write_time,
				     finfo0.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");


	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	/* Check further writes also update the write time */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo2,pinfo2);

		torture_assert_u64_not_equal(tctx,
					     finfo2.all_info.out.write_time,
					     finfo1.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");

		/* Bypass possible filesystem granularity */
		smb_msleep(20);
	}

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);

	/*
	 * check the close does not update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo4);

	torture_assert_u64_equal(tctx,
				 pinfo4.all_info.out.write_time,
				 finfo3.all_info.out.write_time,
				 "Server did not update write time "
				 "immediately");

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Show writes and closes have no effect on updating times once a SETWRITETIME is done.
 */

static bool test_delayed_write_update5(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3, finfo4, finfo5;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4, pinfo5, pinfo6;
	const char *fname = BASEDIR "\\torture_file5.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	torture_comment(tctx, "\nRunning test_delayed_write_update5\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	finfo4 = finfo0;
	finfo5 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;
	pinfo5 = pinfo0;
	pinfo6 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	GET_INFO_BOTH(finfo1,pinfo1);

	torture_assert_u64_not_equal(tctx,
				     finfo1.all_info.out.write_time,
				     finfo0.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	torture_comment(tctx, "Set write time in the future on the file handle\n");
	SET_INFO_FILE(finfo0, time(NULL) + 86400);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);

	torture_comment(tctx, "Set write time in the past on the file handle\n");
	SET_INFO_FILE(finfo0, time(NULL) - 86400);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_LESS(finfo2, finfo1);

	/* make sure there's no delayed update happening */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {

		/* get the times after the first write */
		GET_INFO_BOTH(finfo3,pinfo3);

		if (finfo3.basic_info.out.write_time > finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_result(tctx, TORTURE_FAIL, "Server updated write_time after %.2f seconds "
					"(wrong!)\n",
					diff);
			return false;
		}
		smb_msleep(1 * msec);
	}

	/* sure any further write doesn't update the write time */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo4,pinfo4);

		torture_assert_u64_equal(tctx,
					 finfo4.all_info.out.write_time,
					 finfo3.all_info.out.write_time,
					 "Server did not honor sticky write time");
		smb_msleep(1 * msec);
	}

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	GET_INFO_BOTH(finfo5,pinfo5);
	COMPARE_WRITE_TIME_EQUAL(finfo5, finfo4);

	/*
	 * the close doesn't update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo6);

	torture_assert_u64_equal(tctx,
				 pinfo6.all_info.out.write_time,
				 finfo5.all_info.out.write_time,
				 "Server update writed time when closing");

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Show truncate writes and closes have no effect on updating times once a SETWRITETIME is done.
 */

static bool test_delayed_write_update5b(struct torture_context *tctx,
				        struct smbcli_state *cli,
				        struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3, finfo4, finfo5;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4, pinfo5, pinfo6;
	const char *fname = BASEDIR "\\torture_fileb.txt";
	int fnum1 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;

	torture_comment(tctx, "\nRunning test_delayed_write_update5b\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	finfo4 = finfo0;
	finfo5 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;
	pinfo5 = pinfo0;
	pinfo6 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	GET_INFO_BOTH(finfo1,pinfo1);
	COMPARE_WRITE_TIME_EQUAL(finfo1, finfo0);

	torture_comment(tctx, "Set write time in the future on the file handle\n");
	SET_INFO_FILE(finfo0, time(NULL) + 86400);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);

	torture_comment(tctx, "Set write time in the past on the file handle\n");
	SET_INFO_FILE(finfo0, time(NULL) - 86400);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_LESS(finfo2, finfo1);

	/* make sure there's no delayed update pending */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {

		/* get the times after the first write */
		GET_INFO_BOTH(finfo3,pinfo3);

		if (finfo3.basic_info.out.write_time > finfo2.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_result(tctx, TORTURE_FAIL, "Server updated write_time after %.2f seconds "
					"(wrong!)\n",
					diff);
			ret = false;
			break;
		}
		smb_msleep(1 * msec);
	}

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);
	if (finfo3.basic_info.out.write_time == finfo2.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write_time (correct)\n");
	}

	/* Do any further write (truncates) update the write time ? */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a truncate write on the file handle\n");
		written = smbcli_smbwrite(cli->tree, fnum1, "x", 1024, 0);
		if (written != 0) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo4,pinfo4);

		if (finfo4.basic_info.out.write_time > finfo3.basic_info.out.write_time) {
			double diff = timeval_elapsed(&start);
			torture_result(tctx, TORTURE_FAIL, "Server updated write_time after %.2f seconds "
					"(wrong!)\n",
					diff);
			ret = false;
			break;
		}
		smb_msleep(1 * msec);
	}

	GET_INFO_BOTH(finfo4,pinfo4);
	COMPARE_WRITE_TIME_EQUAL(finfo4, finfo3);
	if (finfo4.basic_info.out.write_time == finfo3.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update write_time (correct)\n");
	}

	/* sleep */
	smb_msleep(5 * msec);

	GET_INFO_BOTH(finfo5,pinfo5);
	COMPARE_WRITE_TIME_EQUAL(finfo5, finfo4);

	/*
	 * the close doesn't update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo6);
	COMPARE_WRITE_TIME_EQUAL(pinfo6, pinfo5);

	if (pinfo6.basic_info.out.write_time == pinfo5.basic_info.out.write_time) {
		torture_comment(tctx, "Server did not update the write_time on close (correct)\n");
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * Open 2 handles on a file. Write one one and then set the
 * WRITE TIME explicitly on the other. Ensure there's no delayed write time
 * update. Ensure the write time is not updated to
 * the close time when the non-explicit set handle is closed.
 *
 */

static bool test_delayed_write_update6(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       struct smbcli_state *cli2)
{
	union smb_fileinfo finfo0, finfo1, finfo2, finfo3, finfo4, finfo5;
	union smb_fileinfo pinfo0, pinfo1, pinfo2, pinfo3, pinfo4, pinfo5, pinfo6, pinfo7;
	const char *fname = BASEDIR "\\torture_file6.txt";
	int fnum1 = -1;
	int fnum2 = -1;
	bool ret = true;
	ssize_t written;
	struct timeval start;
	struct timeval end;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;
	bool first = true;

	torture_comment(tctx, "\nRunning test_delayed_write_update6\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);
again:
	torture_comment(tctx, "Open the file handle\n");
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	if (fnum2 == -1) {
		torture_comment(tctx, "Open the 2nd file handle on 2nd connection\n");
		fnum2 = smbcli_open(cli2->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
		if (fnum2 == -1) {
			ret = false;
			torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
			goto done;
		}
	}

	finfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo0.basic_info.in.file.fnum = fnum1;
	finfo1 = finfo0;
	finfo2 = finfo0;
	finfo3 = finfo0;
	finfo4 = finfo0;
	finfo5 = finfo0;
	pinfo0.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo0.basic_info.in.file.path = fname;
	pinfo1 = pinfo0;
	pinfo2 = pinfo0;
	pinfo3 = pinfo0;
	pinfo4 = pinfo0;
	pinfo5 = pinfo0;
	pinfo6 = pinfo0;
	pinfo7 = pinfo0;

	/* get the initial times */
	GET_INFO_BOTH(finfo0,pinfo0);

	/* do a write */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	GET_INFO_BOTH(finfo1,pinfo1);

	torture_assert_u64_not_equal(tctx,
				     finfo1.all_info.out.write_time,
				     finfo0.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	torture_comment(tctx, "Set write time in the future on the 2nd file handle\n");
	SET_INFO_FILE_EX(finfo0, time(NULL) + 86400, cli2->tree, fnum2);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_GREATER(finfo2, finfo1);

	torture_comment(tctx, "Set write time in the past on the 2nd file handle\n");
	SET_INFO_FILE_EX(finfo0, time(NULL) - 86400, cli2->tree, fnum2);
	GET_INFO_BOTH(finfo2,pinfo2);
	COMPARE_WRITE_TIME_LESS(finfo2, finfo1);

	/* check there's no delayed update */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {

		/* get the times after the first write */
		GET_INFO_BOTH(finfo3,pinfo3);

		torture_assert_u64_equal(tctx,
					 finfo3.all_info.out.write_time,
					 finfo2.all_info.out.write_time,
					 "Server delayed a write time "
					 "update");

		smb_msleep(20);
	}

	GET_INFO_BOTH(finfo3,pinfo3);
	COMPARE_WRITE_TIME_EQUAL(finfo3, finfo2);

	torture_assert_u64_equal(tctx,
				 finfo3.all_info.out.write_time,
				 finfo2.all_info.out.write_time,
				 "Server did not update write time "
				 "immediately");

	/* sure any further write doesn't update the write time */
	start = timeval_current();
	end = timeval_add(&start, 10 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the file handle\n");
		written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_BOTH(finfo4,pinfo4);

		torture_assert_u64_not_equal(tctx,
					     finfo4.all_info.out.write_time,
					     finfo3.all_info.out.write_time,
					     "Server did not update write time "
					     "immediately");

		smb_msleep(20);
	}

	GET_INFO_BOTH(finfo4,pinfo4);

	torture_assert_u64_not_equal(tctx,
				     finfo4.all_info.out.write_time,
				     finfo3.all_info.out.write_time,
				     "Server did not update write time "
				     "immediately");

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	GET_INFO_BOTH(finfo5,pinfo5);

	torture_assert_u64_equal(tctx,
				 finfo5.all_info.out.write_time,
				 finfo4.all_info.out.write_time,
				 "Server update write time");

	/*
	 * the close doesn't update the write time
	 */
	torture_comment(tctx, "Close the file handle\n");
	smbcli_close(cli->tree, fnum1);
	fnum1 = -1;

	GET_INFO_PATH(pinfo6);

	torture_assert_u64_equal(tctx,
				 pinfo6.all_info.out.write_time,
				 finfo5.all_info.out.write_time,
				 "Server update write time on close");

	/* See what the second write handle thinks the time is ? */
	finfo5.basic_info.in.file.fnum = fnum2;
	GET_INFO_FILE2(finfo5);

	torture_assert_u64_equal(tctx,
				 pinfo6.all_info.out.write_time,
				 finfo5.all_info.out.write_time,
				 "Server updated write time");

	/* See if we have lost the sticky write time on handle2 */
	smb_msleep(3 * msec);
	torture_comment(tctx, "Have we lost the sticky write time ?\n");

	/* Make sure any further normal write doesn't update the write time */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a write on the second file handle\n");
		written = smbcli_write(cli2->tree, fnum2, 0, "x", 0, 1);
		if (written != 1) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_FILE2(finfo5);
		GET_INFO_PATH(pinfo6);

		torture_assert_u64_equal(tctx,
					 pinfo6.all_info.out.write_time,
					 finfo5.all_info.out.write_time,
					 "Server updated write time");

		smb_msleep(1 * msec);
	}

	/* What about a truncate write ? */
	start = timeval_current();
	end = timeval_add(&start, 4 * sec, 0);
	while (!timeval_expired(&end)) {
		/* do a write */
		torture_comment(tctx, "Do a truncate write on the second file handle\n");
		written = smbcli_write(cli2->tree, fnum2, 0, "x", 0, 0);
		if (written != 0) {
			torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
			ret = false;
			goto done;
		}
		/* get the times after the write */
		GET_INFO_FILE2(finfo5);
		GET_INFO_PATH(pinfo6);

		torture_assert_u64_equal(tctx,
					 pinfo6.all_info.out.write_time,
					 finfo5.all_info.out.write_time,
					 "Server updated write time");
		smb_msleep(1 * msec);
	}


	/* keep the 2nd handle open and rerun tests */
	if (first) {
		first = false;
		goto again;
	}

	/*
	 * closing the 2nd handle will cause no write time update
	 * as the write time was explicit set on this handle
	 */
	torture_comment(tctx, "Close the 2nd file handle\n");
	smbcli_close(cli2->tree, fnum2);
	fnum2 = -1;

	GET_INFO_PATH(pinfo7);

	torture_assert_u64_equal(tctx,
				 pinfo7.all_info.out.write_time,
				 pinfo6.all_info.out.write_time,
				 "Server updated write time");

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	if (fnum2 != -1)
		smbcli_close(cli2->tree, fnum2);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

static bool test_delayed_write_update7(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_open open_parms;
	union smb_fileinfo finfo1, finfo2, finfo3;
	const char *fname = BASEDIR "\\torture_file7.txt";
	NTSTATUS status;
	int fnum1 = -1;
	bool ret = true;
	TALLOC_CTX *mem_ctx; 

	torture_comment(tctx, "\nRunning test_delayed_write_update7 (timestamp resolution test)\n");

        mem_ctx = talloc_init("test_delayed_write_update7");
        if (!mem_ctx) return false;

	ZERO_STRUCT(finfo1);
	ZERO_STRUCT(finfo2);
	ZERO_STRUCT(finfo3);
	ZERO_STRUCT(open_parms);

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	/* Create the file. */
	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		torture_result(tctx, TORTURE_FAIL, "Failed to open %s", fname);
		return false;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.file.fnum = fnum1;
	finfo2 = finfo1;
	finfo3 = finfo1;

	/* Get the initial timestamps. */
	status = smb_raw_fileinfo(cli->tree, tctx, &finfo1);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	/* Set the pending write time to a value with non zero msec. */
	SET_INFO_FILE_NS(finfo1, time(NULL) + 86400, 103 * NTTIME_MSEC,
			 cli->tree, fnum1);

	/* Get the current pending write time by fnum. */
	status = smb_raw_fileinfo(cli->tree, tctx, &finfo2);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	/* Ensure the time is actually different. */
	if (finfo1.basic_info.out.write_time == finfo2.basic_info.out.write_time) {
		torture_result(tctx, TORTURE_FAIL,
			"setfileinfo time matches original fileinfo time");
		ret = false;
	}

	/* Get the current pending write time by path. */
	finfo3.basic_info.in.file.path = fname;
	status = smb_raw_pathinfo(cli->tree, tctx, &finfo3);

	if (finfo2.basic_info.out.write_time != finfo3.basic_info.out.write_time) {
		torture_result(tctx, TORTURE_FAIL, 
			"qpathinfo time doesn't match fileinfo time");
		ret = false;
	}

	/* Now close the file. Re-open and check that the write
	   time is identical to the one we wrote. */

	smbcli_close(cli->tree, fnum1);

	open_parms.ntcreatex.level = RAW_OPEN_NTCREATEX;
	open_parms.ntcreatex.in.flags = 0;
	open_parms.ntcreatex.in.access_mask = SEC_GENERIC_READ;
	open_parms.ntcreatex.in.file_attr = 0;
	open_parms.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE|
					NTCREATEX_SHARE_ACCESS_READ|
					NTCREATEX_SHARE_ACCESS_WRITE;
	open_parms.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	open_parms.ntcreatex.in.create_options = 0;
	open_parms.ntcreatex.in.fname = fname;

	status = smb_raw_open(cli->tree, mem_ctx, &open_parms);
	talloc_free(mem_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL,
			"setfileinfo time matches original fileinfo time");
		ret = false;
	}

	fnum1 = open_parms.ntcreatex.out.file.fnum;

	/* Check the returned time matches. */
        if (open_parms.ntcreatex.out.write_time != finfo2.basic_info.out.write_time) {
		torture_result(tctx, TORTURE_FAIL,
			"final open time does not match set time");
		ret = false;
	}

 done:

	smbcli_close(cli->tree, fnum1);

	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}

/*
   Test if creating a file in a directory with an open handle updates the
   write timestamp (it should).
*/
static bool test_directory_update8(struct torture_context *tctx, struct smbcli_state *cli)
{
	union smb_fileinfo dir_info1, dir_info2;
	union smb_open open_parms;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	int fnum2 = -1;
	bool ret = true;
	double used_delay = torture_setting_int(tctx, "writetimeupdatedelay", 2000000);
	int normal_delay = 2000000;
	double sec = ((double)used_delay) / ((double)normal_delay);
	int msec = 1000 * sec;
	TALLOC_CTX *mem_ctx = talloc_init("test_delayed_write_update8");

        if (!mem_ctx) return false;

	torture_comment(tctx, "\nRunning test directory write update\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	/* Open a handle on the directory - and leave it open. */
	ZERO_STRUCT(open_parms);
        open_parms.ntcreatex.level = RAW_OPEN_NTCREATEX;
        open_parms.ntcreatex.in.flags = 0;
        open_parms.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_READ;
        open_parms.ntcreatex.in.file_attr = 0;
        open_parms.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE|
                                        NTCREATEX_SHARE_ACCESS_READ|
                                        NTCREATEX_SHARE_ACCESS_WRITE;
        open_parms.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
        open_parms.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
        open_parms.ntcreatex.in.fname = BASEDIR;

        status = smb_raw_open(cli->tree, mem_ctx, &open_parms);
        talloc_free(mem_ctx);

        if (!NT_STATUS_IS_OK(status)) {
                torture_result(tctx, TORTURE_FAIL,
                        "failed to open directory handle");
                ret = false;
		goto done;
        }

        fnum1 = open_parms.ntcreatex.out.file.fnum;

        /* Store the returned write time. */
	ZERO_STRUCT(dir_info1);
	dir_info1.basic_info.out.write_time = open_parms.ntcreatex.out.write_time;

	torture_comment(tctx, "Initial write time %s\n",
	       nt_time_string(tctx, dir_info1.basic_info.out.write_time));

	/* sleep */
	smb_msleep(3 * msec);

	/* Now create a file within the directory. */
	fnum2 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum2 == -1) {
		torture_result(tctx, TORTURE_FAIL, "Failed to open %s", fname);
                ret = false;
		goto done;
	}
	smbcli_close(cli->tree, fnum2);

	/* Read the directory write time again. */
	ZERO_STRUCT(dir_info2);
	dir_info2.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	dir_info2.basic_info.in.file.fnum = fnum1;

	status = smb_raw_fileinfo(cli->tree, tctx, &dir_info2);

	torture_assert_ntstatus_ok(tctx, status, "fileinfo failed");

	/* Ensure it's been incremented. */
	COMPARE_WRITE_TIME_GREATER(dir_info2, dir_info1);

	torture_comment(tctx, "Updated write time %s\n",
	       nt_time_string(tctx, dir_info2.basic_info.out.write_time));

 done:

	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
 * | Time | Handle 1               | Handle 2               |
 * |------+------------------------+------------------------|
 * |    1 | Create file            | Open file              |
 * |      | Check Handle Time = 1  | Check Handle Time = 1  |
 * |      | Check Path Time = 1    | Check Path Time = 1    |
 * |    2 | Write                  |                        |
 * |    3 | Check Handle Time = 2  | Check Handle Time = 2  |
 * |      | Check Path Time = 2    | Check Path Time = 2    |
 * |    4 | Set Sticky Time = 99   |                        |
 * |    5 | Check Handle Time = 99 | Check Handle Time = 99 |
 * |      | Check Path Time = 99   | Check Path Time = 99   |
 * |    6 | Write                  |                        |
 * |    7 | Check Handle Time = 99 | Check Handle Time = 99 |
 * |      | Check Path Time = 99   | Check Path Time = 99   |
 * |    8 |                        | Write                  |
 * |    9 | Check Handle Time = 8  | Check Handle Time = 8  |
 * |      | Check Path Time = 8    | Check Path Time = 8    |
 * |   10 | Write                  |                        |
 * |   11 | Check Handle Time = 8  | Check Handle Time = 8  |
 * |      | Check Path Time = 8    | Check Path Time = 8    |
 * |   12 | Close                  | Close                  |
 * |   13 | Check Path Time = 8    | Check Path Time = 8    |
 */
static bool test_modern_write_time1(struct torture_context *tctx,
				    struct smbcli_state *cli,
				    struct smbcli_state *cli2)
{
	union smb_fileinfo finfo_prev, finfo_curr;
	union smb_fileinfo pinfo_prev, pinfo_curr;
	const char *fname = BASEDIR "\\torture_file_modern1.txt";
	time_t stickytime = time(NULL) + 86400;
	NTTIME stickynttime;
	int fnum1 = -1;
	int fnum2 = -1;
	ssize_t written;
	NTSTATUS status;
	bool ret = true;

	unix_to_nt_time(&stickynttime, stickytime);

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	fnum2 = smbcli_open(cli2->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum2 == -1) {
		ret = false;
		torture_result(tctx, TORTURE_FAIL, __location__": unable to open %s", fname);
		goto done;
	}

	finfo_prev.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo_curr = finfo_prev;

	pinfo_prev.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	pinfo_prev.basic_info.in.file.path = fname;
	pinfo_curr = pinfo_prev;

	/* get the initial times */
	GET_INFO_BOTH_EX(cli, fnum1, finfo_prev, pinfo_prev);

	/* 2 */
	torture_comment(tctx, "Do a write on the file handle\n");
	written = smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);
	if (written != 1) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 1", (int)written);
		ret = false;
		goto done;
	}

	/* 3 */
	GET_INFO_BOTH_EX(cli, fnum1, finfo_curr, pinfo_curr);
	torture_assert_u64_not_equal_goto(tctx,
					  finfo_curr.basic_info.out.write_time,
					  finfo_prev.basic_info.out.write_time,
					  ret, done,
					  "Server did not update write time "
					  "immediately");
	torture_assert_u64_not_equal_goto(tctx,
					  pinfo_curr.basic_info.out.write_time,
					  pinfo_prev.basic_info.out.write_time,
					  ret, done,
					  "Server did not update write time "
					  "immediately");

	GET_INFO_BOTH_EX(cli2, fnum2, finfo_curr, pinfo_curr);
	torture_assert_u64_not_equal_goto(tctx,
					  finfo_curr.basic_info.out.write_time,
					  finfo_prev.basic_info.out.write_time,
					  ret, done,
					  "Server did not update write time "
					  "immediately");
	torture_assert_u64_not_equal_goto(tctx,
					  pinfo_curr.basic_info.out.write_time,
					  pinfo_prev.basic_info.out.write_time,
					  ret, done,
					  "Server did not update write time "
					  "immediately");
	finfo_prev = finfo_curr;
	pinfo_prev = pinfo_curr;

	/* 4 */
	torture_comment(tctx, "Set write time in the future on the 1st file handle\n");
	SET_INFO_FILE_EX(finfo_curr, stickytime, cli->tree, fnum1);


	/* 5 */
	GET_INFO_BOTH_EX(cli, fnum1, finfo_curr, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");
	GET_INFO_BOTH_EX(cli2, fnum2, finfo_curr, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");

	/* 6 */
	written = smbcli_write(cli->tree, fnum1, 0, "xx", 0, 2);
	if (written != 2) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 2", (int)written);
		ret = false;
		goto done;
	}

	/* 7 */
	GET_INFO_BOTH_EX(cli, fnum1, finfo_curr, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");
	GET_INFO_BOTH_EX(cli2, fnum2, finfo_curr, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      stickynttime,
				      ret, done,
				      "Server did not return sticky time");

	/* 8 */
	written = smbcli_write(cli2->tree, fnum2, 0, "xxx", 0, 3);
	if (written != 3) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 3", (int)written);
		ret = false;
		goto done;
	}

	/* 9 */
	GET_INFO_BOTH_EX(cli2, fnum2, finfo_curr, pinfo_curr);
	torture_assert_goto(tctx,
			    finfo_curr.basic_info.out.write_time < stickynttime,
			    ret, done,
			    "Write did not update timestamp");
	torture_assert_goto(tctx,
			    finfo_curr.basic_info.out.write_time >
			    finfo_prev.basic_info.out.write_time,
			    ret, done,
			    "Write did not update timestamp");
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      pinfo_curr.basic_info.out.write_time,
				      ret, done,
				      "Write did not update timestamp");

	GET_INFO_BOTH_EX(cli, fnum1, finfo_curr, pinfo_curr);
	torture_assert_goto(tctx,
			    finfo_curr.basic_info.out.write_time < stickynttime,
			    ret, done,
			    "Write did not update timestamp");
	torture_assert_goto(tctx,
			    finfo_curr.basic_info.out.write_time >
			    finfo_prev.basic_info.out.write_time,
			    ret, done,
			    "Write did not update timestamp");
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      pinfo_curr.basic_info.out.write_time,
				      ret, done,
				      "Write did not update timestamp");
	finfo_prev = finfo_curr;
	pinfo_prev = pinfo_curr;

	/* 10 */
	written = smbcli_write(cli->tree, fnum1, 0, "xxxx", 0, 4);
	if (written != 4) {
		torture_result(tctx, TORTURE_FAIL, __location__": written gave %d - should have been 4", (int)written);
		ret = false;
		goto done;
	}

	/* 11 */
	GET_INFO_BOTH_EX(cli, fnum1, finfo_curr, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      finfo_prev.basic_info.out.write_time,
				      ret, done,
				      "Server update write time");
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      pinfo_prev.basic_info.out.write_time,
				      ret, done,
				      "Server update write time");

	GET_INFO_BOTH_EX(cli2, fnum2, finfo_curr, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      finfo_curr.basic_info.out.write_time,
				      finfo_prev.basic_info.out.write_time,
				      ret, done,
				      "Server update write time");
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      pinfo_prev.basic_info.out.write_time,
				      ret, done,
				      "Server update write time");

	/* 12 */

	status = smbcli_close(cli->tree, fnum1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smbcli_close failed");
	fnum1 = -1;

	status = smbcli_close(cli2->tree, fnum2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smbcli_close failed");
	fnum2 = -1;

	/* 13 */
	GET_INFO_PATH_EX(cli, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      pinfo_prev.basic_info.out.write_time,
				      ret, done,
				      "Server update write time");
	GET_INFO_PATH_EX(cli2, pinfo_curr);
	torture_assert_u64_equal_goto(tctx,
				      pinfo_curr.basic_info.out.write_time,
				      pinfo_prev.basic_info.out.write_time,
				      ret, done,
				      "Server update write time");

done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	if (fnum2 != -1)
		smbcli_close(cli2->tree, fnum2);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/*
   testing of delayed update of write_time
*/
struct torture_suite *torture_delay_write(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "delaywrite");

	torture_suite_add_2smb_test(suite, "finfo update on close", test_finfo_after_write);
	torture_suite_add_1smb_test(suite, "delayed update of write time", test_delayed_write_update);
	torture_suite_add_1smb_test(suite, "update of write time and SMBwrite truncate", test_delayed_write_update1);
	torture_suite_add_1smb_test(suite, "update of write time and SMBwrite truncate expand", test_delayed_write_update1a);
	torture_suite_add_1smb_test(suite, "update of write time using SET_END_OF_FILE", test_delayed_write_update1b);
	torture_suite_add_1smb_test(suite, "update of write time using SET_ALLOCATION_SIZE", test_delayed_write_update1c);
	torture_suite_add_2smb_test(suite, "delayed update of write time using 2 connections", test_delayed_write_update2);
	torture_suite_add_2smb_test(suite, "delayed update of write time 3", test_delayed_write_update3);
	torture_suite_add_2smb_test(suite, "delayed update of write time 3a", test_delayed_write_update3a);
	torture_suite_add_2smb_test(suite, "delayed update of write time 3b", test_delayed_write_update3b);
	torture_suite_add_2smb_test(suite, "delayed update of write time 3c", test_delayed_write_update3c);
	torture_suite_add_2smb_test(suite, "delayed update of write time 4", test_delayed_write_update4);
	torture_suite_add_2smb_test(suite, "delayed update of write time 5", test_delayed_write_update5);
	torture_suite_add_2smb_test(suite, "delayed update of write time 5b", test_delayed_write_update5b);
	torture_suite_add_2smb_test(suite, "delayed update of write time 6", test_delayed_write_update6);
	torture_suite_add_1smb_test(suite, "timestamp resolution test", test_delayed_write_update7);
	torture_suite_add_1smb_test(suite, "directory timestamp update test", test_directory_update8);
	torture_suite_add_2smb_test(suite, "modern_write_time_update-1", test_modern_write_time1);

	return suite;
}
