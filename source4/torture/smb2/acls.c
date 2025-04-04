/*
   Unix SMB/CIFS implementation.

   test security descriptor operations for SMB2

   Copyright (C) Zack Kirsch 2009

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
#include "lib/cmdline/cmdline.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "libcli/resolve/resolve.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/param/param.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define BASEDIR "smb2-testsd"

#define CHECK_ACCESS_IGNORE SEC_STD_SYNCHRONIZE

#define CHECK_ACCESS_FLAGS(_fh, flags) do { \
	union smb_fileinfo _q; \
	_q.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION; \
	_q.access_information.in.file.handle = (_fh); \
	status = smb2_getinfo_file(tree, tctx, &_q); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	/* Handle a Vista bug where SEC_STD_SYNCHRONIZE doesn't come back. */ \
	if ((((flags) & CHECK_ACCESS_IGNORE) == CHECK_ACCESS_IGNORE) && \
	    ((_q.access_information.out.access_flags & CHECK_ACCESS_IGNORE) != CHECK_ACCESS_IGNORE)) { \
		torture_comment(tctx, "SKIPPING (Vista bug): (%s) Incorrect access_flags 0x%08x - should be 0x%08x\n", \
		       __location__, _q.access_information.out.access_flags, (flags)); \
	} \
	if ((_q.access_information.out.access_flags & ~CHECK_ACCESS_IGNORE) != \
	    (((flags) & ~CHECK_ACCESS_IGNORE))) { \
		torture_result(tctx, TORTURE_FAIL, "(%s) Incorrect access_flags 0x%08x - should be 0x%08x\n", \
		       __location__, _q.access_information.out.access_flags, (flags)); \
		ret = false; \
		goto done; \
	} \
} while (0)

#define FAIL_UNLESS(__cond)					\
	do {							\
		if (__cond) {} else {				\
			torture_result(tctx, TORTURE_FAIL, "%s) condition violated: %s\n",	\
			       __location__, #__cond);		\
			ret = false; goto done;			\
		}						\
	} while(0)

#define CHECK_SECURITY_DESCRIPTOR(_sd1, _sd2) do { \
	if (!security_descriptor_equal(_sd1, _sd2)) { \
		torture_warning(tctx, "security descriptors don't match!\n"); \
		torture_warning(tctx, "got:\n"); \
		NDR_PRINT_DEBUG(security_descriptor, _sd1); \
		torture_warning(tctx, "expected:\n"); \
		NDR_PRINT_DEBUG(security_descriptor, _sd2); \
		torture_result(tctx, TORTURE_FAIL, \
			       "%s: security descriptors don't match!\n", \
			       __location__); \
		ret = false; \
	} \
} while (0)

/*
  test the behaviour of the well known SID_CREATOR_OWNER sid, and some generic
  mapping bits
  Note: This test was copied from raw/acls.c.
*/
static bool test_creator_sid(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *fname = BASEDIR "\\creator.txt";
	bool ret = true;
	struct smb2_handle handle = {{0}};
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig, *sd2;
	const char *owner_sid;

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING SID_CREATOR_OWNER\n");

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC | SEC_STD_WRITE_OWNER;
	io.in.create_options = 0;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	torture_comment(tctx, "set a sec desc allowing no write by CREATOR_OWNER\n");
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					SID_CREATOR_OWNER,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "try open for write\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for read\n");
	io.in.desired_access = SEC_FILE_READ_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic write\n");
	io.in.desired_access = SEC_GENERIC_WRITE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic read\n");
	io.in.desired_access = SEC_GENERIC_READ;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "set a sec desc allowing no write by owner\n");
	sd = security_descriptor_dacl_create(tctx,
					0, owner_sid, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "check that sd has been mapped correctly\n");
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

	torture_comment(tctx, "try open for write\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for read\n");
	io.in.desired_access = SEC_FILE_READ_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
			   SEC_FILE_READ_DATA);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "try open for generic write\n");
	io.in.desired_access = SEC_GENERIC_WRITE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic read\n");
	io.in.desired_access = SEC_GENERIC_READ;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
			   SEC_RIGHTS_FILE_READ);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "set a sec desc allowing generic read by owner\n");
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_GENERIC_READ | SEC_STD_ALL,
					0,
					NULL);

	set.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "check that generic read has been mapped correctly\n");
	sd2 = security_descriptor_dacl_create(tctx,
					 0, owner_sid, NULL,
					 owner_sid,
					 SEC_ACE_TYPE_ACCESS_ALLOWED,
					 SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					 0,
					 NULL);

	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

	torture_comment(tctx, "try open for write\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for read\n");
	io.in.desired_access = SEC_FILE_READ_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
			   SEC_FILE_READ_DATA);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "try open for generic write\n");
	io.in.desired_access = SEC_GENERIC_WRITE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "try open for generic read\n");
	io.in.desired_access = SEC_GENERIC_READ;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle, SEC_RIGHTS_FILE_READ);
	smb2_util_close(tree, io.out.file.handle);


	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);


done:
	smb2_util_close(tree, handle);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}


/*
  test the mapping of the SEC_GENERIC_xx bits to SEC_STD_xx and
  SEC_FILE_xx bits
  Note: This test was copied from raw/acls.c.
*/
static bool test_generic_bits(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *fname = BASEDIR "\\generic.txt";
	bool ret = true;
	struct smb2_handle handle = {{0}};
	int i;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig, *sd2;
	const char *owner_sid;
	const struct {
		uint32_t gen_bits;
		uint32_t specific_bits;
	} file_mappings[] = {
		{ 0,                       0 },
		{ SEC_GENERIC_READ,        SEC_RIGHTS_FILE_READ },
		{ SEC_GENERIC_WRITE,       SEC_RIGHTS_FILE_WRITE },
		{ SEC_GENERIC_EXECUTE,     SEC_RIGHTS_FILE_EXECUTE },
		{ SEC_GENERIC_ALL,         SEC_RIGHTS_FILE_ALL },
		{ SEC_FILE_READ_DATA,      SEC_FILE_READ_DATA },
		{ SEC_FILE_READ_ATTRIBUTE, SEC_FILE_READ_ATTRIBUTE }
	};
	const struct {
		uint32_t gen_bits;
		uint32_t specific_bits;
	} dir_mappings[] = {
		{ 0,                   0 },
		{ SEC_GENERIC_READ,    SEC_RIGHTS_DIR_READ },
		{ SEC_GENERIC_WRITE,   SEC_RIGHTS_DIR_WRITE },
		{ SEC_GENERIC_EXECUTE, SEC_RIGHTS_DIR_EXECUTE },
		{ SEC_GENERIC_ALL,     SEC_RIGHTS_DIR_ALL }
	};
	bool has_restore_privilege = false;
	bool has_take_ownership_privilege = false;

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING FILE GENERIC BITS\n");

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_STD_WRITE_DAC |
		SEC_STD_WRITE_OWNER;
	io.in.create_options = 0;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

/*
 * XXX: The smblsa calls use SMB as their transport - need to get rid of
 * dependency.
 */
/*
	status = smblsa_sid_check_privilege(cli,
					    owner_sid,
					    sec_privilege_name(SEC_PRIV_RESTORE));
	has_restore_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "smblsa_sid_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_RESTORE - %s\n", has_restore_privilege?"Yes":"No");

	status = smblsa_sid_check_privilege(cli,
					    owner_sid,
					    sec_privilege_name(SEC_PRIV_TAKE_OWNERSHIP));
	has_take_ownership_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "smblsa_sid_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_TAKE_OWNERSHIP - %s\n", has_take_ownership_privilege?"Yes":"No");
*/

	for (i=0;i<ARRAY_SIZE(file_mappings);i++) {
		uint32_t expected_mask =
			SEC_STD_WRITE_DAC |
			SEC_STD_READ_CONTROL |
			SEC_FILE_READ_ATTRIBUTE |
			SEC_STD_DELETE;
		uint32_t expected_mask_anon = SEC_FILE_READ_ATTRIBUTE;

		if (has_restore_privilege) {
			expected_mask_anon |= SEC_STD_DELETE;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, owner_sid, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						file_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb2_setinfo_file(tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 file_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.out.file.handle,
				   expected_mask | file_mappings[i].specific_bits);
		smb2_util_close(tree, io.out.file.handle);

		if (!has_take_ownership_privilege) {
			continue;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x (anonymous)\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, SID_NT_ANONYMOUS, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						file_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb2_setinfo_file(tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, SID_NT_ANONYMOUS, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 file_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.out.file.handle,
				   expected_mask_anon | file_mappings[i].specific_bits);
		smb2_util_close(tree, io.out.file.handle);
	}

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, handle);
	smb2_util_unlink(tree, fname);


	torture_comment(tctx, "TESTING DIR GENERIC BITS\n");

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_STD_WRITE_DAC |
		SEC_STD_WRITE_OWNER;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

/*
 * XXX: The smblsa calls use SMB as their transport - need to get rid of
 * dependency.
 */
/*
	status = smblsa_sid_check_privilege(cli,
					    owner_sid,
					    sec_privilege_name(SEC_PRIV_RESTORE));
	has_restore_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "smblsa_sid_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_RESTORE - %s\n", has_restore_privilege?"Yes":"No");

	status = smblsa_sid_check_privilege(cli,
					    owner_sid,
					    sec_privilege_name(SEC_PRIV_TAKE_OWNERSHIP));
	has_take_ownership_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "smblsa_sid_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_TAKE_OWNERSHIP - %s\n", has_take_ownership_privilege?"Yes":"No");

*/
	for (i=0;i<ARRAY_SIZE(dir_mappings);i++) {
		uint32_t expected_mask =
			SEC_STD_WRITE_DAC |
			SEC_STD_READ_CONTROL |
			SEC_FILE_READ_ATTRIBUTE |
			SEC_STD_DELETE;
		uint32_t expected_mask_anon = SEC_FILE_READ_ATTRIBUTE;

		if (has_restore_privilege) {
			expected_mask_anon |= SEC_STD_DELETE;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, owner_sid, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						dir_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb2_setinfo_file(tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 dir_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.out.file.handle,
				   expected_mask | dir_mappings[i].specific_bits);
		smb2_util_close(tree, io.out.file.handle);

		if (!has_take_ownership_privilege) {
			continue;
		}

		torture_comment(tctx, "Testing generic bits 0x%08x (anonymous)\n",
		       file_mappings[i].gen_bits);
		sd = security_descriptor_dacl_create(tctx,
						0, SID_NT_ANONYMOUS, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						file_mappings[i].gen_bits,
						0,
						NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		set.set_secdesc.in.sd = sd;

		status = smb2_setinfo_file(tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		sd2 = security_descriptor_dacl_create(tctx,
						 0, SID_NT_ANONYMOUS, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 file_mappings[i].specific_bits,
						 0,
						 NULL);

		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_ACCESS_FLAGS(io.out.file.handle,
				   expected_mask_anon | dir_mappings[i].specific_bits);
		smb2_util_close(tree, io.out.file.handle);
	}

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, handle);
	smb2_util_unlink(tree, fname);

done:
	smb2_util_close(tree, handle);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}


/*
  see what access bits the owner of a file always gets
  Note: This test was copied from raw/acls.c.
*/
static bool test_owner_bits(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *fname = BASEDIR "\\test_owner_bits.txt";
	bool ret = true;
	struct smb2_handle handle = {{0}};
	int i;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig;
	const char *owner_sid;
	uint32_t expected_bits;

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING FILE OWNER BITS\n");

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_STD_WRITE_DAC |
		SEC_STD_WRITE_OWNER;
	io.in.create_options = 0;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

/*
 * XXX: The smblsa calls use SMB as their transport - need to get rid of
 * dependency.
 */
/*
	status = smblsa_sid_check_privilege(cli,
					    owner_sid,
					    sec_privilege_name(SEC_PRIV_RESTORE));
	has_restore_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "smblsa_sid_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_RESTORE - %s\n", has_restore_privilege?"Yes":"No");

	status = smblsa_sid_check_privilege(cli,
					    owner_sid,
					    sec_privilege_name(SEC_PRIV_TAKE_OWNERSHIP));
	has_take_ownership_privilege = NT_STATUS_IS_OK(status);
	if (!NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "smblsa_sid_check_privilege - %s\n", nt_errstr(status));
	}
	torture_comment(tctx, "SEC_PRIV_TAKE_OWNERSHIP - %s\n", has_take_ownership_privilege?"Yes":"No");
*/

	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	expected_bits = SEC_FILE_WRITE_DATA | SEC_FILE_READ_ATTRIBUTE;

	for (i=0;i<16;i++) {
		uint32_t bit = (1<<i);
		io.in.desired_access = bit;
		status = smb2_create(tree, tctx, &io);
		if (expected_bits & bit) {
			if (!NT_STATUS_IS_OK(status)) {
				torture_warning(tctx, "failed with access mask 0x%08x of expected 0x%08x\n",
				       bit, expected_bits);
			}
			CHECK_STATUS(status, NT_STATUS_OK);
			CHECK_ACCESS_FLAGS(io.out.file.handle, bit);
			smb2_util_close(tree, io.out.file.handle);
		} else {
			if (NT_STATUS_IS_OK(status)) {
				torture_warning(tctx, "open succeeded with access mask 0x%08x of "
					"expected 0x%08x - should fail\n",
				       bit, expected_bits);
			}
			CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
		}
	}

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.in.sd = sd_orig;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smb2_util_close(tree, handle);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}



/*
  test the inheritance of ACL flags onto new files and directories
  Note: This test was copied from raw/acls.c.
*/
static bool test_inheritance(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *dname = BASEDIR "\\inheritance";
	const char *fname1 = BASEDIR "\\inheritance\\testfile";
	const char *fname2 = BASEDIR "\\inheritance\\testdir";
	bool ret = true;
	struct smb2_handle handle = {{0}};
	struct smb2_handle handle2 = {{0}};
	int i;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd2, *sd_orig=NULL, *sd_def1, *sd_def2;
	const char *owner_sid;
	const struct dom_sid *creator_owner;
	const struct {
		uint32_t parent_flags;
		uint32_t file_flags;
		uint32_t dir_flags;
	} test_flags[] = {
		{
			0,
			0,
			0
		},
		{
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			SEC_ACE_FLAG_OBJECT_INHERIT |
			SEC_ACE_FLAG_INHERIT_ONLY,
		},
		{
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			SEC_ACE_FLAG_CONTAINER_INHERIT,
		},
		{
			SEC_ACE_FLAG_OBJECT_INHERIT |
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			SEC_ACE_FLAG_OBJECT_INHERIT |
			SEC_ACE_FLAG_CONTAINER_INHERIT,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT |
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT |
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT |
			SEC_ACE_FLAG_CONTAINER_INHERIT |
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY |
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			SEC_ACE_FLAG_OBJECT_INHERIT |
			SEC_ACE_FLAG_INHERIT_ONLY,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY |
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			SEC_ACE_FLAG_CONTAINER_INHERIT,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY |
			SEC_ACE_FLAG_CONTAINER_INHERIT |
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			SEC_ACE_FLAG_CONTAINER_INHERIT |
			SEC_ACE_FLAG_OBJECT_INHERIT,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY |
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY |
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT |
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY |
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT |
			SEC_ACE_FLAG_CONTAINER_INHERIT,
			0,
			0,
		},
		{
			SEC_ACE_FLAG_INHERIT_ONLY |
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT |
			SEC_ACE_FLAG_CONTAINER_INHERIT |
			SEC_ACE_FLAG_OBJECT_INHERIT,
			0,
			0,
		}
	};

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING ACL INHERITANCE\n");

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access = 0;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = dname;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	torture_comment(tctx, "owner_sid is %s\n", owner_sid);

	/*
	 * The Windows Default ACL for a new file, when there is no ACL to be
	 * inherited: FullControl for the owner and SYSTEM.
	 */
	sd_def1 = security_descriptor_dacl_create(tctx,
					    0, owner_sid, NULL,
					    owner_sid,
					    SEC_ACE_TYPE_ACCESS_ALLOWED,
					    SEC_RIGHTS_FILE_ALL,
					    0,
					    SID_NT_SYSTEM,
					    SEC_ACE_TYPE_ACCESS_ALLOWED,
					    SEC_RIGHTS_FILE_ALL,
					    0,
					    NULL);

	/*
	 * Use this in the case the system being tested does not add an ACE for
	 * the SYSTEM SID.
	 */
	sd_def2 = security_descriptor_dacl_create(tctx,
					    0, owner_sid, NULL,
					    owner_sid,
					    SEC_ACE_TYPE_ACCESS_ALLOWED,
					    SEC_RIGHTS_FILE_ALL,
					    0,
					    NULL);

	creator_owner = dom_sid_parse_talloc(tctx, SID_CREATOR_OWNER);

	for (i=0;i<ARRAY_SIZE(test_flags);i++) {
		sd = security_descriptor_dacl_create(tctx,
						0, NULL, NULL,
						SID_CREATOR_OWNER,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_WRITE_DATA,
						test_flags[i].parent_flags,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_ALL | SEC_STD_ALL,
						0,
						NULL);
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;
		status = smb2_setinfo_file(tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		io.in.fname = fname1;
		io.in.create_options = 0;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		handle2 = io.out.file.handle;

		q.query_secdesc.in.file.handle = handle2;
		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		smb2_util_close(tree, handle2);
		smb2_util_unlink(tree, fname1);

		if (!(test_flags[i].parent_flags & SEC_ACE_FLAG_OBJECT_INHERIT)) {
			if (!security_descriptor_equal(q.query_secdesc.out.sd, sd_def1) &&
			    !security_descriptor_equal(q.query_secdesc.out.sd, sd_def2)) {
				torture_warning(tctx, "Expected default sd:\n");
				NDR_PRINT_DEBUG(security_descriptor, sd_def1);
				torture_warning(tctx, "at %d - got:\n", i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			}
			goto check_dir;
		}

		if (q.query_secdesc.out.sd->dacl == NULL ||
		    q.query_secdesc.out.sd->dacl->num_aces != 1 ||
		    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
		    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
				   sd_orig->owner_sid)) {
			torture_warning(tctx, "Bad sd in child file at %d\n", i);
			NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			ret = false;
			goto check_dir;
		}

		if (q.query_secdesc.out.sd->dacl->aces[0].flags !=
		    test_flags[i].file_flags) {
			torture_warning(tctx, "incorrect file_flags 0x%x - expected 0x%x for parent 0x%x with (i=%d)\n",
			       q.query_secdesc.out.sd->dacl->aces[0].flags,
			       test_flags[i].file_flags,
			       test_flags[i].parent_flags,
			       i);
			ret = false;
		}

	check_dir:
		io.in.fname = fname2;
		io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		handle2 = io.out.file.handle;

		q.query_secdesc.in.file.handle = handle2;
		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		smb2_util_close(tree, handle2);
		smb2_util_rmdir(tree, fname2);

		if (!(test_flags[i].parent_flags & SEC_ACE_FLAG_CONTAINER_INHERIT) &&
		    (!(test_flags[i].parent_flags & SEC_ACE_FLAG_OBJECT_INHERIT) ||
		     (test_flags[i].parent_flags & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT))) {
			if (!security_descriptor_equal(q.query_secdesc.out.sd, sd_def1) &&
			    !security_descriptor_equal(q.query_secdesc.out.sd, sd_def2)) {
				torture_warning(tctx, "Expected default sd for dir at %d:\n", i);
				NDR_PRINT_DEBUG(security_descriptor, sd_def1);
				torture_warning(tctx, "got:\n");
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
			}
			continue;
		}

		if ((test_flags[i].parent_flags & SEC_ACE_FLAG_CONTAINER_INHERIT) &&
		    (test_flags[i].parent_flags & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT)) {
			if (q.query_secdesc.out.sd->dacl == NULL ||
			    q.query_secdesc.out.sd->dacl->num_aces != 1 ||
			    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
					   sd_orig->owner_sid) ||
			    q.query_secdesc.out.sd->dacl->aces[0].flags != test_flags[i].dir_flags) {
				torture_warning(tctx, "(CI & NP) Bad sd in child dir - expected 0x%x for parent 0x%x (i=%d)\n",
				       test_flags[i].dir_flags,
				       test_flags[i].parent_flags, i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
				torture_warning(tctx, "FYI, here is the parent sd:\n");
				NDR_PRINT_DEBUG(security_descriptor, sd);
				ret = false;
				continue;
			}
		} else if (test_flags[i].parent_flags & SEC_ACE_FLAG_CONTAINER_INHERIT) {
			if (q.query_secdesc.out.sd->dacl == NULL ||
			    q.query_secdesc.out.sd->dacl->num_aces != 2 ||
			    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
					   sd_orig->owner_sid) ||
			    q.query_secdesc.out.sd->dacl->aces[1].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[1].trustee,
					   creator_owner) ||
			    q.query_secdesc.out.sd->dacl->aces[0].flags != 0 ||
			    q.query_secdesc.out.sd->dacl->aces[1].flags !=
			    (test_flags[i].dir_flags | SEC_ACE_FLAG_INHERIT_ONLY)) {
				torture_warning(tctx, "(CI) Bad sd in child dir - expected 0x%x for parent 0x%x (i=%d)\n",
				       test_flags[i].dir_flags,
				       test_flags[i].parent_flags, i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
				torture_warning(tctx, "FYI, here is the parent sd:\n");
				NDR_PRINT_DEBUG(security_descriptor, sd);
				ret = false;
				continue;
			}
		} else {
			if (q.query_secdesc.out.sd->dacl == NULL ||
			    q.query_secdesc.out.sd->dacl->num_aces != 1 ||
			    q.query_secdesc.out.sd->dacl->aces[0].access_mask != SEC_FILE_WRITE_DATA ||
			    !dom_sid_equal(&q.query_secdesc.out.sd->dacl->aces[0].trustee,
					   creator_owner) ||
			    q.query_secdesc.out.sd->dacl->aces[0].flags != test_flags[i].dir_flags) {
				torture_warning(tctx, "(0) Bad sd in child dir - expected 0x%x for parent 0x%x (i=%d)\n",
				       test_flags[i].dir_flags,
				       test_flags[i].parent_flags, i);
				NDR_PRINT_DEBUG(security_descriptor, q.query_secdesc.out.sd);
				torture_warning(tctx, "FYI, here is the parent sd:\n");
				NDR_PRINT_DEBUG(security_descriptor, sd);
				ret = false;
				continue;
			}
		}
	}

	torture_comment(tctx, "Testing access checks on inherited create with %s\n", fname1);
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					SID_WORLD,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_ALL | SEC_STD_ALL,
					0,
					NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Check DACL we just set. */
	torture_comment(tctx, "checking new sd\n");
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

	io.in.fname = fname1;
	io.in.create_options = 0;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle2 = io.out.file.handle;
	CHECK_ACCESS_FLAGS(handle2, SEC_RIGHTS_FILE_ALL);

	q.query_secdesc.in.file.handle = handle2;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, handle2);

	sd2 = security_descriptor_dacl_create(tctx,
					 0, owner_sid, NULL,
					 owner_sid,
					 SEC_ACE_TYPE_ACCESS_ALLOWED,
					 SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
					 0,
					 NULL);
	CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	status = smb2_create(tree, tctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		torture_warning(tctx, "failed: w2k3 ACL bug (allowed open when ACL should deny)\n");
		ret = false;
		handle2 = io.out.file.handle;
		CHECK_ACCESS_FLAGS(handle2, SEC_RIGHTS_FILE_ALL);
		smb2_util_close(tree, handle2);
	} else {
		if (torture_setting_bool(tctx, "hide_on_access_denied",
					 false)) {
			CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		} else {
			CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
		}
	}

	torture_comment(tctx, "trying without execute\n");
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL & ~SEC_FILE_EXECUTE;
	status = smb2_create(tree, tctx, &io);
	if (torture_setting_bool(tctx, "hide_on_access_denied", false)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	torture_comment(tctx, "and with full permissions again\n");
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	status = smb2_create(tree, tctx, &io);
	if (torture_setting_bool(tctx, "hide_on_access_denied", false)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle2 = io.out.file.handle;
	CHECK_ACCESS_FLAGS(handle2, SEC_FILE_WRITE_DATA);
	smb2_util_close(tree, handle2);

	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd_orig;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, handle);

	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	status = smb2_create(tree, tctx, &io);
	if (torture_setting_bool(tctx, "hide_on_access_denied", false)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle2 = io.out.file.handle;
	CHECK_ACCESS_FLAGS(handle2, SEC_FILE_WRITE_DATA);
	smb2_util_close(tree, handle2);

	smb2_util_unlink(tree, fname1);
	smb2_util_rmdir(tree, dname);

done:
	if (sd_orig != NULL) {
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd_orig;
		status = smb2_setinfo_file(tree, &set);
	}

	smb2_util_close(tree, handle);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

static bool test_inheritance_flags(struct torture_context *tctx,
    struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *dname = BASEDIR "\\inheritance";
	const char *fname1 = BASEDIR "\\inheritance\\testfile";
	bool ret = true;
	struct smb2_handle handle = {{0}};
	struct smb2_handle handle2 = {{0}};
	int i, j;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd2, *sd_orig=NULL;
	const char *owner_sid;
	struct {
		uint32_t parent_set_sd_type; /* 3 options */
		uint32_t parent_set_ace_inherit; /* 1 option */
		uint32_t parent_get_sd_type;
		uint32_t parent_get_ace_inherit;
		uint32_t child_get_sd_type;
		uint32_t child_get_ace_inherit;
	} tflags[16] = {{0}}; /* 2^4 */

	for (i = 0; i < 15; i++) {
		torture_comment(tctx, "i=%d:", i);

		if (i & 1) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			torture_comment(tctx, "AUTO_INHERITED, ");
		}
		if (i & 2) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERIT_REQ;
			torture_comment(tctx, "AUTO_INHERIT_REQ, ");
		}
		if (i & 4) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_PROTECTED;
			torture_comment(tctx, "PROTECTED, ");
			tflags[i].parent_get_sd_type |=
			    SEC_DESC_DACL_PROTECTED;
		}
		if (i & 8) {
			tflags[i].parent_set_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "INHERITED, ");
			tflags[i].parent_get_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
		}

		if ((tflags[i].parent_set_sd_type &
		    (SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ)) ==
		    (SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ)) {
			tflags[i].parent_get_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			tflags[i].child_get_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			tflags[i].child_get_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "  ... parent is AUTO INHERITED");
		}

		if (tflags[i].parent_set_ace_inherit &
		    SEC_ACE_FLAG_INHERITED_ACE) {
			tflags[i].parent_get_ace_inherit =
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "  ... parent ACE is INHERITED");
		}

		torture_comment(tctx, "\n");
	}

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING ACL INHERITANCE FLAGS\n");

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = dname;

	torture_comment(tctx, "creating initial directory %s\n", dname);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "getting original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);
	torture_comment(tctx, "owner_sid is %s\n", owner_sid);

	for (i=0; i < ARRAY_SIZE(tflags); i++) {
		torture_comment(tctx, "setting a new sd on directory, pass #%d\n", i);

		sd = security_descriptor_dacl_create(tctx,
						tflags[i].parent_set_sd_type,
						NULL, NULL,
						owner_sid,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
						SEC_ACE_FLAG_OBJECT_INHERIT |
						SEC_ACE_FLAG_CONTAINER_INHERIT |
						tflags[i].parent_set_ace_inherit,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_ALL | SEC_STD_ALL,
						0,
						NULL);
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;
		status = smb2_setinfo_file(tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		/*
		 * Check DACL we just set, except change the bits to what they
		 * should be.
		 */
		torture_comment(tctx, "  checking new sd\n");

		/* REQ bit should always be false. */
		sd->type &= ~SEC_DESC_DACL_AUTO_INHERIT_REQ;

		if ((tflags[i].parent_get_sd_type & SEC_DESC_DACL_AUTO_INHERITED) == 0)
			sd->type &= ~SEC_DESC_DACL_AUTO_INHERITED;

		q.query_secdesc.in.file.handle = handle;
		q.query_secdesc.in.secinfo_flags = SECINFO_DACL;
		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

		/* Create file. */
		torture_comment(tctx, "  creating file %s\n", fname1);
		io.in.fname = fname1;
		io.in.create_options = 0;
		io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		io.in.desired_access = SEC_RIGHTS_FILE_ALL;
		io.in.create_disposition = NTCREATEX_DISP_CREATE;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		handle2 = io.out.file.handle;
		CHECK_ACCESS_FLAGS(handle2, SEC_RIGHTS_FILE_ALL);

		q.query_secdesc.in.file.handle = handle2;
		q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		torture_comment(tctx, "  checking sd on file %s\n", fname1);
		sd2 = security_descriptor_dacl_create(tctx,
						 tflags[i].child_get_sd_type,
						 owner_sid, NULL,
						 owner_sid,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
						 tflags[i].child_get_ace_inherit,
						 NULL);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		/*
		 * Set new sd on file ... prove that the bits have nothing to
		 * do with the parents bits when manually setting an ACL. The
		 * _AUTO_INHERITED bit comes directly from the ACL set.
		 */
		for (j = 0; j < ARRAY_SIZE(tflags); j++) {
			torture_comment(tctx, "  setting new file sd, pass #%d\n", j);

			/* Change sd type. */
			sd2->type &= ~(SEC_DESC_DACL_AUTO_INHERITED |
			    SEC_DESC_DACL_AUTO_INHERIT_REQ |
			    SEC_DESC_DACL_PROTECTED);
			sd2->type |= tflags[j].parent_set_sd_type;

			sd2->dacl->aces[0].flags &=
			    ~SEC_ACE_FLAG_INHERITED_ACE;
			sd2->dacl->aces[0].flags |=
			    tflags[j].parent_set_ace_inherit;

			set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
			set.set_secdesc.in.file.handle = handle2;
			set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
			set.set_secdesc.in.sd = sd2;
			status = smb2_setinfo_file(tree, &set);
			CHECK_STATUS(status, NT_STATUS_OK);

			/* Check DACL we just set. */
			sd2->type &= ~SEC_DESC_DACL_AUTO_INHERIT_REQ;
			if ((tflags[j].parent_get_sd_type & SEC_DESC_DACL_AUTO_INHERITED) == 0)
				sd2->type &= ~SEC_DESC_DACL_AUTO_INHERITED;

			q.query_secdesc.in.file.handle = handle2;
			q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
			status = smb2_getinfo_file(tree, tctx, &q);
			CHECK_STATUS(status, NT_STATUS_OK);

			CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);
		}

		smb2_util_close(tree, handle2);
		smb2_util_unlink(tree, fname1);
	}

done:
	smb2_util_close(tree, handle);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

/*
 * This is basically a copy of test_inheritance_flags() with an additional twist
 * to change the owner of the testfile, verifying that the security descriptor
 * flags are not altered.
 */
static bool test_sd_flags_vs_chown(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *dname = BASEDIR "\\inheritance";
	const char *fname1 = BASEDIR "\\inheritance\\testfile";
	bool ret = true;
	struct smb2_handle handle = {{0}};
	struct smb2_handle handle2 = {{0}};
	int i, j;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd2, *sd_orig=NULL;
	struct security_descriptor *owner_sd = NULL;
	const char *owner_sid_string = NULL;
	struct dom_sid *owner_sid = NULL;
	struct dom_sid world_sid = global_sid_World;
	struct {
		uint32_t parent_set_sd_type; /* 3 options */
		uint32_t parent_set_ace_inherit; /* 1 option */
		uint32_t parent_get_sd_type;
		uint32_t parent_get_ace_inherit;
		uint32_t child_get_sd_type;
		uint32_t child_get_ace_inherit;
	} tflags[16] = {{0}}; /* 2^4 */

	owner_sd = security_descriptor_dacl_create(tctx,
						   0,
						   SID_WORLD,
						   NULL,
						   NULL);
	torture_assert_not_null_goto(tctx, owner_sd, ret, done,
				     "security_descriptor_dacl_create failed\n");

	for (i = 0; i < 15; i++) {
		torture_comment(tctx, "i=%d:", i);

		if (i & 1) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			torture_comment(tctx, "AUTO_INHERITED, ");
		}
		if (i & 2) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERIT_REQ;
			torture_comment(tctx, "AUTO_INHERIT_REQ, ");
		}
		if (i & 4) {
			tflags[i].parent_set_sd_type |=
			    SEC_DESC_DACL_PROTECTED;
			torture_comment(tctx, "PROTECTED, ");
			tflags[i].parent_get_sd_type |=
			    SEC_DESC_DACL_PROTECTED;
		}
		if (i & 8) {
			tflags[i].parent_set_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "INHERITED, ");
			tflags[i].parent_get_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
		}

		if ((tflags[i].parent_set_sd_type &
		    (SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ)) ==
		    (SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ)) {
			tflags[i].parent_get_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			tflags[i].child_get_sd_type |=
			    SEC_DESC_DACL_AUTO_INHERITED;
			tflags[i].child_get_ace_inherit |=
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "  ... parent is AUTO INHERITED");
		}

		if (tflags[i].parent_set_ace_inherit &
		    SEC_ACE_FLAG_INHERITED_ACE) {
			tflags[i].parent_get_ace_inherit =
			    SEC_ACE_FLAG_INHERITED_ACE;
			torture_comment(tctx, "  ... parent ACE is INHERITED");
		}

		torture_comment(tctx, "\n");
	}

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING ACL INHERITANCE FLAGS\n");

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = dname;

	torture_comment(tctx, "creating initial directory %s\n", dname);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "getting original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = sd_orig->owner_sid;
	owner_sid_string = dom_sid_string(tctx, sd_orig->owner_sid);
	torture_comment(tctx, "owner_sid is %s\n", owner_sid_string);

	for (i=0; i < ARRAY_SIZE(tflags); i++) {
		torture_comment(tctx, "setting a new sd on directory, pass #%d\n", i);

		sd = security_descriptor_dacl_create(tctx,
						tflags[i].parent_set_sd_type,
						NULL, NULL,
						owner_sid_string,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
						SEC_ACE_FLAG_OBJECT_INHERIT |
						SEC_ACE_FLAG_CONTAINER_INHERIT |
						tflags[i].parent_set_ace_inherit,
						SID_WORLD,
						SEC_ACE_TYPE_ACCESS_ALLOWED,
						SEC_FILE_ALL | SEC_STD_ALL,
						0,
						NULL);
		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = handle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;
		status = smb2_setinfo_file(tree, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		/*
		 * Check DACL we just set, except change the bits to what they
		 * should be.
		 */
		torture_comment(tctx, "  checking new sd\n");

		/* REQ bit should always be false. */
		sd->type &= ~SEC_DESC_DACL_AUTO_INHERIT_REQ;

		if ((tflags[i].parent_get_sd_type & SEC_DESC_DACL_AUTO_INHERITED) == 0)
			sd->type &= ~SEC_DESC_DACL_AUTO_INHERITED;

		q.query_secdesc.in.file.handle = handle;
		q.query_secdesc.in.secinfo_flags = SECINFO_DACL;
		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd);

		/* Create file. */
		torture_comment(tctx, "  creating file %s\n", fname1);
		io.in.fname = fname1;
		io.in.create_options = 0;
		io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		io.in.desired_access = SEC_RIGHTS_FILE_ALL;
		io.in.create_disposition = NTCREATEX_DISP_CREATE;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		handle2 = io.out.file.handle;
		CHECK_ACCESS_FLAGS(handle2, SEC_RIGHTS_FILE_ALL);

		q.query_secdesc.in.file.handle = handle2;
		q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
		status = smb2_getinfo_file(tree, tctx, &q);
		CHECK_STATUS(status, NT_STATUS_OK);

		torture_comment(tctx, "  checking sd on file %s\n", fname1);
		sd2 = security_descriptor_dacl_create(tctx,
						 tflags[i].child_get_sd_type,
						 owner_sid_string, NULL,
						 owner_sid_string,
						 SEC_ACE_TYPE_ACCESS_ALLOWED,
						 SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
						 tflags[i].child_get_ace_inherit,
						 NULL);
		CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

		/*
		 * Set new sd on file ... prove that the bits have nothing to
		 * do with the parents bits when manually setting an ACL. The
		 * _AUTO_INHERITED bit comes directly from the ACL set.
		 */
		for (j = 0; j < ARRAY_SIZE(tflags); j++) {
			torture_comment(tctx, "  setting new file sd, pass #%d\n", j);

			/* Change sd type. */
			sd2->type &= ~(SEC_DESC_DACL_AUTO_INHERITED |
			    SEC_DESC_DACL_AUTO_INHERIT_REQ |
			    SEC_DESC_DACL_PROTECTED);
			sd2->type |= tflags[j].parent_set_sd_type;

			sd2->dacl->aces[0].flags &=
			    ~SEC_ACE_FLAG_INHERITED_ACE;
			sd2->dacl->aces[0].flags |=
			    tflags[j].parent_set_ace_inherit;

			set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
			set.set_secdesc.in.file.handle = handle2;
			set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
			set.set_secdesc.in.sd = sd2;
			status = smb2_setinfo_file(tree, &set);
			CHECK_STATUS(status, NT_STATUS_OK);

			/* Check DACL we just set. */
			sd2->type &= ~SEC_DESC_DACL_AUTO_INHERIT_REQ;
			if ((tflags[j].parent_get_sd_type & SEC_DESC_DACL_AUTO_INHERITED) == 0)
				sd2->type &= ~SEC_DESC_DACL_AUTO_INHERITED;

			q.query_secdesc.in.file.handle = handle2;
			q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
			status = smb2_getinfo_file(tree, tctx, &q);
			CHECK_STATUS(status, NT_STATUS_OK);

			CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);

			/*
			 * Check that changing owner doesn't affect SD flags.
			 *
			 * Do this by first changing owner to world and then
			 * back to the original owner. Afterwards compare SD,
			 * should be the same.
			 */
			owner_sd->owner_sid = &world_sid;
			set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
			set.set_secdesc.in.file.handle = handle2;
			set.set_secdesc.in.secinfo_flags = SECINFO_OWNER;
			set.set_secdesc.in.sd = owner_sd;
			status = smb2_setinfo_file(tree, &set);
			CHECK_STATUS(status, NT_STATUS_OK);

			owner_sd->owner_sid = owner_sid;
			set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
			set.set_secdesc.in.file.handle = handle2;
			set.set_secdesc.in.secinfo_flags = SECINFO_OWNER;
			set.set_secdesc.in.sd = owner_sd;
			status = smb2_setinfo_file(tree, &set);
			CHECK_STATUS(status, NT_STATUS_OK);

			q.query_secdesc.in.file.handle = handle2;
			q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
			status = smb2_getinfo_file(tree, tctx, &q);
			CHECK_STATUS(status, NT_STATUS_OK);

			CHECK_SECURITY_DESCRIPTOR(q.query_secdesc.out.sd, sd2);
			torture_assert_goto(tctx, ret, ret, done, "CHECK_SECURITY_DESCRIPTOR failed\n");
		}

		smb2_util_close(tree, handle2);
		smb2_util_unlink(tree, fname1);
	}

done:
	smb2_util_close(tree, handle);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

/*
  test dynamic acl inheritance
  Note: This test was copied from raw/acls.c.
*/
static bool test_inheritance_dynamic(struct torture_context *tctx,
    struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *dname = BASEDIR "\\inheritance";
	const char *fname1 = BASEDIR "\\inheritance\\testfile";
	bool ret = true;
	struct smb2_handle handle = {{0}};
	struct smb2_handle handle2 = {{0}};
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig=NULL;
	const char *owner_sid;

	torture_comment(tctx, "TESTING DYNAMIC ACL INHERITANCE\n");

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access = 0;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = dname;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	torture_comment(tctx, "owner_sid is %s\n", owner_sid);

	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA | SEC_STD_DELETE | SEC_FILE_READ_ATTRIBUTE,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);
	sd->type |= SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ;

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "create a file with an inherited acl\n");
	io.in.fname = fname1;
	io.in.create_options = 0;
	io.in.desired_access = SEC_FILE_READ_ATTRIBUTE;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle2 = io.out.file.handle;
	smb2_util_close(tree, handle2);

	torture_comment(tctx, "try and access file with base rights - should be OK\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle2 = io.out.file.handle;
	smb2_util_close(tree, handle2);

	torture_comment(tctx, "try and access file with extra rights - should be denied\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA | SEC_FILE_EXECUTE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(tctx, "update parent sd\n");
	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA | SEC_STD_DELETE | SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);
	sd->type |= SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_DACL_AUTO_INHERIT_REQ;

	set.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "try and access file with base rights - should be OK\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle2 = io.out.file.handle;
	smb2_util_close(tree, handle2);


	torture_comment(tctx, "try and access now - should be OK if dynamic inheritance works\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA | SEC_FILE_EXECUTE;
	status = smb2_create(tree, tctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		torture_comment(tctx, "Server does not have dynamic inheritance\n");
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "Server does have dynamic inheritance\n");
	}
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	smb2_util_unlink(tree, fname1);

done:
	torture_comment(tctx, "put back original sd\n");
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd_orig;
	status = smb2_setinfo_file(tree, &set);

	smb2_util_close(tree, handle);
	smb2_util_rmdir(tree, dname);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);

	return ret;
}

#define CHECK_STATUS_FOR_BIT_ACTION(status, bits, action) do { \
	if (!(bits & desired_64)) {\
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED); \
		action; \
	} else { \
		CHECK_STATUS(status, NT_STATUS_OK); \
	} \
} while (0)

#define CHECK_STATUS_FOR_BIT(status, bits, access) do { \
	if (NT_STATUS_IS_OK(status)) { \
		if (!(granted & access)) {\
			ret = false; \
			torture_result(tctx, TORTURE_FAIL, "(%s) %s but flags 0x%08X are not granted! granted[0x%08X] desired[0x%08X]\n", \
			       __location__, nt_errstr(status), access, granted, desired); \
			goto done; \
		} \
	} else { \
		if (granted & access) {\
			ret = false; \
			torture_result(tctx, TORTURE_FAIL, "(%s) %s but flags 0x%08X are granted! granted[0x%08X] desired[0x%08X]\n", \
			       __location__, nt_errstr(status), access, granted, desired); \
			goto done; \
		} \
	} \
	CHECK_STATUS_FOR_BIT_ACTION(status, bits, do {} while (0)); \
} while (0)

#if 0
/* test what access mask is needed for getting and setting security_descriptors */
/* Note: This test was copied from raw/acls.c. */
static bool test_sd_get_set(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ret = true;
	struct smb2_create io;
	union smb_fileinfo fi;
	union smb_setfileinfo si;
	struct security_descriptor *sd;
	struct security_descriptor *sd_owner = NULL;
	struct security_descriptor *sd_group = NULL;
	struct security_descriptor *sd_dacl = NULL;
	struct security_descriptor *sd_sacl = NULL;
	struct smb2_handle handle;
	const char *fname = BASEDIR "\\sd_get_set.txt";
	uint64_t desired_64;
	uint32_t desired = 0, granted;
	int i = 0;
#define NO_BITS_HACK (((uint64_t)1)<<32)
	uint64_t open_bits =
		SEC_MASK_GENERIC |
		SEC_FLAG_SYSTEM_SECURITY |
		SEC_FLAG_MAXIMUM_ALLOWED |
		SEC_STD_ALL |
		SEC_FILE_ALL |
		NO_BITS_HACK;
	uint64_t get_owner_bits = SEC_MASK_GENERIC | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_READ_CONTROL;
	uint64_t set_owner_bits = SEC_GENERIC_ALL  | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_WRITE_OWNER;
	uint64_t get_group_bits = SEC_MASK_GENERIC | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_READ_CONTROL;
	uint64_t set_group_bits = SEC_GENERIC_ALL  | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_WRITE_OWNER;
	uint64_t get_dacl_bits  = SEC_MASK_GENERIC | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_READ_CONTROL;
	uint64_t set_dacl_bits  = SEC_GENERIC_ALL  | SEC_FLAG_MAXIMUM_ALLOWED | SEC_STD_WRITE_DAC;
	uint64_t get_sacl_bits  = SEC_FLAG_SYSTEM_SECURITY;
	uint64_t set_sacl_bits  = SEC_FLAG_SYSTEM_SECURITY;

	if (!smb2_util_setup_dir(tctx, tree, BASEDIR))
		return false;

	torture_comment(tctx, "TESTING ACCESS MASKS FOR SD GET/SET\n");

	/* first create a file with full access for everyone */
	sd = security_descriptor_dacl_create(tctx,
					0, SID_NT_ANONYMOUS, SID_BUILTIN_USERS,
					SID_WORLD,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_GENERIC_ALL,
					0,
					NULL);
	sd->type |= SEC_DESC_SACL_PRESENT;
	sd->sacl = NULL;
	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_GENERIC_ALL;
	io.in.create_options = 0;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname;
	io.in.sec_desc = sd;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	status = smb2_util_close(tree, handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * now try each access_mask bit and no bit at all in a loop
	 * and see what's allowed
	 * NOTE: if i == 32 it means access_mask = 0 (see NO_BITS_HACK above)
	 */
	for (i=0; i <= 32; i++) {
		desired_64 = ((uint64_t)1) << i;
		desired = (uint32_t)desired_64;

		/* first open the file with the desired access */
		io.level = RAW_OPEN_SMB2;
		io.in.desired_access = desired;
		io.in.create_disposition = NTCREATEX_DISP_OPEN;
		status = smb2_create(tree, tctx, &io);
		CHECK_STATUS_FOR_BIT_ACTION(status, open_bits, goto next);
		handle = io.out.file.handle;

		/* then check what access was granted */
		fi.access_information.level		= RAW_FILEINFO_ACCESS_INFORMATION;
		fi.access_information.in.file.handle	= handle;
		status = smb2_getinfo_file(tree, tctx, &fi);
		CHECK_STATUS(status, NT_STATUS_OK);
		granted = fi.access_information.out.access_flags;

		/* test the owner */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.handle		= handle;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_OWNER;
		status = smb2_getinfo_file(tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_owner_bits, SEC_STD_READ_CONTROL);
		if (fi.query_secdesc.out.sd) {
			sd_owner = fi.query_secdesc.out.sd;
		} else if (!sd_owner) {
			sd_owner = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.handle		= handle;
		si.set_secdesc.in.secinfo_flags		= SECINFO_OWNER;
		si.set_secdesc.in.sd			= sd_owner;
		status = smb2_setinfo_file(tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_owner_bits, SEC_STD_WRITE_OWNER);

		/* test the group */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.handle		= handle;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_GROUP;
		status = smb2_getinfo_file(tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_group_bits, SEC_STD_READ_CONTROL);
		if (fi.query_secdesc.out.sd) {
			sd_group = fi.query_secdesc.out.sd;
		} else if (!sd_group) {
			sd_group = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.handle		= handle;
		si.set_secdesc.in.secinfo_flags		= SECINFO_GROUP;
		si.set_secdesc.in.sd			= sd_group;
		status = smb2_setinfo_file(tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_group_bits, SEC_STD_WRITE_OWNER);

		/* test the DACL */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.handle		= handle;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_DACL;
		status = smb2_getinfo_file(tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_dacl_bits, SEC_STD_READ_CONTROL);
		if (fi.query_secdesc.out.sd) {
			sd_dacl = fi.query_secdesc.out.sd;
		} else if (!sd_dacl) {
			sd_dacl = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.handle		= handle;
		si.set_secdesc.in.secinfo_flags		= SECINFO_DACL;
		si.set_secdesc.in.sd			= sd_dacl;
		status = smb2_setinfo_file(tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_dacl_bits, SEC_STD_WRITE_DAC);

		/* test the SACL */
		ZERO_STRUCT(fi);
		fi.query_secdesc.level			= RAW_FILEINFO_SEC_DESC;
		fi.query_secdesc.in.file.handle		= handle;
		fi.query_secdesc.in.secinfo_flags	= SECINFO_SACL;
		status = smb2_getinfo_file(tree, tctx, &fi);
		CHECK_STATUS_FOR_BIT(status, get_sacl_bits, SEC_FLAG_SYSTEM_SECURITY);
		if (fi.query_secdesc.out.sd) {
			sd_sacl = fi.query_secdesc.out.sd;
		} else if (!sd_sacl) {
			sd_sacl = sd;
		}
		si.set_secdesc.level			= RAW_SFILEINFO_SEC_DESC;
		si.set_secdesc.in.file.handle		= handle;
		si.set_secdesc.in.secinfo_flags		= SECINFO_SACL;
		si.set_secdesc.in.sd			= sd_sacl;
		status = smb2_setinfo_file(tree, &si);
		CHECK_STATUS_FOR_BIT(status, set_sacl_bits, SEC_FLAG_SYSTEM_SECURITY);

		/* close the handle */
		status = smb2_util_close(tree, handle);
		CHECK_STATUS(status, NT_STATUS_OK);
next:
		continue;
	}

done:
	smb2_util_close(tree, handle);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	smb2_tdis(tree);
	smb2_logoff(tree->session);

	return ret;
}
#endif

static bool test_access_based(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	struct smb2_tree *tree1 = NULL;
	NTSTATUS status;
	struct smb2_create io;
	const char *fname = BASEDIR "\\testfile";
	bool ret = true;
	struct smb2_handle fhandle, dhandle;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig=NULL;
	const char *owner_sid;
	uint32_t flags = 0;
	/*
	 * Can't test without SEC_STD_READ_CONTROL as we
	 * own the file and implicitly have SEC_STD_READ_CONTROL.
	*/
	uint32_t access_masks[] = {
		/* Full READ access. */
		SEC_STD_READ_CONTROL|FILE_READ_DATA|
		FILE_READ_ATTRIBUTES|FILE_READ_EA,

		/* Missing FILE_READ_EA. */
		SEC_STD_READ_CONTROL|FILE_READ_DATA|
		FILE_READ_ATTRIBUTES,

		/* Missing FILE_READ_ATTRIBUTES. */
		SEC_STD_READ_CONTROL|FILE_READ_DATA|
		FILE_READ_EA,

		/* Missing FILE_READ_DATA. */
		SEC_STD_READ_CONTROL|
		FILE_READ_ATTRIBUTES|FILE_READ_EA,
	};
	unsigned int i;
	unsigned int count;
	struct smb2_find f;
	union smb_search_data *d;

	ZERO_STRUCT(fhandle);
	ZERO_STRUCT(dhandle);

	if (!torture_smb2_con_share(tctx, "hideunread", &tree1)) {
		torture_result(tctx, TORTURE_FAIL, "(%s) Unable to connect "
			"to share 'hideunread'\n",
                       __location__);
		ret = false;
		goto done;
	}

	flags = smb2cli_tcon_flags(tree1->smbXcli);

	smb2_util_unlink(tree1, fname);
	smb2_deltree(tree1, BASEDIR);

	torture_comment(tctx, "TESTING ACCESS BASED ENUMERATION\n");

	if ((flags & SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM)==0) {
		torture_result(tctx, TORTURE_FAIL, "(%s) No access enumeration "
			"on share 'hideunread'\n",
                       __location__);
		ret = false;
		goto done;
	}

	if (!smb2_util_setup_dir(tctx, tree1, BASEDIR)) {
		torture_result(tctx, TORTURE_FAIL, "(%s) Unable to setup %s\n",
                       __location__, BASEDIR);
		ret = false;
		goto done;
	}

	/* Get a handle to the BASEDIR directory. */
	status = torture_smb2_testdir(tree1, BASEDIR, &dhandle);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, dhandle);
	ZERO_STRUCT(dhandle);

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.create_options = 0;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access = 0;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname;

	status = smb2_create(tree1, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fhandle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = fhandle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree1, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	torture_comment(tctx, "owner_sid is %s\n", owner_sid);

	/* Setup for the search. */
	ZERO_STRUCT(f);
	f.in.pattern            = "*";
	f.in.continue_flags     = SMB2_CONTINUE_FLAG_REOPEN;
	f.in.max_response_size  = 0x1000;
	f.in.level              = SMB2_FIND_DIRECTORY_INFO;

	for (i = 0; i < ARRAY_SIZE(access_masks); i++) {

		sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					access_masks[i]|SEC_STD_SYNCHRONIZE,
					0,
					NULL);

		set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
		set.set_secdesc.in.file.handle = fhandle;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = sd;
		status = smb2_setinfo_file(tree1, &set);
		CHECK_STATUS(status, NT_STATUS_OK);

		/* Now see if we can see the file in a directory listing. */

		/* Re-open dhandle. */
		status = torture_smb2_testdir(tree1, BASEDIR, &dhandle);
		CHECK_STATUS(status, NT_STATUS_OK);
		f.in.file.handle = dhandle;

		count = 0;
		d = NULL;
		status = smb2_find_level(tree1, tree1, &f, &count, &d);
		TALLOC_FREE(d);

		CHECK_STATUS(status, NT_STATUS_OK);

		smb2_util_close(tree1, dhandle);
		ZERO_STRUCT(dhandle);

		if (i == 0) {
			/* We should see the first sd. */
			if (count != 3) {
				torture_result(tctx, TORTURE_FAIL,
					"(%s) Normal SD - Unable "
					"to see file %s\n",
					__location__,
					BASEDIR);
				ret = false;
				goto done;
			}
		} else {
			/* But no others. */
			if (count != 2) {
				torture_result(tctx, TORTURE_FAIL,
					"(%s) SD 0x%x - can "
					"see file %s\n",
					__location__,
					access_masks[i],
					BASEDIR);
				ret = false;
				goto done;
			}
		}
	}

done:

	if (tree1) {
		smb2_util_close(tree1, fhandle);
		smb2_util_close(tree1, dhandle);
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, BASEDIR);
		smb2_tdis(tree1);
		smb2_logoff(tree1->session);
	}
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

/*
 * test Owner Rights, S-1-3-4
 */
static bool test_owner_rights(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	const char *fname = BASEDIR "\\owner_right.txt";
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	struct security_descriptor *sd_orig = NULL;
	struct security_descriptor *sd = NULL;
	const char *owner_sid = NULL;
	NTSTATUS mxac_status;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done,
			    "smb2_util_setup_dir failed\n");

	torture_comment(tctx, "TESTING OWNER RIGHTS\n");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL |
			SEC_STD_WRITE_DAC |SEC_STD_WRITE_OWNER,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	torture_comment(tctx, "get the original sd\n");

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = handle,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL|SECINFO_OWNER,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");

	sd_orig = gi.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * Add a 2 element ACL
	 * SEC_RIGHTS_FILE_READ for the owner,
	 * SEC_FILE_WRITE_DATA for SID_OWNER_RIGHTS.
	 *
	 * Proves that the owner and SID_OWNER_RIGHTS
	 * ACE entries are additive.
	 */
	sd = security_descriptor_dacl_create(tctx, 0, NULL, NULL,
					     owner_sid,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_RIGHTS_FILE_READ,
					     0,
					     SID_OWNER_RIGHTS,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_FILE_WRITE_DATA,
					     0,
					     NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
				     "SD create failed\n");

	si = (union smb_setfileinfo) {
		.set_secdesc.level = RAW_SFILEINFO_SEC_DESC,
		.set_secdesc.in.file.handle = handle,
		.set_secdesc.in.secinfo_flags = SECINFO_DACL,
		.set_secdesc.in.sd = sd,
	};

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.query_maximal_access = true,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");
	handle = cr.out.file.handle;

	mxac_status = NT_STATUS(cr.out.maximal_access_status);
	torture_assert_ntstatus_ok_goto(tctx, mxac_status, ret, done,
					"smb2_setinfo_file failed\n");

	/*
	 * For some reasons Windows 2016 doesn't set SEC_STD_DELETE but we
	 * do. Mask it out so the test passes against Samba and Windows.
	 */
	torture_assert_int_equal_goto(tctx,
				      cr.out.maximal_access & ~SEC_STD_DELETE,
				      SEC_RIGHTS_FILE_READ |
				      SEC_FILE_WRITE_DATA,
				      ret, done,
				      "Wrong maximum access\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
 * test Owner Rights with a leading DENY ACE, S-1-3-4
 */
static bool test_owner_rights_deny(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	const char *fname = BASEDIR "\\owner_right_deny.txt";
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	struct security_descriptor *sd_orig = NULL;
	struct security_descriptor *sd = NULL;
	const char *owner_sid = NULL;
	NTSTATUS mxac_status;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done,
			"smb2_util_setup_dir failed\n");

	torture_comment(tctx, "TESTING OWNER RIGHTS DENY\n");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL |
			SEC_STD_WRITE_DAC |SEC_STD_WRITE_OWNER,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	torture_comment(tctx, "get the original sd\n");

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = handle,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL|SECINFO_OWNER,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_getinfo_file failed\n");

	sd_orig = gi.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * Add a 2 element ACL
	 * DENY SEC_FILE_DATA_READ for SID_OWNER_RIGHTS
	 * SEC_FILE_READ_DATA for the owner.
	 *
	 * Proves that the owner and SID_OWNER_RIGHTS
	 * ACE entries are additive.
	 */
	sd = security_descriptor_dacl_create(tctx, 0, NULL, NULL,
					SID_OWNER_RIGHTS,
					SEC_ACE_TYPE_ACCESS_DENIED,
					SEC_FILE_READ_DATA,
					0,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ,
					0,
					NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
					"SD create failed\n");

	si = (union smb_setfileinfo) {
		.set_secdesc.level = RAW_SFILEINFO_SEC_DESC,
		.set_secdesc.in.file.handle = handle,
		.set_secdesc.in.secinfo_flags = SECINFO_DACL,
		.set_secdesc.in.sd = sd,
	};

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.query_maximal_access = true,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");
	handle = cr.out.file.handle;

	mxac_status = NT_STATUS(cr.out.maximal_access_status);
	torture_assert_ntstatus_ok_goto(tctx, mxac_status, ret, done,
					"smb2_setinfo_file failed\n");

	/*
	 * For some reasons Windows 2016 doesn't set SEC_STD_DELETE but we
	 * do. Mask it out so the test passes against Samba and Windows.
	 */
	torture_assert_int_equal_goto(tctx,
				      cr.out.maximal_access & ~SEC_STD_DELETE,
				      SEC_RIGHTS_FILE_READ & ~SEC_FILE_READ_DATA,
				      ret, done,
				      "Wrong maximum access\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
 * test Owner Rights with a trailing DENY ACE, S-1-3-4
 */
static bool test_owner_rights_deny1(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	const char *fname = BASEDIR "\\owner_right_deny1.txt";
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	struct security_descriptor *sd_orig = NULL;
	struct security_descriptor *sd = NULL;
	const char *owner_sid = NULL;
	NTSTATUS mxac_status;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done,
			"smb2_util_setup_dir failed\n");

	torture_comment(tctx, "TESTING OWNER RIGHTS DENY1\n");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL |
			SEC_STD_WRITE_DAC |SEC_STD_WRITE_OWNER,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	torture_comment(tctx, "get the original sd\n");

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = handle,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL|SECINFO_OWNER,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_getinfo_file failed\n");

	sd_orig = gi.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * Add a 3 element ACL
	 *
	 * SEC_RIGHTS_FILE_READ allow for owner.
	 * SEC_FILE_WRITE_DATA allow for SID-OWNER-RIGHTS.
	 * SEC_FILE_WRITE_DATA|SEC_FILE_READ_DATA) deny for SID-OWNER-RIGHTS.
	 *
	 * Shows on Windows that trailing DENY entries don't
	 * override granted permissions in max access calculations.
	 */
	sd = security_descriptor_dacl_create(tctx, 0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ,
					0,
					SID_OWNER_RIGHTS,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_WRITE_DATA,
					0,
					SID_OWNER_RIGHTS,
					SEC_ACE_TYPE_ACCESS_DENIED,
					(SEC_FILE_WRITE_DATA|
						SEC_FILE_READ_DATA),
					0,
					NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
					"SD create failed\n");

	si = (union smb_setfileinfo) {
		.set_secdesc.level = RAW_SFILEINFO_SEC_DESC,
		.set_secdesc.in.file.handle = handle,
		.set_secdesc.in.secinfo_flags = SECINFO_DACL,
		.set_secdesc.in.sd = sd,
	};

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.query_maximal_access = true,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");
	handle = cr.out.file.handle;

	mxac_status = NT_STATUS(cr.out.maximal_access_status);
	torture_assert_ntstatus_ok_goto(tctx, mxac_status, ret, done,
					"smb2_setinfo_file failed\n");

	/*
	 * For some reasons Windows 2016 doesn't set SEC_STD_DELETE but we
	 * do. Mask it out so the test passes against Samba and Windows.
	 */
	torture_assert_int_equal_goto(tctx,
				cr.out.maximal_access & ~SEC_STD_DELETE,
				SEC_RIGHTS_FILE_READ | SEC_FILE_WRITE_DATA,
				ret, done,
				"Wrong maximum access\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
 * test that shows that a DENY ACE doesn't remove rights granted
 * by a previous ALLOW ACE.
 */
static bool test_deny1(struct torture_context *tctx,
		       struct smb2_tree *tree)
{
	const char *fname = BASEDIR "\\test_deny1.txt";
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	struct security_descriptor *sd_orig = NULL;
	struct security_descriptor *sd = NULL;
	const char *owner_sid = NULL;
	NTSTATUS mxac_status;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done,
			"smb2_util_setup_dir failed\n");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL |
			SEC_STD_WRITE_DAC |SEC_STD_WRITE_OWNER,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	torture_comment(tctx, "get the original sd\n");

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = handle,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL|SECINFO_OWNER,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_getinfo_file failed\n");

	sd_orig = gi.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * Add a 2 element ACL
	 *
	 * SEC_RIGHTS_FILE_READ|SEC_FILE_WRITE_DATA allow for owner.
	 * SEC_FILE_WRITE_DATA deny for owner
	 *
	 * Shows on Windows that trailing DENY entries don't
	 * override granted permissions.
	 */
	sd = security_descriptor_dacl_create(tctx, 0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ|SEC_FILE_WRITE_DATA,
					0,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_DENIED,
					SEC_FILE_WRITE_DATA,
					0,
					NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
					"SD create failed\n");

	si = (union smb_setfileinfo) {
		.set_secdesc.level = RAW_SFILEINFO_SEC_DESC,
		.set_secdesc.in.file.handle = handle,
		.set_secdesc.in.secinfo_flags = SECINFO_DACL,
		.set_secdesc.in.sd = sd,
	};

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL | SEC_FILE_WRITE_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.query_maximal_access = true,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	mxac_status = NT_STATUS(cr.out.maximal_access_status);
	torture_assert_ntstatus_ok_goto(tctx, mxac_status, ret, done,
					"Wrong maximum access status\n");

	/*
	 * For some reasons Windows 2016 doesn't set SEC_STD_DELETE but we
	 * do. Mask it out so the test passes against Samba and Windows.
	 * SEC_STD_WRITE_DAC comes from being the owner.
	 */
	torture_assert_int_equal_goto(tctx,
				      cr.out.maximal_access & ~SEC_STD_DELETE,
				      SEC_RIGHTS_FILE_READ |
				      SEC_FILE_WRITE_DATA |
				      SEC_STD_WRITE_DAC,
				      ret, done,
				      "Wrong maximum access\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
 * test SEC_FLAG_MAXIMUM_ALLOWED with not-granted access
 *
 * When access_mask contains SEC_FLAG_MAXIMUM_ALLOWED, the server must still
 * process other bits from access_mask. Eg if access_mask contains a right that
 * the requester doesn't have, the function must validate that against the
 * effective permissions.
 */
static bool test_mxac_not_granted(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	const char *fname = BASEDIR "\\test_mxac_not_granted.txt";
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	struct security_descriptor *sd_orig = NULL;
	struct security_descriptor *sd = NULL;
	const char *owner_sid = NULL;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done,
			"smb2_util_setup_dir failed\n");

	torture_comment(tctx, "TESTING OWNER RIGHTS DENY\n");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL |
			SEC_STD_WRITE_DAC |SEC_STD_WRITE_OWNER,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	torture_comment(tctx, "get the original sd\n");

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = handle,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL|SECINFO_OWNER,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_getinfo_file failed\n");

	sd_orig = gi.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	sd = security_descriptor_dacl_create(tctx, 0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_READ_DATA,
					0,
					NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
					"SD create failed\n");

	si = (union smb_setfileinfo) {
		.set_secdesc.level = RAW_SFILEINFO_SEC_DESC,
		.set_secdesc.in.file.handle = handle,
		.set_secdesc.in.secinfo_flags = SECINFO_DACL,
		.set_secdesc.in.sd = sd,
	};

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	cr = (struct smb2_create) {
		.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED |
				     SEC_FILE_WRITE_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "Wrong smb2_create result\n");

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_overwrite_read_only_file(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create c = {};
	struct smb2_create c2 = {};
	const char *fname = BASEDIR "\\test_overwrite_read_only_file.txt";
	struct smb2_handle handle = {{0}};
	struct smb2_handle h2 = {};
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd = NULL, *sd_orig = NULL;
	const char *owner_sid = NULL;
	int i;
	bool ret = true;

	struct tcase {
		int disposition;
		const char *disposition_string;
		NTSTATUS expected_status;
	};

#define TCASE(d, s) {				\
		.disposition = d,		\
		.disposition_string = #d,	\
		.expected_status = s,		\
	}

	struct tcase fs_tcases[] = {
		TCASE(NTCREATEX_DISP_OPEN, NT_STATUS_OK),
		TCASE(NTCREATEX_DISP_SUPERSEDE, NT_STATUS_ACCESS_DENIED),
		TCASE(NTCREATEX_DISP_OVERWRITE, NT_STATUS_ACCESS_DENIED),
		TCASE(NTCREATEX_DISP_OVERWRITE_IF, NT_STATUS_ACCESS_DENIED),
	};

	struct tcase sharing_tcases[] = {
		TCASE(NTCREATEX_DISP_SUPERSEDE, NT_STATUS_SHARING_VIOLATION),
		TCASE(NTCREATEX_DISP_OVERWRITE, NT_STATUS_SHARING_VIOLATION),
		TCASE(NTCREATEX_DISP_OVERWRITE_IF, NT_STATUS_SHARING_VIOLATION),
	};
#undef TCASE

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done, "smb2_util_setup_dir not ok");

	c = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL |
			SEC_STD_WRITE_DAC |
			SEC_STD_WRITE_OWNER,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = c.out.file.handle;

	torture_comment(tctx, "get the original sd\n");

	ZERO_STRUCT(q);
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;

	status = smb2_getinfo_file(tree, tctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_FILE_READ_DATA,
					0,
					NULL);

	ZERO_STRUCT(set);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	smb2_util_close(tree, handle);
	ZERO_STRUCT(handle);

	for (i = 0; i < ARRAY_SIZE(fs_tcases); i++) {
		torture_comment(tctx, "Verify open with %s disposition\n",
				fs_tcases[i].disposition_string);

		c = (struct smb2_create) {
			.in.create_disposition = fs_tcases[i].disposition,
			.in.desired_access = SEC_FILE_READ_DATA,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
			.in.fname = fname,
		};

		status = smb2_create(tree, tctx, &c);
		smb2_util_close(tree, c.out.file.handle);
		torture_assert_ntstatus_equal_goto(
			tctx, status, fs_tcases[i].expected_status, ret, done,
			"smb2_create failed\n");
	};

	torture_comment(tctx, "put back original sd\n");

	c = (struct smb2_create) {
		.in.desired_access = SEC_STD_WRITE_DAC,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = c.out.file.handle;

	ZERO_STRUCT(set);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd_orig;

	status = smb2_setinfo_file(tree, &set);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	for (i = 0; i < ARRAY_SIZE(sharing_tcases); i++) {
		struct tcase *tcase = &sharing_tcases[i];

		torture_comment(tctx, "Verify %s disposition\n",
				tcase->disposition_string);

		torture_comment(tctx, "Read-nonly open file with SHARE_READ\n");

		c = (struct smb2_create) {
			.in.desired_access = SEC_FILE_READ_DATA,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_READ,
			.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
			.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
			.in.fname = fname,
		};

		status = smb2_create(tree, tctx, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		handle = c.out.file.handle;

		torture_comment(tctx, "A second open with %s must return %s\n",
			tcase->disposition_string, nt_errstr(tcase->expected_status));

		c2 = (struct smb2_create) {
			.in.desired_access = SEC_FILE_READ_DATA,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_READ,
			.in.create_disposition = tcase->disposition,
			.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
			.in.fname = fname,
		};

		status = smb2_create(tree, tctx, &c2);
		torture_assert_ntstatus_equal_goto(tctx, status,
						   tcase->expected_status,
						   ret, done,
						   "Wrong status code\n");

		status = smb2_util_close(tree, handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_util_close failed\n");
		ZERO_STRUCT(handle);

		torture_comment(tctx, "First open with %s\n",
				tcase->disposition_string);

		c = (struct smb2_create) {
			.in.desired_access = SEC_FILE_READ_DATA,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_READ,
			.in.create_disposition = tcase->disposition,
			.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
			.in.fname = fname,
		};

		status = smb2_create(tree, tctx, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		handle = c.out.file.handle;

		torture_comment(tctx, "A second read-only open with SHARE_READ "
				"must work\n");

		c = (struct smb2_create) {
			.in.desired_access = SEC_FILE_READ_DATA,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.share_access = NTCREATEX_SHARE_ACCESS_READ,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
			.in.fname = fname,
		};

		status = smb2_create(tree, tctx, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		h2 = c.out.file.handle;

		status = smb2_util_close(tree, handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_util_close failed\n");
		ZERO_STRUCT(handle);

		status = smb2_util_close(tree, h2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_util_close failed\n");
		ZERO_STRUCT(h2);
	}

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
   basic testing of SMB2 ACLs
*/
struct torture_suite *torture_smb2_acls_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "acls");

	torture_suite_add_1smb2_test(suite, "CREATOR", test_creator_sid);
	torture_suite_add_1smb2_test(suite, "GENERIC", test_generic_bits);
	torture_suite_add_1smb2_test(suite, "OWNER", test_owner_bits);
	torture_suite_add_1smb2_test(suite, "INHERITANCE", test_inheritance);
	torture_suite_add_1smb2_test(suite, "INHERITFLAGS", test_inheritance_flags);
	torture_suite_add_1smb2_test(suite, "SDFLAGSVSCHOWN", test_sd_flags_vs_chown);
	torture_suite_add_1smb2_test(suite, "DYNAMIC", test_inheritance_dynamic);
#if 0
	/* XXX This test does not work against XP or Vista. */
	torture_suite_add_1smb2_test(suite, "GETSET", test_sd_get_set);
#endif
	torture_suite_add_1smb2_test(suite, "ACCESSBASED", test_access_based);
	torture_suite_add_1smb2_test(suite, "OWNER-RIGHTS", test_owner_rights);
	torture_suite_add_1smb2_test(suite, "OWNER-RIGHTS-DENY",
			test_owner_rights_deny);
	torture_suite_add_1smb2_test(suite, "OWNER-RIGHTS-DENY1",
			test_owner_rights_deny1);
	torture_suite_add_1smb2_test(suite, "DENY1",
			test_deny1);
	torture_suite_add_1smb2_test(suite, "MXAC-NOT-GRANTED",
			test_mxac_not_granted);
	torture_suite_add_1smb2_test(suite, "OVERWRITE_READ_ONLY_FILE", test_overwrite_read_only_file);

	suite->description = talloc_strdup(suite, "SMB2-ACLS tests");

	return suite;
}

static bool test_acls_non_canonical_flags(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	const char *fname = BASEDIR "\\test_acls_non_canonical_flags.txt";
	struct smb2_create cr;
	struct smb2_handle testdirh = {{0}};
	struct smb2_handle handle = {{0}};
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	struct security_descriptor *sd_orig = NULL;
	struct security_descriptor *sd = NULL;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");

	sd = security_descriptor_dacl_create(tctx,
					     SEC_DESC_DACL_AUTO_INHERITED
					     | SEC_DESC_DACL_AUTO_INHERIT_REQ,
					     NULL,
					     NULL,
					     SID_WORLD,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_RIGHTS_DIR_ALL,
					     SEC_ACE_FLAG_OBJECT_INHERIT
					     | SEC_ACE_FLAG_CONTAINER_INHERIT,
					     NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
					"SD create failed\n");

	si = (union smb_setfileinfo) {
		.set_secdesc.level = RAW_SFILEINFO_SEC_DESC,
		.set_secdesc.in.file.handle = testdirh,
		.set_secdesc.in.secinfo_flags = SECINFO_DACL,
		.set_secdesc.in.sd = sd,
	};

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = testdirh,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_getinfo_file failed\n");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_STD_READ_CONTROL |
			SEC_STD_WRITE_DAC,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	torture_comment(tctx, "get the original sd\n");

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = handle,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_getinfo_file failed\n");

	sd_orig = gi.query_secdesc.out.sd;

	torture_assert_goto(tctx, sd_orig->type & SEC_DESC_DACL_AUTO_INHERITED,
			    ret, done, "Missing SEC_DESC_DACL_AUTO_INHERITED\n");

	/*
	 * SD with SEC_DESC_DACL_AUTO_INHERITED but without
	 * SEC_DESC_DACL_AUTO_INHERITED_REQ, so the resulting SD should not have
	 * SEC_DESC_DACL_AUTO_INHERITED on a Windows box.
	 *
	 * But as we're testing against a share with
	 *
	 *    "acl flag inherited canonicalization = no"
	 *
	 * the resulting SD should have acl flag inherited canonicalization set.
	 */
	sd = security_descriptor_dacl_create(tctx,
					     SEC_DESC_DACL_AUTO_INHERITED,
					     NULL,
					     NULL,
					     SID_WORLD,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_FILE_ALL,
					     0,
					     NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
					"SD create failed\n");

	si = (union smb_setfileinfo) {
		.set_secdesc.level = RAW_SFILEINFO_SEC_DESC,
		.set_secdesc.in.file.handle = handle,
		.set_secdesc.in.secinfo_flags = SECINFO_DACL,
		.set_secdesc.in.sd = sd,
	};

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	cr = (struct smb2_create) {
		.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	gi = (union smb_fileinfo) {
		.query_secdesc.level = RAW_FILEINFO_SEC_DESC,
		.query_secdesc.in.file.handle = handle,
		.query_secdesc.in.secinfo_flags = SECINFO_DACL,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				"smb2_getinfo_file failed\n");

	sd_orig = gi.query_secdesc.out.sd;
	torture_assert_goto(tctx, sd_orig->type & SEC_DESC_DACL_AUTO_INHERITED,
			    ret, done, "Missing SEC_DESC_DACL_AUTO_INHERITED\n");

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, testdirh);
	}
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

struct torture_suite *torture_smb2_acls_non_canonical_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "acls_non_canonical");

	torture_suite_add_1smb2_test(suite, "flags", test_acls_non_canonical_flags);
	return suite;
}
