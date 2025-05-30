/*
   Unix SMB/CIFS implementation.

   local testing of talloc routines.

   Copyright (C) Andrew Tridgell 2004

     ** NOTE! The following LGPL license applies to the talloc
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

#include "replace.h"
#include "system/time.h"
#include <talloc.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include <unistd.h>
#include <sys/wait.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>

#include "talloc_testsuite.h"

#ifndef disable_optimization
#if __has_attribute(optimize)
#define disable_optimization __attribute__((optimize("O0")))
#else /* disable_optimization */
#define disable_optimization
#endif
#endif /* disable_optimization */

static struct timeval private_timeval_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv;
}

static double private_timeval_elapsed(struct timeval *tv)
{
	struct timeval tv2 = private_timeval_current();
	return (tv2.tv_sec - tv->tv_sec) +
	       (tv2.tv_usec - tv->tv_usec)*1.0e-6;
}

#define torture_assert(test, expr, str) if (!(expr)) { \
	printf("failure: %s [\n%s: Expression %s failed: %s\n]\n", \
		test, __location__, #expr, str); \
	return false; \
}

#define torture_assert_str_equal(test, arg1, arg2, desc) \
	if (arg1 == NULL && arg2 == NULL) { /* OK, both NULL == equal */ \
	} else if (arg1 == NULL || arg2 == NULL) {			\
		return false;						\
	} else if (strcmp(arg1, arg2)) {			\
		printf("failure: %s [\n%s: Expected %s, got %s: %s\n]\n", \
		   test, __location__, arg1, arg2, desc); \
		return false; \
	}

#define CHECK_SIZE(test, ptr, tsize) do { \
	if (talloc_total_size(ptr) != (tsize)) { \
		printf("failed: %s [\n%s: wrong '%s' tree size: got %u  expected %u\n]\n", \
		       test, __location__, #ptr, \
		       (unsigned)talloc_total_size(ptr), \
		       (unsigned)tsize); \
		talloc_report_full(ptr, stdout); \
		return false; \
	} \
} while (0)

#define CHECK_BLOCKS(test, ptr, tblocks) do { \
	if (talloc_total_blocks(ptr) != (tblocks)) { \
		printf("failed: %s [\n%s: wrong '%s' tree blocks: got %u  expected %u\n]\n", \
		       test, __location__, #ptr, \
		       (unsigned)talloc_total_blocks(ptr), \
		       (unsigned)tblocks); \
		talloc_report_full(ptr, stdout); \
		return false; \
	} \
} while (0)

#define CHECK_PARENT(test, ptr, parent) do { \
	if (talloc_parent(ptr) != (parent)) { \
		printf("failed: %s [\n%s: '%s' has wrong parent: got %p  expected %p\n]\n", \
		       test, __location__, #ptr, \
		       talloc_parent(ptr), \
		       (parent)); \
		talloc_report_full(ptr, stdout); \
		talloc_report_full(parent, stdout); \
		talloc_report_full(NULL, stdout); \
		return false; \
	} \
} while (0)

static unsigned int test_abort_count;

#if 0
static void test_abort_fn(const char *reason)
{
	printf("# test_abort_fn(%s)\n", reason);
	test_abort_count++;
}

static void test_abort_start(void)
{
	test_abort_count = 0;
	talloc_set_abort_fn(test_abort_fn);
}
#endif

static void test_abort_stop(void)
{
	test_abort_count = 0;
	talloc_set_abort_fn(NULL);
}

static void test_log_stdout(const char *message)
{
	fprintf(stdout, "%s", message);
}

/*
  test references
*/
static bool test_ref1(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("test: ref1\n# SINGLE REFERENCE FREE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	p2 = talloc_named_const(p1, 1, "p2");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 2, "x2");
	talloc_named_const(p1, 3, "x3");

	r1 = talloc_named_const(root, 1, "r1");
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref1", p1, 5);
	CHECK_BLOCKS("ref1", p2, 1);
	CHECK_BLOCKS("ref1", ref, 1);
	CHECK_BLOCKS("ref1", r1, 2);

	fprintf(stderr, "Freeing p2\n");
	talloc_unlink(r1, p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref1", p1, 5);
	CHECK_BLOCKS("ref1", p2, 1);
	CHECK_BLOCKS("ref1", r1, 1);

	fprintf(stderr, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref1", r1, 1);

	fprintf(stderr, "Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(NULL, stderr);

	fprintf(stderr, "Testing NULL\n");
	if (talloc_reference(root, NULL)) {
		return false;
	}

	CHECK_BLOCKS("ref1", root, 1);

	CHECK_SIZE("ref1", root, 0);

	talloc_free(root);
	printf("success: ref1\n");
	return true;
}

/*
  test references
*/
static bool test_ref2(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("test: ref2\n# DOUBLE REFERENCE FREE\n");
	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(root, 1, "r1");
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref2", p1, 5);
	CHECK_BLOCKS("ref2", p2, 1);
	CHECK_BLOCKS("ref2", r1, 2);

	fprintf(stderr, "Freeing ref\n");
	talloc_unlink(r1, ref);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref2", p1, 5);
	CHECK_BLOCKS("ref2", p2, 1);
	CHECK_BLOCKS("ref2", r1, 1);

	fprintf(stderr, "Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref2", p1, 4);
	CHECK_BLOCKS("ref2", r1, 1);

	fprintf(stderr, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref2", r1, 1);

	fprintf(stderr, "Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(root, stderr);

	CHECK_SIZE("ref2", root, 0);

	talloc_free(root);
	printf("success: ref2\n");
	return true;
}

/*
  test references
*/
static bool test_ref3(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("test: ref3\n# PARENT REFERENCE FREE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	p2 = talloc_named_const(root, 1, "p2");
	r1 = talloc_named_const(p1, 1, "r1");
	ref = talloc_reference(p2, r1);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref3", p1, 2);
	CHECK_BLOCKS("ref3", p2, 2);
	CHECK_BLOCKS("ref3", r1, 1);
	CHECK_BLOCKS("ref3", ref, 1);

	fprintf(stderr, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref3", p2, 2);
	CHECK_BLOCKS("ref3", r1, 1);

	fprintf(stderr, "Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, stderr);

	CHECK_SIZE("ref3", root, 0);

	talloc_free(root);

	printf("success: ref3\n");
	return true;
}

/*
  test references
*/
static bool test_ref4(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("test: ref4\n# REFERRER REFERENCE FREE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(root, 1, "r1");
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref4", p1, 5);
	CHECK_BLOCKS("ref4", p2, 1);
	CHECK_BLOCKS("ref4", ref, 1);
	CHECK_BLOCKS("ref4", r1, 2);

	fprintf(stderr, "Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref4", p1, 5);
	CHECK_BLOCKS("ref4", p2, 1);

	fprintf(stderr, "Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("ref4", p1, 4);

	fprintf(stderr, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stderr);

	CHECK_SIZE("ref4", root, 0);

	talloc_free(root);

	printf("success: ref4\n");
	return true;
}


/*
  test references
*/
static bool test_unlink1(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("test: unlink\n# UNLINK\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(p1, 1, "r1");
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("unlink", p1, 7);
	CHECK_BLOCKS("unlink", p2, 1);
	CHECK_BLOCKS("unlink", ref, 1);
	CHECK_BLOCKS("unlink", r1, 2);

	fprintf(stderr, "Unreferencing r1\n");
	talloc_unlink(r1, p2);
	talloc_report_full(root, stderr);

	CHECK_BLOCKS("unlink", p1, 6);
	CHECK_BLOCKS("unlink", p2, 1);
	CHECK_BLOCKS("unlink", r1, 1);

	fprintf(stderr, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stderr);

	CHECK_SIZE("unlink", root, 0);

	talloc_free(root);

	printf("success: unlink\n");
	return true;
}

static int fail_destructor(void *ptr)
{
	return -1;
}

/*
  miscellaneous tests to try to get a higher test coverage percentage
*/
static bool test_misc(void)
{
	void *root, *p1;
	char *p2;
	double *d;
	const char *name;

	printf("test: misc\n# MISCELLANEOUS\n");

	root = talloc_new(NULL);

	p1 = talloc_size(root, 0x7fffffff);
	torture_assert("misc", !p1, "failed: large talloc allowed\n");

	p1 = talloc_strdup(root, "foo");
	talloc_increase_ref_count(p1);
	talloc_increase_ref_count(p1);
	talloc_increase_ref_count(p1);
	CHECK_BLOCKS("misc", p1, 1);
	CHECK_BLOCKS("misc", root, 2);
	talloc_unlink(NULL, p1);
	CHECK_BLOCKS("misc", p1, 1);
	CHECK_BLOCKS("misc", root, 2);
	talloc_unlink(NULL, p1);
	CHECK_BLOCKS("misc", p1, 1);
	CHECK_BLOCKS("misc", root, 2);
	p2 = talloc_strdup(p1, "foo");
	torture_assert("misc", talloc_unlink(root, p2) == -1,
				   "failed: talloc_unlink() of non-reference context should return -1\n");
	torture_assert("misc", talloc_unlink(p1, p2) == 0,
		"failed: talloc_unlink() of parent should succeed\n");
	talloc_unlink(NULL, p1);
	CHECK_BLOCKS("misc", p1, 1);
	CHECK_BLOCKS("misc", root, 2);

	name = talloc_set_name(p1, "my name is %s", "foo");
	torture_assert_str_equal("misc", talloc_get_name(p1), "my name is foo",
		"failed: wrong name after talloc_set_name(my name is foo)");
	torture_assert_str_equal("misc", talloc_get_name(p1), name,
		"failed: wrong name after talloc_set_name(my name is foo)");
	CHECK_BLOCKS("misc", p1, 2);
	CHECK_BLOCKS("misc", root, 3);

	talloc_set_name_const(p1, NULL);
	torture_assert_str_equal ("misc", talloc_get_name(p1), "UNNAMED",
		"failed: wrong name after talloc_set_name(NULL)");
	CHECK_BLOCKS("misc", p1, 2);
	CHECK_BLOCKS("misc", root, 3);

	torture_assert("misc", talloc_free(NULL) == -1,
				   "talloc_free(NULL) should give -1\n");

	talloc_set_destructor(p1, fail_destructor);
	torture_assert("misc", talloc_free(p1) == -1,
		"Failed destructor should cause talloc_free to fail\n");
	talloc_set_destructor(p1, NULL);

	talloc_report(root, stderr);


	p2 = (char *)talloc_zero_size(p1, 20);
	torture_assert("misc", p2[19] == 0, "Failed to give zero memory\n");
	talloc_free(p2);

	torture_assert("misc", talloc_strdup(root, NULL) == NULL,
		"failed: strdup on NULL should give NULL\n");

	p2 = talloc_strndup(p1, "foo", 2);
	torture_assert("misc", strcmp("fo", p2) == 0,
				   "strndup doesn't work\n");
	p2 = talloc_asprintf_append_buffer(p2, "o%c", 'd');
	torture_assert("misc", strcmp("food", p2) == 0,
				   "talloc_asprintf_append_buffer doesn't work\n");
	CHECK_BLOCKS("misc", p2, 1);
	CHECK_BLOCKS("misc", p1, 3);

	p2 = talloc_asprintf_append_buffer(NULL, "hello %s", "world");
	torture_assert("misc", strcmp("hello world", p2) == 0,
		"talloc_asprintf_append_buffer doesn't work\n");
	CHECK_BLOCKS("misc", p2, 1);
	CHECK_BLOCKS("misc", p1, 3);
	talloc_free(p2);

	d = talloc_array(p1, double, 0x20000000);
	torture_assert("misc", !d, "failed: integer overflow not detected\n");

	d = talloc_realloc(p1, d, double, 0x20000000);
	torture_assert("misc", !d, "failed: integer overflow not detected\n");

	talloc_free(p1);
	CHECK_BLOCKS("misc", root, 1);

	p1 = talloc_named(root, 100, "%d bytes", 100);
	CHECK_BLOCKS("misc", p1, 2);
	CHECK_BLOCKS("misc", root, 3);
	talloc_unlink(root, p1);

	p1 = talloc_init("%d bytes", 200);
	p2 = talloc_asprintf(p1, "my test '%s'", "string");
	torture_assert_str_equal("misc", p2, "my test 'string'",
		"failed: talloc_asprintf(\"my test '%%s'\", \"string\") gave: \"%s\"");
	CHECK_BLOCKS("misc", p1, 3);
	CHECK_SIZE("misc", p2, 17);
	CHECK_BLOCKS("misc", root, 1);
	talloc_unlink(NULL, p1);

	p1 = talloc_named_const(root, 10, "p1");
	p2 = (char *)talloc_named_const(root, 20, "p2");
	(void)talloc_reference(p1, p2);
	talloc_report_full(root, stderr);
	talloc_unlink(root, p2);
	talloc_report_full(root, stderr);
	CHECK_BLOCKS("misc", p2, 1);
	CHECK_BLOCKS("misc", p1, 2);
	CHECK_BLOCKS("misc", root, 3);
	talloc_unlink(p1, p2);
	talloc_unlink(root, p1);

	p1 = talloc_named_const(root, 10, "p1");
	p2 = (char *)talloc_named_const(root, 20, "p2");
	(void)talloc_reference(NULL, p2);
	talloc_report_full(root, stderr);
	talloc_unlink(root, p2);
	talloc_report_full(root, stderr);
	CHECK_BLOCKS("misc", p2, 1);
	CHECK_BLOCKS("misc", p1, 1);
	CHECK_BLOCKS("misc", root, 2);
	talloc_unlink(NULL, p2);
	talloc_unlink(root, p1);

	/* Test that talloc_unlink is a no-op */

	torture_assert("misc", talloc_unlink(root, NULL) == -1,
		"failed: talloc_unlink(root, NULL) == -1\n");

	talloc_report(root, stderr);
	talloc_report(NULL, stderr);

	CHECK_SIZE("misc", root, 0);

	talloc_free(root);

	CHECK_SIZE("misc", NULL, 0);

	talloc_enable_null_tracking_no_autofree();
	talloc_enable_leak_report();
	talloc_enable_leak_report_full();

	printf("success: misc\n");

	return true;
}


/*
  test realloc
*/
static bool test_realloc(void)
{
	void *root, *p1, *p2;

	printf("test: realloc\n# REALLOC\n");

	root = talloc_new(NULL);

	p1 = talloc_size(root, 10);
	CHECK_SIZE("realloc", p1, 10);

	p1 = talloc_realloc_size(NULL, p1, 20);
	CHECK_SIZE("realloc", p1, 20);

	talloc_new(p1);

	p2 = talloc_realloc_size(p1, NULL, 30);

	talloc_new(p1);

	p2 = talloc_realloc_size(p1, p2, 40);

	CHECK_SIZE("realloc", p2, 40);
	CHECK_SIZE("realloc", root, 60);
	CHECK_BLOCKS("realloc", p1, 4);

	p1 = talloc_realloc_size(NULL, p1, 20);
	CHECK_SIZE("realloc", p1, 60);

	talloc_increase_ref_count(p2);
	torture_assert("realloc", talloc_realloc_size(NULL, p2, 5) == NULL,
		"failed: talloc_realloc() on a referenced pointer should fail\n");
	CHECK_BLOCKS("realloc", p1, 4);

	talloc_realloc_size(NULL, p2, 0);
	talloc_realloc_size(NULL, p2, 0);
	CHECK_BLOCKS("realloc", p1, 4);
	talloc_realloc_size(p1, p2, 0);
	CHECK_BLOCKS("realloc", p1, 3);

	torture_assert("realloc", talloc_realloc_size(NULL, p1, 0x7fffffff) == NULL,
		"failed: oversize talloc should fail\n");

	talloc_realloc_size(NULL, p1, 0);
	CHECK_BLOCKS("realloc", root, 4);
	talloc_realloc_size(root, p1, 0);
	CHECK_BLOCKS("realloc", root, 1);

	CHECK_SIZE("realloc", root, 0);

	talloc_free(root);

	printf("success: realloc\n");

	return true;
}

/*
  test realloc with a child
*/
static bool test_realloc_child(void)
{
	void *root;
	struct el2 {
		const char *name;
	} *el2, *el2_2, *el2_3, **el_list_save;
	struct el1 {
		int count;
		struct el2 **list, **list2, **list3;
	} *el1;

	printf("test: REALLOC WITH CHILD\n");

	root = talloc_new(NULL);

	el1 = talloc(root, struct el1);
	el1->list = talloc(el1, struct el2 *);
	el1->list[0] = talloc(el1->list, struct el2);
	el1->list[0]->name = talloc_strdup(el1->list[0], "testing");

	el1->list2 = talloc(el1, struct el2 *);
	el1->list2[0] = talloc(el1->list2, struct el2);
	el1->list2[0]->name = talloc_strdup(el1->list2[0], "testing2");

	el1->list3 = talloc(el1, struct el2 *);
	el1->list3[0] = talloc(el1->list3, struct el2);
	el1->list3[0]->name = talloc_strdup(el1->list3[0], "testing2");

	el2 = talloc(el1->list, struct el2);
	CHECK_PARENT("el2", el2, el1->list);
	el2_2 = talloc(el1->list2, struct el2);
	CHECK_PARENT("el2", el2_2, el1->list2);
	el2_3 = talloc(el1->list3, struct el2);
	CHECK_PARENT("el2", el2_3, el1->list3);

	el_list_save = el1->list;
	el1->list = talloc_realloc(el1, el1->list, struct el2 *, 100);
	if (el1->list == el_list_save) {
		printf("failure: talloc_realloc didn't move pointer");
		return false;
	}

	CHECK_PARENT("el1_after_realloc", el1->list, el1);
	el1->list2 = talloc_realloc(el1, el1->list2, struct el2 *, 200);
	CHECK_PARENT("el1_after_realloc", el1->list2, el1);
	el1->list3 = talloc_realloc(el1, el1->list3, struct el2 *, 300);
	CHECK_PARENT("el1_after_realloc", el1->list3, el1);

	CHECK_PARENT("el2", el2, el1->list);
	CHECK_PARENT("el2", el2_2, el1->list2);
	CHECK_PARENT("el2", el2_3, el1->list3);

	/* Finally check realloc with multiple children */
	el1 = talloc_realloc(root, el1, struct el1, 100);
	CHECK_PARENT("el1->list", el1->list, el1);
	CHECK_PARENT("el1->list2", el1->list2, el1);
	CHECK_PARENT("el1->list3", el1->list3, el1);

	talloc_free(root);

	printf("success: REALLOC WITH CHILD\n");
	return true;
}

/*
  test type checking
*/
static bool test_type(void)
{
	void *root;
	struct el1 {
		int count;
	};
	struct el2 {
		int count;
	};
	struct el1 *el1;

	printf("test: type\n# talloc type checking\n");

	root = talloc_new(NULL);

	el1 = talloc(root, struct el1);

	el1->count = 1;

	torture_assert("type", talloc_get_type(el1, struct el1) == el1,
		"type check failed on el1\n");
	torture_assert("type", talloc_get_type(el1, struct el2) == NULL,
		"type check failed on el1 with el2\n");
	talloc_set_type(el1, struct el2);
	torture_assert("type", talloc_get_type(el1, struct el2) == (struct el2 *)el1,
		"type set failed on el1 with el2\n");

	talloc_free(root);

	printf("success: type\n");
	return true;
}

/*
  test steal
*/
static bool test_steal(void)
{
	void *root, *p1, *p2;

	printf("test: steal\n# STEAL\n");

	root = talloc_new(NULL);

	p1 = talloc_array(root, char, 10);
	CHECK_SIZE("steal", p1, 10);

	p2 = talloc_realloc(root, NULL, char, 20);
	CHECK_SIZE("steal", p1, 10);
	CHECK_SIZE("steal", root, 30);

	torture_assert("steal", talloc_steal(p1, NULL) == NULL,
		"failed: stealing NULL should give NULL\n");

	torture_assert("steal", talloc_steal(p1, p1) == p1,
		"failed: stealing to ourselves is a nop\n");
	CHECK_BLOCKS("steal", root, 3);
	CHECK_SIZE("steal", root, 30);

	talloc_steal(NULL, p1);
	talloc_steal(NULL, p2);
	CHECK_BLOCKS("steal", root, 1);
	CHECK_SIZE("steal", root, 0);

	talloc_free(p1);
	talloc_steal(root, p2);
	CHECK_BLOCKS("steal", root, 2);
	CHECK_SIZE("steal", root, 20);

	talloc_free(p2);

	CHECK_BLOCKS("steal", root, 1);
	CHECK_SIZE("steal", root, 0);

	talloc_free(root);

	p1 = talloc_size(NULL, 3);
	talloc_report_full(NULL, stderr);
	CHECK_SIZE("steal", NULL, 3);
	talloc_free(p1);

	printf("success: steal\n");
	return true;
}

/*
  test move
*/
static bool test_move(void)
{
	void *root;
	struct t_move {
		char *p;
		int *x;
	} *t1, *t2;

	printf("test: move\n# MOVE\n");

	root = talloc_new(NULL);

	t1 = talloc(root, struct t_move);
	t2 = talloc(root, struct t_move);
	t1->p = talloc_strdup(t1, "foo");
	t1->x = talloc(t1, int);
	*t1->x = 42;

	t2->p = talloc_move(t2, &t1->p);
	t2->x = talloc_move(t2, &t1->x);
	torture_assert("move", t1->p == NULL && t1->x == NULL &&
	    strcmp(t2->p, "foo") == 0 && *t2->x == 42,
		"talloc move failed");

	talloc_free(root);

	printf("success: move\n");

	return true;
}

/*
  test talloc_realloc_fn
*/
static bool test_realloc_fn(void)
{
	void *root, *p1;

	printf("test: realloc_fn\n# talloc_realloc_fn\n");

	root = talloc_new(NULL);

	p1 = talloc_realloc_fn(root, NULL, 10);
	CHECK_BLOCKS("realloc_fn", root, 2);
	CHECK_SIZE("realloc_fn", root, 10);
	p1 = talloc_realloc_fn(root, p1, 20);
	CHECK_BLOCKS("realloc_fn", root, 2);
	CHECK_SIZE("realloc_fn", root, 20);
	p1 = talloc_realloc_fn(root, p1, 0);
	CHECK_BLOCKS("realloc_fn", root, 1);
	CHECK_SIZE("realloc_fn", root, 0);

	talloc_free(root);

	printf("success: realloc_fn\n");
	return true;
}


static bool test_unref_reparent(void)
{
	void *root, *p1, *p2, *c1;

	printf("test: unref_reparent\n# UNREFERENCE AFTER PARENT FREED\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "orig parent");
	p2 = talloc_named_const(root, 1, "parent by reference");

	c1 = talloc_named_const(p1, 1, "child");
	talloc_reference(p2, c1);

	CHECK_PARENT("unref_reparent", c1, p1);

	talloc_free(p1);

	CHECK_PARENT("unref_reparent", c1, p2);

	talloc_unlink(p2, c1);

	CHECK_SIZE("unref_reparent", root, 1);

	talloc_free(p2);
	talloc_free(root);

	printf("success: unref_reparent\n");
	return true;
}

/* Make the size big enough to not fit into the stack */
#define ALLOC_SIZE (128 * 1024)
#define ALLOC_DUP_STRING "talloc talloc talloc talloc talloc talloc talloc"

/*
  measure the speed of talloc versus malloc
*/
static bool test_speed(void) disable_optimization;
static bool test_speed(void)
{
	void *ctx = talloc_new(NULL);
	unsigned count;
	const int loop = 1000;
	int i;
	struct timeval tv;

	printf("test: speed\n# TALLOC VS MALLOC SPEED\n");

	tv = private_timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = talloc_size(ctx, loop % ALLOC_SIZE);
			p2 = talloc_strdup(p1, ALLOC_DUP_STRING);
			p3 = talloc_size(p1, ALLOC_SIZE);
			(void)p2;
			(void)p3;
			talloc_free(p1);
		}
		count += 3 * loop;
	} while (private_timeval_elapsed(&tv) < 5.0);

	fprintf(stderr, "talloc:\t\t%.0f ops/sec\n", count/private_timeval_elapsed(&tv));

	talloc_free(ctx);

	ctx = talloc_pool(NULL, ALLOC_SIZE * 2);

	tv = private_timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = talloc_size(ctx, loop % ALLOC_SIZE);
			p2 = talloc_strdup(p1, ALLOC_DUP_STRING);
			p3 = talloc_size(p1, ALLOC_SIZE);
			(void)p2;
			(void)p3;
			talloc_free(p1);
		}
		count += 3 * loop;
	} while (private_timeval_elapsed(&tv) < 5.0);

	talloc_free(ctx);

	fprintf(stderr, "talloc_pool:\t%.0f ops/sec\n", count/private_timeval_elapsed(&tv));

	tv = private_timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = malloc(loop % ALLOC_SIZE);
			p2 = strdup(ALLOC_DUP_STRING);
			p3 = malloc(ALLOC_SIZE);
			free(p1);
			free(p2);
			free(p3);
		}
		count += 3 * loop;
	} while (private_timeval_elapsed(&tv) < 5.0);
	fprintf(stderr, "malloc:\t\t%.0f ops/sec\n", count/private_timeval_elapsed(&tv));

	printf("\n# TALLOC_ZERO VS CALLOC SPEED\n");

	ctx = talloc_new(NULL);

	tv = private_timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = talloc_zero_size(ctx, loop % ALLOC_SIZE);
			p2 = talloc_strdup(p1, ALLOC_DUP_STRING);
			p3 = talloc_zero_size(p1, ALLOC_SIZE);
			(void)p2;
			(void)p3;
			talloc_free(p1);
		}
		count += 3 * loop;
	} while (private_timeval_elapsed(&tv) < 5.0);

	fprintf(stderr, "talloc_zero:\t%.0f ops/sec\n", count/private_timeval_elapsed(&tv));

	talloc_free(ctx);

	tv = private_timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = calloc(1, loop % ALLOC_SIZE);
			p2 = strdup(ALLOC_DUP_STRING);
			p3 = calloc(1, ALLOC_SIZE);
			free(p1);
			free(p2);
			free(p3);
		}
		count += 3 * loop;
	} while (private_timeval_elapsed(&tv) < 5.0);
	fprintf(stderr, "calloc:\t\t%.0f ops/sec\n", count/private_timeval_elapsed(&tv));

	printf("success: speed\n");

	return true;
}

static bool test_lifeless(void)
{
	void *top = talloc_new(NULL);
	char *parent, *child;
	void *child_owner = talloc_new(NULL);

	printf("test: lifeless\n# TALLOC_UNLINK LOOP\n");

	parent = talloc_strdup(top, "parent");
	child = talloc_strdup(parent, "child");
	(void)talloc_reference(child, parent);
	(void)talloc_reference(child_owner, child);
	talloc_report_full(top, stderr);
	talloc_unlink(top, parent);
	talloc_unlink(top, child);
	talloc_report_full(top, stderr);
	talloc_free(top);
	talloc_free(child_owner);
	talloc_free(child);

	printf("success: lifeless\n");
	return true;
}

static int loop_destructor_count;

static int test_loop_destructor(char *ptr)
{
	loop_destructor_count++;
	return 0;
}

static bool test_loop(void)
{
	void *top = talloc_new(NULL);
	char *parent;
	struct req1 {
		char *req2, *req3;
	} *req1;

	printf("test: loop\n# TALLOC LOOP DESTRUCTION\n");

	parent = talloc_strdup(top, "parent");
	req1 = talloc(parent, struct req1);
	req1->req2 = talloc_strdup(req1, "req2");
	talloc_set_destructor(req1->req2, test_loop_destructor);
	req1->req3 = talloc_strdup(req1, "req3");
	(void)talloc_reference(req1->req3, req1);
	talloc_report_full(top, stderr);
	talloc_free(parent);
	talloc_report_full(top, stderr);
	talloc_report_full(NULL, stderr);
	talloc_free(top);

	torture_assert("loop", loop_destructor_count == 1,
				   "FAILED TO FIRE LOOP DESTRUCTOR\n");
	loop_destructor_count = 0;

	printf("success: loop\n");
	return true;
}

static int realloc_parent_destructor_count;

static int test_realloc_parent_destructor(char *ptr)
{
	realloc_parent_destructor_count++;
	return 0;
}

static bool test_realloc_on_destructor_parent(void)
{
	void *top = talloc_new(NULL);
	char *parent;
	char *a, *b, *C, *D;
	realloc_parent_destructor_count = 0;

	printf("test: free_for_exit\n# TALLOC FREE FOR EXIT\n");

	parent = talloc_strdup(top, "parent");
	a = talloc_strdup(parent, "a");
	b = talloc_strdup(a, "b");
	C = talloc_strdup(a, "C");
	D = talloc_strdup(b, "D");
	talloc_set_destructor(D, test_realloc_parent_destructor);
	/* Capitalised ones have destructors.
	 *
	 * parent --> a -> b -> D
	 *              -> c
	 */

	a = talloc_realloc(parent, a, char, 2048);

	torture_assert("check talloc_realloc", a != NULL, "talloc_realloc failed");

	talloc_set_destructor(C, test_realloc_parent_destructor);
	/*
	 * parent --> a[2048] -> b -> D
	 *                    -> C
	 *
	 */

	talloc_free(parent);

	torture_assert("check destructor realloc_parent_destructor",
		       realloc_parent_destructor_count == 2,
		       "FAILED TO FIRE free_for_exit_destructor\n");


	printf("success: free_for_exit\n");
	talloc_free(top); /* make ASAN happy */

	return true;
}

static int fail_destructor_str(char *ptr)
{
	return -1;
}

static bool test_free_parent_deny_child(void)
{
	void *top = talloc_new(NULL);
	char *level1;
	char *level2;
	char *level3;

	printf("test: free_parent_deny_child\n# TALLOC FREE PARENT DENY CHILD\n");

	level1 = talloc_strdup(top, "level1");
	level2 = talloc_strdup(level1, "level2");
	level3 = talloc_strdup(level2, "level3");

	talloc_set_destructor(level3, fail_destructor_str);
	talloc_free(level1);
	talloc_set_destructor(level3, NULL);

	CHECK_PARENT("free_parent_deny_child", level3, top);

	talloc_free(top);

	printf("success: free_parent_deny_child\n");
	return true;
}

struct new_parent {
	void *new_parent;
	char val[20];
};

static int reparenting_destructor(struct new_parent *np)
{
	talloc_set_destructor(np, NULL);
	(void)talloc_move(np->new_parent, &np);
	return -1;
}

static bool test_free_parent_reparent_child(void)
{
	void *top = talloc_new(NULL);
	char *level1;
	char *alternate_level1;
	char *level2;
	struct new_parent *level3;

	printf("test: free_parent_reparent_child\n# "
		"TALLOC FREE PARENT REPARENT CHILD\n");

	level1 = talloc_strdup(top, "level1");
	alternate_level1 = talloc_strdup(top, "alternate_level1");
	level2 = talloc_strdup(level1, "level2");
	level3 = talloc(level2, struct new_parent);
	level3->new_parent = alternate_level1;
	memset(level3->val, 'x', sizeof(level3->val));

	talloc_set_destructor(level3, reparenting_destructor);
	talloc_free(level1);

	CHECK_PARENT("free_parent_reparent_child",
		level3, alternate_level1);

	talloc_free(top);

	printf("success: free_parent_reparent_child\n");
	return true;
}

static bool test_free_parent_reparent_child_in_pool(void)
{
	void *top = talloc_new(NULL);
	char *level1;
	char *alternate_level1;
	char *level2;
	void *pool;
	struct new_parent *level3;

	printf("test: free_parent_reparent_child_in_pool\n# "
		"TALLOC FREE PARENT REPARENT CHILD IN POOL\n");

	pool = talloc_pool(top, 1024);
	level1 = talloc_strdup(pool, "level1");
	alternate_level1 = talloc_strdup(top, "alternate_level1");
	level2 = talloc_strdup(level1, "level2");
	level3 = talloc(level2, struct new_parent);
	level3->new_parent = alternate_level1;
	memset(level3->val, 'x', sizeof(level3->val));

	talloc_set_destructor(level3, reparenting_destructor);
	talloc_free(level1);
	talloc_set_destructor(level3, NULL);

	CHECK_PARENT("free_parent_reparent_child_in_pool",
		level3, alternate_level1);

	/* Even freeing alternate_level1 should leave pool alone. */
	talloc_free(alternate_level1);
	talloc_free(top);

	printf("success: free_parent_reparent_child_in_pool\n");
	return true;
}


static bool test_talloc_ptrtype(void)
{
	void *top = talloc_new(NULL);
	struct struct1 {
		int foo;
		int bar;
	} *s1, *s2, **s3, ***s4;
	const char *location1;
	const char *location2;
	const char *location3;
	const char *location4;

	printf("test: ptrtype\n# TALLOC PTRTYPE\n");

	s1 = talloc_ptrtype(top, s1);location1 = __location__;

	if (talloc_get_size(s1) != sizeof(struct struct1)) {
		printf("failure: ptrtype [\n"
		  "talloc_ptrtype() allocated the wrong size %lu (should be %lu)\n"
		  "]\n", (unsigned long)talloc_get_size(s1),
		           (unsigned long)sizeof(struct struct1));
		return false;
	}

	if (strcmp(location1, talloc_get_name(s1)) != 0) {
		printf("failure: ptrtype [\n"
		  "talloc_ptrtype() sets the wrong name '%s' (should be '%s')\n]\n",
			talloc_get_name(s1), location1);
		return false;
	}

	s2 = talloc_array_ptrtype(top, s2, 10);location2 = __location__;

	if (talloc_get_size(s2) != (sizeof(struct struct1) * 10)) {
		printf("failure: ptrtype [\n"
			   "talloc_array_ptrtype() allocated the wrong size "
		       "%lu (should be %lu)\n]\n",
			(unsigned long)talloc_get_size(s2),
		    (unsigned long)(sizeof(struct struct1)*10));
		return false;
	}

	if (strcmp(location2, talloc_get_name(s2)) != 0) {
		printf("failure: ptrtype [\n"
		"talloc_array_ptrtype() sets the wrong name '%s' (should be '%s')\n]\n",
			talloc_get_name(s2), location2);
		return false;
	}

	s3 = talloc_array_ptrtype(top, s3, 10);location3 = __location__;

	if (talloc_get_size(s3) != (sizeof(struct struct1 *) * 10)) {
		printf("failure: ptrtype [\n"
			   "talloc_array_ptrtype() allocated the wrong size "
		       "%lu (should be %lu)\n]\n",
			   (unsigned long)talloc_get_size(s3),
		       (unsigned long)(sizeof(struct struct1 *)*10));
		return false;
	}

	torture_assert_str_equal("ptrtype", location3, talloc_get_name(s3),
		"talloc_array_ptrtype() sets the wrong name");

	s4 = talloc_array_ptrtype(top, s4, 10);location4 = __location__;

	if (talloc_get_size(s4) != (sizeof(struct struct1 **) * 10)) {
		printf("failure: ptrtype [\n"
		      "talloc_array_ptrtype() allocated the wrong size "
		       "%lu (should be %lu)\n]\n",
			   (unsigned long)talloc_get_size(s4),
		       (unsigned long)(sizeof(struct struct1 **)*10));
		return false;
	}

	torture_assert_str_equal("ptrtype", location4, talloc_get_name(s4),
		"talloc_array_ptrtype() sets the wrong name");

	talloc_free(top);

	printf("success: ptrtype\n");
	return true;
}

static int _test_talloc_free_in_destructor(void **ptr)
{
	talloc_free(*ptr);
	return 0;
}

static bool test_talloc_free_in_destructor(void)
{
	void *level0;
	void *level1;
	void *level2;
	void *level3;
	void *level4;
	void **level5;

	printf("test: free_in_destructor\n# TALLOC FREE IN DESTRUCTOR\n");

	level0 = talloc_new(NULL);
	level1 = talloc_new(level0);
	level2 = talloc_new(level1);
	level3 = talloc_new(level2);
	level4 = talloc_new(level3);
	level5 = talloc(level4, void *);

	*level5 = level3;
	(void)talloc_reference(level0, level3);
	(void)talloc_reference(level3, level3);
	(void)talloc_reference(level5, level3);

	talloc_set_destructor(level5, _test_talloc_free_in_destructor);

	talloc_free(level1);

	talloc_free(level0);

	talloc_free(level3); /* make ASAN happy */

	printf("success: free_in_destructor\n");
	return true;
}

static bool test_autofree(void)
{
#if _SAMBA_BUILD_ < 4
	/* autofree test would kill smbtorture */
	void *p;
	printf("test: autofree\n# TALLOC AUTOFREE CONTEXT\n");

	p = talloc_autofree_context();
	talloc_free(p);

	p = talloc_autofree_context();
	talloc_free(p);

	printf("success: autofree\n");
#endif
	return true;
}

static bool test_pool(void)
{
	void *pool;
	void *p1, *p2, *p3, *p4;
	void *p2_2;

	pool = talloc_pool(NULL, 1024);

	p1 = talloc_size(pool, 80);
	memset(p1, 0x11, talloc_get_size(p1));
	p2 = talloc_size(pool, 20);
	memset(p2, 0x11, talloc_get_size(p2));
	p3 = talloc_size(p1, 50);
	memset(p3, 0x11, talloc_get_size(p3));
	p4 = talloc_size(p3, 1000);
	memset(p4, 0x11, talloc_get_size(p4));

	p2_2 = talloc_realloc_size(pool, p2, 20+1);
	torture_assert("pool realloc 20+1", p2_2 == p2, "failed: pointer changed");
	memset(p2, 0x11, talloc_get_size(p2));
	p2_2 = talloc_realloc_size(pool, p2, 20-1);
	torture_assert("pool realloc 20-1", p2_2 == p2, "failed: pointer changed");
	memset(p2, 0x11, talloc_get_size(p2));
	p2_2 = talloc_realloc_size(pool, p2, 20-1);
	torture_assert("pool realloc 20-1", p2_2 == p2, "failed: pointer changed");
	memset(p2, 0x11, talloc_get_size(p2));

	talloc_free(p3);

	/* this should reclaim the memory of p4 and p3 */
	p2_2 = talloc_realloc_size(pool, p2, 400);
	torture_assert("pool realloc 400", p2_2 == p2, "failed: pointer changed");
	memset(p2, 0x11, talloc_get_size(p2));

	talloc_free(p1);

	/* this should reclaim the memory of p1 */
	p2_2 = talloc_realloc_size(pool, p2, 800);
	torture_assert("pool realloc 800", p2_2 == p1, "failed: pointer not changed");
	p2 = p2_2;
	memset(p2, 0x11, talloc_get_size(p2));

	/* this should do a malloc */
	p2_2 = talloc_realloc_size(pool, p2, 1800);
	torture_assert("pool realloc 1800", p2_2 != p2, "failed: pointer not changed");
	p2 = p2_2;
	memset(p2, 0x11, talloc_get_size(p2));

	/* this should reclaim the memory from the pool */
	p3 = talloc_size(pool, 80);
	torture_assert("pool alloc 80", p3 == p1, "failed: pointer changed");
	memset(p3, 0x11, talloc_get_size(p3));

	talloc_free(p2);
	talloc_free(p3);

	p1 = talloc_size(pool, 80);
	memset(p1, 0x11, talloc_get_size(p1));
	p2 = talloc_size(pool, 20);
	memset(p2, 0x11, talloc_get_size(p2));

	talloc_free(p1);

	p2_2 = talloc_realloc_size(pool, p2, 20-1);
	torture_assert("pool realloc 20-1", p2_2 == p2, "failed: pointer changed");
	memset(p2, 0x11, talloc_get_size(p2));
	p2_2 = talloc_realloc_size(pool, p2, 20-1);
	torture_assert("pool realloc 20-1", p2_2 == p2, "failed: pointer changed");
	memset(p2, 0x11, talloc_get_size(p2));

	/* this should do a malloc */
	p2_2 = talloc_realloc_size(pool, p2, 1800);
	torture_assert("pool realloc 1800", p2_2 != p2, "failed: pointer not changed");
	p2 = p2_2;
	memset(p2, 0x11, talloc_get_size(p2));

	/* this should reclaim the memory from the pool */
	p3 = talloc_size(pool, 800);
	torture_assert("pool alloc 800", p3 == p1, "failed: pointer changed");
	memset(p3, 0x11, talloc_get_size(p3));

	talloc_free(pool);

	return true;
}

static bool test_pool_steal(void)
{
	void *root;
	void *pool;
	void *p1, *p2;
	void *p1_2, *p2_2;
	size_t hdr;
	size_t ofs1, ofs2;

	root = talloc_new(NULL);
	pool = talloc_pool(root, 1024);

	p1 = talloc_size(pool, 4 * 16);
	torture_assert("pool allocate 4 * 16", p1 != NULL, "failed ");
	memset(p1, 0x11, talloc_get_size(p1));
	p2 = talloc_size(pool, 4 * 16);
	torture_assert("pool allocate 4 * 16", p2 > p1, "failed: !(p2 > p1) ");
	memset(p2, 0x11, talloc_get_size(p2));

	ofs1 = PTR_DIFF(p2, p1);
	hdr = ofs1 - talloc_get_size(p1);

	talloc_steal(root, p1);
	talloc_steal(root, p2);

	talloc_free(pool);

	p1_2 = p1;

	p1_2 = talloc_realloc_size(root, p1, 5 * 16);
	torture_assert("pool realloc 5 * 16", p1_2 > p2, "failed: pointer not changed");
	memset(p1_2, 0x11, talloc_get_size(p1_2));
	ofs1 = PTR_DIFF(p1_2, p2);
	ofs2 = talloc_get_size(p2) + hdr;

	torture_assert("pool realloc ", ofs1 == ofs2, "failed: pointer offset unexpected");

	p2_2 = talloc_realloc_size(root, p2, 3 * 16);
	torture_assert("pool realloc 5 * 16", p2_2 == p2, "failed: pointer changed");
	memset(p2_2, 0x11, talloc_get_size(p2_2));

	talloc_free(p1_2);

	p2_2 = p2;

	/* now we should reclaim the full pool */
	p2_2 = talloc_realloc_size(root, p2, 8 * 16);
	torture_assert("pool realloc 8 * 16", p2_2 == p1, "failed: pointer not expected");
	p2 = p2_2;
	memset(p2_2, 0x11, talloc_get_size(p2_2));

	/* now we malloc and free the full pool space */
	p2_2 = talloc_realloc_size(root, p2, 2 * 1024);
	torture_assert("pool realloc 2 * 1024", p2_2 != p1, "failed: pointer not expected");
	memset(p2_2, 0x11, talloc_get_size(p2_2));

	talloc_free(p2_2);

	talloc_free(root);

	return true;
}

static bool test_pool_nest(void)
{
	void *p1, *p2, *p3;
	void *e = talloc_new(NULL);

	p1 = talloc_pool(NULL, 1024);
	torture_assert("talloc_pool", p1 != NULL, "failed");

	p2 = talloc_pool(p1, 500);
	torture_assert("talloc_pool", p2 != NULL, "failed");

	p3 = talloc_size(p2, 10);

	talloc_steal(e, p3);

	talloc_free(p2);

	talloc_free(p3);

	talloc_free(p1);

	talloc_free(e); /* make ASAN happy */

	return true;
}

struct pooled {
	char *s1;
	char *s2;
	char *s3;
};

static bool test_pooled_object(void)
{
	struct pooled *p;
	const char *s1 = "hello";
	const char *s2 = "world";
	const char *s3 = "";

	p = talloc_pooled_object(NULL, struct pooled, 3,
			strlen(s1)+strlen(s2)+strlen(s3)+3);

	if (talloc_get_size(p) != sizeof(struct pooled)) {
		return false;
	}

	p->s1 = talloc_strdup(p, s1);

	TALLOC_FREE(p->s1);
	p->s1 = talloc_strdup(p, s2);
	TALLOC_FREE(p->s1);

	p->s1 = talloc_strdup(p, s1);
	p->s2 = talloc_strdup(p, s2);
	p->s3 = talloc_strdup(p, s3);

	TALLOC_FREE(p);
	return true;
}

static bool test_free_ref_null_context(void)
{
	void *p1, *p2, *p3;
	int ret;

	talloc_disable_null_tracking();
	p1 = talloc_new(NULL);
	p2 = talloc_new(NULL);

	p3 = talloc_reference(p2, p1);
	torture_assert("reference", p3 == p1, "failed: reference on null");

	ret = talloc_free(p1);
	torture_assert("ref free with null parent", ret == 0, "failed: free with null parent");
	talloc_free(p2);

	talloc_enable_null_tracking_no_autofree();
	p1 = talloc_new(NULL);
	p2 = talloc_new(NULL);

	p3 = talloc_reference(p2, p1);
	torture_assert("reference", p3 == p1, "failed: reference on null");

	ret = talloc_free(p1);
	torture_assert("ref free with null tracked parent", ret == 0, "failed: free with null parent");
	talloc_free(p2);

	return true;
}

static bool test_rusty(void)
{
	void *root;
	char *p1;

	talloc_enable_null_tracking();
	root = talloc_new(NULL);
	p1 = talloc_strdup(root, "foo");
	talloc_increase_ref_count(p1);
	talloc_report_full(root, stdout);
	talloc_free(root);
	CHECK_BLOCKS("null_context", NULL, 2);
	talloc_free(p1); /* make ASAN happy */

	return true;
}

static bool test_free_children(void)
{
	void *root;
	char *p1, *p2;
	const char *name, *name2;

	talloc_enable_null_tracking();
	root = talloc_new(NULL);
	p1 = talloc_strdup(root, "foo1");
	p2 = talloc_strdup(p1, "foo2");
	(void)p2;

	talloc_set_name(p1, "%s", "testname");
	talloc_free_children(p1);
	/* check its still a valid talloc ptr */
	talloc_get_size(talloc_get_name(p1));
	if (strcmp(talloc_get_name(p1), "testname") != 0) {
		return false;
	}

	talloc_set_name(p1, "%s", "testname");
	name = talloc_get_name(p1);
	talloc_free_children(p1);
	/* check its still a valid talloc ptr */
	talloc_get_size(talloc_get_name(p1));
	torture_assert("name", name == talloc_get_name(p1), "name ptr changed");
	torture_assert("namecheck", strcmp(talloc_get_name(p1), "testname") == 0,
		       "wrong name");
	CHECK_BLOCKS("name1", p1, 2);

	/* note that this does not free the old child name */
	talloc_set_name_const(p1, "testname2");
	name2 = talloc_get_name(p1);
	/* but this does */
	talloc_free_children(p1);
	(void)name2;
	torture_assert("namecheck", strcmp(talloc_get_name(p1), "testname2") == 0,
		       "wrong name");
	CHECK_BLOCKS("name1", p1, 1);

	talloc_report_full(root, stdout);
	talloc_free(root);
	return true;
}

static bool test_memlimit(void)
{
	void *root;
	char *l1, *l2, *l3, *l4, *l5, *t;
	char *pool;
	int i;

	printf("test: memlimit\n# MEMORY LIMITS\n");

	printf("==== talloc_new(NULL)\n");
	root = talloc_new(NULL);

	talloc_report_full(root, stdout);

	printf("==== talloc_size(root, 2048)\n");
	l1 = talloc_size(root, 2048);
	torture_assert("memlimit", l1 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_free(l1)\n");
	talloc_free(l1);

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(root, level 1)\n");
	l1 = talloc_strdup(root, "level 1");
	torture_assert("memlimit", l1 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_set_memlimit(l1, 2048)\n");
	torture_assert("memlimit", talloc_set_memlimit(l1, 2048) == 0,
		"failed: setting memlimit should never fail\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_size(root, 2048)\n");
	l2 = talloc_size(l1, 2048);
	torture_assert("memlimit", l2 == NULL,
		"failed: alloc should fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(l1, level 2)\n");
	l2 = talloc_strdup(l1, "level 2");
	torture_assert("memlimit", l2 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_free(l2)\n");
	talloc_free(l2);

	talloc_report_full(root, stdout);

	printf("==== talloc_size(NULL, 2048)\n");
	l2 = talloc_size(NULL, 2048);

	talloc_report_full(root, stdout);

	printf("==== talloc_steal(l1, l2)\n");
	talloc_steal(l1, l2);

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(l2, level 3)\n");
	l3 = talloc_strdup(l2, "level 3");
	torture_assert("memlimit", l3 == NULL,
		"failed: alloc should fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_free(l2)\n");
	talloc_free(l2);

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(NULL, level 2)\n");
	l2 = talloc_strdup(NULL, "level 2");
	talloc_steal(l1, l2);

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(l2, level 3)\n");
	l3 = talloc_strdup(l2, "level 3");
	torture_assert("memlimit", l3 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_set_memlimit(l3, 1024)\n");
	torture_assert("memlimit", talloc_set_memlimit(l3, 1024) == 0,
		"failed: setting memlimit should never fail\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(l3, level 4)\n");
	l4 = talloc_strdup(l3, "level 4");
	torture_assert("memlimit", l4 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_set_memlimit(l4, 512)\n");
	torture_assert("memlimit", talloc_set_memlimit(l4, 512) == 0,
		"failed: setting memlimit should never fail\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(l4, level 5)\n");
	l5 = talloc_strdup(l4, "level 5");
	torture_assert("memlimit", l5 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_realloc(NULL, l5, char, 600)\n");
	t = talloc_realloc(NULL, l5, char, 600);
	torture_assert("memlimit", t == NULL,
		"failed: alloc should fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_realloc(NULL, l5, char, 5)\n");
	l5 = talloc_realloc(NULL, l5, char, 5);
	torture_assert("memlimit", l5 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(l3, level 4)\n");
	l4 = talloc_strdup(l3, "level 4");
	torture_assert("memlimit", l4 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_set_memlimit(l4, 512)\n");
	torture_assert("memlimit", talloc_set_memlimit(l4, 512) == 0,
		"failed: setting memlimit should never fail\n");

	talloc_report_full(root, stdout);

	printf("==== talloc_strdup(l4, level 5)\n");
	l5 = talloc_strdup(l4, "level 5");
	torture_assert("memlimit", l5 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);

	printf("==== Make new temp context and steal l5\n");
	t = talloc_new(root);
	talloc_steal(t, l5);

	talloc_report_full(root, stdout);

	printf("==== talloc_size(t, 2048)\n");
	l1 = talloc_size(t, 2048);
	torture_assert("memlimit", l1 != NULL,
		"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(root, stdout);
	talloc_free(root);

	/* Test memlimits with pools. */
	printf("==== talloc_pool(NULL, 10*1024)\n");
	pool = talloc_pool(NULL, 10*1024);
	torture_assert("memlimit", pool != NULL,
		"failed: alloc should not fail due to memory limit\n");

	printf("==== talloc_set_memlimit(pool, 10*1024)\n");
	talloc_set_memlimit(pool, 10*1024);
	for (i = 0; i < 9; i++) {
		printf("==== talloc_size(pool, 1024) %i/10\n", i + 1);
		l1 = talloc_size(pool, 1024);
		torture_assert("memlimit", l1 != NULL,
			"failed: alloc should not fail due to memory limit\n");
		talloc_report_full(pool, stdout);
	}
	/* The next alloc should fail. */
	printf("==== talloc_size(pool, 1024) 10/10\n");
	l2 = talloc_size(pool, 1024);
	torture_assert("memlimit", l2 == NULL,
			"failed: alloc should fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	/* Moving one of the children shouldn't change the limit,
	   as it's still inside the pool. */

	printf("==== talloc_new(NULL)\n");
	root = talloc_new(NULL);

	printf("==== talloc_steal(root, l1)\n");
	talloc_steal(root, l1);

	printf("==== talloc_size(pool, 1024)\n");
	l2 = talloc_size(pool, 1024);
	torture_assert("memlimit", l2 == NULL,
			"failed: alloc should fail due to memory limit\n");

	printf("==== talloc_free_children(pool)\n");
	talloc_free(l1);
	talloc_free_children(pool);

	printf("==== talloc_size(pool, 1024)\n");
	l1 = talloc_size(pool, 1024);

	/* try reallocs of increasing size */
	for (i = 1; i < 9; i++) {
		printf("==== talloc_realloc_size(NULL, l1, %i*1024) %i/10\n", i, i + 1);
		l1 = talloc_realloc_size(NULL, l1, i*1024);
		torture_assert("memlimit", l1 != NULL,
			"failed: realloc should not fail due to memory limit\n");
		talloc_report_full(pool, stdout);
	}
	/* The next alloc should fail. */
	printf("==== talloc_realloc_size(NULL, l1, 10*1024) 10/10\n");
	l2 = talloc_realloc_size(NULL, l1, 10*1024);
	torture_assert("memlimit", l2 == NULL,
			"failed: realloc should fail due to memory limit\n");

	/* Increase the memlimit */
	printf("==== talloc_set_memlimit(pool, 11*1024)\n");
	talloc_set_memlimit(pool, 11*1024);

	/* The final realloc should still fail
	   as the entire realloced chunk needs to be moved out of the pool */
	printf("==== talloc_realloc_size(NULL, l1, 10*1024) 10/10\n");
	l2 = talloc_realloc_size(NULL, l1, 10*1024);
	torture_assert("memlimit", l2 == NULL,
			"failed: realloc should fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	printf("==== talloc_set_memlimit(pool, 21*1024)\n");
	talloc_set_memlimit(pool, 21*1024);

	/* There's now sufficient space to move the chunk out of the pool */
	printf("==== talloc_realloc_size(NULL, l1, 10*1024) 10/10\n");
	l2 = talloc_realloc_size(NULL, l1, 10*1024);
	torture_assert("memlimit", l2 != NULL,
			"failed: realloc should not fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	/* ...which should mean smaller allocations can now occur within the pool */
	printf("==== talloc_size(pool, 9*1024)\n");
	l1 = talloc_size(pool, 9*1024);
	torture_assert("memlimit", l1 != NULL,
			"failed: new allocations should be allowed in the pool\n");

	talloc_report_full(pool, stdout);

	/* But reallocs bigger than the pool will still fail */
	printf("==== talloc_realloc_size(NULL, l1, 10*1024)\n");
	l2 = talloc_realloc_size(NULL, l1, 10*1024);
	torture_assert("memlimit", l2 == NULL,
			"failed: realloc should fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	/* ..as well as allocs */
	printf("==== talloc_size(pool, 1024)\n");
	l1 = talloc_size(pool, 1024);
	torture_assert("memlimit", l1 == NULL,
			"failed: alloc should fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	printf("==== talloc_free_children(pool)\n");
	talloc_free_children(pool);

	printf("==== talloc_set_memlimit(pool, 1024)\n");
	talloc_set_memlimit(pool, 1024);

	/* We should still be able to allocate up to the pool limit
	   because the memlimit only applies to new heap allocations */
	printf("==== talloc_size(pool, 9*1024)\n");
	l1 = talloc_size(pool, 9*1024);
	torture_assert("memlimit", l1 != NULL,
			"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	l1 = talloc_size(pool, 1024);
	torture_assert("memlimit", l1 == NULL,
			"failed: alloc should fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	printf("==== talloc_free_children(pool)\n");
	talloc_free_children(pool);

	printf("==== talloc_set_memlimit(pool, 10*1024)\n");
	talloc_set_memlimit(pool, 10*1024);

	printf("==== talloc_size(pool, 1024)\n");
	l1 = talloc_size(pool, 1024);
	torture_assert("memlimit", l1 != NULL,
			"failed: alloc should not fail due to memory limit\n");

	talloc_report_full(pool, stdout);

	talloc_free(pool);
	talloc_free(root);
	printf("success: memlimit\n");

	return true;
}

#ifdef HAVE_PTHREAD

#define NUM_THREADS 100

/* Sync variables. */
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condvar = PTHREAD_COND_INITIALIZER;
static void *intermediate_ptr;

/* Subthread. */
static void *thread_fn(void *arg)
{
	int ret;
	const char *ctx_name = (const char *)arg;
	void *sub_ctx = NULL;
	/*
	 * Do stuff that creates a new talloc hierarchy in
	 * this thread.
	 */
	void *top_ctx = talloc_named_const(NULL, 0, "top");
	if (top_ctx == NULL) {
		return NULL;
	}
	sub_ctx = talloc_named_const(top_ctx, 100, ctx_name);
	if (sub_ctx == NULL) {
		return NULL;
	}

	/*
	 * Now transfer a pointer from our hierarchy
	 * onto the intermediate ptr.
	 */
	ret = pthread_mutex_lock(&mtx);
	if (ret != 0) {
		talloc_free(top_ctx);
		return NULL;
	}
	/* Wait for intermediate_ptr to be free. */
	while (intermediate_ptr != NULL) {
		ret = pthread_cond_wait(&condvar, &mtx);
		if (ret != 0) {
			talloc_free(top_ctx);
			ret = pthread_mutex_unlock(&mtx);
			assert(ret == 0);
			return NULL;
		}
	}

	/* and move our memory onto it from our toplevel hierarchy. */
	intermediate_ptr = talloc_move(NULL, &sub_ctx);

	/* Tell the main thread it's ready for pickup. */
	pthread_cond_broadcast(&condvar);
	ret = pthread_mutex_unlock(&mtx);
	assert(ret == 0);

	talloc_free(top_ctx);
	return NULL;
}

/* Main thread. */
static bool test_pthread_talloc_passing(void)
{
	int i;
	int ret;
	char str_array[NUM_THREADS][20];
	pthread_t thread_id;
	void *mem_ctx;

	/*
	 * Important ! Null tracking breaks threaded talloc.
	 * It *must* be turned off.
	 */
	talloc_disable_null_tracking();

	printf("test: pthread_talloc_passing\n# PTHREAD TALLOC PASSING\n");

	/* Main thread toplevel context. */
	mem_ctx = talloc_named_const(NULL, 0, "toplevel");
	if (mem_ctx == NULL) {
		printf("failed to create toplevel context\n");
		return false;
	}

	/*
	 * Spin off NUM_THREADS threads.
	 * They will use their own toplevel contexts.
	 */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = snprintf(str_array[i],
			       20,
			       "thread:%d",
			       i);
		if (ret < 0) {
			printf("snprintf %d failed\n", i);
			return false;
		}
		ret = pthread_create(&thread_id,
				NULL,
				thread_fn,
				str_array[i]);
		if (ret != 0) {
			printf("failed to create thread %d (%d)\n", i, ret);
			return false;
		}
	}

	printf("Created %d threads\n", NUM_THREADS);

	/* Now wait for NUM_THREADS transfers of the talloc'ed memory. */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = pthread_mutex_lock(&mtx);
		if (ret != 0) {
			printf("pthread_mutex_lock %d failed (%d)\n", i, ret);
			talloc_free(mem_ctx);
			return false;
		}

		/* Wait for intermediate_ptr to have our data. */
		while (intermediate_ptr == NULL) {
			ret = pthread_cond_wait(&condvar, &mtx);
			if (ret != 0) {
				printf("pthread_cond_wait %d failed (%d)\n", i,
					ret);
				talloc_free(mem_ctx);
				ret = pthread_mutex_unlock(&mtx);
				assert(ret == 0);
			}
		}

		/* and move it onto our toplevel hierarchy. */
		(void)talloc_move(mem_ctx, &intermediate_ptr);

		/* Tell the sub-threads we're ready for another. */
		pthread_cond_broadcast(&condvar);
		ret = pthread_mutex_unlock(&mtx);
		assert(ret == 0);
	}

	CHECK_SIZE("pthread_talloc_passing", mem_ctx, NUM_THREADS * 100);
#if 1
	/* Dump the hierarchy. */
	talloc_report(mem_ctx, stdout);
#endif
	talloc_free(mem_ctx);
	printf("success: pthread_talloc_passing\n");
	return true;
}
#endif

static void test_magic_protection_abort(const char *reason)
{
	/* exit with errcode 42 to communicate successful test to the parent process */
	if (strcmp(reason, "Bad talloc magic value - unknown value") == 0) {
		_exit(42);
	} else {
		printf("talloc aborted for an unexpected reason\n");
	}
}

static int test_magic_protection_destructor(int *ptr)
{
	_exit(404); /* Not 42 */
}

static bool test_magic_protection(void)
{
	void *pool = talloc_pool(NULL, 1024);
	int *p1, *p2;
	pid_t pid;
	int exit_status;

	printf("test: magic_protection\n");
	p1 = talloc(pool, int);
	p2 = talloc(pool, int);

	/* To avoid complaints from the compiler assign values to the p1 & p2. */
	*p1 = 6;
	*p2 = 9;

	pid = fork();
	if (pid == 0) {
		talloc_set_abort_fn(test_magic_protection_abort);
		talloc_set_destructor(p2, test_magic_protection_destructor);

		/*
		 * Simulate a security attack
		 * by triggering a buffer overflow in memset to overwrite the
		 * constructor in the next pool chunk.
		 *
		 * Real attacks would attempt to set a real destructor.
		 */
		BURN_PTR_SIZE(p1, 32);

		/* Then the attack takes effect when the memory's freed. */
		talloc_free(pool);

		/* Never reached. Make compilers happy */
		return true;
	}

	while (wait(&exit_status) != pid);

	talloc_free(pool); /* make ASAN happy */

	if (!WIFEXITED(exit_status)) {
		printf("Child exited through unexpected abnormal means\n");
		return false;
	}
	if (WEXITSTATUS(exit_status) != 42) {
		printf("Child exited with wrong exit status\n");
		return false;
	}
	if (WIFSIGNALED(exit_status)) {
		printf("Child received unexpected signal\n");
		return false;
	}

	printf("success: magic_protection\n");
	return true;
}

static void test_magic_free_protection_abort(const char *reason)
{
	/* exit with errcode 42 to communicate successful test to the parent process */
	if (strcmp(reason, "Bad talloc magic value - access after free") == 0) {
		_exit(42);
	}
	/* not 42 */
	_exit(404);
}

static bool test_magic_free_protection(void)
{
	void *pool = talloc_pool(NULL, 1024);
	int *p1, *p2, *p3;
	pid_t pid;
	int exit_status;

	printf("test: magic_free_protection\n");
	p1 = talloc(pool, int);
	p2 = talloc(pool, int);

	/* To avoid complaints from the compiler assign values to the p1 & p2. */
	*p1 = 6;
	*p2 = 9;

	p3 = talloc_realloc(pool, p2, int, 2048);
	torture_assert("pool realloc 2048",
		       p3 != p2,
		       "failed: pointer not changed");

	/*
	 * Now access the memory in the pool after the realloc().  It
	 * should be marked as free, so use of the old pointer should
	 * trigger the abort function
	 */
	pid = fork();
	if (pid == 0) {
		talloc_set_abort_fn(test_magic_free_protection_abort);

		talloc_get_name(p2);

		/* Never reached. Make compilers happy */
		return true;
	}

	while (wait(&exit_status) != pid);

	if (!WIFEXITED(exit_status)) {
		printf("Child exited through unexpected abnormal means\n");
		return false;
	}
	if (WEXITSTATUS(exit_status) != 42) {
		printf("Child exited with wrong exit status\n");
		return false;
	}
	if (WIFSIGNALED(exit_status)) {
		printf("Child received unexpected signal\n");
		return false;
	}

	talloc_free(pool);

	printf("success: magic_free_protection\n");
	return true;
}

static void test_reset(void)
{
	talloc_set_log_fn(test_log_stdout);
	test_abort_stop();
	talloc_disable_null_tracking();
	talloc_enable_null_tracking_no_autofree();
}

bool torture_local_talloc(struct torture_context *tctx)
{
	bool ret = true;

	setlinebuf(stdout);

	test_reset();
	ret &= test_pooled_object();
	test_reset();
	ret &= test_pool_nest();
	test_reset();
	ret &= test_ref1();
	test_reset();
	ret &= test_ref2();
	test_reset();
	ret &= test_ref3();
	test_reset();
	ret &= test_ref4();
	test_reset();
	ret &= test_unlink1();
	test_reset();
	ret &= test_misc();
	test_reset();
	ret &= test_realloc();
	test_reset();
	ret &= test_realloc_child();
	test_reset();
	ret &= test_steal();
	test_reset();
	ret &= test_move();
	test_reset();
	ret &= test_unref_reparent();
	test_reset();
	ret &= test_realloc_fn();
	test_reset();
	ret &= test_type();
	test_reset();
	ret &= test_lifeless();
	test_reset();
	ret &= test_loop();
	test_reset();
	ret &= test_free_parent_deny_child();
	test_reset();
	ret &= test_realloc_on_destructor_parent();
	test_reset();
	ret &= test_free_parent_reparent_child();
	test_reset();
	ret &= test_free_parent_reparent_child_in_pool();
	test_reset();
	ret &= test_talloc_ptrtype();
	test_reset();
	ret &= test_talloc_free_in_destructor();
	test_reset();
	ret &= test_pool();
	test_reset();
	ret &= test_pool_steal();
	test_reset();
	ret &= test_free_ref_null_context();
	test_reset();
	ret &= test_rusty();
	test_reset();
	ret &= test_free_children();
	test_reset();
	ret &= test_memlimit();
#ifdef HAVE_PTHREAD
	test_reset();
	ret &= test_pthread_talloc_passing();
#endif


	if (ret) {
		test_reset();
		ret &= test_speed();
	}
	test_reset();
	ret &= test_autofree();
	test_reset();
	ret &= test_magic_protection();
	test_reset();
	ret &= test_magic_free_protection();

	test_reset();
	talloc_disable_null_tracking();
	return ret;
}
