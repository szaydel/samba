/* 
   Unix SMB/CIFS implementation.
   test suite for the charcnv functions

   Copyright (C) Jelmer Vernooij 2007
   
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

#undef strcasecmp
#undef strncasecmp

struct torture_suite *torture_local_charset(TALLOC_CTX *mem_ctx);

static bool test_toupper_m(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, toupper_m('c'), 'C', "c");
	torture_assert_int_equal(tctx, toupper_m('Z'), 'Z', "z");
	torture_assert_int_equal(tctx, toupper_m(0xFFFF4565), 0xFFFF4565, "0xFFFF4565");
	return true;
}

static bool test_tolower_m(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, tolower_m('C'), 'c', "c");
	torture_assert_int_equal(tctx, tolower_m('z'), 'z', "z");
	torture_assert_int_equal(tctx, tolower_m(0xFFFF4565), 0xFFFF4565, "0xFFFF4565");
	return true;
}

static bool test_codepoint_cmpi(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, codepoint_cmpi('a', 'a'), 0, "same char");
	torture_assert_int_equal(tctx, codepoint_cmpi('A', 'a'), 0, "upcase version");
	torture_assert_int_equal(tctx, codepoint_cmpi('b', 'a'), 1, "right diff");
	torture_assert_int_equal(tctx, codepoint_cmpi('b', 'A'), 1, "left greater, mixed case");
	torture_assert_int_equal(tctx, codepoint_cmpi('C', 'a'), 1, "left greater, mixed case");
	torture_assert_int_equal(tctx, codepoint_cmpi('a', 'b'), -1, "right greater");
	torture_assert_int_equal(tctx, codepoint_cmpi('A', 'B'), -1, "right greater, upper case");
	torture_assert_int_equal(tctx, codepoint_cmpi(0xc5, 0xc5), 0,
				 "Latin Capital Letter A with Ring Above");
	torture_assert_int_equal(tctx, codepoint_cmpi(0xc5, 0xe5), 0,
				 "Latin both Letter A with Ring Above, lower right");
	torture_assert_int_equal(tctx, codepoint_cmpi(0xe5, 0xde), -1,
				 "å < Þ");
	return true;
}

static bool test_strcasecmp(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, strcasecmp("foo", "bar"), 4, "different strings both lower");
	torture_assert_int_equal(tctx, strcasecmp("foo", "Bar"), 4, "different strings lower/upper");
	torture_assert_int_equal(tctx, strcasecmp("Foo", "bar"), 4, "different strings upper/lower");
	torture_assert_int_equal(tctx, strcasecmp("AFoo", "_bar"), 2, "different strings upper/lower");
	torture_assert_int_equal(tctx, strcasecmp("foo", "foo"), 0, "same case strings");
	torture_assert_int_equal(tctx, strcasecmp("foo", "Foo"), 0, "different case strings");

	/*
	 * Note that strcasecmp() doesn't allow NULL arguments
	 */
	return true;
}

static bool test_strcasecmp_m(struct torture_context *tctx)
{
	/* file.{accented e} in iso8859-1 */
	const char file_iso8859_1[7] = { 0x66, 0x69, 0x6c, 0x65, 0x2d, 0xe9, 0 };
	/* file.{accented e} in utf8 */
	const char file_utf8[8] =      { 0x66, 0x69, 0x6c, 0x65, 0x2d, 0xc3, 0xa9, 0 };
	torture_assert_int_greater(tctx, strcasecmp_m("foo", "bar"), 0, "different strings both lower");
	torture_assert_int_less(tctx, strcasecmp_m("bar", "foo"), 0, "different strings both lower");
	torture_assert_int_greater(tctx, strcasecmp_m("foo", "Bar"), 0, "different strings lower/upper");
	torture_assert_int_greater(tctx, strcasecmp_m("Foo", "bar"), 0, "different strings upper/lower");
	torture_assert_int_greater(tctx, strcasecmp_m("AFoo", "_bar"), 0, "different strings upper/lower");
	torture_assert_int_equal(tctx, strcasecmp_m("foo", "foo"), 0, "same case strings");
	torture_assert_int_equal(tctx, strcasecmp_m("foo", "Foo"), 0, "different case strings");
	torture_assert_int_greater(tctx, strcasecmp_m("food", "Foo"), 0, "strings differ towards the end");
	torture_assert_int_less(tctx, strcasecmp_m("food", "Fool"), 0, "strings differ towards the end");
	torture_assert_int_less(tctx, strcasecmp_m(NULL, "Foo"),  0, "one NULL");
	torture_assert_int_greater(tctx, strcasecmp_m("foo", NULL),  0, "other NULL");
	torture_assert_int_equal(tctx, strcasecmp_m(NULL, NULL),   0, "both NULL");
	torture_assert_int_greater(tctx, strcasecmp_m(file_iso8859_1, file_utf8), 0,
		"file.{accented e} should differ");
	return true;
}


static bool test_strequal_m(struct torture_context *tctx)
{
	torture_assert(tctx, !strequal_m("foo", "bar"), "different strings");
	torture_assert(tctx, strequal_m("foo", "foo"), "same case strings");
	torture_assert(tctx, strequal_m("foo", "Foo"), "different case strings");
	torture_assert(tctx, !strequal_m(NULL, "Foo"), "one NULL");
	torture_assert(tctx, !strequal_m("foo", NULL), "other NULL");
	torture_assert(tctx, strequal_m(NULL, NULL), "both NULL");
	return true;
}

static bool test_strcsequal(struct torture_context *tctx)
{
	torture_assert(tctx, !strcsequal("foo", "bar"), "different strings");
	torture_assert(tctx, strcsequal("foo", "foo"), "same case strings");
	torture_assert(tctx, !strcsequal("foo", "Foo"), "different case strings");
	torture_assert(tctx, !strcsequal(NULL, "Foo"), "one NULL");
	torture_assert(tctx, !strcsequal("foo", NULL), "other NULL");
	torture_assert(tctx, strcsequal(NULL, NULL), "both NULL");
	return true;
}

static bool test_string_replace_m(struct torture_context *tctx)
{
	char data[6] = "bla";
	string_replace_m(data, 'b', 'c');
	torture_assert_str_equal(tctx, data, "cla", "first char replaced");
	memcpy(data, "bab", 4);
	string_replace_m(data, 'b', 'c');
	torture_assert_str_equal(tctx, data, "cac", "other chars replaced");
	memcpy(data, "bba", 4);
	string_replace_m(data, 'b', 'c');
	torture_assert_str_equal(tctx, data, "cca", "other chars replaced");
	memcpy(data, "blala", 6);
	string_replace_m(data, 'o', 'c');
	torture_assert_str_equal(tctx, data, "blala", "no chars replaced");
	string_replace_m(NULL, 'b', 'c');
	return true;
}

static bool test_strncasecmp(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, strncasecmp("foo", "bar", 3), 4, "different strings both lower");
	torture_assert_int_equal(tctx, strncasecmp("foo", "Bar", 3), 4, "different strings lower/upper");
	torture_assert_int_equal(tctx, strncasecmp("Foo", "bar", 3), 4, "different strings upper/lower");
	torture_assert_int_equal(tctx, strncasecmp("AFoo", "_bar", 4), 2, "different strings upper/lower");
	torture_assert_int_equal(tctx, strncasecmp("foo", "foo", 3), 0, "same case strings");
	torture_assert_int_equal(tctx, strncasecmp("foo", "Foo", 3), 0, "different case strings");
	torture_assert_int_equal(tctx, strncasecmp("fool", "Foo", 3),0, "different case strings");
	torture_assert_int_equal(tctx, strncasecmp("fool", "Fool", 40), 0, "over size");
	torture_assert_int_equal(tctx, strncasecmp("BLA", "Fool", 0),0, "empty");

	/*
	 * Note that strncasecmp() doesn't allow NULL arguments
	 */
	return true;
}

static bool test_strncasecmp_m(struct torture_context *tctx)
{
	/* file.{accented e} in iso8859-1 */
	const char file_iso8859_1[7] = { 0x66, 0x69, 0x6c, 0x65, 0x2d, 0xe9, 0 };
	/* file.{accented e} in utf8 */
	const char file_utf8[8] =      { 0x66, 0x69, 0x6c, 0x65, 0x2d, 0xc3, 0xa9, 0 };
	torture_assert_int_greater(tctx, strncasecmp_m("foo", "bar", 3), 0, "different strings both lower");
	torture_assert_int_greater(tctx, strncasecmp_m("foo", "Bar", 3), 0, "different strings lower/upper");
	torture_assert_int_greater(tctx, strncasecmp_m("Foo", "bar", 3), 0, "different strings upper/lower");
	torture_assert_int_greater(tctx, strncasecmp_m("AFoo", "_bar", 4), 0, "different strings upper/lower");
	torture_assert_int_equal(tctx, strncasecmp_m("foo", "foo", 3), 0, "same case strings");
	torture_assert_int_equal(tctx, strncasecmp_m("foo", "Foo", 3), 0, "different case strings");
	torture_assert_int_equal(tctx, strncasecmp_m("fool", "Foo", 3),0, "different case strings");
	torture_assert_int_equal(tctx, strncasecmp_m("fool", "Fool", 40), 0, "over size");
	torture_assert_int_equal(tctx, strncasecmp_m("BLA", "Fool", 0),0, "empty");
	torture_assert_int_less(tctx, strncasecmp_m(NULL, "Foo", 3),  0, "one NULL");
	torture_assert_int_greater(tctx, strncasecmp_m("foo", NULL, 3),  0, "other NULL");
	torture_assert_int_equal(tctx, strncasecmp_m(NULL, NULL, 3),   0, "both NULL");
	torture_assert_int_greater(tctx, strncasecmp_m(file_iso8859_1, file_utf8, 6), 0,
		"file.{accented e} should differ");
	return true;
}

static bool test_next_token_null(struct torture_context *tctx)
{
	char *buf = NULL;
	torture_assert(tctx,
		       !next_token_talloc(tctx, NULL, &buf, " "),
		       "null ptr works");
	return true;
}

static bool test_next_token(struct torture_context *tctx)
{
	const char *teststr = "foo bar bla";
	char *buf = NULL;
	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "foo", "token matches");
	torture_assert_str_equal(tctx, teststr, "bar bla", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "bar", "token matches");
	torture_assert_str_equal(tctx, teststr, "bla", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "bla", "token matches");
	torture_assert_str_equal(tctx, teststr, "", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       !next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token doesn't work");
	return true;
}

static bool test_next_token_implicit_sep(struct torture_context *tctx)
{
	const char *teststr = "foo\tbar\n bla";
	char *buf = NULL;

	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, NULL),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "foo", "token matches");
	torture_assert_str_equal(tctx, teststr, "bar\n bla", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, NULL),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "bar", "token matches");
	torture_assert_str_equal(tctx, teststr, " bla", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, NULL),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "bla", "token matches");
	torture_assert_str_equal(tctx, teststr, "", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       !next_token_talloc(tctx, &teststr, &buf, NULL),
		       "finding token doesn't work");
	return true;
}

static bool test_next_token_seps(struct torture_context *tctx)
{
	const char *teststr = ",foo bla";
	char *buf = NULL;
	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, ","),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "foo bla", "token matches");
	torture_assert_str_equal(tctx, teststr, "", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       !next_token_talloc(tctx, &teststr, &buf, ","),
		       "finding token doesn't work");
	return true;
}

static bool test_next_token_quotes(struct torture_context *tctx)
{
	const char *teststr = "\"foo bar\" bla";
	char *buf = NULL;
	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "foo bar", "token matches");
	torture_assert_str_equal(tctx, teststr, "bla", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "bla", "token matches");
	torture_assert_str_equal(tctx, teststr, "", "ptr modified correctly");
	TALLOC_FREE(buf);

	torture_assert(tctx,
		       !next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token doesn't work");
	return true;
}

static bool test_next_token_quote_wrong(struct torture_context *tctx)
{
	const char *teststr = "\"foo bar bla";
	char *buf = NULL;
	torture_assert(tctx,
		       next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token works");
	torture_assert_str_equal(tctx, buf, "foo bar bla", "token matches");
	torture_assert_str_equal(tctx, teststr, "", "ptr modified correctly");

	torture_assert(tctx,
		       !next_token_talloc(tctx, &teststr, &buf, " "),
		       "finding token doesn't work");
	return true;
}

static bool test_strlen_m(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, strlen_m("foo"), 3, "simple len");
	torture_assert_int_equal(tctx, strlen_m("foo\x83l"), 6, "extended len");
	torture_assert_int_equal(tctx, strlen_m(""), 0, "empty");
	torture_assert_int_equal(tctx, strlen_m(NULL), 0, "NULL");
	return true;
}

static bool test_strlen_m_term(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, strlen_m_term("foo"), 4, "simple len");
	torture_assert_int_equal(tctx, strlen_m_term("foo\x83l"), 7, "extended len");
	torture_assert_int_equal(tctx, strlen_m_term(""), 1, "empty");
	torture_assert_int_equal(tctx, strlen_m_term(NULL), 0, "NULL");
	return true;
}

static bool test_strlen_m_term_null(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, strlen_m_term_null("foo"), 4, "simple len");
	torture_assert_int_equal(tctx, strlen_m_term_null("foo\x83l"), 7, "extended len");
	torture_assert_int_equal(tctx, strlen_m_term_null(""), 0, "empty");
	torture_assert_int_equal(tctx, strlen_m_term_null(NULL), 0, "NULL");
	return true;
}

static bool test_strhaslower(struct torture_context *tctx)
{
	torture_assert(tctx, strhaslower("a"), "one low char");
	torture_assert(tctx, strhaslower("aB"), "one low, one up char");
	torture_assert(tctx, !strhaslower("B"), "one up char");
	torture_assert(tctx, !strhaslower(""), "empty string");
	torture_assert(tctx, !strhaslower("3"), "one digit");
	return true;
}

static bool test_strhasupper(struct torture_context *tctx)
{
	torture_assert(tctx, strhasupper("B"), "one up char");
	torture_assert(tctx, strhasupper("aB"), "one low, one up char");
	torture_assert(tctx, !strhasupper("a"), "one low char");
	torture_assert(tctx, !strhasupper(""), "empty string");
	torture_assert(tctx, !strhasupper("3"), "one digit");
	return true;
}

static bool test_count_chars_m(struct torture_context *tctx)
{
	torture_assert_int_equal(tctx, count_chars_m("foo", 'o'), 2, "simple");
	torture_assert_int_equal(tctx, count_chars_m("", 'o'), 0, "empty");
	torture_assert_int_equal(tctx, count_chars_m("bla", 'o'), 0, "none");
	torture_assert_int_equal(tctx, count_chars_m("bla", '\0'), 0, "null");
	return true;
}

struct torture_suite *torture_local_charset(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "charset");

	torture_suite_add_simple_test(suite, "toupper_m", test_toupper_m);
	torture_suite_add_simple_test(suite, "tolower_m", test_tolower_m);
	torture_suite_add_simple_test(suite, "codepoint_cmpi", test_codepoint_cmpi);
	torture_suite_add_simple_test(suite, "strcasecmp", test_strcasecmp);
	torture_suite_add_simple_test(suite, "strcasecmp_m", test_strcasecmp_m);
	torture_suite_add_simple_test(suite, "strequal_m", test_strequal_m);
	torture_suite_add_simple_test(suite, "strcsequal", test_strcsequal);
	torture_suite_add_simple_test(suite, "string_replace_m", test_string_replace_m);
	torture_suite_add_simple_test(suite, "strncasecmp", test_strncasecmp);
	torture_suite_add_simple_test(suite, "strncasecmp_m", test_strncasecmp_m);
	torture_suite_add_simple_test(suite, "next_token", test_next_token);
	torture_suite_add_simple_test(suite, "next_token_null", test_next_token_null);
	torture_suite_add_simple_test(suite, "next_token_implicit_sep", test_next_token_implicit_sep);
	torture_suite_add_simple_test(suite, "next_token_quotes", test_next_token_quotes);
	torture_suite_add_simple_test(suite, "next_token_seps", test_next_token_seps);
	torture_suite_add_simple_test(suite, "next_token_quote_wrong", test_next_token_quote_wrong);
	torture_suite_add_simple_test(suite, "strlen_m", test_strlen_m);
	torture_suite_add_simple_test(suite, "strlen_m_term", test_strlen_m_term);
	torture_suite_add_simple_test(suite, "strlen_m_term_null", test_strlen_m_term_null);
	torture_suite_add_simple_test(suite, "strhaslower", test_strhaslower);
	torture_suite_add_simple_test(suite, "strhasupper", test_strhasupper);
	torture_suite_add_simple_test(suite, "count_chars_m", test_count_chars_m);

	return suite;
}
