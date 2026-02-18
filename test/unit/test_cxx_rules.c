// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz-minunit.h"
#include "../../src/cplusplus/v3/v3.h"
#include "../../src/cplusplus/demangle.h"

/**
 * Regression test for heap-buffer-overflow in parse_base36.
 *
 * parse_base36() used to read p->cur[sz] without checking whether
 * p->cur + sz < p->end, causing an out-of-bounds read when the
 * mangled input ends with base36 characters (0-9, A-Z) inside a
 * substitution reference (e.g. "S0" without a trailing "_").
 *
 * Additionally, strchr(base, '\0') returns non-NULL (it matches the
 * NUL terminator of the base string), so even encountering '\0' at
 * the buffer boundary did not stop the loop.
 *
 * These inputs must be handled gracefully (return NULL) without
 * reading past the buffer.
 */
bool test_parse_base36_oob(void) {
	// "NS0" -> rule_type -> rule_class_enum_type -> rule_name ->
	//   rule_nested_name (N) -> rule_substitution (S) ->
	//   parse_seq_id -> parse_base36 reads "0" then would read OOB.
	char *r = cp_demangle_v3_type("NS0", DEM_OPT_ALL);
	mu_assert_null(r, "NS0 should fail gracefully");

	// Substitution ref ending with uppercase base36 chars
	r = cp_demangle_v3_type("NSA", DEM_OPT_ALL);
	mu_assert_null(r, "NSA should fail gracefully");

	// Multiple base36 digits running to end of string
	r = cp_demangle_v3_type("NS1Z", DEM_OPT_ALL);
	mu_assert_null(r, "NS1Z should fail gracefully");

	// Bare substitution at top level
	r = cp_demangle_v3_type("S0", DEM_OPT_ALL);
	mu_assert_null(r, "S0 should fail gracefully");

	// Also test via cp_demangle (the full entry point, tries v3 type as fallback)
	r = cp_demangle("S0", DEM_OPT_ALL);
	mu_assert_null(r, "cp_demangle S0 should fail gracefully");

	r = cp_demangle("NS0", DEM_OPT_ALL);
	mu_assert_null(r, "cp_demangle NS0 should fail gracefully");

	mu_end;
}

int all_tests() {
	mu_run_test(test_parse_base36_oob);

	return tests_passed != tests_run;
}

mu_main(all_tests);
