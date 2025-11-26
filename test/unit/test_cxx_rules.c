// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz-minunit.h"
#include "../../src/cplusplus/v3.h"

int test_rule_prefix() {
	CpDemOptions options = {};
	mu_assert_streq_free(demangle_rule("DC1a2abE", rule_prefix, options), "aab", "");
	mu_assert_streq_free(demangle_rule("DC1a2bcEDC1d2efE", rule_prefix, options), "abcdef", "");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rule_prefix);
	return tests_passed != tests_run;
}

mu_main(all_tests);
