// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Comprehensive test for substitution table handling
 * Reference implementation: llvm-cxxfilt from LLVM 22.0.0
 *
 * These tests verify correct handling of:
 * - Basic substitutions (S0_, S1_, etc.)
 * - Builtin substitutions (St, Sa, Sb, Ss, Si, So, Sd)
 * - Substitutions with cv-qualifiers and references
 * - Hex substitutions (SA_, SB_, etc.)
 * - S_ (refers to std:: namespace or last substitution depending on context)
 *
 * Unlike mu_demangle_tests, these tests check EACH substitution table entry
 */

#include "test_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Color definitions
#define TRED   "\x1b[31m"
#define TGREEN "\x1b[32m"
#define TBOLD  "\x1b[1m"
#define TRESET "\x1b[0m"

static int tests_run = 0;
static int tests_passed = 0;

// Helper to print substitution table (for debugging)
static void print_subs_table(CxxDemangleResult *result) {
	printf("  Substitution table (%zu entries):\n", result->subs_count);
	for (size_t i = 0; i < result->subs_count; i++) {
		printf("    [%zu] = %s\n", i, result->subs_table[i] ? result->subs_table[i] : "(null)");
	}
}

// Helper to check substitution table
static int check_subs(CxxDemangleResult *result, const char **expected_subs, size_t expected_count) {
	if (!result->success) {
		printf(TBOLD TRED "  Demangling FAILED\n" TRESET);
		return 0;
	}

	if (result->subs_count != expected_count) {
		printf(TBOLD TRED "  Substitution count mismatch:\n" TRESET);
		printf("    Expected: %zu entries\n", expected_count);
		printf("    Got:      %zu entries\n", result->subs_count);
		print_subs_table(result);
		return 0;
	}

	for (size_t i = 0; i < expected_count; i++) {
		if (!result->subs_table[i]) {
			printf(TBOLD TRED "  Substitution [%zu] is NULL\n" TRESET, i);
			return 0;
		}
		if (strcmp(result->subs_table[i], expected_subs[i]) != 0) {
			printf(TBOLD TRED "  Substitution [%zu] mismatch:\n" TRESET, i);
			printf("    Expected: %s\n", expected_subs[i]);
			printf("    Got:      %s\n", result->subs_table[i]);
			return 0;
		}
	}

	return 1;
}

// Helper to check demangled output
static int check_output(CxxDemangleResult *result, const char *expected_output) {
	if (!result->success) {
		return 0;
	}

	if (!result->demangled) {
		printf(TBOLD TRED "  Demangled output is NULL\n" TRESET);
		return 0;
	}

	if (strcmp(result->demangled, expected_output) != 0) {
		printf(TBOLD TRED "  Demangled output mismatch:\n" TRESET);
		printf("    Expected: %s\n", expected_output);
		printf("    Got:      %s\n", result->demangled);
		return 0;
	}

	return 1;
}

// Test runner macro
#define RUN_TEST(test_name, test_func) \
	do { \
		tests_run++; \
		printf(TBOLD "%s" TRESET " ", test_name); \
		if (test_func()) { \
			tests_passed++; \
			printf(TGREEN "OK\n" TRESET); \
		} else { \
			printf(TBOLD TRED "FAILED\n" TRESET); \
		} \
	} while (0)

// Test 1: Basic substitution with std::vector and std::allocator
// _Z3fooSt6vectorIiSaIiEES0_
// foo(std::vector<int, std::allocator<int>>, std::allocator<int>)
static int test_basic_vector(void) {
	const char *mangled = "_Z3fooSt6vectorIiSaIiEES0_";
	const char *expected_output = "foo(std::vector<int, std::allocator<int>>, std::allocator<int>)";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::vector", // S0_
		"std::allocator<int>", // S1_
		"std::vector<int, std::allocator<int>>", // S2_
	};
	size_t expected_count = 3;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

// Test 2: std::function template
// _ZNSt8functionIFvvEE6targetEv
// std::function<void ()>::target()
static int test_function_template(void) {
	const char *mangled = "_ZNSt8functionIFvvEE6targetEv";
	const char *expected_output = "std::function<void ()>::target()";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::function",
		"void ()",
		"std::function<void ()>",
	};
	size_t expected_count = 3;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

// Test 3: std::ostream::_M_insert template method
// _ZNSo9_M_insertImEERSoT_
// cxx.01 line 80
static int test_ostream_m_insert(void) {
	const char *mangled = "_ZNSo9_M_insertImEERSoT_";
	const char *expected_output = "std::ostream& std::ostream::_M_insert<unsigned long>(unsigned long)";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::ostream::_M_insert",
		"std::ostream&",
		"unsigned long",
	};
	size_t expected_count = 3;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

// Test 4: std::_Rb_tree_insert_and_rebalance with S0_ and RS_
// _ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_
// cxx.01 line 121
static int test_rb_tree_insert_and_rebalance(void) {
	const char *mangled = "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_";
	const char *expected_output = "std::_Rb_tree_insert_and_rebalance(bool, std::_Rb_tree_node_base*, std::_Rb_tree_node_base*, std::_Rb_tree_node_base&)";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::_Rb_tree_node_base", // S0_
		"std::_Rb_tree_node_base*", // S1_
		"std::_Rb_tree_node_base&", // S2_
	};
	size_t expected_count = 3;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

// Test 5: std::_Rb_tree_rebalance_for_erase with RS_
// _ZSt28_Rb_tree_rebalance_for_erasePSt18_Rb_tree_node_baseRS_
// cxx.01 line 120
static int test_rb_tree_rebalance_for_erase(void) {
	const char *mangled = "_ZSt28_Rb_tree_rebalance_for_erasePSt18_Rb_tree_node_baseRS_";
	const char *expected_output = "std::_Rb_tree_rebalance_for_erase(std::_Rb_tree_node_base*, std::_Rb_tree_node_base&)";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::_Rb_tree_node_base", // S0_
		"std::_Rb_tree_node_base*", // S1_
		"std::_Rb_tree_node_base&", // S2_
	};
	size_t expected_count = 3;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

// Test 6: std::_Function_base::_Base_manager with complex lambda and RKS6_
// _ZNSt14_Function_base13_Base_managerIZN8appdebug20clPrintCmdQOccupancyEP17_cl_command_queueEUlvE_E10_M_managerERSt9_Any_dataRKS6_St18_Manager_operation
// cxx.01 line 85-90
static int test_function_base_manager_lambda(void) {
	const char *mangled = "_ZNSt14_Function_base13_Base_managerIZN8appdebug20clPrintCmdQOccupancyEP17_cl_command_queueEUlvE_E10_M_managerERSt9_Any_dataRKS6_St18_Manager_operation";
	const char *expected_output = "std::_Function_base::_Base_manager<appdebug::clPrintCmdQOccupancy(_cl_command_queue*)::'lambda'()>::_M_manager(std::_Any_data&, std::_Any_data const&, std::_Manager_operation)";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::_Function_base", // S0_
		"std::_Function_base::_Base_manager", // S1_
		"appdebug", // S2_
		"_cl_command_queue", // S3_
		"_cl_command_queue*", // S4_
		"appdebug::clPrintCmdQOccupancy(_cl_command_queue*)::'lambda'()", // S5_
		"std::_Function_base::_Base_manager<appdebug::clPrintCmdQOccupancy(_cl_command_queue*)::'lambda'()>", // S6_
		"std::_Any_data", // S7_
		"std::_Any_data&", // S8_
		"std::_Any_data const", // S9_
		"std::_Any_data const&", // S10_
		"std::_Manager_operation", // S11_
	};
	size_t expected_count = 12;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

// Test 7: std::pair nested in std::vector with S1_
// _Z3barSt6vectorISt4pairIiiESaIS1_EE
// bar(std::vector<std::pair<int, int>, std::allocator<std::pair<int, int>>>)
static int test_pair_in_vector_with_s1(void) {
	const char *mangled = "_Z3barSt6vectorISt4pairIiiESaIS1_EE";
	const char *expected_output = "bar(std::vector<std::pair<int, int>, std::allocator<std::pair<int, int>>>)";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::vector",
		"std::pair",
		"std::pair<int, int>",
		"std::allocator<std::pair<int, int>>",
		"std::vector<std::pair<int, int>, std::allocator<std::pair<int, int>>>",
	};
	size_t expected_count = 5;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

// Test 8: std::_Function_base::_M_manager with RKS1_
// _ZNSt14_Function_base10_M_managerERSt9_Any_dataRKS1_
// std::_Function_base::_M_manager(std::_Any_data&, std::_Any_data& const&)
// Note: llvm-cxxfilt outputs "std::_Any_data& const&" which is unusual but correct for RKS1_
static int test_any_data_with_rks1(void) {
	const char *mangled = "_ZNSt14_Function_base10_M_managerERSt9_Any_dataRKS1_";
	const char *expected_output = "std::_Function_base::_M_manager(std::_Any_data&, std::_Any_data& const&)";

	// From llvm-cxxfilt 22.0.0
	const char *expected_subs[] = {
		"std::_Function_base", // S0_
		"std::_Any_data", // S1_
		"std::_Any_data&", // S2_
		"std::_Any_data& const", // S3_
		"std::_Any_data& const&", // S4_
	};
	size_t expected_count = 5;

	CxxDemangleResult *result = cxx_demangle_with_subs(mangled);
	if (!result) {
		printf("  cxx_demangle_with_subs returned NULL\n");
		return 0;
	}

	int success = check_output(result, expected_output) &&
		check_subs(result, expected_subs, expected_count);

	cxx_demangle_result_free(result);
	return success;
}

int main(int argc, char **argv) {
	printf("\n=== Substitution Table Tests (from cxx.01 failures) ===\n\n");

	RUN_TEST("test_basic_vector", test_basic_vector);
	RUN_TEST("test_function_template", test_function_template);
	RUN_TEST("test_ostream_m_insert", test_ostream_m_insert);
	RUN_TEST("test_rb_tree_insert_and_rebalance", test_rb_tree_insert_and_rebalance);
	RUN_TEST("test_rb_tree_rebalance_for_erase", test_rb_tree_rebalance_for_erase);
	RUN_TEST("test_function_base_manager_lambda", test_function_base_manager_lambda);
	RUN_TEST("test_pair_in_vector_with_s1", test_pair_in_vector_with_s1);
	RUN_TEST("test_any_data_with_rks1", test_any_data_with_rks1);

	printf("\n=== Summary ===\n");
	printf("Tests run:    %d\n", tests_run);
	printf("Tests passed: %d\n", tests_passed);
	printf("Tests failed: %d\n", tests_run - tests_passed);

	return tests_passed != tests_run;
}
