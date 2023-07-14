// SPDX-FileCopyrightText: 2015 Jeffrey Crowell <crowell@bu.edu>
// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

// minunit.h comes from http://www.jera.com/techinfo/jtns/jtn002.html
//
// You may use the code in this tech note for any purpose,
// with the understanding that it comes with NO WARRANTY.

#ifndef _MINUNIT_H_
#define _MINUNIT_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define RZ_API
#include "rz_libdemangle.h"

typedef struct mu_demangling_test_s {
	int line;
	const char *input;
	const char *expected;
} mu_demangling_test_t;

typedef uint8_t ut8;
typedef int bool;
#define true  1
#define false 0

#if __WINDOWS__
#define TRED
#define TGREEN
#define TYELLOW
#define TBLUE
#define TMAGENTA
#define TCYAN
#define TBOLD
#define TRESET
#else
#define TRED     "\x1b[31m"
#define TGREEN   "\x1b[32m"
#define TYELLOW  "\x1b[33m"
#define TBLUE    "\x1b[34m"
#define TMAGENTA "\x1b[35m"
#define TCYAN    "\x1b[36m"
#define TBOLD    "\x1b[1m"
#define TRESET   "\x1b[0m"
#endif

#define MU_PASSED 1
#define MU_ERR    0

#define MU_TEST_UNBROKEN 0
#define MU_TEST_BROKEN   1

#define MU_BUF_SIZE 10240

#define mu_perror(line, message) \
	do { \
		printf(TBOLD TRED "ERR\n[XX] Failed to demangle line %d: " TRESET "%s\n\n", line, message); \
	} while (0)

#define mu_fail(line, message) \
	do { \
		mu_perror(line, message); \
		if (mu_test_status != MU_TEST_BROKEN) \
			return MU_ERR; \
	} while (0)

#define mu_assert(line, message, test) \
	do { \
		if (!(test)) { \
			mu_fail(line, message); \
			mu_test_status = MU_TEST_UNBROKEN; \
		} \
	} while (0)

#define mu_end(line, input, expected) \
	do { \
		printf(TGREEN "OK" TRESET " line %d: '%s' -> '%s'\n", line, input, expected ? expected : "NULL"); \
		return MU_PASSED; \
	} while (0)

#define mu_assert_null(actual, input, line) \
	do { \
		char _meqstr[MU_BUF_SIZE]; \
		void *act__ = (actual); \
		snprintf(_meqstr, MU_BUF_SIZE, "expected %s to be NULL but instead got %s.", input, actual); \
		free(act__); \
		mu_assert(line, _meqstr, (act__) == NULL); \
	} while (0)

#define mu_assert_streq_free(actual, expected, line) \
	do { \
		char *act2__ = (actual); \
		char _meqstr[MU_BUF_SIZE]; \
		const char *act__ = (actual); \
		act__ = act__ ? act__ : "(null)"; \
		const char *exp__ = (expected); \
		exp__ = exp__ ? exp__ : "(null)"; \
		snprintf(_meqstr, MU_BUF_SIZE, "expected %s, got %s.", (exp__), (act__)); \
		int is_success = strcmp((exp__), (act__)) == 0; \
		free(act2__); \
		mu_assert(line, _meqstr, is_success); \
	} while (0)

#define mu_demangle_test_name(name) demangling_##name##_tests
#define mu_demangle_func_name(name) demangle_with_##name
#define mu_demangle_test_size(name) (sizeof(mu_demangle_test_name(name)) / sizeof((mu_demangle_test_name(name))[0]))

#define mu_demangle_str_message(name, input, expected, line) \
	do { \
		char *output = libdemangle_handler_##name(input, RZ_DEMANGLE_OPT_ENABLE_ALL); \
		if (expected) { \
			mu_assert_streq_free(output, expected, line); \
		} else { \
			mu_assert_null(output, input, line); \
		} \
	} while (0)

#define mu_demangle_with(name) \
	bool mu_demangle_func_name(name)(mu_demangling_test_t * test) { \
		mu_demangle_str_message(name, test->input, test->expected, test->line); \
		mu_end(test->line, test->input, test->expected); \
	}

#define mu_demangle_tests(name, ...) \
	mu_demangling_test_t mu_demangle_test_name(name)[] = { \
		__VA_ARGS__ \
	}

#define mu_demangle_test(input, expected) \
	{ __LINE__, input, expected }

#define mu_run_test_named(test, name, ...) \
	do { \
		int result; \
		printf(TBOLD "%s" TRESET " ", name); \
		mu_test_status = MU_TEST_UNBROKEN; \
		result = test(__VA_ARGS__); \
		tests_run++; \
		tests_passed += result; \
	} while (0)

#define mu_demangle_loop(name, demangler) \
	do { \
		for (size_t i = 0; i < mu_demangle_test_size(name); ++i) { \
			mu_demangling_test_t *t = &mu_demangle_test_name(name)[i]; \
			mu_run_test_named(mu_demangle_func_name(demangler), #name, t); \
		} \
	} while (0)

int tests_run = 0;
int tests_passed = 0;
int mu_test_status = MU_TEST_UNBROKEN;

#define mu_main(name, demangler) \
	mu_demangle_with(demangler); \
	int main(int argc, char **argv) { \
		mu_demangle_loop(name, demangler); \
		return tests_passed != tests_run; \
	}

#define mu_main2(name) \
	mu_demangle_with(name); \
	int main(int argc, char **argv) { \
		mu_demangle_loop(name, name); \
		return tests_passed != tests_run; \
	}

#endif
