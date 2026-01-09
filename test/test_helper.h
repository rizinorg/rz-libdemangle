// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef TEST_HELPER_H
#define TEST_HELPER_H

#include <stddef.h>

/**
 * Result structure for testing C++ demangling with substitution table inspection
 */
typedef struct {
	char *demangled; // Final demangled string (must be freed)
	char **subs_table; // Array of substitution table entries (each must be freed)
	size_t subs_count; // Number of entries in substitution table
	int success; // 1 if demangling succeeded, 0 otherwise
} CxxDemangleResult;

/**
 * Demangle a C++ symbol and return both the result and substitution table
 *
 * @param mangled The mangled symbol
 * @return CxxDemangleResult structure (caller must free all strings and the arrays)
 */
CxxDemangleResult *cxx_demangle_with_subs(const char *mangled);

/**
 * Free a CxxDemangleResult structure
 */
void cxx_demangle_result_free(CxxDemangleResult *result);

#endif /* TEST_HELPER_H */
