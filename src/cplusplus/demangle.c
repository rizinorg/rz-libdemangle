// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangle.h"

/**
 * \brief Demangle a C++ symbol, automatically selecting the appropriate scheme.
 *
 * Tries demangling strategies in the following order:
 *   1. If the symbol contains a "_Z" pattern (with possible leading underscores),
 *      attempt v3 (Itanium ABI) demangling via \ref cp_demangle_v3.
 *   2. If v3 fails or the pattern is absent, attempt v2 (legacy) demangling
 *      via \ref cp_demangle_v2.
 *   3. If v2 also fails, attempt bare-type demangling via \ref cp_demangle_v3_type.
 *
 * \param mangled NUL-terminated mangled symbol string. Must not be NULL.
 * \param opts    Demangling options controlling output verbosity (see \ref CpDemOptions).
 * \return Newly allocated demangled string on success, or NULL if all strategies fail.
 *         The caller is responsible for freeing the returned string.
 */
char *cp_demangle(const char *mangled, CpDemOptions opts) {
	if (!mangled) {
		return NULL;
	}

	char *res = NULL;

	// Look for _Z pattern in the string, accounting for vendor-specific prefixes
	const char *p = mangled;
	while (*p == '_') {
		p++;
		if (*p == 'Z') {
			// Found _Z pattern after vendor prefix
			res = cp_demangle_v3(mangled, opts);
			break;
		}
	}

	/* if it does not start with "_Z" or v3 demangling failed */
	if (!res) {
		/* match : _ */
		res = cp_demangle_v2(mangled, opts);
	}

	/* if v2 also failed, try as a bare type (no _Z prefix) */
	if (!res) {
		res = cp_demangle_v3_type(mangled, opts);
	}

	return res;
}
