// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangle.h"

/**
 * \b Demangle given "mangled" declaration using either GNU v2 or GNU v3 grammar.
 *
 * The returned string is allocated and hence must be freed by caller after use.
 *
 * \p mangled : A C++ declaration mangled using either GNU v2 or GNU v3 grammar scheme.
 * \p opts
 *
 * \return Demangled name on success.
 * \return NULL otherwise.
 * */
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
