// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_libdemangle.h>
#include "rust.h"

DEM_LIB_EXPORT char *libdemangle_handler_rust(const char *symbol, RzDemangleOpts opts) {
	char *result = rust_demangle_legacy(symbol);
	if (result) {
		return result;
	}

	return rust_demangle_v0(symbol, opts & RZ_DEMANGLE_OPT_SIMPLIFY);
}
