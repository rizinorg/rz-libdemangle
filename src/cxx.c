// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "borland.h"
#include "cplusplus/demangle.h"
#include <rz_libdemangle.h>

static CpDemOptions options_convert(RzDemangleOpts opts) {
	CpDemOptions copts = DEM_OPT_ANSI | DEM_OPT_PARAMS;
	if (opts & RZ_DEMANGLE_OPT_ENABLE_ALL) {
		copts |= DEM_OPT_ALL;
	}
	if (opts & RZ_DEMANGLE_OPT_SIMPLIFY) {
		copts |= DEM_OPT_SIMPLE;
	}
	if (opts & RZ_DEMANGLE_OPT_BASE) {
		// no corresponding flag in CpDemOptions
	}
	if (opts == 0) {
		copts = DEM_OPT_ALL - DEM_OPT_SIMPLE;
	}
	return copts;
}

DEM_LIB_EXPORT char *libdemangle_handler_cxx(const char *symbol, RzDemangleOpts opts) {
	char *result = demangle_borland_delphi(symbol);
	if (result) {
		return result;
	}

	return (char *)cp_demangle(symbol, options_convert(opts));
}
