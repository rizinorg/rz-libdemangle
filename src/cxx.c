// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "borland.h"
#include "cplusplus/demangle.h"
#include <rz_libdemangle.h>

DEM_LIB_EXPORT char *libdemangle_handler_cxx(const char *symbol, RzDemangleOpts opts) {
	char *result = demangle_borland_delphi(symbol);
	if (result) {
		return result;
	}

	return (char *)cp_demangle(symbol, cp_options_convert(opts));
}
