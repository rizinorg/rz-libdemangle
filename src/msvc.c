// SPDX-FileCopyrightText: 2015-2018 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include "demangler.h"
#include <rz_libdemangle.h>

DEM_LIB_EXPORT char *libdemangle_handler_msvc(const char *str, RzDemangleOpts opts) {
	char *out = NULL;
	SDemangler *mangler = 0;

	create_demangler(&mangler);
	if (!mangler) {
		return NULL;
	}
	if (init_demangler(mangler, (char *)str) == eDemanglerErrOK) {
		mangler->demangle(mangler, &out /*demangled_name*/);
	}
	free_demangler(mangler);
	return out;
}
