// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CP_DEMANGLE_H
#define CP_DEMANGLE_H

#include "rz_libdemangle.h"

#include <stddef.h>
#include <stdint.h>

typedef enum {
	DEM_OPT_NONE = 0, /**< \b No setting */
	DEM_OPT_ANSI = 1 << 0, /**< \b Emit qualifiers like const, volatile, etc... */
	DEM_OPT_PARAMS = 1 << 1, /**< \b Emit parameters in demangled output. */
	DEM_OPT_SIMPLE = 1 << 2, /**< \b Simplify the output, to make it more human readable */
	DEM_OPT_ALL = 0xff /**< \b Everything, everywhere, all at once! */
} CpDemOptions;

static inline CpDemOptions cp_options_convert(RzDemangleOpts opts) {
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

char *cp_demangle_v2(const char *mangled, CpDemOptions opts);
char *cp_demangle_v3(const char *mangled, CpDemOptions opts);
char *cp_demangle(const char *mangled, CpDemOptions opts);

#endif // CP_DEMANGLE_H
