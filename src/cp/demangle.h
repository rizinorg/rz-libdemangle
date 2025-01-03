// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CP_DEMANGLE_H
#define CP_DEMANGLE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    DEM_OPT_NONE   = 0,      /**< \b No setting */
    DEM_OPT_ANSI   = 1 << 0, /**< \b Emit qualifiers like const, volatile, etc... */
    DEM_OPT_PARAMS = 1 << 1, /**< \b Emit parameters in demangled output. */
    DEM_OPT_SIMPLE = 1 << 2, /**< \b Simplify the output, to make it more human readable */
    DEM_OPT_ALL    = 0xff    /**< \b Everything, everywhere, all at once! */
} CpDemOptions;

const char *cp_demangle (const char *mangled, CpDemOptions opts);

#endif // CP_DEMANGLE_H
