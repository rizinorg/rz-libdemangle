// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangle.h"

/* defined in src/cp/v2.c */
const char* cp_demangle_v2 (const char* mangled, CpDemOptions opts);

/* defined in src/cp/v3.c */
const char* cp_demangle_v3 (const char* mangled, CpDemOptions opts);

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
const char* cp_demangle (const char* mangled, CpDemOptions opts) {
    if (!mangled) {
        return NULL;
    }

    const char* res = NULL;

    if (mangled[0] == '_') {
        if (mangled[1] == 'Z') {
            /* match : _Z */
            res = cp_demangle_v3 (mangled, opts);
        }
    }

    /* if it does not start with "_Z" or v3 demangling failed */
    if (!res) {
        /* match : _ */
        return cp_demangle_v2 (mangled, opts);
    } else {
        return res;
    }
}
