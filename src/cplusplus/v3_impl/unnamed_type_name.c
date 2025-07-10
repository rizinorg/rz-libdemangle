// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "macros.h"
#include "types.h"

bool first_of_rule_non_neg_number (const char* i) {
    return (i[0] == '_') || strchr ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", *i);
}

DEFN_RULE (non_neg_number, {
    if (READ ('_')) {
        dem_string_append_char (dem, '1');
        TRACE_RETURN_SUCCESS (dem);
    }

    char* e   = NULL;
    ut32  num = strtoul (CUR(), &e, 10) + 2;
    if(!e) {
        TRACE_RETURN_FAILURE();
    }
    dem_string_appendf (dem, "%u", num);
    msi->cur = e;

    TRACE_RETURN_SUCCESS (dem);
});

DEFN_RULE (unnamed_type_name, {
    if (READ_STR ("Ut")) {
        st64 tidx = -1;
        READ_NUMBER (tidx);
        if (tidx >= 0) {
            // do something
        } else {
            TRACE_RETURN_FAILURE();
        }

        if (READ ('_')) {
            TRACE_RETURN_SUCCESS (dem);
        }
    } else if (READ_STR ("Ul")) {
        DEFER_VAR (d);
        MATCH (
            APPEND_STR ("{lambda(") && RULE_ATLEAST_ONCE_WITH_SEP (type, ", ") && READ ('E') &&
            APPEND_CHR (')') &&
            OPTIONAL (RULE_DEFER (d, non_neg_number) && APPEND_CHR ('#') && APPEND_DEFER_VAR (d)) &&
            APPEND_CHR ('}') && APPEND_TYPE (dem)
        );
    }

    TRACE_RETURN_FAILURE();
});
