// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DemString* get_last_nested_name (DemString* full, DemString* last) {
    const char* b = strrchr (full->buf, ':');
    b             = b ? b + 1 : full->buf;

    dem_string_init (last);
    dem_string_appends (last, b);

    return last;
}

DEFN_RULE (prefix, {
    DEFER_VAR (pfx_nested);
    DEFER_VAR (last_name);
    // {prefix-start} {prefix-nested-class-or-namespace}
    // {prefix-start}
    MATCH (
        RULE (prefix_start) &&
        OPTIONAL (
            RULE_DEFER (pfx_nested, prefix_nested_class_or_namespace) && APPEND_STR ("::") &&
            dem_string_concat (dem, pfx_nested) && APPEND_TYPE (dem) &&
            OPTIONAL (
                first_of_rule_ctor_name (CUR()) ?
                    (APPEND_STR ("::") && get_last_nested_name (pfx_nested, last_name) &&
                     dem_string_concat (dem, last_name)) :
                first_of_rule_dtor_name (CUR()) ?
                    (APPEND_STR ("::~") && get_last_nested_name (pfx_nested, last_name) &&
                     dem_string_concat (dem, last_name)) :
                    (0)
            ) &&
            (dem_string_deinit (last_name), dem_string_deinit (pfx_nested), 1)
        )
    );
});
