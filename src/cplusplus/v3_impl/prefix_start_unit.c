// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (prefix_start_unit, {
    DEFER_VAR (cname);
    MATCH (
        RULE_DEFER (cname, prefix_or_template_prefix_start) && dem_string_concat (dem, cname) &&
        APPEND_TYPE (dem) && OPTIONAL (RULE (template_args) && APPEND_TYPE (dem)) &&
        OPTIONAL (
            (first_of_rule_ctor_name (CUR()) && APPEND_STR ("::") &&
             dem_string_concat (dem, cname)) ||
            (first_of_rule_dtor_name (CUR()) && APPEND_STR ("::~") &&
             dem_string_concat (dem, cname))
        ) &&
        (dem_string_deinit (cname), 1)
    );
    dem_string_deinit (cname);

    MATCH (RULE (decltype) && APPEND_TYPE (dem));
    MATCH (RULE (closure_prefix));
});
