// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

bool is_template (DemString* n) {
    return n->buf[n->len - 1] == '>' && n->buf[n->len - 2] != '>';
}

DEFN_RULE (encoding, {
    bool is_const_fn = false;
    DEFER_VAR (n);
    DEFER_VAR (rt);
    DEFER_VAR (p);

    MATCH (
        // determine if this function has const or const& at the end
        OPTIONAL (
            is_const_fn = (PEEK_AT (0) == 'N' && PEEK_AT (1) == 'K') || (PEEK_AT (0) == 'K')
        ) &&

        // get function name (can be template or non-template)
        RULE_DEFER (n, name) && dem_string_concat (dem, n) &&

        // determine whether this is a template function alongside normal demangling
        // template functions specify a return type
        // If this is a template function then get return type first
        OPTIONAL (
            is_template (n) && RULE_DEFER (rt, type) && dem_string_append_prefix_n (dem, " ", 1) &&
            dem_string_append_prefix_n (dem, rt->buf, rt->len) && (dem_string_deinit (rt), 1)
        ) &&

        // get function params
        // set it as optional, because there's a rule which just matches for name,
        // so to supress the noise of backtracking, we just make it optional here
        OPTIONAL (
            RULE_DEFER (p, bare_function_type) && APPEND_CHR ('(') && APPEND_DEFER_VAR (p) &&
            APPEND_CHR (')')
        ) &&

        // append const if it was detected to be a constant function
        OPTIONAL (is_const_fn && APPEND_STR (" const")) &&

        // deinit name on a successful match for
        // - name
        // - name <params>
        // - <ret> name <params>
        (dem_string_deinit (n), 1)
    );

    dem_string_deinit (n);
    dem_string_deinit (rt);
    dem_string_deinit (p);

    // MATCH (RULE (name));

    MATCH (RULE (special_name));
});
