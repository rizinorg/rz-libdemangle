// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "first.h"
#include "macros.h"
#include "types.h"

// unqualified names come in sequence from prefix_nested_class_or_namespace in form of A::B::C
// we need to extract the last unqualified name from the dem string
const char* extract_last_unqualified_name (DemString* dem) {
    if (!dem) {
        return NULL;
    }
    const char* ptr = dem->buf + dem->len - 1;
    while (ptr >= dem->buf && *ptr != ':') {
        ptr--;
    }
    return ptr + 1;
}

DEFN_RULE (prefix_start_rr, {
    DEFER_VAR (pfx_rr);
    DEFER_VAR (cname);
    // {prefix-nested-class-or-namespace} {ctor-dtor-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (
        RULE (prefix_nested_class_or_namespace) && APPEND_TYPE (dem) &&
        OPTIONAL (
            (RULE (ctor_name) && APPEND_STR ("::")) || (RULE (dtor_name) && APPEND_STR ("::~"))
        ) &&
        dem_string_append (dem, extract_last_unqualified_name (dem)) && RULE (template_args) &&
        APPEND_TYPE (dem) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        )
    );

    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (
        RULE (prefix_nested_class_or_namespace) && APPEND_STR("::") && RULE (unqualified_name) && APPEND_TYPE (dem) &&
        RULE (template_args) && APPEND_TYPE (dem) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        )
    );
    dem_string_deinit (pfx_rr);

    // {unqualified-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (
        RULE_DEFER (cname, unqualified_name) && dem_string_concat (dem, cname) &&
        APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        ) &&
        OPTIONAL (
            (first_of_rule_ctor_name (CUR()) && APPEND_STR ("::") &&
             dem_string_concat (dem, cname)) ||
            (first_of_rule_dtor_name (CUR()) && APPEND_STR ("::~") &&
             dem_string_concat (dem, cname))
        ) &&
        (dem_string_deinit (cname), 1)
    );
    dem_string_deinit (cname);
    dem_string_deinit (pfx_rr);
});
