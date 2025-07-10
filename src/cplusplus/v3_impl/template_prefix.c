// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (template_prefix, {
    // {prefix-start} {prefix-nested-class-or-namespace} {unqualified-name}
    // {prefix-start} {unqualified-name}
    DEFER_VAR (nname);
    MATCH (
        RULE (prefix_start) &&
        OPTIONAL (
            RULE_DEFER (nname, prefix_nested_class_or_namespace) && APPEND_STR ("::") &&
            APPEND_DEFER_VAR (nname)
        ) &&
        APPEND_STR ("::") && RULE (unqualified_name)
    );

    // {prefix-or-template-prefix-start}
    MATCH (RULE (prefix_or_template_prefix_start));
});
