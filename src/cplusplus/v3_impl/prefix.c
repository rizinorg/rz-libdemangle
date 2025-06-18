// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (prefix, {
    // {prefix-start} {prefix-nested-class-or-namespace}
    MATCH (RULE (prefix_start) && APPEND_STR ("::") && RULE (prefix_nested_class_or_namespace));

    // {prefix-start}
    MATCH (RULE (prefix_start));
});
