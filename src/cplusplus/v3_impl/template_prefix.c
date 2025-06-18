// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (template_prefix, {
    // {prefix-or-template-prefix-start}
    MATCH (RULE (prefix_start) && RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name));
    
    // {prefix-start} {unqualified-name}
    MATCH (RULE (prefix_start) && RULE (unqualified_name));
    
    // {prefix-start} {prefix-nested-class-or-namespace} {unqualified-name}
    MATCH (RULE (prefix_or_template_prefix_start));
}); 