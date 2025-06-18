// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (prefix_start_rr, {
    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && APPEND_TYPE (dem) && 
           RULE (template_args) && APPEND_TYPE (dem) && OPTIONAL (RULE (prefix_start_rr)));
    
    // {unqualified-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (RULE (unqualified_name) && APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem) && 
           OPTIONAL (RULE (prefix_start_rr)));
}); 
