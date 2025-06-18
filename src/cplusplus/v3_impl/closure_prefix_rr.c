// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

// TODO: merge common patterns, to keep trace as small as possible!

DEFN_RULE (closure_prefix_rr, {
    // {unqualified-name} M
    MATCH (RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) && 
           RULE (unqualified_name) && APPEND_TYPE(dem) && RULE (template_args) && READ ('M') && APPEND_TYPE (dem) && 
           RULE (closure_prefix_rr));
    
    // {prefix-start-rr} {unqualified-name} M
    MATCH (RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) && 
           RULE (unqualified_name) && APPEND_TYPE(dem) && RULE (template_args) && READ ('M') && APPEND_TYPE (dem));
    
    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) && 
           RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem) && RULE (closure_prefix_rr));
    
    // {unqualified-name} {template-args} M
    MATCH (RULE (prefix_start_rr) && RULE (unqualified_name) && APPEND_TYPE(dem) && RULE (template_args) && 
           READ ('M') && APPEND_TYPE(dem) && RULE (closure_prefix_rr));
    
    // {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && APPEND_TYPE(dem) && 
           RULE (template_args) && READ ('M') && APPEND_TYPE(dem) && RULE (closure_prefix_rr));
    
    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M
    MATCH (RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) && 
           RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M
    MATCH (RULE (prefix_start_rr) && RULE (unqualified_name) && APPEND_TYPE(dem) && RULE (template_args) && 
           READ ('M') && APPEND_TYPE(dem));
    
    // {unqualified-name} M {closure-prefix-rr}
    MATCH (RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && APPEND_TYPE(dem) && 
           RULE (template_args) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-start-rr} {unqualified-name} M {closure-prefix-rr}
    MATCH (RULE (prefix_start_rr) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem) && 
           RULE (closure_prefix_rr));
    
    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M {closure-prefix-rr}
    MATCH (RULE (unqualified_name) && APPEND_TYPE(dem) && RULE (template_args) && READ ('M') && APPEND_TYPE(dem) && 
           RULE (closure_prefix_rr));
    
    // {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (RULE (prefix_start_rr) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-start-rr} {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (RULE (unqualified_name) && APPEND_TYPE(dem) && RULE (template_args) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem) && RULE (closure_prefix_rr));
    
    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
}); 