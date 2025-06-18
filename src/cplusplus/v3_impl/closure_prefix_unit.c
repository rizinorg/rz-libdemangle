// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

// TODO: merge common patterns, to keep trace as small as possible!


DEFN_RULE (closure_prefix_unit, {
    // {prefix-or-template-prefix-start} {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) && 
           RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) && 
           RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {decltype} {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) && 
           RULE (prefix_start_rr) && RULE (unqualified_name) && RULE (template_args) && 
           READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-or-template-prefix-start} {template-args} {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) && 
           RULE (prefix_start_rr) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-or-template-prefix-start} {prefix-start-rr} {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (prefix_start_rr) && 
           RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {decltype} {prefix-start-rr} {unqualified-name} M
    MATCH (RULE (decltype) && APPEND_TYPE (dem) && RULE (prefix_start_rr) && 
           RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-or-template-prefix-start} {template-args} {prefix-start-rr} {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) && 
           RULE (unqualified_name) && RULE (template_args) && READ ('M') && APPEND_TYPE (dem));
    
    // {prefix-or-template-prefix-start} {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (prefix_start_rr) && 
           RULE (unqualified_name) && RULE (template_args) && READ ('M') && APPEND_TYPE (dem));
    
    // {decltype} {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (RULE (decltype) && APPEND_TYPE (dem) && RULE (prefix_start_rr) && 
           RULE (unqualified_name) && RULE (template_args) && READ ('M') && APPEND_TYPE (dem));
    
    // {prefix-or-template-prefix-start} {template-args} {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) && 
           RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {unqualified-name} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (prefix_start_rr) && 
           RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-or-template-prefix-start} {unqualified-name} {template-args} M
    MATCH (RULE (decltype) && APPEND_TYPE (dem) && RULE (prefix_start_rr) && 
           RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {decltype} {unqualified-name} {template-args} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (unqualified_name) && 
           RULE (template_args) && READ ('M') && APPEND_TYPE (dem));
    
    // {prefix-or-template-prefix-start} {template-args} {unqualified-name} {template-args} M
    MATCH (RULE (decltype) && APPEND_TYPE (dem) && RULE (unqualified_name) && 
           RULE (template_args) && READ ('M') && APPEND_TYPE (dem));
    
    // {prefix-or-template-prefix-start} {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {decltype} {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (RULE (decltype) && APPEND_TYPE (dem) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
    
    // {prefix-or-template-prefix-start} {template-args} {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) && 
           READ ('M'));
    
    // {prefix-or-template-prefix-start} {template-args} M
    MATCH (RULE (unqualified_name) && READ ('M') && APPEND_TYPE(dem));
}); 