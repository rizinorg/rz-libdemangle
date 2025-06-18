// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef FIRST_H
#define FIRST_H

#include <stddef.h>
#include <string.h>
#include "../../demangler_util.h"

// Structure to represent first set entries 
typedef struct {
    const char *str;
    int len;
} first_set_entry_t;

// Helper function to check if string starts with any entry in a first set
static inline bool first_set_matches(const char *input, const first_set_entry_t *first_set) {
    if (!input || !first_set) return false;
    
    for (int i = 0; first_set[i].str != NULL; i++) {
        if (strncmp(input, first_set[i].str, first_set[i].len) == 0) {
            return true;
        }
    }
    return false;
}

// First set checking functions

// mangled-name rule
static inline bool first_of_rule_mangled_name(const char *input) {
    return strncmp(input, "_Z", 2) == 0;
}

// name rule - will be defined after all dependencies

// special-name rule  
static inline bool first_of_rule_special_name(const char *input) {
    return input[0] == 'T' ||
    strncmp(input, "TV", 2) == 0 || strncmp(input, "TT", 2) == 0 || 
    strncmp(input, "TI", 2) == 0 || strncmp(input, "TS", 2) == 0 ||
      strncmp(input, "Tc", 2) == 0 ||
      strncmp(input, "GV", 2) == 0 || strncmp(input, "GR", 2) == 0 ||
       strncmp(input, "GTt", 3) == 0;
}

// encoding rule - will be defined after name

// nested-name rule
static inline bool first_of_rule_nested_name(const char *input) {
    return input[0] == 'N';
}

// abi-tag rule
static inline bool first_of_rule_abi_tag(const char *input) {
    return input[0] == 'B';
}

// number rule
static inline bool first_of_rule_number(const char *input) {
    return strchr("n0123456789", input[0]) != NULL;
}

// seq-id rule
static inline bool first_of_rule_seq_id(const char *input) {
    return strchr("_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", input[0]) != NULL;
}

// operator-name rule
static inline bool first_of_rule_operator_name(const char *input) {
    static const first_set_entry_t direct_terminals[] = {
        {"nw", 2}, {"na", 2}, {"dl", 2}, {"da", 2}, {"aw", 2},
        {"ps", 2}, {"ng", 2}, {"ad", 2}, {"de", 2}, {"co", 2},
        {"pl", 2}, {"mi", 2}, {"ml", 2}, {"dv", 2}, {"rm", 2},
        {"an", 2}, {"or", 2}, {"eo", 2}, {"aS", 2}, {"pL", 2},
        {"mI", 2}, {"mL", 2}, {"dV", 2}, {"rM", 2}, {"aN", 2},
        {"oR", 2}, {"eO", 2}, {"ls", 2}, {"rs", 2}, {"lS", 2},
        {"rS", 2}, {"eq", 2}, {"ne", 2}, {"lt", 2}, {"gt", 2},
        {"le", 2}, {"ge", 2}, {"ss", 2}, {"nt", 2}, {"aa", 2},
        {"oo", 2}, {"pp", 2}, {"mm", 2}, {"cm", 2}, {"pm", 2},
        {"pt", 2}, {"cl", 2}, {"ix", 2}, {"qu", 2},
        {NULL, 0}
    };
    if (first_set_matches(input, direct_terminals)) {
        return true;
    }
    
    // Check patterns: cv {type}, li {source-name}, v {digit} {source-name}
    if (input && strncmp(input, "cv", 2) == 0) {
        return true;  // cv {type}
    }
    if (input && strncmp(input, "li", 2) == 0) {
        return true;  // li {source-name}
    }
    if (input && input[0] == 'v' && input[1] >= '0' && input[1] <= '9') {
        return true;  // v {digit} {source-name}
    }
    
    return false;
}

// call-offset rule
static inline bool first_of_rule_call_offset(const char *input) {
    return input[0] == 'h' || input[0] == 'v';
}

// nv-offset rule (starts with number)
static inline bool first_of_rule_nv_offset(const char *input) {
    return strchr("n0123456789", input[0]) != NULL;
}

// v-offset rule (starts with number)
static inline bool first_of_rule_v_offset(const char *input) {
    return strchr("n0123456789", input[0]) != NULL;
}

// ctor-name rule
static inline bool first_of_rule_ctor_name(const char *input) {
    return strncmp(input, "C1", 2) == 0 || strncmp(input, "C2", 2) == 0 || strncmp(input, "C3", 2) == 0 || strncmp(input, "CI1", 3) == 0 || strncmp(input, "CI2", 3) == 0;
}

// dtor-name rule
static inline bool first_of_rule_dtor_name(const char *input) {
    return strncmp(input, "D0", 2) == 0 || strncmp(input, "D1", 2) == 0 || strncmp(input, "D2", 2) == 0;
}

// ctor-dtor-name rule (combination of ctor and dtor)
static inline bool first_of_rule_ctor_dtor_name(const char *input) {
    return strncmp(input, "C1", 2) == 0 || strncmp(input, "C2", 2) == 0 || strncmp(input, "C3", 2) == 0 || strncmp(input, "CI1", 3) == 0 || strncmp(input, "CI2", 3) == 0 || strncmp(input, "D0", 2) == 0 || strncmp(input, "D1", 2) == 0 || strncmp(input, "D2", 2) == 0;
}

// extended-qualifier rule
static inline bool first_of_rule_extended_qualifier(const char *input) {
    return input[0] == 'U';
}

// CV-qualifiers rule
static inline bool first_of_rule_cv_qualifiers(const char *input) {
    return input[0] == 'r' || input[0] == 'V' || input[0] == 'K';
}

// ref-qualifier rule
static inline bool first_of_rule_ref_qualifier(const char *input) {
    return input[0] == 'R' || input[0] == 'O';
}

// builtin-type rule
static inline bool first_of_rule_builtin_type(const char *input) {
    static const first_set_entry_t direct_terminals[] = {
        {"v", 1}, {"w", 1}, {"b", 1}, {"c", 1}, {"a", 1}, {"h", 1},
        {"s", 1}, {"t", 1}, {"i", 1}, {"j", 1}, {"l", 1}, {"m", 1},
        {"x", 1}, {"y", 1}, {"n", 1}, {"o", 1}, {"f", 1}, {"d", 1},
        {"e", 1}, {"g", 1}, {"z", 1}, {"Dd", 2}, {"De", 2}, {"Df", 2},
        {"Dh", 2}, {"DF", 2}, {"DF16b", 5}, {"DB", 2}, {"DU", 2}, 
        {"Di", 2}, {"Ds", 2}, {"Du", 2}, {"Da", 2}, {"Dc", 2}, {"Dn", 2}, 
        {"DS", 2}, {"DA", 2}, {"DR", 2},
        {NULL, 0}
    };
    if (first_set_matches(input, direct_terminals)) {
        return true;
    }
    
    // Check u {source-name} [{template-args}] pattern
    if (input && input[0] == 'u') {
        return true;  // u {source-name} [{template-args}]
    }
    
    return false;
}

// function-type rule (can start with CV qualifiers, exception specs, and F)
static inline bool first_of_rule_function_type(const char *input) {
    // Direct terminals that can start function-type 
    static const first_set_entry_t first_set[] = { 
        {"PF", 2}, {"PD", 2}, {"PDO", 3}, {"PDw", 3}, {"PDx", 3},

        // Standalone patterns (since all are optional)
        {"Do", 2}, {"DO", 2}, {"Dw", 2},  // exception-spec
        {"Dx", 2},  // Dx
        {"F", 1},   // F (required part)

        {"PrF", 3}, {"PrD", 3}, {"PrDO", 4}, {"PrDw", 4}, {"PrDx", 4},
        {"PKF", 3}, {"PKD", 3}, {"PKDO", 4}, {"PKDw", 4}, {"PKDx", 4},
        {"PVF", 3}, {"PVD", 3}, {"PVDO", 4}, {"PVDw", 4}, {"PVDx", 4},
        {"PrKF", 4}, {"PrKD", 4}, {"PrKDO", 5}, {"PrKDw", 5}, {"PrKDx", 5},
        {"PVKF", 4}, {"PVKD", 4}, {"PVKDO", 5}, {"PVKDw", 5}, {"PVKDx", 5},
        {"PrVF", 4}, {"PrVD", 4}, {"PrVDO", 5}, {"PrVDw", 5}, {"PrVDx", 5},
        {"PrVKF", 5}, {"PrVKD", 5}, {"PrVKDO", 6}, {"PrVKDw", 6}, {"PrVKDx", 6},
        {NULL, 0}
    };
    return first_set_matches(input, first_set);
}

// exception-spec rule
static inline bool first_of_rule_exception_spec(const char *input) {
    return strncmp(input, "Do", 2) == 0 || strncmp(input, "DO", 2) == 0 || strncmp(input, "Dw", 2) == 0;
}

// decltype rule
static inline bool first_of_rule_decltype(const char *input) {
    return strncmp(input, "Dt", 2) == 0 || strncmp(input, "DT", 2) == 0;
}

// class-enum-type rule - will be defined after dependencies

// closure-type-name rule (moved here to resolve dependency)
static inline bool first_of_rule_closure_type_name(const char *input) {
    return strncmp(input, "Ul", 2) == 0;
}

// unnamed-type-name rule
static inline bool first_of_rule_unnamed_type_name(const char *input) {
    return strncmp(input, "Ut", 2) == 0 || first_of_rule_closure_type_name(input);
}

// unqualified-name rule (expands {operator-name}, {ctor-dtor-name}, {source-name}, {unnamed-type-name}, DC)
static inline bool first_of_rule_unqualified_name(const char *input) {
    return strncmp(input, "DC", 2) == 0 || first_of_rule_operator_name(input) || 
           first_of_rule_ctor_dtor_name(input) ||
           first_of_rule_number(input) ||  // source-name starts with number
           first_of_rule_unnamed_type_name(input);
}

// unscoped-name rule (expands {unqualified-name} and St {unqualified-name})
static inline bool first_of_rule_unscoped_name(const char *input) {
    return strncmp(input, "St", 2) == 0 || first_of_rule_unqualified_name(input);
}

// array-type rule
static inline bool first_of_rule_array_type(const char *input) {
    return strncmp(input, "A", 1) == 0;
}

// pointer-to-member-type rule
static inline bool first_of_rule_pointer_to_member_type(const char *input) {
    return strncmp(input, "M", 1) == 0;
}

// template-param rule
static inline bool first_of_rule_template_param(const char *input) {
    return input[0] == 'T';
}

// function-param rule
static inline bool first_of_rule_function_param(const char *input) {
    return strncmp(input, "fp", 2) == 0 || strncmp(input, "fL", 2) == 0 || strncmp(input, "fpT", 3) == 0 || first_of_rule_number(input);
}

// template-args rule
static inline bool first_of_rule_template_args(const char *input) {
    return input[0] == 'I';
}

// base-unresolved-name rule (moved before unresolved-name to resolve dependency)
static inline bool first_of_rule_base_unresolved_name(const char *input) {
    return strncmp(input, "on", 2) == 0 || strncmp(input, "dn", 2) == 0 || first_of_rule_number(input);
}

// unresolved-name rule
static inline bool first_of_rule_unresolved_name(const char *input) {
    return strncmp(input, "sr", 2) == 0 || strncmp(input, "srN", 3) == 0 || strncmp(input, "gs", 2) == 0 || first_of_rule_base_unresolved_name(input);
}

// expr-primary rule
static inline bool first_of_rule_expr_primary(const char *input) {
    return input[0] == 'L';
}

// initializer rule
static inline bool first_of_rule_initializer(const char *input) {
    return strncmp(input, "pi", 2) == 0;
}

// float rule
static inline bool first_of_rule_float(const char *input) {
    return strchr("0123456789abcdef", input[0]) != NULL;
}

// local-name rule
static inline bool first_of_rule_local_name(const char *input) {
    return input[0] == 'Z';
}

// discriminator rule
static inline bool first_of_rule_discriminator(const char *input) {
    return input[0] == '_';
}

// lambda-sig rule - will be defined after dependencies

// identifier rule (not in grammar explicitly, but needed)
static inline bool first_of_rule_identifier(const char *input) {
    // Identifiers start with letters or underscore
    char first_char = input[0];
    return (first_char >= 'a' && first_char <= 'z') ||
           (first_char >= 'A' && first_char <= 'Z') ||
           (first_char == '_');
}

// substitution rule
static inline bool first_of_rule_substitution(const char *input) {
    return input[0] == 'S';
}

// template-template-param rule (moved here to resolve dependency with type rule)
static inline bool first_of_rule_template_template_param(const char *input) {
    // template-template-param expands {template-param} and {substitution}
    return first_of_rule_template_param(input) || first_of_rule_substitution(input);
}

// class-enum-type rule (moved here to resolve dependencies)
static inline bool first_of_rule_class_enum_type(const char *input) {
    // Check direct terminals
    static const first_set_entry_t direct_terminals[] = {
        {"Ts", 2}, {"Tu", 2}, {"Te", 2},
        // For {name}, we include the first sets of nested-name, unscoped-name, local-name
        {"N", 1},  // nested-name
        {"St", 2}, // unscoped-name (St pattern)
        {"Z", 1},  // local-name
        {NULL, 0}
    };
    if (first_set_matches(input, direct_terminals)) {
        return true;
    }
    
    // Check {name} expansions that start with numbers (unqualified-name -> source-name)
    return first_of_rule_number(input) ||
           first_of_rule_operator_name(input) ||
           first_of_rule_ctor_dtor_name(input) ||
           first_of_rule_unnamed_type_name(input) ||
           first_of_rule_substitution(input);
}

// type rule (CV qualifiers and others) - defined after dependencies
static inline bool first_of_rule_type(const char *input) {
    if (first_of_rule_cv_qualifiers(input)) {
        return true;
    }

    // Check direct terminals first
    static const first_set_entry_t direct_terminals[] = {
        {"P", 1}, {"R", 1}, {"O", 1},
        {"C", 1}, {"G", 1}, {"Dp", 2},
        {NULL, 0}
    };
    if (first_set_matches(input, direct_terminals)) {
        return true;
    }
    
    // Check non-terminals that can start type
    return first_of_rule_builtin_type(input) ||
           first_of_rule_extended_qualifier(input) ||  // This covers both single and {extended-qualifier}+ patterns
           first_of_rule_function_type(input) ||
           first_of_rule_class_enum_type(input) ||
           first_of_rule_array_type(input) ||
           first_of_rule_pointer_to_member_type(input) ||
           first_of_rule_template_param(input) ||
           first_of_rule_template_template_param(input) ||
           first_of_rule_decltype(input) ||
           first_of_rule_substitution(input);
}

// unscoped-template-name rule (expands {unscoped-name} and {substitution})
static inline bool first_of_rule_unscoped_template_name(const char *input) {
    return first_of_rule_unscoped_name(input) || first_of_rule_substitution(input);
}

// name rule (expands {nested-name}, {unscoped-name}, {unscoped-template-name}, {local-name})
static inline bool first_of_rule_name(const char *input) {
    return first_of_rule_nested_name(input) ||
           first_of_rule_unscoped_name(input) ||
           first_of_rule_unscoped_template_name(input) ||  // {unscoped-template-name} {template-args} starts with unscoped-template-name
           first_of_rule_local_name(input);
}

// encoding rule (expands {name} and {special-name})
static inline bool first_of_rule_encoding(const char *input) {
    return first_of_rule_name(input) || first_of_rule_special_name(input);
}

// template-arg rule (defined after dependencies)
static inline bool first_of_rule_template_arg(const char *input) {
    // Check direct terminals
    static const first_set_entry_t direct_terminals[] = {
        {"X", 1}, {"J", 1},
        {NULL, 0}
    };
    if (first_set_matches(input, direct_terminals)) {
        return true;
    }
    
    // Check non-terminals: {type} and {expr-primary}
    return first_of_rule_type(input) || first_of_rule_expr_primary(input);
}

// expression rule (defined after dependencies)
static inline bool first_of_rule_expression(const char *input) {
    // Check direct terminals
    static const first_set_entry_t direct_terminals[] = {
        {"pp_", 3}, {"mm_", 3}, {"cl", 2}, {"cp", 2}, {"cv", 2}, {"tl", 2},
        {"il", 2}, {"nw", 2}, {"na", 2}, {"dl", 2}, {"da", 2}, {"dc", 2},
        {"sc", 2}, {"cc", 2}, {"rc", 2}, {"ti", 2}, {"te", 2}, {"st", 2},
        {"sz", 2}, {"at", 2}, {"az", 2}, {"nx", 2}, {"dt", 2}, {"pt", 2},
        {"ds", 2}, {"sZ", 2}, {"sP", 2}, {"sp", 2}, {"fl", 2}, {"fr", 2},
        {"fL", 2}, {"fR", 2}, {"tw", 2}, {"tr", 2}, {"u", 1}, {"gs", 2},
        {NULL, 0}
    };
    if (first_set_matches(input, direct_terminals)) {
        return true;
    }
    
    // Check non-terminals: {operator-name}, {template-param}, {function-param}, {unresolved-name}, {expr-primary}
    return first_of_rule_operator_name(input) ||
           first_of_rule_template_param(input) ||
           first_of_rule_function_param(input) ||
           first_of_rule_unresolved_name(input) ||
           first_of_rule_expr_primary(input);
}

// braced-expression rule (defined after dependencies)
static inline bool first_of_rule_braced_expression(const char *input) {
    return strncmp(input, "di", 2) == 0 || strncmp(input, "dx", 2) == 0 || strncmp(input, "dX", 2) == 0 || first_of_rule_expression(input);
}

// lambda-sig rule (defined after dependencies)
static inline bool first_of_rule_lambda_sig(const char *input) {
    // lambda-sig starts with {type}+ (parameter types or "v" if no parameters)
    return first_of_rule_type(input);
}

// Missing rules from grammar:

// source-name rule
static inline bool first_of_rule_source_name(const char *input) {
    // source-name starts with {number} {identifier}
    return first_of_rule_number(input);
}

// abi-tags rule
static inline bool first_of_rule_abi_tags(const char *input) {
    // abi-tags starts with {abi-tag}
    return first_of_rule_abi_tag(input);
}

// bare-function-type rule
static inline bool first_of_rule_bare_function_type(const char *input) {
    // bare-function-type starts with {type}+ (return type, then parameter types)
    return first_of_rule_type(input);
}

// simple-id rule
static inline bool first_of_rule_simple_id(const char *input) {
    // simple-id: {source-name} [ {template-args} ]
    // First set is just {source-name} since template-args is optional
    return first_of_rule_source_name(input);
}

// unresolved-type rule
static inline bool first_of_rule_unresolved_type(const char *input) {
    // unresolved-type expands:
    // {template-param} [ {template-args} ]  - template-param can optionally have template-args
    // {decltype}
    // {substitution}
    return first_of_rule_template_param(input) ||
           first_of_rule_decltype(input) ||
           first_of_rule_substitution(input);
}

// destructor-name rule
static inline bool first_of_rule_destructor_name(const char *input) {
    // destructor-name expands {unresolved-type} and {simple-id}
    return first_of_rule_unresolved_type(input) || first_of_rule_simple_id(input);
}

// Missing prefix-related rules:

// unresolved-qualifier-level rule
static inline bool first_of_rule_unresolved_qualifier_level(const char *input) {
    // unresolved-qualifier-level expands {simple-id}
    return first_of_rule_simple_id(input);
}

// prefix-or-template-prefix-start rule
static inline bool first_of_rule_prefix_or_template_prefix_start(const char *input) {
    // prefix-or-template-prefix-start expands {unqualified-name}, {template-param}, {substitution}
    return first_of_rule_unqualified_name(input) ||
           first_of_rule_template_param(input) ||
           first_of_rule_substitution(input);
}

// prefix-nested-class-or-namespace rule
static inline bool first_of_rule_prefix_nested_class_or_namespace(const char *input) {
    // prefix-nested-class-or-namespace expands {unqualified-name}
    return first_of_rule_unqualified_name(input);
}

// prefix-start-rr rule
static inline bool first_of_rule_prefix_start_rr(const char *input) {
    // prefix-start-rr expands:
    // {unqualified-name} {template-args}
    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args}
    // {unqualified-name} {template-args} {prefix-start-rr}
    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} {prefix-start-rr}
    return first_of_rule_unqualified_name(input) ||
           first_of_rule_prefix_nested_class_or_namespace(input);
}

// closure-prefix-unit rule
static inline bool first_of_rule_closure_prefix_unit(const char *input) {
    // closure-prefix-unit has many productions, but they all start with:
    // {prefix-or-template-prefix-start}, {decltype}, or {unqualified-name}
    return first_of_rule_prefix_or_template_prefix_start(input) ||
           first_of_rule_decltype(input) ||
           first_of_rule_unqualified_name(input);
}

// closure-prefix-rr rule
static inline bool first_of_rule_closure_prefix_rr(const char *input) {
    // closure-prefix-rr expands:
    // {unqualified-name} M
    // {prefix-start-rr} {unqualified-name} M
    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    // {unqualified-name} {template-args} M
    // ... (all start with unqualified-name or prefix-start-rr)
    return first_of_rule_unqualified_name(input) ||
           first_of_rule_prefix_start_rr(input);
}

// prefix-start-unit rule
static inline bool first_of_rule_prefix_start_unit(const char *input) {
    // prefix-start-unit expands:
    // {prefix-or-template-prefix-start}
    // {decltype}
    // {prefix-or-template-prefix-start} {template-args}
    // {closure-prefix}
    return first_of_rule_prefix_or_template_prefix_start(input) ||
           first_of_rule_decltype(input);
           // Note: closure-prefix creates circular dependency, handled separately
}

// closure-prefix rule
static inline bool first_of_rule_closure_prefix(const char *input) {
    // closure-prefix expands:
    // {closure-prefix-unit}
    // {closure-prefix-unit} {closure-prefix-rr}
    return first_of_rule_closure_prefix_unit(input);
}

// prefix-start rule
static inline bool first_of_rule_prefix_start(const char *input) {
    // prefix-start expands:
    // {prefix-start-unit}
    // {prefix-start-unit} {prefix-start-rr}
    return first_of_rule_prefix_start_unit(input);
}

// prefix rule
static inline bool first_of_rule_prefix(const char *input) {
    // prefix expands:
    // {prefix-start}
    // {prefix-start} {prefix-nested-class-or-namespace}
    return first_of_rule_prefix_start(input);
}

// template-prefix rule
static inline bool first_of_rule_template_prefix(const char *input) {
    // template-prefix expands:
    // {prefix-or-template-prefix-start}
    // {prefix-start} {unqualified-name}
    // {prefix-start} {prefix-nested-class-or-namespace} {unqualified-name}
    return first_of_rule_prefix_or_template_prefix_start(input) ||
           first_of_rule_prefix_start(input);
}

// Missing first set functions that the existing code expects:

// vendor-specific-suffix rule
static inline bool first_of_rule_vendor_specific_suffix(const char *input) {
    // This is a vendor-specific extension, typically starts with any character
    return input != NULL;
}

// offset-number rule (alias for number)
static inline bool first_of_rule_offset_number(const char *input) {
    return first_of_rule_number(input);
}

// virtual-offset-number rule (alias for number)
static inline bool first_of_rule_virtual_offset_number(const char *input) {
    return first_of_rule_number(input);
}

// digit rule
static inline bool first_of_rule_digit(const char *input) {
    return strchr("0123456789", input[0]) != NULL;
}

// qualifiers rule (alias for cv-qualifiers)
static inline bool first_of_rule_qualifiers(const char *input) {
    return first_of_rule_cv_qualifiers(input);
}

// range-begin-expression rule (alias for expression)
static inline bool first_of_rule_range_begin_expression(const char *input) {
    return first_of_rule_expression(input);
}

// range-end-expression rule (alias for expression)
static inline bool first_of_rule_range_end_expression(const char *input) {
    return first_of_rule_expression(input);
}

// field-source-name rule (alias for source-name)
static inline bool first_of_rule_field_source_name(const char *input) {
    return first_of_rule_source_name(input);
}

// index-expression rule (alias for expression)
static inline bool first_of_rule_index_expression(const char *input) {
    return first_of_rule_expression(input);
}

// real-part-float rule (alias for float)
static inline bool first_of_rule_real_part_float(const char *input) {
    return first_of_rule_float(input);
}

// imag-part-float rule (alias for float)
static inline bool first_of_rule_imag_part_float(const char *input) {
    return first_of_rule_float(input);
}

// pointer-type rule
static inline bool first_of_rule_pointer_type(const char *input) {
    return input[0] == 'P';
}

// value-number rule (alias for number)
static inline bool first_of_rule_value_number(const char *input) {
    return first_of_rule_number(input);
}

// value-float rule (alias for float)
static inline bool first_of_rule_value_float(const char *input) {
    return first_of_rule_float(input);
}

// string-type rule
static inline bool first_of_rule_string_type(const char *input) {
    // String types are typically array types
    return first_of_rule_array_type(input);
}

// non-negative-number rule (alias for number)
static inline bool first_of_rule_non_negative_number(const char *input) {
    return first_of_rule_number(input);
}

// top-level-cv-qualifiers rule (alias for cv-qualifiers)
static inline bool first_of_rule_top_level_cv_qualifiers(const char *input) {
    return first_of_rule_cv_qualifiers(input);
}

#endif // FIRST_H 