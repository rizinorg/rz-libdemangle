// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (type, {
    MATCH (RULE (function_type) && APPEND_TYPE (dem));

    MATCH_AND_DO(first_of_rule_extended_qualifier(CUR()) && RULE_ATLEAST_ONCE(extended_qualifier), {
        MATCH (READ_STR ("rVK") && RULE (type) && APPEND_STR (" restrict const volatile"));
        MATCH (READ_STR ("rV") && RULE (type) && APPEND_STR (" restrict volatile"));
        MATCH (READ_STR ("rK") && RULE (type) && APPEND_STR (" restrict const"));
        MATCH (READ_STR ("VK") && RULE (type) && APPEND_STR (" const volatile"));
        MATCH (READ ('P') && RULE (type) && APPEND_STR ("*") && APPEND_TYPE (dem));
        MATCH (READ ('R') && RULE (type) && APPEND_STR ("&") && APPEND_TYPE (dem));
        MATCH (READ ('K') && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem));
        MATCH (READ ('O') && RULE (type) && APPEND_STR ("&&") && APPEND_TYPE (dem));
        MATCH_FAILED();
    });

    MATCH (READ ('C') && RULE (type)); // complex pair (C99)
    MATCH (READ ('G') && RULE (type)); // imaginary (C99)

    MATCH (READ ('P') && RULE (type) && APPEND_STR ("*") && APPEND_TYPE (dem));
    MATCH (READ ('R') && RULE (type) && APPEND_STR ("&") && APPEND_TYPE (dem));
    MATCH (READ ('O') && RULE (type) && APPEND_STR ("&&") && APPEND_TYPE (dem));
    
    MATCH (READ_STR ("rVK") && RULE (type) && APPEND_STR (" restrict const volatile"));
    MATCH (READ_STR ("rV") && RULE (type) && APPEND_STR (" restrict volatile"));
    MATCH (READ_STR ("rK") && RULE (type) && APPEND_STR (" restrict const"));
    MATCH (READ_STR ("VK") && RULE (type) && APPEND_STR (" const volatile"));
    MATCH (READ ('r') && RULE (type) && APPEND_STR (" restrict"));
    MATCH (READ ('V') && RULE (type) && APPEND_STR (" volatile"));
    MATCH (READ ('K') && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem));

    // MATCH (RULE (template_template_param) && APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem));
    MATCH (RULE (template_param) && APPEND_TYPE (dem) && OPTIONAL(RULE (template_args) && APPEND_TYPE (dem)));
    MATCH (RULE (substitution) && RULE (template_args) && APPEND_TYPE (dem));


    MATCH (RULE (builtin_type));
    MATCH (READ_STR ("Dp") && RULE (type)); // pack expansion (C++11)

    // Extended qualifiers with CV qualifiers
    MATCH (RULE (class_enum_type) && APPEND_TYPE (dem));
    MATCH (RULE (array_type) && APPEND_TYPE (dem));
    MATCH (RULE (pointer_to_member_type) && APPEND_TYPE (dem));
    // MATCH (RULE (template_param) && APPEND_TYPE (dem));
    MATCH (RULE (decltype) && APPEND_TYPE (dem));
    MATCH (RULE (substitution));
});
