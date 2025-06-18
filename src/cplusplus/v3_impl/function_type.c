// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (function_type, {
    DEFER_VAR (rtype);
    bool is_ptr = false;

    // if PF creates a (*)
    // simple F does not create any bracket
    // Example : PFvPvE -> void (*)(void*)
    // Example : FvPvE -> void (void*)

    MATCH (
        OPTIONAL(is_ptr = READ('P')) &&
         
        OPTIONAL(RULE (cv_qualifiers)) && OPTIONAL (RULE (exception_spec)) &&
        OPTIONAL (READ_STR ("Dx")) && READ ('F') && OPTIONAL (READ ('Y')) && 

        // Return type. If return type is builtin type, then it's not substitutable
        // If return type is a type, then it's substitutable, so add using APPEND_TYPE
        (RULE_DEFER(rtype, builtin_type) || ((RULE_DEFER(rtype, type)) && APPEND_TYPE(rtype))) &&
        APPEND_DEFER_VAR(rtype) && 

        // if a pointer then we'll have a function pointer (*)
        (is_ptr ? APPEND_STR(" (*)") : APPEND_CHR(' ')) &&
        
        // arguments
        APPEND_STR("(") && RULE_ATLEAST_ONCE_WITH_SEP (type, ", ") && APPEND_STR(")") &&

        OPTIONAL (RULE (ref_qualifier)) && READ ('E')
    );
    dem_string_deinit (rtype);
});
