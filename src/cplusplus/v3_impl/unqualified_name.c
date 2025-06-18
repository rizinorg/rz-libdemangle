// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (unqualified_name, {
// NOTE(brightprogrammer):
// Manual replacements, this is not in original grammar
#if REPLACE_GLOBAL_N_WITH_ANON_NAMESPACE
    MATCH (READ_STR ("DC") && RULE_ATLEAST_ONCE (source_name) && READ ('E'));
#endif

    MATCH (RULE (operator_name) && OPTIONAL (RULE (abi_tags)));
    MATCH (READ_STR ("12_GLOBAL__N_1") && APPEND_STR ("(anonymous namespace)"));
    MATCH (RULE (ctor_dtor_name));
    MATCH (RULE (source_name));
    /* MATCH (RULE (expr_primary)); */
    MATCH (RULE (unnamed_type_name));
}); 
