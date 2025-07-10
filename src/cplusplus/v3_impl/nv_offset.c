// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (nv_digit, {
    if (IS_DIGIT (PEEK())) {
        ADV();
        TRACE_RETURN_SUCCESS (dem);
    }

    TRACE_RETURN_FAILURE();
});

#define first_of_rule_nv_digit first_of_rule_digit

DEFN_RULE (nv_offset, { MATCH (OPTIONAL (READ ('n')) && RULE_ATLEAST_ONCE (nv_digit)); });
