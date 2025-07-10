// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "macros.h"
#include "types.h"

DEFN_RULE (prefix_start, {
    DEFER_VAR (pfx_rr);
    MATCH (
        RULE (prefix_start_unit) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        )
    );
});
