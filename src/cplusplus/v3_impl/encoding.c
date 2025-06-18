// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (encoding, {
    bool is_const_fn = false;
    MATCH (
        OPTIONAL (
            is_const_fn = (PEEK_AT (0) == 'N' && PEEK_AT (1) == 'K') || (PEEK_AT (0) == 'K')
        ) &&
        RULE (name) && APPEND_CHR ('(') && RULE (bare_function_type) && APPEND_CHR (')') &&
        OPTIONAL (is_const_fn && APPEND_STR (" const"))
    );
    MATCH (RULE (name));
    MATCH (RULE (special_name));
});
