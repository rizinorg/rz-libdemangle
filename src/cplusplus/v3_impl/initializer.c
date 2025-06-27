// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (initializer, {
    MATCH (
        READ_STR ("pi") && APPEND_STR (" (") && RULE_MANY_WITH_SEP (expression, ", ") &&
        APPEND_CHR (')') && READ ('E')
    );
});