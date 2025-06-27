// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (template_arg, {
    MATCH (READ ('X') && RULE (expression) && READ ('E'));
    MATCH (READ ('J') && RULE_MANY (template_arg) && READ ('E'));
    MATCH (RULE (type));
    MATCH (RULE (expr_primary));
});