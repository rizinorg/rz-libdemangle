// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (exception_spec, {
    MATCH (READ_STR ("DO") && RULE (expression) && READ ('E'));
    MATCH (READ_STR ("Dw") && RULE_ATLEAST_ONCE (type) && READ ('E'));
    MATCH (READ_STR ("Do"));
}); 