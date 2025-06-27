// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (decltype, {
    MATCH (READ_STR ("Dt") && RULE (expression) && READ ('E'));
    MATCH (READ_STR ("DT") && RULE (expression) && READ ('E'));
});