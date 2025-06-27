// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (prefix_start, {
    MATCH (RULE (prefix_start_unit) && RULE (prefix_start_rr));
    MATCH (RULE (prefix_start_unit));
});
