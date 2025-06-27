// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (closure_prefix, {
    // {closure-prefix-unit}
    MATCH (RULE (closure_prefix_unit) && RULE (closure_prefix_rr));

    // {closure-prefix-unit} {closure-prefix-rr}
    MATCH (RULE (closure_prefix_unit));
});