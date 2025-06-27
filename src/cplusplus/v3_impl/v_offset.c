// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (v_offset, {
    // ignore the number
    DEFER_VAR (_);
    MATCH (
        RULE_DEFER (_, offset_number) && READ ('_') && RULE_DEFER (_, virtual_offset_number) &&
        (dem_string_deinit (_), 1)
    );
});