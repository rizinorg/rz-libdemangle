// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (call_offset, {
    MATCH (READ ('h') && APPEND_STR ("non-virtual thunk to ") && RULE (nv_offset) && READ ('_'));
    MATCH (READ ('v') && APPEND_STR ("virtual thunk to ") && RULE (v_offset) && READ ('_'));
}); 