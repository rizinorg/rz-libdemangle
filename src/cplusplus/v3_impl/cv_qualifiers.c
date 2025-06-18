// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (cv_qualifiers, {
    MATCH (READ ('r') && APPEND_STR ("restrict"));
    MATCH (READ ('V') && APPEND_STR ("volatile"));
    MATCH (READ ('K') && SET_CONST());
}); 