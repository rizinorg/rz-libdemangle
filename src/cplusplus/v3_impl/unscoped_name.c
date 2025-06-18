// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (unscoped_name, {
    MATCH (READ_STR ("St") && APPEND_STR ("std::")&& RULE (unqualified_name) && APPEND_TYPE(dem));
    MATCH (RULE (unqualified_name));
}); 