// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (digit, {
    if (IS_DIGIT (PEEK())) {
        APPEND_CHR (PEEK());
        ADV();
        return dem;
    }
}); 