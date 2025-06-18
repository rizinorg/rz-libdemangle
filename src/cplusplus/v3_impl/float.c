// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (float, {
    bool r = false;
    while (IS_DIGIT (PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
        r = true;
        ADV();
    }
    return r ? dem : NULL;
}); 