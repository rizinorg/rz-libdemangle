// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (discriminator, {
    if (READ ('_')) {
        // matched two "_"
        if (READ ('_')) {
            st64 numlt10 = -1;
            READ_NUMBER (numlt10);
            if (numlt10 >= 10) {
                // do something
                return dem;
            }
        } else {
            // matched single "_"
            st64 numlt10 = -1;
            READ_NUMBER (numlt10);
            if (numlt10 >= 0 && numlt10 < 10) {
                // do something
                return dem;
            }
        }
    }
}); 