// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (unnamed_type_name, {
    if (READ_STR ("Ut")) {
        st64 tidx = -1;
        READ_NUMBER (tidx);
        if (tidx >= 0) {
            // do something
        } else {
            return NULL;
        }

        if (READ ('_')) {
            return dem;
        }
    }
}); 