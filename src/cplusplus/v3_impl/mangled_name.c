// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (mangled_name, {
    MATCH (
        READ_STR ("_Z") && RULE (encoding) && OPTIONAL (READ ('.') && RULE (vendor_specific_suffix))
    );
});