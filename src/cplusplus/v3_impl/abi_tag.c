// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (abi_tag, {
    // will generate " \"<source_name>\","
    MATCH (READ ('B') && APPEND_STR (" \"") && RULE (source_name) && APPEND_STR ("\","));
}); 