// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (local_name, {
    MATCH (
        READ ('Z') && RULE (encoding) && READ_STR ("Ed") && 
        OPTIONAL (RULE (number)) && READ ('_') && RULE (name)
    );
    MATCH (
        READ ('Z') && RULE (encoding) && READ ('E') && RULE (name) && 
        OPTIONAL (RULE (discriminator))
    );
    MATCH (
        READ ('Z') && RULE (encoding) && READ_STR ("Es") && 
        OPTIONAL (RULE (discriminator))
    );
}); 