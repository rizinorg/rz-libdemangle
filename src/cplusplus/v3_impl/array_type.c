// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (array_type, {
    MATCH (READ ('A') && OPTIONAL (RULE (number)) && READ ('_') && RULE (type));
    MATCH (READ ('A') && RULE (expression) && READ ('_') && RULE (type));
}); 