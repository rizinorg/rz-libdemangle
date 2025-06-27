// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (extended_qualifier, {
    MATCH (READ ('U') && RULE (source_name) && RULE (template_args));
    MATCH (READ ('U') && RULE (source_name));
});