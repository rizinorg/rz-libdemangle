// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (prefix_or_template_prefix_start, {
    MATCH (RULE (unqualified_name));
    MATCH (RULE (template_param));
    MATCH (RULE (substitution));
});
