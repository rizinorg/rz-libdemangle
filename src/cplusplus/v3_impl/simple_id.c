// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (simple_id, {
    MATCH (
        RULE (source_name) && APPEND_TYPE (dem) &&
        OPTIONAL (RULE (template_args) && APPEND_TYPE (dem))
    );
});