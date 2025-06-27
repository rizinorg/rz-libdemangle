// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (name, {
    MATCH (RULE (unscoped_name) && APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem));
    MATCH (RULE (substitution) && RULE (template_args) && APPEND_TYPE (dem));

    MATCH (
        RULE (nested_name)
    ); // NOTE: Nested name adds type selectively automatically, so no need to do it here!
    MATCH (RULE (unscoped_name));
    MATCH (RULE (local_name) && APPEND_TYPE (dem));
});
