// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (base_unresolved_name, {
    MATCH (READ_STR ("on") && RULE (operator_name) && RULE (template_args));
    MATCH (READ_STR ("on") && RULE (operator_name));
    MATCH (READ_STR ("dn") && RULE (destructor_name));
    MATCH (RULE (simple_id));
}); 