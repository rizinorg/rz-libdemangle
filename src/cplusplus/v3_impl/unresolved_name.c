// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (unresolved_name, {
    MATCH (
        READ_STR ("srN") && RULE (unresolved_type) &&
        RULE_ATLEAST_ONCE (unresolved_qualifier_level) && READ ('E') &&
        RULE (base_unresolved_name)
    );
    MATCH (
        OPTIONAL (READ_STR ("gs") && APPEND_STR ("::")) && READ_STR ("sr") &&
        RULE_ATLEAST_ONCE (unresolved_qualifier_level) && READ ('E') &&
        RULE (base_unresolved_name)
    );
    MATCH (READ_STR ("sr") && RULE (unresolved_type) && RULE (base_unresolved_name));
    MATCH (OPTIONAL (READ_STR ("gs") && APPEND_STR ("::")) && RULE (base_unresolved_name));
}); 