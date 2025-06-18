// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (unresolved_type, {
    MATCH (RULE (template_param) && FORCE_APPEND_TYPE (dem) && OPTIONAL (RULE (template_args) && APPEND_TYPE (dem)));
    MATCH (RULE (decltype));
    MATCH (RULE (substitution));
}); 