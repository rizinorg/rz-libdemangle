// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (function_param, {
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && RULE (non_negative_number) &&
        READ ('_')
    );
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && READ ('_')
    );
    MATCH (
        READ_STR ("fp") && RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') &&
        RULE (non_negative_number) && READ ('_')
    );
    MATCH (READ_STR ("fp") && RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && READ ('_'));
    MATCH (READ_STR ("fPT"));
});