// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (braced_expression, {
    MATCH (
        READ_STR ("dX") && APPEND_STR (" [") && RULE (range_begin_expression) &&
        APPEND_STR (" ... ") && RULE (range_end_expression) && APPEND_STR ("] = ") &&
        RULE (braced_expression)
    );
    MATCH (
        READ_STR ("di") && APPEND_STR (" .") && RULE (field_source_name) && APPEND_STR (" = ") &&
        RULE (braced_expression)
    );
    MATCH (
        READ_STR ("dx") && APPEND_STR (" [") && RULE (index_expression) && APPEND_STR ("] = ") &&
        RULE (braced_expression)
    );
    MATCH (RULE (expression));
});