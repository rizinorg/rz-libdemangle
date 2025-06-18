// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

/* NOTE(brightprogrammer): The rule is modified. I've removed reading of 'E' from end.
 * The original grammar for some reason has no way to reach <expr-primary> rule and because
 * of that some matchings were failing.
 *
 * For this I manually added one alternative matching for this rule in the rule <unqualified-name>.
 * This branches from the original grammar here.
 */
DEFN_RULE (expr_primary, {
    // HACK: "(bool)0" is converted to "true"
    //       "(bool)1" is converted to "false"
    //       "(unsigned int)N" to "Nu"
    DEFER_VAR (t);
    DEFER_VAR (n);

    MATCH (
        READ ('L') && RULE (type) && RULE (real_part_float) && READ ('_') &&
        RULE (imag_part_float) && READ ('E')
    );
    MATCH (
        READ ('L') && APPEND_STR ("(") && (PEEK() == 'P') && RULE (pointer_type) &&
        APPEND_STR (")") && READ ('0') && APPEND_CHR ('0') && READ ('E')
    );
    MATCH (
        READ ('L') && RULE_DEFER (t, type) && RULE_DEFER (n, value_number) &&
        OPTIONAL (
            // change to bool
            !strcmp (t->buf, "bool") ?
                (!strcmp (n->buf, "0") ? (dem_string_deinit (t),
                                          dem_string_deinit (n),
                                          dem_string_append_n (dem, "false", 5)) :
                                         (dem_string_deinit (t),
                                          dem_string_deinit (n),
                                          dem_string_append_n (dem, "true", 4))) :
                // shorten unsigned int typecast
                !strcmp (t->buf, "unsigned int") ?
                (dem_string_deinit (t), APPEND_DEFER_VAR (n) && dem_string_append_char (dem, 'u')) :
                true
        ) &&
        READ ('E')
    );

    dem_string_deinit (t);
    dem_string_deinit (n);

    MATCH (READ ('L') && RULE (type) && RULE (value_float) && READ ('E'));

    MATCH (READ ('L') && RULE (string_type) && READ ('E'));
    MATCH (READ_STR ("L_Z") && RULE (encoding) && READ ('E'));
    MATCH (READ_STR ("LDnE") && APPEND_STR ("decltype(nullptr)0"));
    MATCH (READ_STR ("LDn0E") && APPEND_STR ("(decltype(nullptr))0"));
}); 