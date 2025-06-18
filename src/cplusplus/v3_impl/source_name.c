// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (source_name, {
    /* positive number providing length of name followed by it */
    st64 name_len = 0;
    READ_NUMBER (name_len);

    if (name_len > 0) {
        /* identifiers don't start with digits or any other special characters */
        if (name_len-- && (IS_ALPHA (PEEK()) || PEEK() == '_')) {
            APPEND_CHR (PEEK());
            ADV();

            /* keep matching while length remains and a valid character is found*/
            while (name_len-- && (IS_ALPHA (PEEK()) || IS_DIGIT (PEEK()) || PEEK() == '_')) {
                APPEND_CHR (PEEK());
                ADV();
            }

            /* if length is non-zero after reading, then the name is invalid. */
            /* NOTE(brightprogrammer): for correct cases length actually goes "-1" here */
            if (name_len > 0) {
                return NULL;
            }

            /* if atleast one character matches */
            return dem;
        }
    }
}); 