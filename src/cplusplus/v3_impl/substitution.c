// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (substitution, {
    // HACK(brightprogrammer): This is not in original grammar, but this works!
    // Because having a "7__cxx11" just after a substitution "St" does not make sense to original grammar
    // Placing it here is also important, the order matters!
    MATCH (READ ('S') && RULE (seq_id) && READ ('_'));

    MATCH (READ_STR ("St7__cxx11") && APPEND_STR ("std::__cxx11"));
    MATCH (READ_STR ("St") && APPEND_STR ("std"));
    MATCH (READ_STR ("Sa") && APPEND_STR ("std::allocator"));
    MATCH (READ_STR ("Sb") && APPEND_STR ("std::basic_string"));
    MATCH (
        READ_STR ("Ss") &&
        // APPEND_STR ("std::basic_string<char, std::char_traits<char>, std::allocator<char>>")
        APPEND_STR ("std::string")
    );
    MATCH (
        READ_STR ("Si") && APPEND_STR ("std::istream")
        // APPEND_STR ("std::basic_istream<char, std::char_traits<char>>")
    );
    MATCH (
        READ_STR ("So") && APPEND_STR ("std::ostream")
        // APPEND_STR ("std::basic_ostream<char, std::char_traits<char>>")
    );

    MATCH (
        READ_STR ("Sd") && APPEND_STR ("std::iostream")
        // APPEND_STR ("std::basic_iostream<char, std::char_traits<char>>")
    );
});