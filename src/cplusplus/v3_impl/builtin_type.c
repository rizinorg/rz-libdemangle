// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (builtin_type, {
    MATCH (READ_STR ("DF") && APPEND_STR ("_Float") && RULE (number) && READ ('_'));
    MATCH (
        READ_STR ("DF") && APPEND_STR ("_Float") && RULE (number) && READ ('x') && APPEND_STR ("x")
    );
    MATCH (
        READ_STR ("DF") && APPEND_STR ("std::bfloat") && RULE (number) && READ ('b') &&
        APPEND_STR ("_t")
    );
    MATCH (
        READ_STR ("DB") && APPEND_STR ("signed _BitInt(") && RULE (number) && APPEND_STR (")") &&
        READ ('_')
    );
    MATCH (
        READ_STR ("DB") && APPEND_STR ("signed _BitInt(") && RULE (expression) &&
        APPEND_STR (")") && READ ('_')
    );
    MATCH (
        READ_STR ("DU") && APPEND_STR ("unsigned _BitInt(") && RULE (number) && APPEND_STR (")") &&
        READ ('_')
    );
    MATCH (
        READ_STR ("DU") && APPEND_STR ("unsigned _BitInt(") && RULE (expression) &&
        APPEND_STR (")") && READ ('_')
    );
    MATCH (READ ('u') && RULE (source_name) && OPTIONAL (RULE (template_args)));
    MATCH (READ_STR ("DS") && READ_STR ("DA") && APPEND_STR ("_Sat _Accum"));
    MATCH (READ_STR ("DS") && READ_STR ("DR") && APPEND_STR ("_Sat _Fract"));
    MATCH (READ ('v') && APPEND_STR ("void"));
    MATCH (READ ('w') && APPEND_STR ("wchar_t"));
    MATCH (READ ('b') && APPEND_STR ("bool"));
    MATCH (READ ('c') && APPEND_STR ("char"));
    MATCH (READ ('a') && APPEND_STR ("signed char"));
    MATCH (READ ('h') && APPEND_STR ("unsigned char"));
    MATCH (READ ('s') && APPEND_STR ("short"));
    MATCH (READ ('t') && APPEND_STR ("unsigned short"));
    MATCH (READ ('i') && APPEND_STR ("int"));
    MATCH (READ ('j') && APPEND_STR ("unsigned int"));
    MATCH (READ ('l') && APPEND_STR ("long"));
    MATCH (READ ('m') && APPEND_STR ("unsigned long"));
    MATCH (READ ('x') && APPEND_STR ("long long"));
    MATCH (READ ('y') && APPEND_STR ("unsigned long long"));
    MATCH (READ ('n') && APPEND_STR ("__int128"));
    MATCH (READ ('o') && APPEND_STR ("unsigned __int128"));
    MATCH (READ ('f') && APPEND_STR ("float"));
    MATCH (READ ('d') && APPEND_STR ("double"));
    MATCH (READ ('e') && APPEND_STR ("long double"));
    MATCH (READ ('g') && APPEND_STR ("__float128"));
    MATCH (READ ('z') && APPEND_STR ("..."));
    MATCH (READ_STR ("Dd") && APPEND_STR ("decimal64"));
    MATCH (READ_STR ("De") && APPEND_STR ("decimal128"));
    MATCH (READ_STR ("Df") && APPEND_STR ("decimal32"));
    MATCH (READ_STR ("Dh") && APPEND_STR ("half"));
    MATCH (READ_STR ("Di") && APPEND_STR ("char32_t"));
    MATCH (READ_STR ("Ds") && APPEND_STR ("char16_t"));
    MATCH (READ_STR ("Du") && APPEND_STR ("char8_t"));
    MATCH (READ_STR ("Da") && APPEND_STR ("auto"));
    MATCH (READ_STR ("Dc") && APPEND_STR ("decltype(auto)"));
    MATCH (READ_STR ("Dn") && APPEND_STR ("std::nullptr_t"));
    MATCH (READ_STR ("DA") && APPEND_STR ("_Accum"));
    MATCH (READ_STR ("DR") && APPEND_STR ("_Fract"));
});