// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include "types.h"


bool we_are_at_an_unqualified_name_starting (const char* p) {
    if (!p || !*p) {
        return false;
    }

    // Check for special global namespace replacement (starting with "12_GLOBAL__N_1")
    if (p[0] == '1' && p[1] == '2' && p[2] == '_' && strncmp (p, "12_GLOBAL__N_1", 14) == 0) {
        return true;
    }

    // Check for source_name (starting with digits)
    if (p[0] >= '0' && p[0] <= '9') {
        return true;
    }

    // Handle 'C' character patterns
    if (p[0] == 'C') {
        // Check for complete ctor names (C1, C2, C3, C4, C5, CI1, CI2)
        if (p[1] == '1' || p[1] == '2' || p[1] == '3' || p[1] == '4' || p[1] == '5') {
            return true;
        }
        if (p[1] == 'I' && p[2] && (p[2] == '1' || p[2] == '2')) {
            return true;
        }
        // Check for operator names starting with 'c'
        if (p[1] == 'o' || p[1] == 'l' || p[1] == 'm' || p[1] == 'p' || p[1] == 'v' ||
            p[1] == 'c') {
            return true;
        }
    }

    // Handle 'D' character patterns (more specific patterns first)
    if (p[0] == 'D') {
        // Check for structured binding declaration first (DC)
        if (p[1] == 'C') {
            return true;
        }
        // Check for dtor names (D0, D1, D2, D4, D5)
        if (p[1] == '0' || p[1] == '1' || p[1] == '2' || p[1] == '4' || p[1] == '5') {
            return true;
        }
        // Check for decltype (Dt, DT)
        if (p[1] == 't' || p[1] == 'T') {
            return true;
        }
        // Check for operator names starting with 'd'
        if (p[1] == 'l' || p[1] == 'a' || p[1] == 'e' || p[1] == 'v' || p[1] == 'V') {
            return true;
        }
    }

    // Check for operator names (match at least 2 characters when possible)
    if (p[0] == 'n') {
        if (p[1] == 'w' || p[1] == 'a' || p[1] == 'g' || p[1] == 't' || p[1] == 'x') {
            return true;
        }
    }
    if (p[0] == 'a') {
        if (p[1] == 'w' || p[1] == 'd' || p[1] == 'n' || p[1] == 'a' || p[1] == 'S' ||
            p[1] == 'N' || p[1] == 't' || p[1] == 'z') {
            return true;
        }
    }
    if (p[0] == 'p') {
        if (p[1] == 's' || p[1] == 'l' || p[1] == 'L' || p[1] == 'p' || p[1] == 'm' ||
            p[1] == 't') {
            return true;
        }
    }
    if (p[0] == 'm') {
        if (p[1] == 'i' || p[1] == 'l' || p[1] == 'I' || p[1] == 'L' || p[1] == 'm') {
            return true;
        }
    }
    if (p[0] == 'r') {
        if (p[1] == 'm' || p[1] == 's' || p[1] == 'M' || p[1] == 'S' || p[1] == 'c') {
            return true;
        }
    }
    if (p[0] == 'e') {
        if (p[1] == 'o' || p[1] == 'O' || p[1] == 'q') {
            return true;
        }
    }
    if (p[0] == 'l') {
        if (p[1] == 's' || p[1] == 'S' || p[1] == 't' || p[1] == 'e' || p[1] == 'i') {
            return true;
        }
    }
    if (p[0] == 'g') {
        if (p[1] == 't' || p[1] == 'e') {
            return true;
        }
    }
    if (p[0] == 's') {
        if (p[1] == 's' || p[1] == 'r' || p[1] == 'Z' || p[1] == 'P' || p[1] == 'p' ||
            p[1] == 't' || p[1] == 'z' || p[1] == 'c') {
            return true;
        }
    }
    if (p[0] == 'o') {
        if (p[1] == 'r' || p[1] == 'R' || p[1] == 'o' || p[1] == 'n') {
            return true;
        }
    }
    if (p[0] == 'q') {
        if (p[1] == 'u') {
            return true;
        }
    }
    if (p[0] == 'i') {
        if (p[1] == 'x' || p[1] == 'l') {
            return true;
        }
    }
    if (p[0] == 't') {
        if (p[1] == 'i' || p[1] == 'e' || p[1] == 'l' || p[1] == 'w' || p[1] == 'r') {
            return true;
        }
    }
    if (p[0] == 'f') {
        if (p[1] == 'l' || p[1] == 'r' || p[1] == 'L' || p[1] == 'R' || p[1] == 'p') {
            return true;
        }
    }
    if (p[0] == 'v') {
        // vendor extended operator: v {digit} {source-name}
        if (p[1] >= '0' && p[1] <= '9') {
            return true;
        }
    }

    // Check for unnamed_type_name (starting with 'U')
    if (p[0] == 'U') {
        if (p[1] == 't' || p[1] == 'l') { // Ut for unnamed type, Ul for closure/lambda
            return true;
        }
    }

    // Check for template parameters (T_ or T{number}_)
    if (p[0] == 'T') {
        if (p[1] == '_' || (p[1] >= '0' && p[1] <= '9')) {
            return true;
        }
    }

    // Check for substitutions (S_ or S{seq-id}_ or special ones like St, Sa, Sb, Ss, Si, So, Sd)
    if (p[0] == 'S') {
        if (p[1] == '_' || p[1] == 't' || p[1] == 'a' || p[1] == 'b' || p[1] == 's' ||
            p[1] == 'i' || p[1] == 'o' || p[1] == 'd' || (p[1] >= '0' && p[1] <= '9') ||
            (p[1] >= 'A' && p[1] <= 'Z')) {
            return true;
        }
    }

    // Check for vendor extended expressions/types starting with 'u'
    if (p[0] == 'u') {
        return true;
    }

    return false;
}

DEFN_RULE (prefix_nested_class_or_namespace, {
    // {unqualified-name} {prefix-nested-class-or-namespace}
    MATCH (RULE (unqualified_name) && APPEND_TYPE (dem) && APPEND_STR ("::") && RULE (prefix_nested_class_or_namespace) && APPEND_TYPE (dem));

    // {unqualified-name}
    MATCH (RULE (unqualified_name) && we_are_at_an_unqualified_name_starting (msi->cur) && APPEND_TYPE (dem));
});
