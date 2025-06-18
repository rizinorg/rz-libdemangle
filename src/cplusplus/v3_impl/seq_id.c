// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (seq_id, {
    if (IS_DIGIT (PEEK()) || IS_UPPER (PEEK())) {
        char* base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
        char* pos  = NULL;
        ut64  pow  = 1;
        ut64  sid  = 1;
        while ((pos = strchr (base, PEEK()))) {
            st64 based_val  = pos - base;
            sid            += based_val * pow;
            pow            *= 36;
            ADV();
        }
        if(m->trace) {fprintf(stderr, "[TRACE] seq_id: %llu : %s : %s\n", sid, vec_ptr_at (&m->detected_types, sid)->buf, CUR() - 2);}
        return SUBSTITUTE_TYPE (sid);
    } else if (PEEK() == '_') {
        if(m->trace) {fprintf(stderr, "[TRACE] seq_id: 0 : %s : %s\n", vec_ptr_at (&m->detected_types, 0)->buf, CUR() - 2);}
        return SUBSTITUTE_TYPE (0);
    }
}); 
