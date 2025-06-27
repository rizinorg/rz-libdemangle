// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (template_param, {
    SAVE_POS();
    if (READ ('T')) {
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
            if (!READ ('_')) {
                RESTORE_POS();
                return NULL;
            }
            sid = sid + m->template_idx_start;
            if (m->template_params.length > sid &&
                vec_ptr_at (&m->template_params, sid)->name.buf) {
                FORCE_APPEND_TYPE (&vec_ptr_at (&m->template_params, sid)->name);
            }
            return SUBSTITUTE_TPARAM (sid);
        } else if (READ ('_')) {
            size_t sid = m->template_idx_start;
            if (m->template_params.length > sid &&
                vec_ptr_at (&m->template_params, sid)->name.buf) {
                FORCE_APPEND_TYPE (&vec_ptr_at (&m->template_params, sid)->name);
            }
            return SUBSTITUTE_TPARAM (sid);
        }
    }
    RESTORE_POS();
});