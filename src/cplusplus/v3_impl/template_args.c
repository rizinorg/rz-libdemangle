// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (template_args, {
    bool is_const;

    // we going down the rabbit hope
    m->t_level++;

    // in case we reset the template types (m->template_params)
    size_t template_idx_start = m->last_reset_idx;
    size_t last_reset_idx     = m->template_params.length;

    // if we're here more than once at the topmost level (t->level = 0)
    // then this means we have something like A<..>::B<...>
    // were we're just starting to read B, and have already parsed and generate template for A
    // now B won't be using A's template type substitutions, so we increase the offset
    // from which we use the template substitutions.
    if (m->template_reset) {
        m->template_idx_start = template_idx_start;
        m->last_reset_idx     = last_reset_idx;
        m->template_reset     = false;
    }

    MATCH_AND_DO (
        OPTIONAL ((is_const = IS_CONST()) && UNSET_CONST()) && READ ('I') && APPEND_CHR ('<') &&
            RULE_ATLEAST_ONCE_WITH_SEP (template_arg, ", ") && APPEND_CHR ('>') && READ ('E'),
        {
            // uppity up up
            m->t_level--;

            // number of <templates> at level 0
            if (!m->t_level) {
                m->template_reset = true;
            }

            if (is_const) {
                SET_CONST();
            }
        }
    );

    m->t_level--;
}); 