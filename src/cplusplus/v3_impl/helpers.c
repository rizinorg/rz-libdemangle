// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

bool meta_tmp_init (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return false;
    }

    vec_concat (&tmp->detected_types, &og->detected_types);
    vec_concat (&tmp->template_params, &og->template_params);
    tmp->is_ctor               = og->is_ctor;
    tmp->is_dtor               = og->is_dtor;
    tmp->is_const              = og->is_const;
    tmp->trace                 = og->trace;
    tmp->template_idx_start    = og->template_idx_start;
    tmp->last_reset_idx        = og->last_reset_idx;
    tmp->t_level               = og->t_level;
    tmp->template_reset        = og->template_reset;
    tmp->is_ctor_or_dtor_at_l0 = og->is_ctor_or_dtor_at_l0;

    return false;
}

void meta_tmp_apply (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return;
    }

    // transfer of ownership from tmp to og
    vec_reserve (&og->detected_types, tmp->detected_types.length);
    memcpy (og->detected_types.data, tmp->detected_types.data, vec_mem_size (&tmp->detected_types));
    og->detected_types.length = tmp->detected_types.length;
    memset (tmp->detected_types.data, 0, vec_mem_size (&tmp->detected_types));
    UNUSED (vec_deinit (&tmp->detected_types));

    // transfer of ownership from tmp to og
    vec_reserve (&og->template_params, tmp->template_params.length);
    memcpy (
        og->template_params.data,
        tmp->template_params.data,
        vec_mem_size (&tmp->template_params)
    );
    og->template_params.length = tmp->template_params.length;
    memset (tmp->template_params.data, 0, vec_mem_size (&tmp->template_params));
    UNUSED (vec_deinit (&tmp->template_params));

    og->is_ctor               = tmp->is_ctor;
    og->is_dtor               = tmp->is_dtor;
    og->is_const              = tmp->is_const;
    og->template_idx_start    = tmp->template_idx_start;
    og->last_reset_idx        = tmp->last_reset_idx;
    og->t_level               = tmp->t_level;
    og->template_reset        = tmp->template_reset;
    og->is_ctor_or_dtor_at_l0 = tmp->is_ctor_or_dtor_at_l0;
}

void meta_tmp_fini (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return;
    }

    // Only clean up newly added items in tmp (beyond og's original length)
    // Items 0..og->length-1 are shared and should not be cleaned up
    for (size_t i = og->detected_types.length; i < tmp->detected_types.length; i++) {
        Name* dt = vec_ptr_at (&tmp->detected_types, i);
        dem_string_deinit (&dt->name);
        dt->num_parts = 0;
    }
    UNUSED (vec_deinit (&tmp->detected_types));

    for (size_t i = og->template_params.length; i < tmp->template_params.length; i++) {
        Name* tp = vec_ptr_at (&tmp->template_params, i);
        dem_string_deinit (&tp->name);
        tp->num_parts = 0;
    }
    UNUSED (vec_deinit (&tmp->template_params));

    memset (tmp, 0, sizeof (*tmp));
}

/**
 * \b Parse sequence ID from mangled string iterator.
 *
 * Parses a sequence ID following the Itanium ABI specification:
 * - Empty (just '_'): returns 0
 * - Base-36 digits followed by '_': returns parsed value + 1
 *
 * \p msi   Mangled string iterator positioned at the sequence ID
 * \p m     Meta context (used for tracing if enabled)
 *
 * \return Parsed sequence ID (1 for empty, 2+ for base-36 values) on success
 * \return 0 on failure (invalid format)
 */
size_t parse_sequence_id (StrIter* msi, Meta* m) {
    if (!msi || !m) {
        return 0;
    }

    size_t sid           = 1; // Start at 1 for empty sequence
    bool   parsed_seq_id = false;

    if (IS_DIGIT (PEEK()) || IS_UPPER (PEEK())) {
        char*  base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
        char*  pos  = NULL;
        size_t pow  = 1;
        sid         = 2; // Start at 2 for base-36 sequences (1 + parsed value)
        while ((pos = strchr (base, PEEK()))) {
            size_t based_val  = (size_t)(pos - base);
            sid              += based_val * pow;
            pow              *= 36;
            ADV();
        }
        parsed_seq_id = true;
    } else if (PEEK() == '_') {
        sid           = 1; // Empty sequence maps to 1
        parsed_seq_id = true;
    }

    if (!parsed_seq_id || !READ ('_')) {
        return 0;
    }

    return sid;
}

/**
 * \b Takes a rule and matches at least one occurence of it.
 * Meaning one or more rule matches. If not even a single match is available,
 * then returns NULL.
 *
 * \p rule  Rule to apply one or more times.
 * \p dem   Demangled string will be stored here.
 * \p msi   Mangled string iter.
 *
 * \return dem If at least one rule match exists for given rule.
 * \return NULL otherwise.
 */
DemString* match_one_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m
) {
    if (!first || !rule || !dem || !msi || !m) {
        return NULL;
    }

    if (m->trace) {
        printf (
            "[TRACE] match_one_or_more_rules: entering, current char: '%.*s', pos: %zu\n",
            (int)(msi->end - msi->cur),
            CUR(),
            msi->cur - msi->beg
        );
    }

    // NOTE(brightprogrammer): Just here to check the current iteration in debugger
    // No special use
    ut32 iter_for_dbg = 0;

    SAVE_POS();
    /* match atleast once, and then */
    if (first (CUR()) && rule (dem, msi, m) && ++iter_for_dbg) {
        if (m->trace) {
            printf (
                "[TRACE] match_one_or_more_rules: first match successful, iteration: %u\n",
                iter_for_dbg
            );
        }

        /* match as many as possible */
        while (first (CUR())) {
            DemString tmp = {0};
            SAVE_POS();
            if (rule (&tmp, msi, m) && ++iter_for_dbg) {
                if (m->trace) {
                    printf (
                        "[TRACE] match_one_or_more_rules: additional match successful, iteration: "
                        "%u\n",
                        iter_for_dbg
                    );
                }

                /* add separator before appending demangled string */
                if (sep) {
                    dem_string_append_prefix_n (&tmp, sep, strlen (sep));
                }

                /* append the demangled string and deinit tmp */
                dem_string_concat (dem, &tmp);
                dem_string_deinit (&tmp);
            } else {
                if (m->trace) {
                    printf (
                        "[TRACE] match_one_or_more_rules: additional match failed, stopping loop\n"
                    );
                }
                RESTORE_POS();
                dem_string_deinit (&tmp);
                break;
            }
        }

        if (m->trace) {
            printf (
                "[TRACE] match_one_or_more_rules: success, total iterations: %u\n",
                iter_for_dbg
            );
        }
        return dem;
    }

    if (m->trace) {
        printf ("[TRACE] match_one_or_more_rules: failed to match even once\n");
    }
    RESTORE_POS();
    return NULL;
}

/**
 * \b Takes a rule and matches at any number of occurences of it.
 * Meaning one or more rule matches. If not even a single match is available,
 * then returns NULL.
 *
 * \p rule  Rule to apply any number of times.
 * \p sep   If provided, is appended after each rule match success.
 * \p dem   Demangled string will be stored here.
 * \p msi   Mangled string iter.
 *
 * \return dem If given arguments are non-null.
 * \return NULL otherwise.
 */
DemString* match_zero_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m
) {
    if (!rule || !dem || !msi || !m) {
        return NULL;
    }

    if (m->trace) {
        printf (
            "[TRACE] match_zero_or_more_rules: entering, current char: '%.*s', pos: %zu\n",
            (int)(msi->end - msi->cur),
            CUR(),
            msi->cur - msi->beg
        );
    }

    ut32 match_count = 0;
    while (true) {
        DemString tmp = {0};
        SAVE_POS();
        if (first (CUR()) && rule (&tmp, msi, m)) {
            match_count++;
            if (m->trace) {
                printf (
                    "[TRACE] match_zero_or_more_rules: match successful, count: %u\n",
                    match_count
                );
            }

            if (sep) {
                dem_string_append (&tmp, sep);
            }
            dem_string_concat (dem, &tmp);
            dem_string_deinit (&tmp);
        } else {
            if (m->trace) {
                printf ("[TRACE] match_zero_or_more_rules: match failed, stopping loop\n");
            }
            RESTORE_POS();
            dem_string_deinit (&tmp);
            break;
        }
    }

    /* remove last sep */
    // if (sep) {
    //     for (int l = 0; l < strlen (sep); l++) {
    //         dem->buf[--dem->len] = 0;
    //     }
    // }

    if (m->trace) {
        printf ("[TRACE] match_zero_or_more_rules: success, total matches: %u\n", match_count);
    }

    /* we always match, even if nothing matches */
    return dem;
}

// counts the number of :: in a name and adds 1 to it
// but ignores :: inside template arguments (between < and >)
static ut32 count_name_parts (Name* n) {
    // count number of parts
    const char* it     = n->name.buf;
    const char* end    = it + n->name.len;
    n->num_parts       = 1;
    int template_depth = 0;

    while (it < end) {
        if (*it == '<') {
            template_depth++;
        } else if (*it == '>') {
            template_depth--;
        } else if (template_depth == 0 && it[0] == ':' && it[1] == ':') {
            // Only count :: when we're not inside template arguments
            if (it[2]) {
                n->num_parts++;
                it += 2; // advance past the "::" to avoid infinite loop
                continue;
            } else {
                fprintf (stderr, "invalid name provided to be appended : %s", n->name.buf);
                dem_string_deinit (&n->name);
                n->num_parts = 0;
                return 0;
            }
        }
        it++;
    }
    return n->num_parts;
}

/**
 * Append given type name to list of all detected types.
 * This vector is then used to refer back to a detected type in substitution
 * rules.
 */
bool append_type (Meta* m, DemString* t, bool force_append) {
    if (!m || !t || !t->len) {
        return false;
    }

    // A hack to ingore constant values getting forcefully added from RULE(template_param)
    // because templates sometimes get values like "true", "false", "4u", etc...
    if (IS_DIGIT (t->buf[0]) || !strcmp (t->buf, "true") || !strcmp (t->buf, "false")) {
        return true;
    }

    // sometimes by mistake "std" is appended as type, but name manglers don't generate it to be a type
    if (!strcmp (t->buf, "std")) {
        return true;
    }

    // If we're not forcefully appending values, then check for uniqueness of times
    if (!force_append) {
        vec_foreach_ptr (&m->detected_types, dt, {
            if (!strcmp (dt->name.buf, t->buf)) {
                return true;
            }
        });
    }

    UNUSED (vec_reserve (&m->detected_types, m->detected_types.length + 1));
    m->detected_types.length += 1;

    Name* new_name = vec_end (&m->detected_types);
    dem_string_init_clone (&new_name->name, t);
    if (!count_name_parts (new_name)) {
        m->detected_types.length--;
        return false;
    }

    if (m->trace) {
        printf (
            "[TRACE] append_type: %llu %s (parts = %u)\n",
            m->detected_types.length,
            new_name->name.buf,
            new_name->num_parts
        );
    }
    return true;
}

/**
 * Much like `append_type`, but for templates.
 */
bool append_tparam (Meta* m, DemString* t) {
    if (!m || !t || !t->len) {
        return false;
    }

    UNUSED (vec_reserve (&m->template_params, m->template_params.length + 1));
    m->template_params.length += 1;

    Name* new_name = vec_end (&m->template_params);
    dem_string_init_clone (&new_name->name, t);
    if (!count_name_parts (new_name)) {
        m->template_params.length--;
        return false;
    }

    if (m->trace) {
        printf (
            "[TRACE] append_tparam : %llu %s (parts = %u)\n",
            m->template_params.length,
            new_name->name.buf,
            new_name->num_parts
        );
    }

    return true;
}
