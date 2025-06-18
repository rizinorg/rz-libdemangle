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

    for (DemString* ds = tmp->detected_types.data + og->detected_types.length;
         ds < tmp->detected_types.data + tmp->detected_types.length;
         ds++) {
        dem_string_deinit (ds);
    }
    UNUSED (vec_deinit (&tmp->detected_types));

    for (DemString* ds = tmp->template_params.data + og->template_params.length;
         ds < tmp->template_params.data + tmp->template_params.length;
         ds++) {
        dem_string_deinit (ds);
    }

    UNUSED (vec_deinit (&tmp->template_params));
    memset (tmp, 0, sizeof (*tmp));
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
DemString*
    match_one_or_more_rules (DemRuleFirst first, DemRule rule, const char* sep, DemString* dem, StrIter* msi, Meta* m) {
    if (!first || !rule || !dem || !msi || !m) {
        return NULL;
    }

    if (m->trace) {
        printf("[TRACE] match_one_or_more_rules: entering, current char: '%.*s', pos: %zu\n", 
               (int)(msi->end - msi->cur), CUR(), msi->cur - msi->beg);
    }

    // NOTE(brightprogrammer): Just here to check the current iteration in debugger
    // No special use
    ut32 iter_for_dbg = 0;

    SAVE_POS();
    /* match atleast once, and then */
    if (first (CUR()) && rule (dem, msi, m) && ++iter_for_dbg) {
        if (m->trace) {
            printf("[TRACE] match_one_or_more_rules: first match successful, iteration: %u\n", iter_for_dbg);
        }
        
        /* match as many as possible */
        while (first (CUR())) {
            DemString tmp = {0};
            SAVE_POS();
            if (rule (&tmp, msi, m) && ++iter_for_dbg) {
                if (m->trace) {
                    printf("[TRACE] match_one_or_more_rules: additional match successful, iteration: %u\n", iter_for_dbg);
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
                    printf("[TRACE] match_one_or_more_rules: additional match failed, stopping loop\n");
                }
                RESTORE_POS();
                dem_string_deinit (&tmp);
                break;
            }
        }

        if (m->trace) {
            printf("[TRACE] match_one_or_more_rules: success, total iterations: %u\n", iter_for_dbg);
        }
        return dem;
    }

    if (m->trace) {
        printf("[TRACE] match_one_or_more_rules: failed to match even once\n");
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
    DemRule     rule,
    const char* sep,
    DemString*  dem,
    StrIter*    msi,
    Meta*       m
) {
    if (!rule || !dem || !msi || !m) {
        return NULL;
    }

    if (m->trace) {
        printf("[TRACE] match_zero_or_more_rules: entering, current char: '%.*s', pos: %zu\n", 
               (int)(msi->end - msi->cur), CUR(), msi->cur - msi->beg);
    }

    ut32 match_count = 0;
    while (true) {
        DemString tmp = {0};
        SAVE_POS();
        if (first (CUR()) && rule (&tmp, msi, m)) {
            match_count++;
            if (m->trace) {
                printf("[TRACE] match_zero_or_more_rules: match successful, count: %u\n", match_count);
            }
            
            if (sep) {
                dem_string_append (&tmp, sep);
            }
            dem_string_concat (dem, &tmp);
            dem_string_deinit (&tmp);
        } else {
            if (m->trace) {
                printf("[TRACE] match_zero_or_more_rules: match failed, stopping loop\n");
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
        printf("[TRACE] match_zero_or_more_rules: success, total matches: %u\n", match_count);
    }
    
    /* we always match, even if nothing matches */
    return dem;
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

    // sometimes by mistake "std" is appended as type, but name manglers don't expect it to be a type
    if (!strcmp (t->buf, "std")) {
        return true;
    }

    // If we're not forcefully appending values, then check for uniqueness of times
    if (!force_append) {
        vec_foreach_ptr (&m->detected_types, dt, {
            if (!strcmp (dt->buf, t->buf)) {
                return true;
            }
        });
    }

    UNUSED (vec_reserve (&m->detected_types, m->detected_types.length + 1));
    m->detected_types.length += 1;
    dem_string_init_clone (vec_end (&m->detected_types), t);
    if(m->trace) {printf("[TRACE] append_type: %llu %s\n", m->detected_types.length, t->buf);}
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
    dem_string_init_clone (vec_end (&m->template_params), t);
    return true;
}

bool make_nested_name (DemString* dem, DemString* pfx, Meta* m) {
    if (!dem || !pfx) {
        return false;
    }

    // if we encounter end of string or :: from reverse search
    // then we have our constructor name
    char* rbeg = strrchr (pfx->buf, ':');
    if ((!rbeg && (rbeg = pfx->buf)) || (rbeg[-1] == ':' && rbeg++)) {
        // generate constructor/destructor name
        if (IS_CTOR()) {
            dem_string_concat (dem, pfx);
            dem_string_append (dem, "::");
            dem_string_append (dem, rbeg);
            if (!m->t_level) {
                m->is_ctor_or_dtor_at_l0 = true;
            }
            UNSET_CTOR();
        } else if (IS_DTOR()) {
            dem_string_concat (dem, pfx);
            dem_string_append (dem, "::~");
            dem_string_append (dem, rbeg);
            if (!m->t_level) {
                m->is_ctor_or_dtor_at_l0 = true;
            }
            UNSET_CTOR();
        } else {
            dem_string_concat (dem, pfx);
        }

        dem_string_deinit (pfx);

        return true;
    } else {
        dem_string_deinit (pfx);
        return false;
    }
}

/*
 * NOTE(brightprogrammer):
 *
 * Another place we find where the grammar is not consistent with real examples.
 * we can have a `ctor_dtor_name` rule just after `template_args` in a `nested_name`,
 * and if you follow the original grammar, there's no way to reach this.
 *
 * I manually added to match an `unqualified_name` after `template_args` in `nested_name`
 * and now it works, with the help of this patch function.
 */
bool make_template_nested_name (DemString* dem, DemString* pfx, DemString* targs, Meta* m) {
    if (!dem || !pfx || !targs) {
        return false;
    }

    // HACK: a hacky way to find name of constructor
    // find content before first "<" (template argument start)
    // find last appearance of "::" that comes just before found "<"

    char* n_end = strchr (pfx->buf, '<');
    char* n_beg = NULL;
    if (n_end) {
        char* pos = pfx->buf;
        while (pos && pos < n_end && (n_beg = pos, pos = strchr (pos, ':'))) {
            pos++;
        }
        if (n_beg == pfx->buf) {
            n_beg = NULL;
        }
    }

    size_t n_len = 0;
    if (n_end && n_beg) {
        n_len = n_end - n_beg;
    } else {
        n_beg = pfx->buf;
        n_len = pfx->len;
    }

    if (IS_CTOR()) {
        dem_string_concat (dem, pfx);
        dem_string_concat (dem, targs);
        dem_string_append (dem, "::");
        dem_string_append_n (dem, n_beg, n_len);
        if (!m->t_level) {
            m->is_ctor_or_dtor_at_l0 = true;
        }
        UNSET_CTOR();
    } else if (IS_DTOR()) {
        dem_string_concat (dem, pfx);
        dem_string_concat (dem, targs);
        dem_string_append (dem, "::~");
        dem_string_append_n (dem, n_beg, n_len);
        if (!m->t_level) {
            m->is_ctor_or_dtor_at_l0 = true;
        }
        UNSET_DTOR();
    } else {
        dem_string_concat (dem, pfx);
        dem_string_concat (dem, targs);
    }

    dem_string_deinit (pfx);
    dem_string_deinit (targs);

    return true;
}
