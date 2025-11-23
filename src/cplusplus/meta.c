#include "types.h"


bool meta_tmp_init (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return false;
    }

    vec_concat (&tmp->detected_types, &og->detected_types);
    vec_concat (&tmp->template_params, &og->template_params);
    vec_concat (&tmp->parent_type_kinds, &og->parent_type_kinds);
    ;
    tmp->is_ctor  = og->is_ctor;
    tmp->is_dtor  = og->is_dtor;
    tmp->is_const = og->is_const;

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
    vec_move (&og->detected_types, &tmp->detected_types);
    vec_move (&og->template_params, &tmp->template_params);
    vec_move (&og->parent_type_kinds, &tmp->parent_type_kinds);

    og->is_ctor  = tmp->is_ctor;
    og->is_dtor  = tmp->is_dtor;
    og->is_const = tmp->is_const;

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
    UNUSED (vec_deinit (&tmp->parent_type_kinds));

    memset (tmp, 0, sizeof (*tmp));
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

    return true;
}

/**
 * Refer back to a previous type from detected types and then add that
 * type to the currently demangled string
 */
DemString* meta_substitute_type (Meta* m, ut64 id, DemString* dem) {
    if (m->detected_types.length > id) {
        Name* type_name = vec_ptr_at (&m->detected_types, id);
        if (type_name && type_name->name.buf) {
            dem_string_append (dem, type_name->name.buf);
            return dem;
        }
    }
    return NULL;
}

DemString* meta_substitute_tparam (Meta* m, ut64 id, DemString* dem) {
    if (m->template_params.length > id) {
        Name* tparam_name = vec_ptr_at (&m->template_params, id);
        if (tparam_name && tparam_name->name.buf) {
            dem_string_append (dem, tparam_name->name.buf);
            return dem;
        }
    }
    return NULL;
}

// counts the number of :: in a name and adds 1 to it
// but ignores :: inside template arguments (between < and >)
ut32 count_name_parts (Name* n) {
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
                // this case is possible and must be ignored with an error
                dem_string_deinit (&n->name);
                n->num_parts = 0;
                return 0;
            }
        }
        it++;
    }
    return n->num_parts;
}

void names_deinit (Names* xs) {
    vec_foreach_ptr (xs, x, { dem_string_deinit (&x->name); });
    vec_deinit (xs);
}
