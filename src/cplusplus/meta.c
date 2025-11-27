// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <time.h>

#include "types.h"

static inline void meta_copy (Meta* dst, Meta* src) {
    if (dst == src) {
        return;
    }
    dst->is_const              = src->is_const;
    dst->is_ctor               = src->is_ctor;
    dst->is_dtor               = src->is_dtor;
    dst->is_const              = src->is_const;
    dst->trace                 = src->trace;
    dst->template_idx_start    = src->template_idx_start;
    dst->last_reset_idx        = src->last_reset_idx;
    dst->t_level               = src->t_level;
    dst->template_reset        = src->template_reset;
    dst->is_ctor_or_dtor_at_l0 = src->is_ctor_or_dtor_at_l0;
    VecF (Name, deinit) (&dst->detected_types);
    VecF (Name, deinit) (&dst->template_params);
}


bool meta_tmp_init (Meta* og, Meta* tmp) {
    if (!(og && tmp && og != tmp)) {
        return false;
    }
    meta_copy (tmp, og);
    vec_foreach_ptr (&og->detected_types, n, {
        Name new_name = {0};
        dem_string_init_clone (&new_name.name, &n->name);
        new_name.num_parts = n->num_parts;
        VecF (Name, append) (&tmp->detected_types, &new_name);
    });
    vec_foreach_ptr (&og->template_params, n, {
        Name new_name = {0};
        dem_string_init_clone (&new_name.name, &n->name);
        new_name.num_parts = n->num_parts;
        VecF (Name, append) (&tmp->template_params, &new_name);
    });
    return true;
}

void meta_tmp_apply (Meta* og, Meta* tmp) {
    if (!(og && tmp && og != tmp)) {
        return;
    }
    if (!(VecF (Name, empty) (&tmp->detected_types) || VecF (Name, empty) (&tmp->template_params)
        )) {
        return;
    }
    meta_copy (og, tmp);
    VecF (Name, move) (&og->detected_types, &tmp->detected_types);
    VecF (Name, move) (&og->template_params, &tmp->template_params);
    memset (tmp, 0, sizeof (Meta));
}

void meta_tmp_fini (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return;
    }

    // Clean up all items in tmp as they are deep copies
    for (size_t i = 0; i < tmp->detected_types.length; i++) {
        Name* dt = VecF (Name, at) (&tmp->detected_types, i);
        dem_string_deinit (&dt->name);
        dt->num_parts = 0;
    }
    free (VecF (Name, data) (&tmp->detected_types));

    for (size_t i = 0; i < tmp->template_params.length; i++) {
        Name* tp = VecF (Name, at) (&tmp->template_params, i);
        dem_string_deinit (&tp->name);
        tp->num_parts = 0;
    }
    free (VecF (Name, data) (&tmp->template_params));

    memset (tmp, 0, sizeof (*tmp));
}

static const char* builtin_type_stings[] = {
    "void",
    "wchar_t",
    "bool",
    "char",
    "signed char",
    "unsigned char",
    "short",
    "unsigned short",
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "long long",
    "__int64",
    "unsigned long long",
    "__int64",
    "__int128",
    "unsigned __int128",
    "float",
    "double",
    "long double",
    "__float80",
    "__float128",
    "...",
    "decimal64",
    "decimal128",
    "decimal32",
    "half",
    "char32_t",
    "char16_t",
    "char8_t",
    "auto",
    "decltype(auto)",
    "std::nullptr_t",
    "_Accum",
    "_Fract",
    NULL,
};
static const char* builtin_type_prefix_stings[] = {
    "_Float",
    "std::bfloat",
    "signed _BitInt(",
    "signed _BitInt(",
    "unsigned _BitInt(",
    "unsigned _BitInt(",
};

bool is_builtin_type (const char* t) {
    if (!(t && *t)) {
        return false;
    }
    for (size_t i = 0; i < sizeof (builtin_type_stings) / sizeof (builtin_type_stings[0]); i++) {
        if (!builtin_type_stings[i]) {
            break;
        }
        if (strcmp (builtin_type_stings[i], t) == 0) {
            return true;
        }
    }
    for (size_t i = 0;
         i < sizeof (builtin_type_prefix_stings) / sizeof (builtin_type_prefix_stings[0]);
         i++) {
        if (!builtin_type_prefix_stings[i]) {
            break;
        }
        if (strncmp (t, builtin_type_prefix_stings[i], strlen (builtin_type_prefix_stings[i])) ==
            0) {
            return true;
        }
    }
    return false;
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

    if (!t->buf) {
        return false;
    }

    if (is_builtin_type (t->buf)) {
        return true;
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

    Name* new_name = VecF (Name, append) (&m->detected_types, NULL);
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
bool meta_substitute_type (Meta* m, ut64 id, DemString* dem) {
    if (m->detected_types.length > id) {
        Name* type_name = vec_ptr_at (&m->detected_types, id);
        if (type_name && type_name->name.buf) {
            dem_string_append (dem, type_name->name.buf);
            return true;
        }
    }
    return false;
}

bool meta_substitute_tparam (Meta* m, ut64 id, DemString* dem) {
    if (m->template_params.length > id) {
        Name* tparam_name = vec_ptr_at (&m->template_params, id);
        if (tparam_name && tparam_name->name.buf) {
            dem_string_append (dem, tparam_name->name.buf);
            return true;
        }
    }
    return false;
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

void name_deinit (Name* x) {
    if (!x)
        return;
    dem_string_deinit (&x->name);
}
