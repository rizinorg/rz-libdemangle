// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangle.h"

#include <stdio.h>

#include "cp/param.h"
#include "cp/vec.h"
#include "demangler_util.h"


// See issue :
//   https://github.com/rizinorg/rz-libdemangle/issues/8
//
// For name mangling scheme for GNU v2 ABI, see section 8.4 (Gnu v2 name mangling)
//   https://github.com/rizinorg/rizin/files/6154867/calling_conventions.pdf
//
// A better formatted document can be found here :
//   https://kb.brightprogrammer.in/s/15fd1dd9-d47d-4ec1-9339-7c111db41ab5
//
// For name mangling scheme for GNU v3 ABI, see
//   https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling-structure

/**
 * \b String iterator
 **/
typedef struct StrIter {
    const char* beg; /**< \b Beginning position of string. */
    const char* end; /**< \b Ending of string (usually points to the null-terminator char). */
    const char* cur; /**< \b Current read position. */
} StrIter;

typedef Vec (DemString) ClassNameVec;

typedef struct {
    StrIter      original;
    CpDemOptions opts;

    ClassNameVec qualifiers;
    DemString    base_name;    // Used to identify base type in list of function params
    ParamVec     func_params;  // Names of all function params
    bool         has_params;   // There are cases where control never reaches `cpdem_func_params`

    DemString suffix;          // anything that is to be put at the very end of demangled output
    DemString prefix;          // a return type, or another keyword to be put before name
    DemString custom_operator; // A special case of operator "__op<L><TYPE>"

    bool has_special_name;     /* __vt or _GLOBAL$I/D$, etc... */
    bool is_ctor;
    bool is_dtor;
    ut8  operator_type;        // 0 if not an operator, otherwise a positive value
} CpDem;

static CpDem*      cpdem_init (CpDem* dem, const char* mangled, CpDemOptions opts);
static const char* cpdem_get_demangled (CpDem* dem);
static CpDem*      cpdem_public_name (CpDem* dem);
static CpDem*      cpdem_deinit (CpDem* dem);

static const struct {
    const char* from;
    const char* to;
    size_t      len;
} operators_map[] = {
    {0 /* dummy entry to make sure indices start from 1 */},
    {.from = "_aad_", .to = "operator&=", .len = 5},
    {.from = "_adv_", .to = "operator/=", .len = 5},
    {.from = "_aer_", .to = "operator^=", .len = 5},
    {.from = "_als_", .to = "operator<<=", .len = 5},
    {.from = "_aml_", .to = "operator*=", .len = 5},
    {.from = "_amd_", .to = "operator%=", .len = 5},
    {.from = "_ami_", .to = "operator-=", .len = 5},
    {.from = "_aor_", .to = "operator|=", .len = 5},
    {.from = "_apl_", .to = "operator+=", .len = 5},
    {.from = "_ars_", .to = "operator>>=", .len = 5},

    {.from = "_aa_", .to = "operator&&", .len = 4},
    {.from = "_ad_", .to = "operator&", .len = 4},
    {.from = "_as_", .to = "operator=", .len = 4},

    {.from = "_cl_", .to = "operator()", .len = 4},
    {.from = "_co_", .to = "operator~", .len = 4},
    {.from = "_cm_", .to = "operator,", .len = 4},

    {.from = "_dl_", .to = "operator delete", .len = 4},
    {.from = "_dv_", .to = "operator/", .len = 4},

    {.from = "_eq_", .to = "operator==", .len = 4},
    {.from = "_er_", .to = "operator^", .len = 4},

    {.from = "_ge_", .to = "operator>=", .len = 4},
    {.from = "_gt_", .to = "operator>", .len = 4},

    {.from = "_le_", .to = "operator<=", .len = 4},
    {.from = "_ls_", .to = "operator<<", .len = 4},
    {.from = "_lt_", .to = "operator<", .len = 4},

    {.from = "_md_", .to = "operator%", .len = 4},
    {.from = "_mi_", .to = "operator-", .len = 4},
    {.from = "_ml_", .to = "operator*", .len = 4},
    {.from = "_mm_", .to = "operator--", .len = 4},

    {.from = "_ne_", .to = "operator!=", .len = 4},
    {.from = "_nt_", .to = "operator!", .len = 4},
    {.from = "_nw_", .to = "operator new", .len = 4},

    {.from = "_oo_", .to = "operator||", .len = 4},
    /* explicitly matched : {.from = "__op<L>TYPE_", .to = "operator", .len = 3}, */
    {.from = "_or_", .to = "operator|", .len = 4},

    {.from = "_pl_", .to = "operator+", .len = 4},
    {.from = "_pp_", .to = "operator++", .len = 4},

    {.from = "_rf_", .to = "operator->", .len = 4},
    {.from = "_rm_", .to = "operator->*", .len = 4},
    {.from = "_rs_", .to = "operator>>", .len = 4},

    {.from = "_vc_", .to = "operator[]", .len = 4},
    {.from = "_vd_", .to = "operator delete[]", .len = 4},
    {.from = "_vn_", .to = "operator new[]", .len = 4},
};
#define OPERATOR_MAP_SIZE (sizeof (operators_map) / sizeof (operators_map[0]))

/**
 * \b Takes a mangled input, and returns corresponding demangled form.
 *
 * The returned string is allocated new. It is the responsibility of caller to
 * free the returned string.
 *
 * \p mangled : Mangled input.
 * \p opts : Options for demangling.
 *
 * \return Demangled output on success.
 * \return NULL otherwise.
 */
const char* cp_demangle (const char* mangled, CpDemOptions opts) {
    if (!mangled) {
        fprintf (stderr, "invalid arguments\n");
        return NULL;
    }

    CpDem dem = {0};
    if (!cpdem_init (&dem, mangled, opts)) {
        return NULL;
    }

    if (!cpdem_public_name (&dem)) {
        cpdem_deinit (&dem);
        return NULL;
    }

    const char* res = NULL;
    if (!(res = cpdem_get_demangled (&dem))) {
        cpdem_deinit (&dem);
        return NULL;
    }

    cpdem_deinit (&dem);
    return res;
}

static ut64   cpdem_get_qualifier_count (CpDem* dem);
static CpDem* cpdem_qualifiers_list (CpDem* dem);
static CpDem* cpdem_name (CpDem* dem);
static CpDem* cpdem_class_names (CpDem* dem, ClassNameVec* class_names, ut64 qualifiers_count);
static CpDem* cpdem_param_type (CpDem* dem, ParamVec* params);
static CpDem* cpdem_func_params (CpDem* dem);
static CpDem* cpdem_template_param_type (CpDem* dem, ParamVec* params);
static CpDem* cpdem_template_class (CpDem* dem, DemString* tclass_name);
static CpDem* cpdem_custom_type_name (CpDem* dem, DemString* name);

/**
 * Reads a number from current demangling position to provided "var" variable.
 * Automatically will adjust next read position if numbe read is successful, otherwise, will
 * set var to -1
 */
#define cpdem_number(dem, var)                                                                     \
    do {                                                                                           \
        if (!(dem)) {                                                                              \
            (var) = 0;                                                                             \
            break;                                                                                 \
        }                                                                                          \
                                                                                                   \
        char* end = NULL;                                                                          \
        (var)     = strtoll (CUR ((dem)), &end, 10);                                               \
        if (!end) {                                                                                \
            (var) = -1;                                                                            \
            break;                                                                                 \
        }                                                                                          \
        SET_CUR (dem, end);                                                                        \
    } while (0)


/* Current read position */
/* NOTE that this returns char* (pointer) instead of char */
#define CUR(dem)           ((dem)->original.cur)
#define BEG(dem)           ((dem)->original.beg)
#define END(dem)           ((dem)->original.end)
#define IN_RANGE(dem, pos) ((pos) >= BEG (dem) ? ((pos) < END (dem) ? 1 : 0) : 0)
#define SET_CUR(dem, pos)  ((dem)->original.cur = IN_RANGE (dem, pos) ? (pos) : CUR (dem))

#define IS_BASE_NAME_A_TYPE(dem) ((dem)->qualifiers.length && (dem)->base_name->length)

/* is constructor, destructor or an operator */
#define IS_XTOR(dem)                                                                               \
    ((dem)->is_ctor || (dem)->is_dtor || (dem)->operator_type || (dem)->custom_operator.len)

/* Read but don't advance */
#define PEEK(dem) (IN_RANGE (dem, CUR (dem)) ? *(dem)->original.cur : 0)

/* Read and advance one position */
#define READ(dem) (IN_RANGE (dem, CUR (dem)) ? *(dem)->original.cur++ : 0)

/* Advance by one character */
/* NOTE that this returns char* (pointer) instead of char */
#define ADV(dem) (IN_RANGE (dem, CUR (dem)) ? (dem)->original.cur++ : NULL)
#define ADV_BY(dem, n)                                                                             \
    (IN_RANGE (dem, CUR (dem)) ? ((dem)->original.cur = (dem)->original.cur + (n)) : NULL)

/* Is current character a terminator */
#define IS_TERM(dem) ((PEEK (dem) == '.') || (PEEK (dem) == '$'))

CpDem* cpdem_init (CpDem* dem, const char* mangled, CpDemOptions opts) {
    if (!dem || !mangled) {
        return NULL;
    }

    memset (dem, 0, sizeof (CpDem));
    dem->original =
        ((StrIter) {.beg = mangled, .end = mangled + strlen (mangled) + 1, .cur = mangled});
    dem->opts = opts;
    dem_string_init (&dem->base_name);
    dem_string_init (&dem->suffix);
    dem_string_init (&dem->prefix);
    param_vec_init (&dem->func_params);
    return dem;
}

CpDem* cpdem_deinit (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    /* free all demstring and deinit qualifiers vector */
    vec_foreach_ptr (&dem->qualifiers, q, { dem_string_deinit (q); });
    vec_deinit (&dem->qualifiers);

    // deinit all func params first
    param_vec_deinit (&dem->func_params);

    dem_string_deinit (&dem->base_name);
    dem_string_deinit (&dem->prefix);
    dem_string_deinit (&dem->suffix);
    dem_string_deinit (&dem->custom_operator);

    memset (dem, 0, sizeof (CpDem));
    return dem;
}

const char* cpdem_get_demangled (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    // append name first
    DemString demangled = {0};
    dem_string_init (&demangled);

    /* add prefix if present */
    if (dem->prefix.len) {
        dem_string_concat (&demangled, &dem->prefix);
        dem_string_append_char (&demangled, ' ');
    }

    /* add all qualifiers */
    if (dem->qualifiers.length) {
        vec_foreach_ptr (&dem->qualifiers, q, {
            dem_string_concat (&demangled, q);
            dem_string_append_n (&demangled, "::", 2);
        });

        if (IS_XTOR (dem)) {
            /* when adding into constructor or destructor, we don't need template params,
             * make sure to not add that, but stopping at "<" */
            DemString* last_qualifier = vec_end (&dem->qualifiers);
            char*      buf            = last_qualifier->buf;
            size_t     buf_len        = last_qualifier->len;
            if (dem->is_ctor) {
                char* name_end = memchr (buf, '<', buf_len);
                name_end       = name_end ? name_end : buf + buf_len;
                dem_string_append_n (&demangled, buf, name_end - buf);
            } else if (dem->is_dtor) {
                char* name_end = memchr (buf, '<', buf_len);
                name_end       = name_end ? name_end : buf + buf_len;
                dem_string_append_char (&demangled, '~');
                dem_string_append_n (&demangled, buf, name_end - buf);
            }
        } else {
            dem_string_concat (&demangled, &dem->base_name);
        }
    } else {
        /* if there are no qualifiers, then there surely is a base name */
        dem_string_concat (&demangled, &dem->base_name);
    }

    if (dem->operator_type) {
        dem_string_append (&demangled, operators_map[dem->operator_type].to);
    } else if (dem->custom_operator.len) {
        dem_string_append_n (&demangled, "operator ", 9);
        dem_string_concat (&demangled, &dem->custom_operator);
    }

    // append all params if they exist
    if (dem->has_params) {
        dem_string_append_char (&demangled, '(');
        if (dem->func_params.length) {
            bool is_first_param = true;
            vec_foreach_ptr (&dem->func_params, param, {
                // prepend a comma before every param if that param is not the first one.
                if (is_first_param) {
                    is_first_param = false;
                } else {
                    dem_string_append_n (&demangled, ", ", 2);
                }

                // demangled += prefix name suffix
                if (param->prefix.len) {
                    dem_string_concat (&demangled, &param->prefix);
                    dem_string_append_char (&demangled, ' ');
                }
                dem_string_concat (&demangled, &param->name);
                if (param->suffix.len) {
                    dem_string_append_char (&demangled, ' ');
                    dem_string_concat (&demangled, &param->suffix);
                }
            });
        } else {
            dem_string_append_n (&demangled, "void", 4);
        }
        dem_string_append_char (&demangled, ')');
    }

    /* add suffix if present */
    if (dem->suffix.len) {
        dem_string_append_char (&demangled, ' ');
        dem_string_concat (&demangled, &dem->suffix);
    }

    const char* res = dem_str_ndup (demangled.buf, demangled.len);
    dem_string_deinit (&demangled);

    return res;
}

CpDem* cpdem_public_name (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    bool has_vt = false;

    /* special names */
    if (PEEK (dem) == '_') {
        const char* trial_start_pos = CUR (dem);
        ADV (dem); /* skip _ */

        /* _ <qualifiers list> <list term> <name> */
        if (IN_RANGE (dem, CUR (dem) + 3) &&
            (!strncmp (CUR (dem), "vt", 2) || !strncmp (CUR (dem), "_vt", 3))) {
            /* match past  "_vt$" or "_vt." or "__vt_" */
            if (PEEK (dem) == 'v') {
                ADV_BY (dem, 2);
                if (IS_TERM (dem)) {
                    ADV (dem);
                    dem_string_append (&dem->suffix, "virtual table");
                    has_vt = true;
                } else {
                    SET_CUR (dem, trial_start_pos);
                }
            } else {
                ADV_BY (dem, 3);
                if (PEEK (dem) == '_') {
                    ADV (dem);
                    dem_string_append (&dem->suffix, "virtual table");
                    has_vt = true;
                } else {
                    SET_CUR (dem, trial_start_pos);
                }
            }

            /* continue to match past this, a name will come */
        } else if (IN_RANGE (dem, CUR (dem) + 3) && !strncmp (CUR (dem), "_t", 2)) {
            ADV_BY (dem, 2);

            /* type_info [node | function] */
            bool ch = PEEK (dem);
            if ((ch == 'i' || ch == 'f')) {
                ADV (dem);
                ClassNameVec class_names = {0};
                if (cpdem_class_names (dem, &class_names, 1)) {
                    dem_string_append (
                        &dem->suffix,
                        ((ch == 'i') ? "type_info node" : "type_info function")
                    );

                    dem_string_concat (&dem->base_name, vec_end (&class_names));
                    vec_foreach_ptr (&class_names, cn, { dem_string_deinit (cn); });
                    vec_deinit (&class_names);
                    return dem;
                } else {
                    ParamVec types = {0};
                    param_vec_init (&types);
                    if (cpdem_param_type (dem, &types) && types.length) {
                        dem_string_append (
                            &dem->suffix,
                            ((ch == 'i') ? "type_info node" : "type_info function")
                        );

                        DemString ti = vec_front (&types).name;
                        dem_string_concat (&dem->base_name, &ti);
                        param_vec_deinit (&types);
                        return dem;
                    } else {
                        SET_CUR (dem, trial_start_pos);
                        param_vec_deinit (&types);
                        /* continue parsing from beginning */
                    }
                }
            } else {
                SET_CUR (dem, trial_start_pos);
                /* continue parsing from beginning */
            }
        } else if (IN_RANGE (dem, CUR (dem) + 10) && !strncmp (CUR (dem), "GLOBAL_$", 8)) {
            ADV_BY (dem, 8);     /* skip GLOBAL_$ */

            if (PEEK (dem) == 'I') {
                ADV_BY (dem, 2); /* skip I$ */
                dem_string_append (&dem->prefix, "global constructors keyed to");
                dem->has_special_name = true;
            } else if (PEEK (dem) == 'D') {
                ADV_BY (dem, 2); /* skip I$ */
                dem_string_append (&dem->prefix, "global destructors keyed to");
                dem->has_special_name = true;
            } else {
                /* I don't identify you */
                return NULL;
            }

            /* continue from here to parse names, qualifiers, etc... like usual */
        } else if (cpdem_qualifiers_list (dem)) {
            if (IS_TERM (dem) && ADV (dem) && cpdem_name (dem)) {
                return dem;
            }
        } else {
            SET_CUR (dem, trial_start_pos);
        }
    }

    /* <name> */
    if (!dem->has_special_name) {
        if (!cpdem_name (dem)) {
            return NULL;
        }
    }

    bool has_special_name_with_qualifiers = false;

    /* there may be one or two _ depending on scanned name */
    if (IS_XTOR (dem)) {
        /* skip _ */
        if (PEEK (dem) == '_') {
            ADV (dem);
        } else {
            return NULL;
        }
    } else {
        /* an extra _ will be here only if this is not a special name */
        if (dem->has_special_name && PEEK (dem) == '_') {
            ADV (dem); /* skip _ */
            has_special_name_with_qualifiers = true;
        } else if (dem->has_special_name) {
            /* do nothing */
        } else if (PEEK (dem) == '_') {
            ADV (dem);     /* skip _ */
            if (PEEK (dem) == '_') {
                ADV (dem); /* skip _ */
            } else {
                return NULL;
            }
        } else if (has_vt) {
            /* do nothing */
        } else {
            return NULL;
        }
    }

    switch (PEEK (dem)) {
        /* <name> __F [<parameter type>]+ */
        case 'F' :
            ADV (dem);
            return cpdem_func_params (dem);

        /* <name> __H */
        case 'H' :
            ADV (dem);
            // TODO: return cpdem_template_param_type (dem);
            return NULL;

        /* <name> __C */
        case 'C' : {
            /* function marked as const, meaning won't change any of the arguments passed to it */
            ADV (dem);
            dem_string_append_n (&dem->suffix, "const", 5);
            if (cpdem_qualifiers_list (dem)) {
                cpdem_func_params (dem);
                return dem;
            } else {
                return NULL;
            }
        }

        /* <name> __ <qualifiers list> [<parameter type>]+ */
        /* [ _ <qualifiers list> <list term> ] <name> */
        /* <name> */
        default :
            if (has_special_name_with_qualifiers) {
                /* _ <qualifiers list> <list term> <name> */
                if (cpdem_qualifiers_list (dem)) {
                    if (IS_TERM (dem)) {
                        ADV (dem);
                        if (!cpdem_name (dem)) {
                            return NULL;
                        }
                    } else {
                        return NULL;
                    }
                } else {
                    return NULL;
                }
            } else if (dem->has_special_name) {
                if (!cpdem_name (dem)) {
                    return NULL;
                }
            } else {
                if (cpdem_qualifiers_list (dem)) {
                    /* <name> __ <qualifiers list> [<parameter type>]+ */
                    /* function params are optional here, therefore we won't check if they return anything or not */
                    cpdem_func_params (dem);
                } else if (has_vt) {
                    /* do nothing */
                } else {
                    return NULL;
                }
            }

            return dem;
    }

    return dem;
}

static ut64 cpdem_get_qualifier_count (CpDem* dem) {
    if (!dem) {
        return 0;
    }

    ut64 qualifier_count = 0;

    /* if more than 1 qualifier */
    /* Q */
    if (PEEK (dem) == 'Q') {
        ADV (dem);

        char* end = NULL;

        /* if more than 9 qualifiers */
        /* Q _ */
        if (PEEK (dem) == '_') {
            ADV (dem);

            /* Q _ <qualifiers count> _ */
            qualifier_count = strtoull (CUR (dem), &end, 10);
            if (!end || !IN_RANGE (dem, end) || *end != '_' || !qualifier_count) {
                return 0;
            }
        } else if (PEEK (dem) >= '0' && PEEK (dem) <= '9') {
            /* single digit count */
            /* Q <qualifiers count> */
            qualifier_count = PEEK (dem) - '0';
            ADV (dem);
        } else {
            return 0;
        }

        /* update current position */
        SET_CUR (dem, end);
    } else if ((PEEK (dem) >= '0' && PEEK (dem) <= '9') || PEEK (dem) == 't') {
        /* if just one qualifier, then length of qualifier comes first */
        qualifier_count = 1;
    } else {
        /* this was a mistake, and this is not a qualifier, backtrack */
        return 0;
    }

    return qualifier_count;
}

CpDem* cpdem_qualifiers_list (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    ut64 qualifier_count = cpdem_get_qualifier_count (dem);
    if (!qualifier_count) {
        return NULL;
    }

    /* get each qualifier */
    /* <qualifiers count> [<name length> <class name>]+ */
    return cpdem_class_names (dem, &dem->qualifiers, qualifier_count);
}

CpDem* cpdem_name (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    if (PEEK (dem) == '_') {
        const char* trial_start_pos = CUR (dem);
        ADV (dem);

        // destructor
        if (PEEK (dem) == '$' || PEEK (dem) == '.') {
            ADV (dem);
            dem->is_dtor = true;
            return dem;
        } else if (PEEK (dem) == '_') {
            // opreator TYPE()
            // __op<L>TYPE_ : L is length and TYPE is name of type of length <L> characters
            if (IN_RANGE (dem, CUR (dem) + 4) && !strncmp (CUR (dem), "_op", 3)) {
                // read past _op
                ADV_BY (dem, 3);

                ParamVec params = {0};
                param_vec_init (&params);

                /* NOTE: for now, this method will match more strings than it should.
                 * If the provided string is correct, then the output will be correct,
                 * if however the given input is incorrect, then it'll output wrong demangled output,
                 * instead of return NULL (rejection) */

                if (cpdem_param_type (dem, &params) && params.length) {
                    if (PEEK (dem) == '_') {
                        ADV (dem);
                        Param* p = vec_begin (&params);
                        dem_string_concat (&dem->custom_operator, &p->name);
                        param_vec_deinit (&params);
                        return dem;
                    } else {
                        /* restore to iniital parsing position and try for a normal name */
                        SET_CUR (dem, trial_start_pos);
                        param_vec_deinit (&params);
                        goto parse_name;
                    }
                }
            } else {
                // any other operator
                // try to match through each one, and if fails then it's a constructor
                // note that index starts from 1
                for (size_t x = 1; x < OPERATOR_MAP_SIZE; x++) {
                    if (IN_RANGE (dem, CUR (dem) + operators_map[x].len) &&
                        !strncmp (CUR (dem), operators_map[x].from, operators_map[x].len)) {
                        ADV_BY (dem, operators_map[x].len);
                        dem->operator_type = x;
                        return dem;
                    }
                }
            }

            // constructor
            dem->is_ctor = true;
            return dem;
        } else {
            // restore initial position, because this is a name now, not an operator
            // this name begins with underscore
            SET_CUR (dem, trial_start_pos);
        }
    }

parse_name:
    /* match <name> if operator match didn't work */
    while (PEEK (dem)) {
        const char* cur = CUR (dem);
        if (IN_RANGE (dem, CUR (dem) + 2) &&
            (cur[0] == '_' && (cur[1] == '_' || dem->has_special_name))) {
            /* depeneding on whether decl has a special name or not,
             * there will be an extra _ or a qualifier following up */
            char next_char = dem->has_special_name ? cur[1] : cur[2];

            switch (next_char) {
                case 'C' : /* const function */
                case 'F' : /* function params */
                case 'H' : /* template function */
                case 'Q' : /* qualifier list */
                case 't' : /* template class */

                /* a sigle qualifier starts */
                case '0' :
                case '1' :
                case '2' :
                case '3' :
                case '4' :
                case '5' :
                case '6' :
                case '7' :
                case '8' :
                case '9' : {
                    return dem;
                }

                default : {
                    /* add this character to name */
                    break;
                }
            }
        }

        dem_string_append_char (&dem->base_name, READ (dem));
    }

    return dem;
}

CpDem* cpdem_class_names (CpDem* dem, ClassNameVec* class_names, ut64 qualifiers_count) {
    if (!dem || !class_names || !qualifiers_count) {
        return NULL;
    }

    /* get each qualifier and append in qualifier name vector */
    vec_reserve (class_names, qualifiers_count);

    while (qualifiers_count--) {
        DemString name = {0};
        dem_string_init (&name);

        switch (PEEK (dem)) {
            /* template class */
            case 't' : {
                ADV (dem);
                if (!cpdem_template_class (dem, &name)) {
                    dem_string_deinit (&name);
                    return NULL;
                }
                break;
            }

            case '0' :
            case '1' :
            case '2' :
            case '3' :
            case '4' :
            case '5' :
            case '6' :
            case '7' :
            case '8' :
            case '9' : {
                if (!cpdem_custom_type_name (dem, &name)) {
                    dem_string_deinit (&name);
                    return NULL;
                }
                break;
            }

            default : {
                return NULL;
            }
        }

        vec_append (class_names, &name);
    }

    return dem;
}

/**
 * \b Get parameter type at current read position, demangle it and add to param vec.
 *    There are different types of parameter vectors. So the caller passes their own
 *    parameter vector to append the demangled parameter to.
 * 
 * ParamVec is required because of types that get repeated many times. In
 * that case many entries need to be appended at once.
 *
 * \p dem    Demangling context.
 * \p params Parameter vector to append demangled parameter to.
 *
 * \return dem on success.
 * \return NULL otherwise.
 */
CpDem* cpdem_param_type (CpDem* dem, ParamVec* params) {
    if (!dem || !params) {
        return NULL;
    }

    Param param = {0};
    param_init (&param);

#define ADD_PARAM(x)                                                                               \
    dem_string_append (&param.name, x) ?                                                           \
        (param_vec_append (params, &param) ? dem : (param_deinit (&param), NULL)) :                \
        (param_deinit (&param), NULL)

    /** read a custom type from current read position and add it to params vector if success */
#define ADD_NAMED_PARAM()                                                                          \
    cpdem_custom_type_name (dem, &param.name) ?                                                    \
        (param_vec_append (params, &param) ? dem : (param_deinit (&param), NULL)) :                \
        (param_deinit (&param), NULL)

#define ADD_QUALIFIER_LIST()                                                                       \
    do {                                                                                           \
        ut64 qualifiers_count = cpdem_get_qualifier_count (dem);                                   \
        if (!qualifiers_count) {                                                                   \
            return NULL;                                                                           \
        }                                                                                          \
                                                                                                   \
        ClassNameVec qualifiers = {0};                                                             \
        vec_init (&qualifiers);                                                                    \
        if (!cpdem_class_names (dem, &qualifiers, qualifiers_count)) {                             \
            return NULL;                                                                           \
        }                                                                                          \
                                                                                                   \
        vec_foreach_ptr (&qualifiers, q, {                                                         \
            dem_string_concat (&param.name, q);                                                    \
            dem_string_append_n (&param.name, "::", 2);                                            \
            dem_string_deinit (q);                                                                 \
        });                                                                                        \
                                                                                                   \
        /* HACK: to remove last two extraneous ":" (colon) symbols */                              \
        param.name.buf[--param.name.len] = 0;                                                      \
        param.name.buf[--param.name.len] = 0;                                                      \
        vec_deinit (&qualifiers);                                                                  \
                                                                                                   \
        param_vec_append (params, &param);                                                         \
    } while (0)

#define MATCH_TYPE()                                                                               \
    case 'b' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("bool");                                                                 \
    }                                                                                              \
    case 'c' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("char");                                                                 \
    }                                                                                              \
    case 'd' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("double");                                                               \
    }                                                                                              \
    case 'e' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("...");                                                                  \
    }                                                                                              \
    case 'f' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("float");                                                                \
    }                                                                                              \
    case 'i' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("int");                                                                  \
    }                                                                                              \
    case 'l' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("long");                                                                 \
    }                                                                                              \
    case 'r' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("long double");                                                          \
    }                                                                                              \
    case 's' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("short");                                                                \
    }                                                                                              \
    case 't' : {                                                                                   \
        ADV (dem);                                                                                 \
        if (cpdem_template_class (dem, &param.name)) {                                             \
            param_vec_append (params, &param);                                                     \
            return dem;                                                                            \
        } else {                                                                                   \
            param_deinit (&param);                                                                 \
            return NULL;                                                                           \
        }                                                                                          \
    }                                                                                              \
    case 'v' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("void");                                                                 \
    }                                                                                              \
    case 'w' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("wchar_t");                                                              \
    }                                                                                              \
    case 'x' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_PARAM ("long long");                                                            \
    }                                                                                              \
    case 'U' : {                                                                                   \
        ADV (dem);                                                                                 \
        switch (PEEK (dem)) {                                                                      \
                /* Uc */                                                                           \
            case 'c' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("unsigned char");                                                \
                /* Us */                                                                           \
            case 's' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("unsigned short");                                               \
                /* Ui */                                                                           \
            case 'i' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("unsigned int");                                                 \
                /* Ul */                                                                           \
            case 'l' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("unsigned long");                                                \
                /* Ux */                                                                           \
            case 'x' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("unsigned long long");                                           \
            default :                                                                              \
                return NULL;                                                                       \
        }                                                                                          \
        break;                                                                                     \
    }                                                                                              \
    case 'Q' : {                                                                                   \
        ADD_QUALIFIER_LIST();                                                                      \
        return dem;                                                                                \
    }                                                                                              \
    case 'S' : {                                                                                   \
        ADV (dem);                                                                                 \
        switch (PEEK (dem)) {                                                                      \
                /* Sc */                                                                           \
            case 'c' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("signed char");                                                  \
            default :                                                                              \
                return NULL;                                                                       \
        }                                                                                          \
        break;                                                                                     \
    }                                                                                              \
    case 'J' : {                                                                                   \
        ADV (dem);                                                                                 \
        switch (PEEK (dem)) {                                                                      \
            /* Jf */                                                                               \
            case 'f' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("__complex__ float");                                            \
            /* Jd */                                                                               \
            case 'd' :                                                                             \
                ADV (dem);                                                                         \
                return ADD_PARAM ("__complex__ double");                                           \
            default :                                                                              \
                return NULL;                                                                       \
        }                                                                                          \
        break;                                                                                     \
    }                                                                                              \
    case '0' :                                                                                     \
    case '1' :                                                                                     \
    case '2' :                                                                                     \
    case '3' :                                                                                     \
    case '4' :                                                                                     \
    case '5' :                                                                                     \
    case '6' :                                                                                     \
    case '7' :                                                                                     \
    case '8' :                                                                                     \
    case '9' : {                                                                                   \
        return ADD_NAMED_PARAM();                                                                  \
    }                                                                                              \
    default : {                                                                                    \
        /* we tried all combinations but this is an invalid type, cannot continue */               \
        return NULL;                                                                               \
    }

    st64 num_reps = 1;
    st64 typeidx  = -1;
    bool is_ref   = false;
    bool is_ptr   = false;

    switch (PEEK (dem)) {
        /* X */
        MATCH_TYPE();

        /* G<LX>X */
        case 'G' : {
            ADV (dem);

            /* there are two types of cases for G 
             * - G<LX>X               (ADD_NAMED_PARAM())
             * - GQ2<qualifiers>      (ADD_QUALIFIER_LIST()) 
             * G will never appear in case of pointers, references or in template paramter list 
             * */
            switch (PEEK (dem)) { MATCH_TYPE(); }

            break;
        }

        /* R - References */
        case 'R' : {
case_r:
            ADV (dem); /* skip R */
            param_append_to (&param, suffix, "&");
            is_ref = true;

            switch (PEEK (dem)) {
                MATCH_TYPE();

                case 'R' : {
                    goto case_r;
                }

                case 'P' : {
                    goto logic_intersection_between_case_r_and_p;
                }

                case 'T' : {
                    goto logic_intersection_between_case_r_and_t;
                }

                case 'C' : {
                    goto logic_intersection_between_case_r_and_c;
                }

                case 'V' : {
                    goto logic_intersection_between_case_r_and_v;
                }
            }
        }

        /* P - Pointers */
        case 'P' : {
case_p:
logic_intersection_between_case_r_and_p:
            ADV (dem); /* skip P */

            /* need to prepend it this way, because we might already have & in the suffix */
            param_prepend_to (&param, suffix, "*");
            is_ptr = true;

            switch (PEEK (dem)) {
                /* PX or RPX */
                MATCH_TYPE();

                case 'P' : {
                    goto case_p;
                }

                case 'T' : {
                    goto logic_intersection_between_p_and_t_or_r_and_p_and_t;
                }

                case 'C' : {
                    goto logic_intersection_between_case_p_and_c;
                }

                /* PVX */
                case 'V' : {
                    goto logic_intersection_between_case_p_and_v;
                }
            }

            break;
        }

        /* C */
        case 'C' : {
logic_intersection_between_case_r_and_c:
logic_intersection_between_case_p_and_c:
            ADV (dem); /* skip C */
            param_append_to (&param, prefix, "const");

            switch (PEEK (dem)) {
                /* CX */
                MATCH_TYPE();

                case 'P' : {
                    goto case_p;
                }

                /* CVX */
                case 'V' : {
                    goto logic_intersection_between_case_c_and_v;
                }
            }
            break;
        }

        /* V */
        case 'V' : {
logic_intersection_between_case_r_and_v:
logic_intersection_between_case_p_and_v:
logic_intersection_between_case_c_and_v:
            ADV (dem); /* skip V */
            param_append_to (&param, prefix, "volatile");

            switch (PEEK (dem)) {
                /* VX */
                MATCH_TYPE();
            }
            break;
        }

            /* repeated names */
        case 'N' : {
            ADV (dem); /* skip N */

            /* get number of repetitions to copy here */
            cpdem_number (dem, num_reps);
            if (num_reps <= 0) {
                return NULL;
            }

            /* if length is more than single digit in it's string form, then there will be a "_" just after it */
            if (PEEK (dem) == '_') {
                ADV (dem);
            } else {
                /* we over-read, and there's a two digit number present here, first digit for num_reps and second for typeidx */
                SET_CUR (dem, CUR (dem) - 2);
                num_reps = READ (dem) - '0';
            }

            /* next we're expecting a number that indexes into parameter vector to refer to a type already demangled */
            if (PEEK (dem) >= '0' && PEEK (dem) <= '9') {
                goto logic_intersection_between_case_n_and_t;
            }
        }
        /* T - reference back to a repeated type */
        case 'T' : {
logic_intersection_between_case_r_and_t:
logic_intersection_between_p_and_t_or_r_and_p_and_t:
            ADV (dem); /* skip T */

logic_intersection_between_case_n_and_t:
            /* get type index to copy here */
            cpdem_number (dem, typeidx);
            if (typeidx < 0 || typeidx > dem->func_params.length) {
                return NULL;
            }

            /* if length is more than single digit in it's string form, then there will be a "_" just after it */
            if (PEEK (dem) == '_') {
                ADV (dem);
            }

            /* deinit this one, because we'll be directly initing clones */
            param_deinit (&param);

            /* create base typename is to be provided for index 0 in list of recognized types */
            char* base_typename = NULL;
            if (dem->qualifiers.length) {
                if (dem->base_name.len) {
                    base_typename = strdup (dem->base_name.buf);
                } else {
                    DemString tname = {0};
                    vec_foreach_ptr (&dem->qualifiers, q, {
                        dem_string_concat (&tname, q);
                        dem_string_append_n (&tname, "::", 2);
                    });

                    /* HACK: to remove extraneous "::" */
                    tname.buf[--tname.len] = 0;
                    tname.buf[--tname.len] = 0;

                    base_typename = strndup (tname.buf, tname.len);
                    dem_string_deinit (&tname);
                }
            }

            /* refer back to param list */
            if (base_typename && (typeidx == 0)) {
                /* the very first type is name of function itself, it should be considered at index 0 */
                for (ut64 r = 0; r < num_reps; r++) {
                    Param p = {0};
                    param_init (&p);

                    /* if we fell down from R */
                    if (is_ref) {
                        /* num_reps will be 1 in this case */
                        param_append_to (&p, suffix, "&");
                    }

                    /* if we fell down from P */
                    if (is_ptr) {
                        /* num_reps will be 1 in this case */
                        param_prepend_to (&p, suffix, "*");
                    }

                    param_append_to (&p, name, base_typename);
                    param_vec_append (params, &p);
                }
            } else {
                /* if base name is considered as first type then assume array index starts at 1 in vector */
                if (base_typename) {
                    typeidx--;
                }

                /* for each rep, make clone of a type at previous index and put it at the end in the param vec */
                for (ut64 r = 0; r < num_reps; r++) {
                    Param p = {0};
                    param_init_clone (&p, vec_ptr_at (params, typeidx));

                    /* if we fell down from R */
                    if (is_ref) {
                        /* num_reps will be 1 in this case */
                        param_append_to (&p, suffix, "&");
                    }

                    /* if we fell down from P */
                    if (is_ptr) {
                        /* num_reps will be 1 in this case */
                        param_prepend_to (&p, suffix, "*");
                    }

                    param_vec_append (params, &p);
                }
            }

            if (base_typename) {
                free (base_typename);
            }

            break;
        }
    }

    return dem;
}

/**
 * \b Parse as many parameter types as possible.
 *
 * \param dem Demangling context.
 *
 * \return dem on success.
 * \return NULL on failure.
 */
CpDem* cpdem_func_params (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    dem->has_params = true;

    /* parse as many params as possible */
    while (PEEK (dem) && cpdem_param_type (dem, &dem->func_params)) {}

    return dem;
}

CpDem* cpdem_template_param_type (CpDem* dem, ParamVec* params) {
    if (!dem || !params) {
        return NULL;
    }

    switch (PEEK (dem)) {
        case 'Z' : {
            ADV (dem);

            /* parse a single parameter type */
            if (!cpdem_param_type (dem, params)) {
                return NULL;
            }

            break;
        }

        default : {
            /* parse a single parameter type */
            if (!cpdem_param_type (dem, params)) {
                return NULL;
            }

            /* store before and after read positions of value */
            const char* pos_before_val = CUR (dem);
            st64        val            = 0;
            cpdem_number (dem, val);
            const char* pos_after_val = CUR (dem);

            /* make it as if string is clear */
            Param* param    = vec_end (params);
            param->name.len = param->prefix.len = param->suffix.len = 0;

            if (!strcmp (param->name.buf, "bool")) {
                /* if the type is bool, then value will be converted to true/false */
                dem_string_append (&param->name, val ? "true" : "false");
            } else {
                /* no need to convert value back to string, we already have that */
                size_t val_string_len = pos_after_val - pos_before_val;
                dem_string_append_n (&param->name, pos_before_val, val_string_len);
            }
        }
    }

    return dem;
}

CpDem* cpdem_template_class (CpDem* dem, DemString* tclass_name) {
    if (!dem || !tclass_name) {
        return NULL;
    }

    /* get custom type name first */
    DemString class_name = {0};
    if (!cpdem_custom_type_name (dem, &class_name)) {
        dem_string_deinit (&class_name);
        return NULL;
    }

    /* number of template parameters */
    st64 numtp = 0;
    cpdem_number (dem, numtp);
    if (numtp <= 0) {
        return NULL;
    }

    ParamVec params = {0};
    param_vec_init (&params);

    /* parse each template parameter */
    while (numtp--) {
        if (!cpdem_template_param_type (dem, &params)) {
            param_vec_deinit (&params);
            return NULL;
        }
    }

    /* merge class name and template parameters */
    dem_string_concat (tclass_name, &class_name);
    bool first_param = true;
    dem_string_append_char (tclass_name, '<');
    vec_foreach_ptr (&params, p, {
        if (first_param) {
            first_param = false;
        } else {
            dem_string_append_n (tclass_name, ", ", 2);
        }

        /* tclass_name += <prefix> <name> <suffix> */
        if (p->prefix.len) {
            dem_string_concat (tclass_name, &p->prefix);
            dem_string_append_char (tclass_name, ' ');
        }
        dem_string_concat (tclass_name, &p->name);
        if (p->suffix.len) {
            dem_string_append_char (tclass_name, ' ');
            dem_string_concat (tclass_name, &p->suffix);
        }
    });
    dem_string_append_char (tclass_name, '>');

    /* release temp resources */
    dem_string_deinit (&class_name);
    param_vec_deinit (&params);

    return dem;
}

/**
 * Read a custom type name from mangled character array.
 *
 * \param dem       : Demanling context.
 * \param name_dstr : DemString object to append name to.
 * 
 * \return dem on success;
 * \return NULL otherwise.
 */
CpDem* cpdem_custom_type_name (CpDem* dem, DemString* name) {
    if (!dem || !name) {
        return NULL;
    }

    if (PEEK (dem) >= '0' && PEEK (dem) <= '9') {
        char* end          = NULL;
        ut64  typename_len = strtoull (CUR (dem), &end, 10);
        if (!dem || !IN_RANGE (dem, end) || !typename_len ||
            !IN_RANGE (dem, CUR (dem) + typename_len)) {
            return NULL;
        }
        SET_CUR (dem, end);

        dem_string_append_n (name, CUR (dem), typename_len);
        ADV_BY (dem, typename_len);
    } else {
        return NULL;
    }

    return dem;
}
