// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangle.h"

#include <stdio.h>

#include "cp/fparam.h"
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

typedef struct {
    StrIter      original;
    CpDemOptions opts;

    DemString* name;      // TODO: convert this to a vector of qualifier strings
    DemString* base_name; // this will just be the base <name> and not [<qualifier name> ::]+ <name>
    FuncParamVec func_params;
    bool         has_params;

    bool is_ctor;
    bool is_dtor;
    bool is_operator;
} CpDem;

static CpDem*      cpdem_init (CpDem* dem, const char* mangled, CpDemOptions opts);
static const char* cpdem_get_demangled (CpDem* dem);
static CpDem*      cpdem_public_name (CpDem* dem);

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
    return cpdem_get_demangled (cpdem_public_name (cpdem_init (&dem, mangled, opts)));
}

static CpDem* cpdem_deinit (CpDem* dem);
static CpDem* cpdem_qualifiers_list (CpDem* dem);
static CpDem* cpdem_name (CpDem* dem);
static CpDem* cpdem_class_names (CpDem* dem, ut64 qualifiers_count);
static CpDem* cpdem_func_params (CpDem* dem);
static CpDem* cpdem_template_params (CpDem* dem);

/* Current read position */
/* NOTE that this returns char* (pointer) instead of char */
#define CUR(dem)           ((dem)->original.cur)
#define BEG(dem)           ((dem)->original.beg)
#define END(dem)           ((dem)->original.end)
#define IN_RANGE(dem, pos) ((pos) >= BEG (dem) ? ((pos) < END (dem) ? 1 : 0) : 0)
#define SET_CUR(dem, pos)  ((dem)->original.cur = IN_RANGE (dem, pos) ? (pos) : CUR (dem))

/* Read but don't advance */
#define PEEK(dem) (IN_RANGE (dem, CUR (dem)) ? *(dem)->original.cur : 0)

/* Read and advance one position */
#define READ(dem) (IN_RANGE (dem, CUR (dem)) ? *(dem)->original.cur++ : 0)

/* Advance by one character */
/* NOTE that this returns char* (pointer) instead of char */
#define ADV(dem) (IN_RANGE (dem, CUR (dem)) ? (dem)->original.cur++ : NULL)

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
    dem->name = dem_string_new();
    fparam_vec_init (&dem->func_params);
    return dem;
}

CpDem* cpdem_deinit (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    // deinit all func params first
    fparam_vec_deinit (&dem->func_params);

    if (dem->name) {
        dem_string_free (dem->name);
    }

    if (dem->base_name) {
        dem_string_free (dem->base_name);
    }

    memset (dem, 0, sizeof (CpDem));
    return dem;
}

const char* cpdem_get_demangled (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    // append name first
    DemString* demangled = dem_string_new();
    dem_string_concat (demangled, dem->name);

    // append all params
    if (dem->has_params) {
        bool is_first_param = true;
        dem_string_append_char (demangled, '(');
        vec_foreach_ptr (&dem->func_params, param, {
            // prepend a comma before every param if that param is not the first one.
            if (is_first_param) {
                is_first_param = false;
            } else {
                dem_string_append_n (demangled, ", ", 2);
            }

            // demangled += prefix name suffix
            if (param->prefix->len) {
                dem_string_concat (demangled, param->prefix);
                dem_string_append_char (demangled, ' ');
            }
            dem_string_concat (demangled, param->name);
            if (param->suffix->len) {
                dem_string_append_char (demangled, ' ');
                dem_string_concat (demangled, param->suffix);
            }
        });
        dem_string_append_char (demangled, ')');
    }

    const char* res = dem_str_ndup (dem_string_buffer (demangled), dem_string_length (demangled));
    dem_string_free (demangled);

    cpdem_deinit (dem);
    return res;
}

CpDem* cpdem_public_name (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    /* try matching for [_ <qualifiers list> <list term>] <name>*/
    if (PEEK (dem) == '_') {
        ADV (dem);

        /* _ <qualifiers list> <list term> <name> */
        if (cpdem_qualifiers_list (dem)) {
            if (IS_TERM (dem) && ADV (dem) && cpdem_name (dem)) {
                return dem;
            }
        }

        SET_CUR (dem, CUR (dem) - 1);
    }

    /* <name> */
    if (!cpdem_name (dem)) {
        return NULL;
    }

    if (IN_RANGE (dem, CUR (dem) + 3)) {
        /* there may be one or two _ depending on scanned name */
        if (dem->is_dtor || dem->is_ctor || dem->is_operator) {
            /* skip _ */
            ADV (dem);
        } else {
            /* skip __ */
            ADV (dem);
            ADV (dem);
        }

        switch (PEEK (dem)) {
            /* <name> __F [<parameter type>]+ */
            case 'F' :
                ADV (dem);
                return cpdem_func_params (dem);

            /* <name> __H */
            case 'H' :
                ADV (dem);
                return cpdem_template_params (dem);

            /* <name> __ <qualifiers list> [<parameter type>]+ */
            default :
                if (!cpdem_qualifiers_list (dem)) {
                    return NULL;
                }

                // this means func params is optional
                // the docs don't imply this, but tests consider this optional in case of ctor and dtor
                // this means old gnuv2 working demangled assumed optional as well
                cpdem_func_params (dem);
                return dem;
        }
    } else {
        /* XXX: Unreachable code, becaue cpdem_name already performs all required bounds check */
        return NULL;
    }

    return dem;
}

CpDem* cpdem_qualifiers_list (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    ut64 qualifier_count = 1;

    /* if there are qualifiers, then the first name is a type in it's own */
    dem->base_name = dem_string_new();
    dem_string_concat (dem->base_name, dem->name);

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
                return NULL;
            }
        } else if (PEEK (dem) >= '0' && PEEK (dem) <= '9') {
            /* single digit count */
            /* Q <qualifiers count> */
            qualifier_count = PEEK (dem) - '0';
            ADV (dem);
        } else {
            return NULL;
        }

        /* update current position */
        SET_CUR (dem, end);
    }

    /* get each qualifier */
    /* <qualifiers count> [<name length> <class name>]+ */
    return cpdem_class_names (dem, qualifier_count);
}

CpDem* cpdem_name (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    static const struct {
        const char* from;
        const char* to;
        size_t      len;
    } map[] = {
        {.from = "_aad_",        .to = "operator&=", .len = 5},
        {.from = "_adv_",        .to = "operator/=", .len = 5},
        {.from = "_aer_",        .to = "operator^=", .len = 5},
        {.from = "_als_",       .to = "operator<<=", .len = 5},
        {.from = "_aml_",        .to = "operator*=", .len = 5},
        {.from = "_amd_",        .to = "operator%=", .len = 5},
        {.from = "_ami_",        .to = "operator-=", .len = 5},
        {.from = "_aor_",        .to = "operator|=", .len = 5},
        {.from = "_apl_",        .to = "operator+=", .len = 5},
        {.from = "_ars_",       .to = "operator>>=", .len = 5},

        { .from = "_aa_",        .to = "operator&&", .len = 4},
        { .from = "_ad_",         .to = "operator&", .len = 4},
        { .from = "_as_",         .to = "operator=", .len = 4},

        { .from = "_cl_",        .to = "operator()", .len = 4},
        { .from = "_co_",         .to = "operator~", .len = 4},
        { .from = "_cm_",         .to = "operator,", .len = 4},

        { .from = "_dl_",   .to = "operator delete", .len = 4},
        { .from = "_dv_",         .to = "operator/", .len = 4},

        { .from = "_eq_",        .to = "operator==", .len = 4},
        { .from = "_er_",         .to = "operator^", .len = 4},

        { .from = "_ge_",        .to = "operator>=", .len = 4},
        { .from = "_gt_",         .to = "operator>", .len = 4},

        { .from = "_le_",        .to = "operator<=", .len = 4},
        { .from = "_ls_",        .to = "operator<<", .len = 4},
        { .from = "_lt_",         .to = "operator<", .len = 4},

        { .from = "_md_",         .to = "operator%", .len = 4},
        { .from = "_mi_",         .to = "operator-", .len = 4},
        { .from = "_ml_",         .to = "operator*", .len = 4},
        { .from = "_mm_",        .to = "operator--", .len = 4},

        { .from = "_ne_",        .to = "operator!=", .len = 4},
        { .from = "_nt_",         .to = "operator!", .len = 4},
        { .from = "_nw_",      .to = "operator new", .len = 4},

        { .from = "_oo_",          .to = "operator", .len = 4},
        /* explicitly matched : {.from = "__op<L>TYPE_", .to = "operator", .len = 3}, */
        { .from = "_or_",         .to = "operator|", .len = 4},

        { .from = "_pl_",         .to = "operator+", .len = 4},
        { .from = "_pp_",        .to = "operator++", .len = 4},

        { .from = "_rf_",        .to = "operator->", .len = 4},
        { .from = "_rm_",       .to = "operator->*", .len = 4},
        { .from = "_rs_",        .to = "operator>>", .len = 4},

        { .from = "_vc_",        .to = "operator[]", .len = 4},
        { .from = "_vd_", .to = "operator delete[]", .len = 4},
        { .from = "_vn_",    .to = "operator new[]", .len = 4},
    };

    /* TODO: _$ and _ */
    size_t map_count = sizeof (map) / sizeof (map[0]);

    /* if name begins with _, then it might be a constructor, a destructor or an operator. */
    if (PEEK (dem) == '_') {
        ADV (dem);

        // destructor
        if (PEEK (dem) == '$' || PEEK (dem) == '.') {
            ADV (dem);
            dem->is_dtor = true;
            return dem;
        } else if (PEEK (dem) == '_') {
            // opreator TYPE()
            // __op<L>TYPE_ : L is length and TYPE is name of type of length <L> characters
            if (IN_RANGE (dem, CUR (dem) + 4) && !strncmp (CUR (dem), "_op", 3) &&
                !IS_DIGIT (CUR (dem)[3])) {
                // read past _op
                SET_CUR (dem, CUR (dem) + 3);

                // get length of name
                char* end = NULL;
                ut64  len = strtoull (CUR (dem), &end, 10);
                if (!end) {
                    return NULL;
                }
                SET_CUR (dem, end);

                // add operator as name
                dem_string_append (dem->name, "operator ");
                dem_string_append_n (dem->name, CUR (dem), len);
                SET_CUR (dem, CUR (dem) + len);
                dem_string_append_n (dem->name, "()", 2);
                return dem;
            } else {
                // any other operator
                for (size_t x = 0; x < map_count; x++) {
                    if (IN_RANGE (dem, CUR (dem) + map[x].len) &&
                        !strncmp (CUR (dem), map[x].from, map[x].len)) {
                        dem_string_append (dem->name, map[x].to);
                        SET_CUR (dem, CUR (dem) + map[x].len);
                        dem->is_operator = true;
                        return dem;
                    }
                }
            }


            // constructor
            dem->is_ctor = true;
            return dem;
        } else {
            // move back one position, because this is a name now, not an operator
            // this name begins with underscore
            SET_CUR (dem, CUR (dem) - 1);
        }
    }

    /* match <name> if operator match didn't work */
    while (PEEK (dem)) {
        dem_string_append_char (dem->name, READ (dem));

        /* __ [F | Q | [0-9]] */
        /* If a qualifier(s) list or a function parameter(s) list starts then name ends there */
        if (IN_RANGE (dem, CUR (dem) + 2)) {
            const char* cur = CUR (dem);
            if (cur[0] == '_' && cur[1] == '_' &&
                (cur[2] == 'F' || cur[2] == 'Q' || cur[2] == 'H' || IS_DIGIT (cur[2]))) {
                break;
            }
        }
    }


    return dem;
}

CpDem* cpdem_class_names (CpDem* dem, ut64 qualifiers_count) {
    if (!dem || !qualifiers_count) {
        return NULL;
    }

    /* temporary string to append class/namespace names in order */
    DemString* class_names    = dem_string_new();
    DemString* last_qualifier = NULL;

    if (dem->is_ctor || dem->is_dtor) {
        last_qualifier = dem_string_new();
    }

    /* get each qualifier and append in class names list */
    while (qualifiers_count--) {
        /* <name length> */
        char* end         = NULL;
        ut64  name_length = strtoull (CUR (dem), &end, 10);
        if (!end || !IN_RANGE (dem, end) || !*end || !name_length) {
            return NULL;
        }
        SET_CUR (dem, end);

        /* <name length> <class name> */
        dem_string_append_n (class_names, CUR (dem), name_length);
        dem_string_append_n (class_names, "::", 2);

        /* save last qualifier */
        if ((dem->is_ctor || dem->is_dtor) && !qualifiers_count) {
            dem_string_append_n (last_qualifier, CUR (dem), name_length);
        }

        SET_CUR (dem, CUR (dem) + name_length);
    }

    if (dem->is_ctor) {
        dem_string_concat (class_names, last_qualifier);
        dem_string_free (last_qualifier);
        dem->is_ctor = false;
    } else if (dem->is_dtor) {
        dem_string_append_prefix_n (last_qualifier, "~", 1);
        dem_string_concat (class_names, last_qualifier);
        dem_string_free (last_qualifier);
        dem->is_dtor = false;
    }

    dem_string_append_prefix_n (
        dem->name,
        dem_string_buffer (class_names),
        dem_string_length (class_names)
    );
    dem_string_free (class_names);

    return dem;
}

CpDem* cpdem_func_params (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    dem->has_params = true;

#define APPEND(x) APPEND_N (x, strlen (x))
#define APPEND_N(x, l)                                                                             \
    do {                                                                                           \
        dem_string_append_n (param.name, x, l);                                                    \
        fparam_vec_append (&dem->func_params, &param);                                             \
    } while (0)

#define X()                                                                                        \
    do {                                                                                           \
        if (PEEK (dem) >= '0' && PEEK (dem) <= '9') {                                              \
            char* end          = NULL;                                                             \
            ut64  typename_len = strtoull (CUR (dem), &end, 10);                                   \
            if (!dem || !IN_RANGE (dem, end) || !typename_len ||                                   \
                !IN_RANGE (dem, CUR (dem) + typename_len)) {                                       \
                fparam_vec_deinit (&dem->func_params);                                             \
                return NULL;                                                                       \
            }                                                                                      \
            SET_CUR (dem, end);                                                                    \
                                                                                                   \
            APPEND_N (CUR (dem), typename_len);                                                    \
            SET_CUR (dem, CUR (dem) + typename_len);                                               \
        } else {                                                                                   \
            not_done = false;                                                                      \
        }                                                                                          \
    } while (0)

#define MATCH_TYPE()                                                                               \
    case 'b' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("bool");                                                                           \
        break;                                                                                     \
    case 'c' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("char");                                                                           \
        break;                                                                                     \
    case 'd' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("double");                                                                         \
        break;                                                                                     \
    case 'e' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("...");                                                                            \
        break;                                                                                     \
    case 'f' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("float");                                                                          \
        break;                                                                                     \
    case 'i' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("int");                                                                            \
        break;                                                                                     \
    case 'l' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("long");                                                                           \
        break;                                                                                     \
    case 'r' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("long double");                                                                    \
        break;                                                                                     \
    case 's' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("short");                                                                          \
        break;                                                                                     \
    case 'v' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("void");                                                                           \
        break;                                                                                     \
    case 'w' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("wchar_t");                                                                        \
        break;                                                                                     \
    case 'x' :                                                                                     \
        ADV (dem);                                                                                 \
        APPEND ("long long");                                                                      \
        break;                                                                                     \
    case 'G' : {                                                                                   \
        ADV (dem);                                                                                 \
        X();                                                                                       \
        break;                                                                                     \
    }                                                                                              \
    case 'U' :                                                                                     \
        ADV (dem);                                                                                 \
        switch (PEEK (dem)) {                                                                      \
                /* Uc */                                                                           \
            case 'c' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("unsigned char");                                                          \
                break;                                                                             \
                /* Us */                                                                           \
            case 's' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("unsigned short");                                                         \
                break;                                                                             \
                /* Ui */                                                                           \
            case 'i' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("unsigned int");                                                           \
                break;                                                                             \
                /* Ul */                                                                           \
            case 'l' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("unsigned long");                                                          \
                break;                                                                             \
                /* Ux */                                                                           \
            case 'x' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("unsigned long long");                                                     \
                break;                                                                             \
            default :                                                                              \
                not_done = false;                                                                  \
                fparam_vec_deinit (&dem->func_params);                                             \
                break;                                                                             \
        }                                                                                          \
        break;                                                                                     \
    case 'S' :                                                                                     \
        ADV (dem);                                                                                 \
        switch (PEEK (dem)) {                                                                      \
                /* Sc */                                                                           \
            case 'c' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("signed char");                                                            \
                break;                                                                             \
            default :                                                                              \
                not_done = false;                                                                  \
                fparam_vec_deinit (&dem->func_params);                                             \
                break;                                                                             \
        }                                                                                          \
        break;                                                                                     \
    case 'J' :                                                                                     \
        ADV (dem);                                                                                 \
        switch (PEEK (dem)) {                                                                      \
            /* Jf */                                                                               \
            case 'f' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("__complex__ float");                                                      \
                break;                                                                             \
            /* Jd */                                                                               \
            case 'd' :                                                                             \
                ADV (dem);                                                                         \
                APPEND ("__complex__ double");                                                     \
                break;                                                                             \
            default :                                                                              \
                not_done = false;                                                                  \
                fparam_vec_deinit (&dem->func_params);                                             \
                break;                                                                             \
        }                                                                                          \
        break;                                                                                     \
    case '0' :                                                                                     \
    case '1' :                                                                                     \
    case '2' :                                                                                     \
    case '3' :                                                                                     \
    case '4' :                                                                                     \
    case '5' :                                                                                     \
    case '6' :                                                                                     \
    case '7' :                                                                                     \
    case '8' :                                                                                     \
    case '9' :                                                                                     \
        X();                                                                                       \
        break;                                                                                     \
    default :                                                                                      \
        not_done = false;                                                                          \
        fparam_vec_deinit (&dem->func_params);                                                     \
        break;

    /* set to false the moment we encouter something we don't know about */
    bool not_done = true;

    while (not_done && PEEK (dem)) {
        FuncParam param;
        fparam_init (&param);

        switch (PEEK (dem)) {
            /* X */
            MATCH_TYPE();

            /* R - References */
            case 'R' :
                ADV (dem); /* skip R */
                fparam_append_to (&param, suffix, "&");
                /* let it fall through, becase 'R' and 'P' differ only at first */

            /* P - Pointers */
            case 'P' : {
                /* if it's not falling through 'R', but a direct case of 'P' */
                if (PEEK (dem) == 'P') {
                    ADV (dem); /* skip P */

                    /* need to prepend it this way, because we might already have & in the suffix */
                    fparam_prepend_to (&param, suffix, "*");
                }

                switch (PEEK (dem)) {
                    /* PX or RPX */
                    MATCH_TYPE();

                    case 'C' : {
                        ADV (dem); /* skip C */
                        fparam_append_to (&param, prefix, "const");

                        switch (PEEK (dem)) {
                            /* PCX */
                            MATCH_TYPE();

                            case 'V' : {
                                ADV (dem); /* skip V */
                                fparam_append_to (&param, prefix, " volatile");

                                switch (PEEK (dem)) {
                                    /* PCVX */
                                    MATCH_TYPE();
                                }
                                break;
                            }
                        }
                        break;
                    }

                    /* PVX */
                    case 'V' : {
                        ADV (dem); /* skip V */
                        fparam_append_to (&param, prefix, "volatile");
                        X();
                        break;
                    }
                }

                break;
            }

            /* T - reference back to a repeated type */
            case 'T' : {
                ADV (dem); /* skip T */

                /* get type index to copy here */
                char* end     = NULL;
                ut64  typeidx = strtoull (CUR (dem), &end, 10);
                if (!end || typeidx > dem->func_params.length) {
                    not_done = false;
                    fparam_vec_deinit (&dem->func_params);
                    break;
                }
                SET_CUR (dem, end);

                /* if length is more than single digit in it's string form, then there will be a "_" just after it */
                if (PEEK (dem) == '_') {
                    ADV (dem);
                }

                /* refer back to param list */
                if (typeidx == 0) {
                    /* the very first type is name of function itself, it should be considered at index 0 */
                    if (dem->base_name) {
                        FuncParam param;
                        fparam_init (&param);
                        fparam_append_to (&param, name, dem_string_buffer (dem->base_name));
                        fparam_vec_append (&dem->func_params, &param);
                    } else {
                        not_done = false;
                        fparam_vec_deinit (&dem->func_params);
                        break;
                    }
                } else {
                    fparam_deinit (&param);
                    fparam_init_clone (&param, vec_ptr_at (&dem->func_params, typeidx - 1));
                    fparam_vec_append (&dem->func_params, &param);
                }
                break;
            }
        }
    }

#undef APPEND
#undef APPEND_N
#undef X

    /* there mustn't be anything else after parsing all function param types */
    if (PEEK (dem)) {
        vec_deinit (&dem->func_params);
        return NULL;
    }

    if (!dem->func_params.length) {
        FuncParam param;
        fparam_init (&param);
        fparam_append_to (&param, name, "void");
        vec_append (&dem->func_params, &param);
    }

    return dem;
}

CpDem* cpdem_template_params (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    return dem;
}
