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

typedef struct {
    StrIter      original;
    CpDemOptions opts;

    DemString* name;      // TODO: convert this to a vector of qualifier strings
    DemString* base_name; // This is the name that we have before prepending qualifiers
    ParamVec   func_params;
    bool       has_params;

    DemString* suffix; // anything that is to be put at the very end of demangled output
    DemString* prefix; // a return type, or another keyword to be put before name

    bool is_ctor;
    bool is_dtor;
    bool is_operator;
} CpDem;

static CpDem*      cpdem_init (CpDem* dem, const char* mangled, CpDemOptions opts);
static const char* cpdem_get_demangled (CpDem* dem);
static CpDem*      cpdem_public_name (CpDem* dem);
static CpDem*      cpdem_deinit (CpDem* dem);

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

static CpDem* cpdem_qualifiers_list (CpDem* dem);
static CpDem* cpdem_name (CpDem* dem);
static CpDem* cpdem_class_names (CpDem* dem, ut64 qualifiers_count);
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
    dem->opts   = opts;
    dem->name   = dem_string_new();
    dem->suffix = dem_string_new();
    dem->prefix = dem_string_new();
    param_vec_init (&dem->func_params);
    return dem;
}

CpDem* cpdem_deinit (CpDem* dem) {
    if (!dem) {
        return NULL;
    }

    // deinit all func params first
    param_vec_deinit (&dem->func_params);

    if (dem->name) {
        dem_string_free (dem->name);
    }

    if (dem->base_name) {
        dem_string_free (dem->base_name);
    }

    if (dem->prefix) {
        dem_string_free (dem->prefix);
    }

    if (dem->suffix) {
        dem_string_free (dem->suffix);
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
        // vec_foreach_ptr (&dem->func_params, param, {
        for (Param* param = dem->func_params.data;
             param < dem->func_params.data + dem->func_params.length;
             param++) {
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
        }
        // });
        dem_string_append_char (demangled, ')');
    }

    const char* res = dem_str_ndup (dem_string_buffer (demangled), dem_string_length (demangled));
    dem_string_free (demangled);

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
                // TODO: return cpdem_template_param_type (dem);
                return NULL;

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
    } else if ((PEEK (dem) >= '0' && PEEK (dem) <= '9') || PEEK (dem) == 't') {
        /* if just one qualifier, then length of qualifier comes first */
        qualifier_count = 1;
    } else {
        /* this was a mistake, and this is not a qualifier, backtrack */
        return NULL;
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
                st64 len;
                cpdem_number (dem, len);
                if (len <= 0) {
                    return NULL;
                }

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

        /* __ [F | Q | H | t | [0-9]] */
        /* If a qualifier(s) list or a function parameter(s) list starts then name ends there */
        if (IN_RANGE (dem, CUR (dem) + 2)) {
            const char* cur = CUR (dem);
            if (cur[0] == '_' && cur[1] == '_' &&
                (cur[2] == 'F' || cur[2] == 'Q' || cur[2] == 'H' || cur[2] == 't' ||
                 IS_DIGIT (cur[2]))) {
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

    if (dem->is_ctor || dem->is_dtor || dem->is_operator) {
        last_qualifier = dem_string_new();
    }

    // if it's constructor or destructor or an operator
    // then the last qualifier is the base name
    // in this case, name.len is zero
    // if name.len is not zero, then base name is set to that
    dem->base_name = dem_string_new();

    /* get each qualifier and append in class names list */
    while (qualifiers_count--) {
        DemString* name = dem_string_new();

        if (PEEK (dem) == 't') {
            ADV (dem);
            if (!cpdem_template_class (dem, name)) {
                dem_string_free (name);
                return NULL;
            }
        } else {
            if (!cpdem_custom_type_name (dem, name)) {
                dem_string_free (name);
                return NULL;
            }
        }

        dem_string_concat (class_names, name);
        /* if the mangled name represents a constructor or a destructor
         * then save the last qualifier in the list of qualifiers */
        if ((dem->is_ctor || dem->is_dtor || dem->is_operator) && !qualifiers_count) {
            dem_string_concat (last_qualifier, name);
        }
        dem_string_free (name);
        dem_string_append_n (class_names, "::", 2);
    }

    /* set base name */
    if (dem->is_ctor || dem->is_operator || dem->is_dtor) {
        dem_string_concat (dem->base_name, last_qualifier);
    } else if (dem->name->len) {
        dem_string_concat (dem->base_name, dem->name);
    }

    /* add a constructor or destructor name if required */
    if (dem->is_ctor) {
        dem_string_concat (class_names, last_qualifier);
        dem->is_ctor = dem->is_operator = false;
    } else if (dem->is_dtor) {
        dem_string_append_prefix_n (last_qualifier, "~", 1);
        dem_string_concat (class_names, last_qualifier);
        dem->is_dtor = false;
    }

    dem_string_free (last_qualifier);

    /* qualifiers appear at the very beginning */
    dem_string_append_prefix_n (
        dem->name,
        dem_string_buffer (class_names),
        dem_string_length (class_names)
    );
    dem_string_free (class_names);

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
    dem_string_append (param.name, x) ?                                                            \
        (param_vec_append (params, &param) ? dem : (param_deinit (&param), NULL)) :                \
        (param_deinit (&param), NULL)

    /** read a custom type from current read position and add it to params vector if success */
#define ADD_NAMED_PARAM()                                                                          \
    cpdem_custom_type_name (dem, param.name) ?                                                     \
        (param_vec_append (params, &param) ? dem : (param_deinit (&param), NULL)) :                \
        (param_deinit (&param), NULL)

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
        if (cpdem_template_class (dem, param.name)) {                                              \
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
    case 'G' : {                                                                                   \
        ADV (dem);                                                                                 \
        return ADD_NAMED_PARAM();                                                                  \
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

            /* refer back to param list */
            if (dem->base_name && (typeidx == 0)) {
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

                    param_append_to (&p, name, dem_string_buffer (dem->base_name));
                    param_vec_append (params, &p);
                }
            } else {
                /* if base name is considered as first type then assume array index starts at 1 in vector */
                if (dem->base_name) {
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

    /* if no parameters present, but we did come here to get params, just append void */
    if (!dem->func_params.length) {
        Param param = {0};
        param_init (&param);
        param_append_to (&param, name, "void");
        vec_append (&dem->func_params, &param);
    }

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
            Param* param     = vec_end (params);
            param->name->len = param->prefix->len = param->suffix->len = 0;

            if (!strncmp (param->name->buf, "bool", 4)) {
                /* if the type is bool, then value will be converted to true/false */
                dem_string_append (param->name, val ? "true" : "false");
            } else {
                /* no need to convert value back to string, we already have that */
                size_t val_string_len = pos_after_val - pos_after_val;
                dem_string_append_n (param->name, pos_before_val, val_string_len);
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
    DemString* class_name = dem_string_new();
    if (!cpdem_custom_type_name (dem, class_name)) {
        dem_string_free (class_name);
        return NULL;
    }

    /* number of template parameters */
    st64 numtp = 0;
    cpdem_number (dem, numtp);
    if (numtp <= 0) {
        dem_string_free (tclass_name);
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
    dem_string_concat (tclass_name, class_name);
    bool first_param = true;
    dem_string_append_char (tclass_name, '<');
    vec_foreach_ptr (&params, p, {
        if (first_param) {
            first_param = false;
        } else {
            dem_string_append_n (tclass_name, ", ", 2);
        }

        /* tclass_name += <prefix> <name> <suffix> */
        if (dem_string_length (p->prefix)) {
            dem_string_concat (tclass_name, p->prefix);
            dem_string_append_char (tclass_name, ' ');
        }
        dem_string_concat (tclass_name, p->name);
        if (dem_string_length (p->suffix)) {
            dem_string_append_char (tclass_name, ' ');
            dem_string_concat (tclass_name, p->suffix);
        }
    });
    dem_string_append_char (tclass_name, '>');

    /* release temp resources */
    dem_string_free (class_name);
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
        SET_CUR (dem, CUR (dem) + typename_len);
    } else {
        return NULL;
    }

    return dem;
}
