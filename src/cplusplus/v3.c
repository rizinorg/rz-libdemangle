// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Documentation for used grammar can be found at either of
 * - https://files.brightprogrammer.in/cxx-abi/
 * - https://itanium-cxx-abi.github.io/cxx-abi/
 */

#include "cplusplus/vec.h"
#include "demangler_util.h"

#define DBG_PRINT_DETECTED_TYPES   0
#define DBG_PRINT_DETECTED_TPARAMS 0

#define REPLACE_GLOBAL_N_WITH_ANON_NAMESPACE 1

#if 0
#    ifndef __has_builtin
#        define __has_builtin(n) (0)
#    endif

#    if __has_builtin(__builtin_debugtrap)
#        define rz_sys_breakpoint() __builtin_debugtrap()
#    endif

#    ifndef rz_sys_breakpoint
#        if __WINDOWS__
#            define rz_sys_breakpoint()                                                            \
                { __debugbreak(); }
#        else
#            if __GNUC__
#                define rz_sys_breakpoint() __builtin_trap()
#            elif __i386__ || __x86_64__
#                define rz_sys_breakpoint() __asm__ volatile ("int3");
#            elif __arm64__ || __aarch64__
#                define rz_sys_breakpoint() __asm__ volatile ("brk 0");
// #define rz_sys_breakpoint() __asm__ volatile ("brk #1");
#            elif (__arm__ || __thumb__)
#                if __ARM_ARCH > 5
#                    define rz_sys_breakpoint() __asm__ volatile ("bkpt $0");
#                else
#                    define rz_sys_breakpoint() __asm__ volatile ("svc $1");
#                endif
#            elif __mips__
#                define rz_sys_breakpoint() __asm__ volatile ("break");
// #  define rz_sys_breakpoint() __asm__ volatile ("teq $0, $0");
#            elif __EMSCRIPTEN__
// TODO: cannot find a better way to breakpoint in wasm/asm.js
#                define rz_sys_breakpoint()                                                        \
                    {                                                                              \
                        char* a = NULL;                                                            \
                        *a      = 0;                                                               \
                    }
#            else
#                warning rz_sys_breakpoint not implemented for this platform
#                define rz_sys_trap() __asm__ __volatile__ (".word 0");
#                define rz_sys_breakpoint()                                                        \
                    {                                                                              \
                        char* a = NULL;                                                            \
                        *a      = 0;                                                               \
                    }
#            endif
#        endif
#    endif
#else
#    define rz_sys_breakpoint()
#endif

/**
 * \b String iterator
 **/
typedef struct StrIter {
    const char* beg; /**< \b Beginning position of string. */
    const char* end; /**< \b Ending of string (usually points to the null-terminator char). */
    const char* cur; /**< \b Current read position. */
} StrIter;

typedef Vec (DemString) StrVec;

/**
 * \b Give current read position.
 *
 * \return const char pointer to current read position.
 */
#define CUR() (msi->cur)

/**
 * \b Give position where string begins. 
 *
 * \return const char pointer to beginning of mangled string.
 */
#define BEG() (msi->beg)

/**
 * \b Give position of NULL terminator. 
 *
 * \return const char pointer to end of mangled string.
 */
#define END() (msi->end)

/**
 * \b Check whether the provided position is in range of readable address.
 *
 * \p read_pos : char pointer to check for range.
 *
 * \return 1 if in range.
 * \return 0 otherwise. 
 */
#define IN_RANGE(read_pos) ((read_pos) >= BEG() ? ((read_pos) < END() ? 1 : 0) : 0)

/**
 * \b Seek to given read position if it's in range. This will change the current
 * read position to given target_read_pos.
 *
 * \p target_read_pos : char pointer specifying the target read position to seek to.
 *
 * \return target_read_pos on success.
 * \return CUR() otherwise.
 */
#define SEEK_TO(target_read_pos) (msi->cur = IN_RANGE (target_read_pos) ? (target_read_pos) : CUR())

/**
 * Peek one character from current read position in demangling context.
 * This will NOT advance, unlike READ().
 *
 * \return char on success.
 * \return 0 if no more characters left
 */
#define PEEK() (IN_RANGE (CUR()) ? *msi->cur : 0)

/**
 * \b Read one character from current read position in demangling context
 * and then advance by one position.
 *
 * \return 1 on success.
 * \return 0 otherwise. 
 */
#define READ(ch)          (IN_RANGE (CUR()) ? ((*msi->cur == ch) ? (ADV(), 1) : 0) : 0)
#define READ_OPTIONAL(ch) (READ (ch) || true)

/**
 * \b Read multiple characters in a null-terminated character array,
 * and if the string is found starting from current position, return 1, and
 * advance by that many characters.
 * 
 * \return 1 on success.
 * \return 0 otherwise.
 */
#define READ_STR(s)                                                                                \
    (IN_RANGE (CUR() + sizeof (s) - 1) ?                                                           \
         (!strncmp (CUR(), s, sizeof (s) - 1) ? (ADV_BY (sizeof (s) - 1), 1) : 0) :                \
         0)
#define READ_STR_OPTIONAL(s) (READ_STR (s) || true)

/**
 * \b Advance current read position by one character, if this next
 * position is in range, otherwise stay at current read position.
 *
 * \return updated read position on success.
 * \return NULL otherwise.
 */
#define ADV() (IN_RANGE (CUR() + 1) ? msi->cur++ : NULL)

/**
 * \b Advance current read position by "n" characters, if this next
 * position is in range, otherwise stay at current read position.
 *
 * \return updated read position on success.
 * \return NULL otherwise.
 */
#define ADV_BY(n) (IN_RANGE (CUR() + n) ? (msi->cur = msi->cur + (n)) : NULL)

/**
 * \b Save current read position in demangling context to restore it later.
 * This is used when we know that while matching a rule we might fail, and we'll
 * need to backtrack. For this we must remember the initial trial start pos.
 */
#define SAVE_POS() const char* _____trial_start_pos = CUR();

/**
 * \b Restore saved position
 */
#define RESTORE_POS()                                                                              \
    do {                                                                                           \
        SEEK_TO (_____trial_start_pos);                                                            \
    } while (0)

/**
 * Reads a number from current demangling position to provided "var" variable.
 * Automatically will adjust next read position if numbe read is successful, otherwise, will
 * set var to -1
 */
#define READ_NUMBER(var)                                                                           \
    do {                                                                                           \
        char* end = NULL;                                                                          \
        (var)     = strtoll (CUR(), &end, 10);                                                     \
        if (!end) {                                                                                \
            (var) = -1;                                                                            \
            break;                                                                                 \
        }                                                                                          \
        SEEK_TO (end);                                                                             \
    } while (0)

typedef struct Meta {
    StrVec detected_types;
    StrVec template_params;
    bool   is_ctor;
    bool   is_dtor;
    bool   is_const;

    // detected templates are reset everytime a new template argument list starts at the same level
    // instead of taking care of that, we just rebase from where we start our substitution
    // this way we just keep adding templates and incrementing this idx_start on every reset
    // so a T_ (index = 0) can actually refer to index = 5
    int template_idx_start;
    int last_reset_idx;

    // template level, detects the depth of RULE(template_args) expansion
    // if we expand above level 1 (starts at level 1), then we stop appending parameters to template
    // parameter list
    int  t_level;
    bool template_reset;
} Meta;

static inline bool meta_tmp_init (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return false;
    }

    vec_concat (&tmp->detected_types, &og->detected_types);
    vec_concat (&tmp->template_params, &og->template_params);
    tmp->is_ctor            = og->is_ctor;
    tmp->is_dtor            = og->is_dtor;
    tmp->is_const           = og->is_const;
    tmp->template_idx_start = og->template_idx_start;
    tmp->last_reset_idx     = og->last_reset_idx;
    tmp->t_level            = og->t_level;
    tmp->template_reset     = og->template_reset;

    return false;
}

static inline void meta_tmp_apply (Meta* og, Meta* tmp) {
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

    og->is_ctor            = tmp->is_ctor;
    og->is_dtor            = tmp->is_dtor;
    og->is_const           = tmp->is_const;
    og->template_idx_start = tmp->template_idx_start;
    og->last_reset_idx     = tmp->last_reset_idx;
    og->t_level            = tmp->t_level;
    og->template_reset     = tmp->template_reset;
}

static inline void meta_tmp_fini (Meta* og, Meta* tmp) {
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

#define IS_CTOR()  (m->is_ctor)
#define IS_DTOR()  (m->is_dtor)
#define IS_CONST() (m->is_const)

#define SET_CTOR()  (m->is_dtor = false, (m->is_ctor = true))
#define SET_DTOR()  (m->is_ctor = false, (m->is_dtor = true))
#define SET_CONST() (m->is_const = true)

#define UNSET_CTOR()  (m->is_dtor = false, m->is_ctor = false, true)
#define UNSET_DTOR()  (m->is_ctor = false, m->is_dtor = false, true)
#define UNSET_CONST() (m->is_const = false, true)

/**
 * Type of rules.
 *
 * \p dem Demangled string.
 * \p msi Mangled string iter.
 *
 * \return dem on success.
 * \return NULL otherwise.
 */
typedef DemString* (*DemRule) (DemString* dem, StrIter* msi, Meta* m);

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
static DemString*
    match_one_or_more_rules (DemRule rule, const char* sep, DemString* dem, StrIter* msi, Meta* m) {
    if (!rule || !dem || !msi || !m) {
        return NULL;
    }

    // NOTE(brightprogrammer): Just here to check the current iteration in debugger
    // No special use
    ut32 iter_for_dbg = 0;

    SAVE_POS();
    /* match atleast once, and then */
    if (rule (dem, msi, m) && ++iter_for_dbg) {
        /* match as many as possible */
        while (true) {
            DemString tmp = {0};
            SAVE_POS();
            if (rule (&tmp, msi, m) && ++iter_for_dbg) {
                /* add separator before appending demangled string */
                if (sep) {
                    dem_string_append_prefix_n (&tmp, sep, strlen (sep));
                }

                /* append the demangled string and deinit tmp */
                dem_string_concat (dem, &tmp);
                dem_string_deinit (&tmp);
            } else {
                RESTORE_POS();
                dem_string_deinit (&tmp);
                break;
            }
        }

        return dem;
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
static DemString* match_zero_or_more_rules (
    DemRule     rule,
    const char* sep,
    DemString*  dem,
    StrIter*    msi,
    Meta*       m
) {
    if (!rule || !dem || !msi || !m) {
        return NULL;
    }

    while (true) {
        DemString tmp = {0};
        SAVE_POS();
        if (rule (&tmp, msi, m)) {
            if (sep) {
                dem_string_append (&tmp, sep);
            }
            dem_string_concat (dem, &tmp);
            dem_string_deinit (&tmp);
        } else {
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

    /* we always match, even if nothing matches */
    return dem;
}

/**
 * \b Call a rule.
 *
 * \p x Rule name.
 * 
 * \return DemString containing demangled string generated by the called rule.
 * \return NULL if rule match fails for any reason.
 */
#define RULE(x) rule_##x (dem, msi, m)

/**
 * \b Defer the demangling to `var`.
 *
 * This is used in cases where we don't want to immidiately add the demangled
 * string generated by an issued rule. The demangled string stored in provided `var`
 * can then be later on appended to a higher level demangled string generated by
 * a higher level rule.
 *
 * If a rule X calls another rule Y, then rule X is called the higher level rule
 * in this context.
 *
 * \p var Variable to defer the demangled name to.
 * \p x   Rule name
 *
 * \return DemString containing demangled string generated by the called rule.
 * \return NULL if rule match fails for any reason.
 */
#define RULE_DEFER(var, x) rule_##x ((var), msi, m)
#define DEFER_VAR(var)                                                                             \
    DemString  tmp_defer_var_##var = {};                                                           \
    DemString* var                 = &tmp_defer_var_##var;                                         \
    dem_string_init (var);
#define APPEND_DEFER_VAR(var) (dem_string_concat (dem, (var)), dem_string_deinit (var), 1)

/**
 * Always evaluate to true, even if rule does not match.
 * */
#define OPTIONAL(x) ((x) || true)

/**
 * \b Match given rule name atleast once.
 *
 * \p x Rule name
 *
 * \return DemString containing demangled string generated by the called rule.
 * \return NULL if rule match fails for any reason.
 */
#define RULE_ATLEAST_ONCE(x)               match_one_or_more_rules (rule_##x, NULL, dem, msi, m)
#define RULE_ATLEAST_ONCE_WITH_SEP(x, sep) match_one_or_more_rules (rule_##x, sep, dem, msi, m)

/**
 * \b Match given rule name any number of times.
 *
 * \p x Rule name
 *
 * \return DemString containing demangled string generated by the called rule.
 * \return NULL if rule match fails for any reason.
 */
#define RULE_MANY(x)               match_zero_or_more_rules (rule_##x, NULL, dem, msi, m)
#define RULE_MANY_WITH_SEP(x, sep) match_zero_or_more_rules (rule_##x, sep, dem, msi, m)
#define RULE_DEFER_MANY(var, x)    match_zero_or_more_rules (rule_##x, NULL, (var), msi, m)

/**
 * \b Declare a new rule so that it can be used with RULE(...) macro later on.
 *
 * \p x Rule name
 */
#define DECL_RULE(x) static DemString* rule_##x (DemString* dem, StrIter* msi, Meta* m)

/**
 * \b Declare a rule alias x for rule y.
 *
 * For example, a rule alias <function_name> for rule <name>
 * This will define a function then and there for rule alias, so
 * no explicit defnition must be present.
 *
 * \p alias_x Name of rule alias
 * \p for_y   Name of rule to create alias for.
 */
#define DECL_RULE_ALIAS(alias_x, for_y) DEFN_RULE (alias_x, { MATCH (RULE (for_y)); })

/**
 * \b Define a rule with name x and given rule body.
 *
 * This will define a function for the given rule name.
 * The rule body will generally contain further rule matchings.
 *
 * \p x          Rule name.
 * \p rule_body  Rule body.
 *
 * \return DemString* containing currently demangled string on success.
 * \return NULL otherwise.
 */
#define DEFN_RULE(x, rule_body)                                                                    \
    DECL_RULE (x) {                                                                                \
        if (!strncmp (msi->cur, "RAT__KcRAT0__S6_", strlen ("RAT__KcRAT0__S6_"))) {                \
            rz_sys_breakpoint();                                                                   \
        }                                                                                          \
        if (!dem || !msi || !m) {                                                                  \
            return NULL;                                                                           \
        }                                                                                          \
        { rule_body }                                                                              \
        return NULL;                                                                               \
    }

#define MATCH_FAILED()                                                                             \
    do {                                                                                           \
        meta_tmp_fini (_og_meta, &_tmp_meta);                                                      \
        /* if rule matched, then concat tmp with original and switch back names */                 \
        dem_string_deinit (&_tmp_dem);                                                             \
        dem = _og_dem;                                                                             \
        m   = _og_meta;                                                                            \
        RESTORE_POS();                                                                             \
        break;                                                                                     \
    } while (0)

/**
 * \b Match for given rules in a recoverable manner. If rule matching fails,
 * the demangled string in current context is not changed. This allows
 * multiple matches to be tried one after another without any if-else
 * case, just like an alternation.
 *
 * In other words, this MATCH macro provides a way to backtrack out of the box.
 * If rule matching is successful then it'll add the demangled string and return.
 * 
 * Since the first match will be appended to demangled string in current context,
 * it's very important to match the superset languages first, and then subsets.
 * For example, see how `RULE(mangled_name)` is defined.
 *
 * NOTE: By default, match_and_do will always be successful, once it attempts
 * to execute the given code body. But this can be changed by calling MATCH_FAIL()
 * to say that the mayching actually failed inside the given code body, and
 * the rule must continue looking for an alternative match by continuing the code
 * execution
 *
 * WARN: never return from a rule, this will disrupt the control flow.
 * 
 * \p rules  A sequence concatenation or alternation of RULEs and READs
 * \p body   What to do if rule matches.
 */
#define MATCH_AND_DO(rules, body)                                                                  \
    do {                                                                                           \
        SAVE_POS();                                                                                \
        /* make a temporary string to prevent from altering real string */                         \
        DemString  _tmp_dem = {0};                                                                 \
        DemString* _og_dem  = dem;                                                                 \
        dem                 = &_tmp_dem;                                                           \
        Meta  _tmp_meta     = {0};                                                                 \
        Meta* _og_meta      = m;                                                                   \
        m                   = &_tmp_meta;                                                          \
        meta_tmp_init (_og_meta, &_tmp_meta);                                                      \
        if ((rules)) {                                                                             \
            /* caller execute code */                                                              \
            {body};                                                                                \
                                                                                                   \
            meta_tmp_apply (_og_meta, &_tmp_meta);                                                 \
            /* if rule matched, then concat tmp with original and switch back names */             \
            dem_string_concat (_og_dem, &_tmp_dem);                                                \
            dem_string_deinit (&_tmp_dem);                                                         \
                                                                                                   \
            dem = _og_dem;                                                                         \
            m   = _og_meta;                                                                        \
            return dem;                                                                            \
        } else {                                                                                   \
            MATCH_FAILED();                                                                        \
        }                                                                                          \
    } while (0)

#define MATCH(rules) MATCH_AND_DO (rules, {})

#define MATCH_AND_CONTINUE(rules)                                                                  \
    do {                                                                                           \
        SAVE_POS();                                                                                \
        /* make a temporary string to prevent from altering real string */                         \
        DemString  _tmp_dem = {0};                                                                 \
        DemString* _og_dem  = dem;                                                                 \
        dem                 = &_tmp_dem;                                                           \
        Meta  _tmp_meta     = {0};                                                                 \
        Meta* _og_meta      = m;                                                                   \
        m                   = &_tmp_meta;                                                          \
        meta_tmp_init (_og_meta, &_tmp_meta);                                                      \
        if ((rules)) {                                                                             \
            meta_tmp_apply (_og_meta, &_tmp_meta);                                                 \
            /* if rule matched, then concat tmp with original and switch back names */             \
            dem_string_concat (_og_dem, &_tmp_dem);                                                \
            dem_string_deinit (&_tmp_dem);                                                         \
                                                                                                   \
            dem = _og_dem;                                                                         \
            m   = _og_meta;                                                                        \
        } else {                                                                                   \
            MATCH_FAILED();                                                                        \
        }                                                                                          \
    } while (0)

#define APPEND_STR(s) dem_string_append (dem, s)
#define APPEND_CHR(c) dem_string_append_char (dem, c)

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
    return true;
}
#define APPEND_TYPE(tname)       append_type (m, (tname), false)
#define FORCE_APPEND_TYPE(tname) append_type (m, (tname), true)

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
#define APPEND_TPARAM(tname) OPTIONAL (m->t_level < 2 && append_tparam (m, (tname)))

/**
 * Refer back to a previous type from detected types and then add that
 * type to the currently demangled string
 */
#define SUBSTITUTE_TYPE(id)                                                                        \
    (m->detected_types.length > (id) ?                                                             \
         (APPEND_STR (vec_ptr_at (&m->detected_types, (id))->buf) ? dem : NULL) :                  \
         NULL)

#define SUBSTITUTE_TPARAM(id)                                                                      \
    (m->template_params.length > (id) ?                                                            \
         (APPEND_STR (vec_ptr_at (&m->template_params, (id))->buf) ? dem : NULL) :                 \
         NULL)

/* TODO: what to do with this? */
typedef enum CpDemOptions {
    x,
    y
} CpDemOptions;

DECL_RULE (mangled_name);

const char* cp_demangle_v3 (const char* mangled, CpDemOptions opts) {
    if (!mangled) {
        return NULL;
    }

    StrIter  si  = {.beg = mangled, .cur = mangled, .end = mangled + strlen (mangled) + 1};
    StrIter* msi = &si;

    DemString* dem = dem_string_new();

    Meta  meta = {0};
    Meta* m    = &meta;

    if (RULE (mangled_name)) {
#if DBG_PRINT_DETECTED_TYPES
        dem_string_append (dem, " || ");
        vec_foreach_ptr (&m->detected_types, t, {
            dem_string_append_n (dem, "\n[", 2);
            dem_string_concat (dem, t);
            dem_string_append_n (dem, "]", 1);
        });
#endif
#if DBG_PRINT_DETECTED_TPARAMS
        dem_string_append (dem, " || ");
        m->template_params.data     += m->template_idx_start;
        m->template_params.length   -= m->template_idx_start;
        m->template_params.capacity -= m->template_idx_start;
        vec_foreach_ptr (&m->template_params, t, {
            dem_string_append_n (dem, "\n", 1);
            dem_string_concat (dem, t);
        });
        m->template_params.length   += m->template_idx_start;
        m->template_params.capacity += m->template_idx_start;
        m->template_params.data     -= m->template_idx_start;
#endif
        vec_deinit (&meta.detected_types);
        return dem_string_drain (dem);
    } else {
        vec_deinit (&meta.detected_types);
        dem_string_free (dem);
        return NULL;
    }

    return NULL;
}

/*
    _ZN
        St8__detail17__regex_algo_implI
                                        PKcSaI
                                                N
                                                    St7__cxx119sub_matchI
                                                                            S2_
                                                                        E
                                                E
                                            EcN
                                                S3_12regex_traitsI
                                                                    c
                                                                 E
                                              E
                                      E
     EbT_S9_RN
                S3_13match_resultsI
                                    S9_T0_
                                  E
             ERKN
                    S3_11basic_regexI
                                        T1_T2_
                                    E
                EN
                    St15regex_constants15match_flag_type
                 EN
                    S_20_RegexExecutorPolicy
                  Eb
 */

/********************************* LIST OF ALL RULE DECLARATIONS IN GRAMMAR *******************************/
DECL_RULE (encoding);
DECL_RULE (name);
DECL_RULE (unscoped_name);
DECL_RULE (nested_name);
DECL_RULE (cv_qualifiers);
DECL_RULE (ref_qualifier);
DECL_RULE (prefix);
// DECL_RULE (closure_prefix);
DECL_RULE (template_param);
DECL_RULE (decltype);
DECL_RULE (template_prefix);
DECL_RULE (unqualified_name);
DECL_RULE_ALIAS (variable_or_member_unqualified_name, unqualified_name);
// DECL_RULE_ALIAS (variable_template_template_prefix, template_prefix);
DECL_RULE (ctor_dtor_name);
DECL_RULE (source_name);
DECL_RULE (number);
// DECL_RULE_ALIAS (positive_length_number, number);
// DECL_RULE (identifier);
DECL_RULE (unnamed_type_name);
DECL_RULE (abi_tag);
DECL_RULE (abi_tags);
DECL_RULE (operator_name);
DECL_RULE (type);
DECL_RULE (builtin_type);
DECL_RULE (expression);
DECL_RULE (unresolved_name);
DECL_RULE (function_param);
DECL_RULE_ALIAS (top_level_cv_qualifiers, cv_qualifiers);
DECL_RULE_ALIAS (non_negative_number, number)
DECL_RULE (expr_primary);
DECL_RULE (float);
DECL_RULE_ALIAS (value_number, number);
DECL_RULE_ALIAS (value_float, float);
DECL_RULE_ALIAS (string_type, type);
/* DECL_RULE_ALIAS (nullptr_type, type); */
DECL_RULE_ALIAS (pointer_type, type);
DECL_RULE_ALIAS (real_part_float, float);
DECL_RULE_ALIAS (imag_part_float, float);
DECL_RULE (initializer);
DECL_RULE (braced_expression);
DECL_RULE_ALIAS (field_source_name, source_name);
DECL_RULE_ALIAS (index_expression, expression);
DECL_RULE_ALIAS (range_begin_expression, expression);
DECL_RULE_ALIAS (range_end_expression, expression);
DECL_RULE (base_unresolved_name);
DECL_RULE (simple_id);
DECL_RULE (destructor_name);
DECL_RULE (unresolved_type);
DECL_RULE (unresolved_qualifier_level);
DECL_RULE_ALIAS (instantiation_dependent_expression, expression);
DECL_RULE (qualified_type);
DECL_RULE (qualifiers);
DECL_RULE (extended_qualifier);
DECL_RULE (function_type);
DECL_RULE (exception_spec);
DECL_RULE (class_enum_type);
DECL_RULE (array_type);
DECL_RULE_ALIAS (element_type, type);
DECL_RULE_ALIAS (instantiation_dependent_array_bound_expression, expression);
DECL_RULE_ALIAS (array_bound_number, number);
DECL_RULE (pointer_to_member_type);
DECL_RULE_ALIAS (class_type, type);
/* DECL_RULE_ALIAS (member_type, type); */
DECL_RULE (template_template_param);
DECL_RULE (digit);
DECL_RULE_ALIAS (template_unqualified_name, unqualified_name);
DECL_RULE (template_args);
DECL_RULE (template_arg);
// DECL_RULE (unscoped_template_name);
DECL_RULE (substitution);
DECL_RULE (seq_id);
DECL_RULE (local_name);
DECL_RULE_ALIAS (function_encoding, encoding);
DECL_RULE_ALIAS (entity_name, name);
DECL_RULE (discriminator);
DECL_RULE (vendor_specific_suffix);
DECL_RULE (special_name);
DECL_RULE (call_offset);
DECL_RULE_ALIAS (base_encoding, encoding);
DECL_RULE (call_offset);
DECL_RULE (nv_offset);
DECL_RULE (v_offset);
DECL_RULE_ALIAS (offset_number, number);
DECL_RULE_ALIAS (virtual_offset_number, number);
DECL_RULE_ALIAS (function_name, name);
DECL_RULE_ALIAS (data_name, name);
DECL_RULE (bare_function_type);
DECL_RULE_ALIAS (signature_type, type);
/**********************************************************************************************************/

DEFN_RULE (mangled_name, {
    MATCH (
        READ_STR ("_Z") && RULE (encoding) && OPTIONAL (READ ('.') && RULE (vendor_specific_suffix))
    );
});

// DEFN_RULE (encoding, {
DemString* rule_encoding (DemString* dem, StrIter* msi, Meta* m) {
    bool is_const = false;

    DEFER_VAR (param_list);
    DEFER_VAR (fname);
    DEFER_VAR (rtype);

    MATCH (
        // function name
        RULE_DEFER (fname, function_name) &&

        // If last detected type is same as this function name
        // then we made a mistake
        OPTIONAL (
            m->detected_types.length && !strcmp (vec_end (&m->detected_types)->buf, fname->buf) &&
            (dem_string_deinit (vec_end (&m->detected_types)), true) &&
            (m->detected_types.length--, true)
        ) &&

        OPTIONAL (IS_CONST() && (is_const = true) && UNSET_CONST()) &&

        // HACK(brightprogrammer):
        // functions with template parameters have return type encoded
        // this is a hack to detect whether a function has templates,
        // it might be bad, but it works!
        OPTIONAL (
            // possibly a template
            (fname->buf[fname->len - 1] == '>') &&

            // not ends with an "operator>"
            (fname->len > 9 ? !!strncmp (fname->buf + fname->len - 9, "operator>", 9) : true) &&

            // if function type is a builtin type then we don't want to append it to list of detected types
            // in any other case we do!
            (RULE_DEFER (rtype, builtin_type) || (RULE_DEFER (rtype, type) && APPEND_TYPE (rtype)))
        ) &&

        // param list
        RULE_DEFER (param_list, bare_function_type) &&

        // apply return type first
        OPTIONAL ((rtype->len) && APPEND_DEFER_VAR (rtype) && APPEND_CHR (' ')) &&

        // generate rest of the name <name> ( <params> ) [const] [&]
        APPEND_DEFER_VAR (fname) && APPEND_CHR ('(') && APPEND_DEFER_VAR (param_list) &&
        APPEND_CHR (')') && OPTIONAL (is_const && APPEND_STR (" const"))
    );

    dem_string_deinit (param_list);
    dem_string_deinit (fname);
    dem_string_deinit (rtype);

    MATCH (RULE (data_name));
    MATCH (RULE (special_name));
    return NULL;
}
// });

// DEFN_RULE (name, {
DemString* rule_name (DemString* dem, StrIter* msi, Meta* m) {
    bool is_const = false;
    MATCH (RULE (nested_name));

    // next two matches are breakdown of RULE(unscoped_template_name)
    // where if we match a substitution we don't want to append it as a detected type
    MATCH (
        RULE (unscoped_name) && APPEND_TYPE (dem) &&
        OPTIONAL ((is_const = IS_CONST()) && UNSET_CONST()) && RULE (template_args) &&
        APPEND_TYPE (dem) && OPTIONAL (is_const && APPEND_STR (" const"))
    );
    MATCH (
        RULE (substitution) && OPTIONAL ((is_const = IS_CONST()) && UNSET_CONST()) &&
        RULE (template_args) && OPTIONAL (is_const && APPEND_STR (" const"))
    );

    MATCH (RULE (unscoped_name));
    MATCH (RULE (local_name));
    // });
    return NULL;
}

DEFN_RULE (local_name, {
    MATCH (
        READ ('Z') && RULE (function_encoding) && READ ('E') && APPEND_STR ("::") &&
        RULE (entity_name) && OPTIONAL (RULE (discriminator))
    );

    MATCH (
        READ ('Z') && RULE (function_encoding) && READ_STR ("Es") && APPEND_STR ("::") &&
        OPTIONAL (RULE (discriminator))
    );
});

DEFN_RULE (discriminator, {
    if (READ ('_')) {
        // matched two "_"
        if (READ ('_')) {
            st64 numlt10 = -1;
            READ_NUMBER (numlt10);
            if (numlt10 >= 10) {
                // do something
                return dem;
            }
        } else {
            // matched single "_"
            st64 numlt10 = -1;
            READ_NUMBER (numlt10);
            if (numlt10 >= 0 && numlt10 < 10) {
                // do something
                return dem;
            }
        }
    }
});

// NOTE(brightprogrammer): I don't know how to decode this. Is this is a normal RULE(suffix)?
// Will have to go through tests to see.
DEFN_RULE (vendor_specific_suffix, { return NULL; });

/* 
 * NOTE: Taken from old c++v3 demangler code
 * Some of these are tested, others are not encountered yet.
 *
 * <special-name> ::= TV <type>
		  ::= TT <type>
		  ::= TI <type>
		  ::= TS <type>
		  ::= TA <template-arg>
		  ::= GV <(object) name>
		  ::= T <call-offset> <(base) encoding>
		  ::= Tc <call-offset> <call-offset> <(base) encoding>
   Also g++ extensions:
		  ::= TC <type> <(offset) number> _ <(base) type>
		  ::= TF <type>
		  ::= TJ <type>
		  ::= GR <name>
		  ::= GA <encoding>
		  ::= Gr <resource name>
		  ::= GTt <encoding>
		  ::= GTn <encoding>
*/

DEFN_RULE (special_name, {
    MATCH (READ_STR ("TV") && APPEND_STR ("vtable for ") && RULE (type));
    MATCH (READ_STR ("TT") && APPEND_STR ("construction vtable index for ") && RULE (type));
    MATCH (READ_STR ("TI") && APPEND_STR ("typeinfo for ") && RULE (type));
    MATCH (READ_STR ("TS") && APPEND_STR ("typeinfo name for ") && RULE (type));
    MATCH (
        READ_STR ("Tc") && APPEND_STR ("covariant thunk for") && RULE (call_offset) &&
        RULE (call_offset) && RULE (base_encoding)
    );

    // untested, so I'm placing any string I want to here, so that i can be deteced as bug in testing
    MATCH (READ_STR ("GV") && APPEND_STR ("guard variable ") && RULE (name));
    MATCH (READ_STR ("No") && APPEND_STR ("guard variable ") && RULE (type));
    MATCH (READ_STR ("GR") && APPEND_STR ("first temporary ") && RULE (name) && READ ('_'));
    MATCH (
        READ_STR ("GR") && APPEND_STR ("subsequent temporary ") && RULE (name) && RULE (seq_id) &&
        READ ('_')
    );
    MATCH (
        READ_STR ("GTt") && APPEND_STR ("transaction save function entry point for ") &&
        RULE (encoding)
    );

    MATCH (READ ('T') && RULE (call_offset) && RULE (base_encoding));
});

DEFN_RULE (call_offset, {
    MATCH (READ ('h') && APPEND_STR ("non-virtual thunk to ") && RULE (nv_offset) && READ ('_'));
    MATCH (READ ('v') && APPEND_STR ("virtual thunk to ") && RULE (v_offset) && READ ('_'));
});

DEFN_RULE (nv_offset, {
    // ignore the number
    DEFER_VAR (_);
    MATCH (RULE_DEFER (_, offset_number) && (dem_string_deinit (_), 1));
});

DEFN_RULE (v_offset, {
    // ignore the number
    DEFER_VAR (_);
    MATCH (
        RULE_DEFER (_, offset_number) && READ ('_') && RULE_DEFER (_, virtual_offset_number) &&
        (dem_string_deinit (_), 1)
    );
});

DEFN_RULE (unscoped_name, {
    MATCH (OPTIONAL (READ_STR ("St") && APPEND_STR ("std::")) && RULE (unqualified_name));
});

static inline bool make_nested_name (DemString* dem, DemString* pfx, DemString* uname, Meta* m) {
    if (!dem || !pfx || !uname) {
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
            UNSET_CTOR();
        } else if (IS_DTOR()) {
            dem_string_concat (dem, pfx);
            dem_string_append (dem, "::~");
            dem_string_append (dem, rbeg);
            UNSET_DTOR();
        } else {
            dem_string_concat (dem, pfx);
            if (uname->len) {
                APPEND_STR ("::");
                dem_string_concat (dem, uname);
            }
        }

        dem_string_deinit (pfx);
        dem_string_deinit (uname);

        return true;
    } else {
        dem_string_deinit (pfx);
        dem_string_deinit (uname);
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
static inline bool make_template_nested_name (
    DemString* dem,
    DemString* pfx,
    DemString* targs,
    DemString* uname,
    Meta*      m
) {
    if (!dem || !pfx || !targs || !uname) {
        return false;
    }

    // HACK: a hacky way to find name of constructor
    // find content before first "<" (template argument start)
    // find last appearance of "::" that comes before found "<"

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
        UNSET_CTOR();
    } else if (IS_DTOR()) {
        dem_string_concat (dem, pfx);
        dem_string_concat (dem, targs);
        dem_string_append (dem, "::~");
        dem_string_append_n (dem, n_beg, n_len);
        UNSET_DTOR();
    } else {
        dem_string_concat (dem, pfx);
        dem_string_concat (dem, targs);
        if (uname->len) {
            APPEND_STR ("::");
            dem_string_concat (dem, uname);
        }
    }

    dem_string_deinit (pfx);
    dem_string_deinit (uname);
    dem_string_deinit (targs);

    return true;
}

// DEFN_RULE (nested_name, {
DemString* rule_nested_name (DemString* dem, StrIter* msi, Meta* m) {
    DEFER_VAR (ref);
    DEFER_VAR (pfx);
    DEFER_VAR (uname);

    /*
     * HACK(brightprogrammer):
     * Reference qualifiers are present at the end of type names. The way we match
     * the grammar rules (linearly, from left to right), there is no direct way to append
     * the matched reference qualifier at the end.
     *
     * For this we use RULE_DEFER to temporarily store the deferred rule, and then
     * append it later on after complete matching is done
     */

    /* NOTE(brightprogrammer):
     * these two rules make up matching for the rule
     *   <nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E 
     */
    MATCH (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) && RULE_DEFER (ref, ref_qualifier) &&
        RULE_DEFER (pfx, prefix) && RULE_DEFER (uname, unqualified_name) &&
        make_nested_name (dem, pfx, uname, m) && READ ('E') && APPEND_DEFER_VAR (ref)
    );
    dem_string_deinit (ref);
    dem_string_deinit (pfx);
    dem_string_deinit (uname);


    MATCH (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) && RULE_DEFER (pfx, prefix) &&
        RULE_DEFER (uname, unqualified_name) && make_nested_name (dem, pfx, uname, m) && READ ('E')
    );
    dem_string_deinit (ref);
    dem_string_deinit (pfx);
    dem_string_deinit (uname);


    DEFER_VAR (targs);

    /* NOTE(brightprogrammer):
     * these two rules make up matching for the rule
     *   <nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <template-args> E
     *
     * NOTE(brightprogrammer):
     * Rule for <template-args> in concatenation below is not an optional rule.
     * The parser already detects template args before we reach here (inside template-prefix),
     * and I don't want to really pay attention to how this happens, I've already changed the grammar
     * a lot, and my head is exploding from long debugging sessions.
     * So, I'll just make it optional here, for just-in-case, otherwise the matching works as expected.
     */
    MATCH (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) && RULE_DEFER (ref, ref_qualifier) &&
        RULE_DEFER (pfx, template_prefix) && OPTIONAL (RULE_DEFER (targs, template_args)) &&
        OPTIONAL (RULE_DEFER (uname, unqualified_name)) &&
        make_template_nested_name (dem, pfx, targs, uname, m) && READ ('E') &&
        APPEND_DEFER_VAR (ref)
    );
    dem_string_deinit (ref);
    dem_string_deinit (pfx);
    dem_string_deinit (uname);
    dem_string_deinit (targs);


    MATCH (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) && RULE_DEFER (pfx, template_prefix) &&
        OPTIONAL (RULE_DEFER (targs, template_args)) &&

        OPTIONAL (RULE_DEFER (uname, unqualified_name)) &&
        make_template_nested_name (dem, pfx, targs, uname, m) && READ ('E')
    );
    dem_string_deinit (ref);
    dem_string_deinit (pfx);
    dem_string_deinit (uname);
    dem_string_deinit (targs);
    // });
    return NULL;
}

DEFN_RULE (cv_qualifiers, {
    MATCH (READ ('r') && APPEND_STR ("restrict"));
    MATCH (READ ('V') && APPEND_STR ("volatile"));
    MATCH (READ ('K') && SET_CONST());
});

DEFN_RULE (ref_qualifier, {
    MATCH (READ ('R') && APPEND_STR ("&"));
    MATCH (READ ('O') && APPEND_STR ("&&"));
});

DECL_RULE_ALIAS (prefix_b, template_args);

DEFN_RULE (prefix_c, { return dem; });

DEFN_RULE (prefix_X, {
    MATCH (RULE (unqualified_name) && APPEND_TYPE (dem));
    MATCH (RULE (template_param) && APPEND_TYPE (dem));
    MATCH (RULE (decltype) && APPEND_TYPE (dem));
    MATCH (RULE (substitution));
});

DECL_RULE_ALIAS (template_prefix_l, template_unqualified_name);

DECL_RULE (template_prefix_Y);

DEFN_RULE (closure_prefix_m, { MATCH (RULE (variable_or_member_unqualified_name) && READ ('M')); });

DECL_RULE (closure_prefix_Z);
// DEFN_RULE (prefix__template_prefix__closure_prefix__T, {
//     MATCH (
//         APPEND_STR ("::") && RULE (template_prefix_l) && RULE (prefix_b) &&
//         OPTIONAL (RULE (prefix__template_prefix__closure_prefix__T))
//     );
//     MATCH (
//         APPEND_STR ("::") && RULE (closure_prefix_m) && RULE (prefix_c) &&
//         OPTIONAL (RULE (prefix__template_prefix__closure_prefix__T))
//     );

//     return dem; // match empty
// });

/*
 * HACK(brightprogrammer):
 * Turns out that the way we generate demangled names is not helpful when a child
 * node requires data from parent node. Node being a rule application.
 *
 * For this a better idea is to inline the rule application then and there, and
 * what's better than using a macro?
 *
 * So, this macro imitates what the above rule definition tries to do.
 * TODO: no use of having a macro, this can be a RULE() as well!
 *
 * XXX: Even after getting a correct demangled string RULE(template_prefix) is discarding the value for some reason
 * - clang::CodeGen::DominatingValue<clang::CodeGen::RValue>::saved_type::needsSaving
 * I suspect it's because of this macro!
 * */
#define prefix__template_prefix__closure_prefix__T()                                               \
    do {                                                                                           \
        bool matched = true;                                                                       \
        DEFER_VAR (un);                                                                            \
        while (matched) {                                                                          \
            matched = false;                                                                       \
                                                                                                   \
            DEFER_VAR (accu); /* accumulator */                                                    \
                                                                                                   \
            dem_string_concat (accu, dem);                                                         \
            DemString* parent_dem = dem;                                                           \
                                                                                                   \
            MATCH_AND_CONTINUE (                                                                   \
                dem_string_append (accu, "::") && RULE_DEFER (accu, template_prefix_l) &&          \
                APPEND_TYPE (accu) &&                                                              \
                OPTIONAL (                                                                         \
                    RULE_DEFER (un, source_name) && dem_string_append (accu, "::") &&              \
                    dem_string_concat (accu, un) && APPEND_TYPE (accu)                             \
                ) &&                                                                               \
                RULE_DEFER (accu, prefix_b) && APPEND_TYPE (accu) && (matched = true) &&           \
                (dem_string_deinit (parent_dem), dem_string_init_clone (dem, accu))                \
            );                                                                                     \
                                                                                                   \
            dem_string_deinit (un);                                                                \
                                                                                                   \
            if (matched) {                                                                         \
                continue;                                                                          \
            }                                                                                      \
                                                                                                   \
            dem_string_deinit (accu);                                                              \
            dem_string_concat (accu, dem);                                                         \
                                                                                                   \
            MATCH_AND_CONTINUE (                                                                   \
                dem_string_append (accu, "::") && RULE_DEFER (accu, closure_prefix_m) &&           \
                APPEND_TYPE (accu) && RULE_DEFER (accu, prefix_c) && APPEND_TYPE (accu) &&         \
                (matched = true) &&                                                                \
                (dem_string_deinit (parent_dem), dem_string_init_clone (dem, accu))                \
            );                                                                                     \
        }                                                                                          \
    } while (0)


// DEFN_RULE (prefix, {
DemString* rule_prefix (DemString* dem, StrIter* msi, Meta* m) {
    DEFER_VAR (pfx);

    if (RULE_DEFER (pfx, prefix_X)) {
        const char* last_pos        = msi->cur;
        const char* second_last_pos = msi->cur;

        DEFER_VAR (curr_name);
        DEFER_VAR (last_name);
        DEFER_VAR (second_last_name);

        Meta last_meta        = {0};
        Meta second_last_meta = {0};

        meta_tmp_init (m, &last_meta);
        meta_tmp_init (m, &second_last_meta);

        while (true) {
            // if we get a match at current position, then we append the last match
            // if we don't get a match at current position, then we don't get a change to append a last match
            // this mechanism forces this rule to leave out the last unqualified_name
            if (RULE_DEFER (curr_name, unqualified_name)) {
                // <total_name> += :: <last_name>
                // this condition is true on second iteration,
                // when last_name is not empty for the first time
                if (second_last_pos != last_pos) {
                    dem_string_append (pfx, "::");
                    dem_string_concat (pfx, last_name);
                    APPEND_TYPE (pfx);
                }

                // update second last name to store last name
                //    and last name to store current name
                dem_string_deinit (second_last_name);
                dem_string_concat (second_last_name, last_name);
                dem_string_deinit (last_name);
                dem_string_concat (last_name, curr_name);
                dem_string_deinit (curr_name);

                // update second last meta to store last meta
                //    and last meta to store current meta
                {
                    UNUSED (vec_reserve (
                        &second_last_meta.detected_types,
                        last_meta.detected_types.length
                    ));
                    memcpy (
                        second_last_meta.detected_types.data,
                        last_meta.detected_types.data,
                        vec_mem_size (&last_meta.detected_types)
                    );
                    second_last_meta.detected_types.length = last_meta.detected_types.length;
                    second_last_meta.is_ctor               = last_meta.is_ctor;
                    second_last_meta.is_dtor               = last_meta.is_dtor;

                    UNUSED (vec_reserve (&last_meta.detected_types, m->detected_types.length));
                    memcpy (
                        last_meta.detected_types.data,
                        m->detected_types.data,
                        vec_mem_size (&m->detected_types)
                    );
                    last_meta.detected_types.length = m->detected_types.length;
                    last_meta.is_ctor               = m->is_ctor;
                    last_meta.is_dtor               = m->is_dtor;
                }

                // update second last pos to store last pos
                //    and last pos to store current pos
                second_last_pos = last_pos;
                last_pos        = msi->cur;
            } else {
                // if match fails, then we restore back to last matched position
                // and return as if that's not yet matched
                msi->cur = second_last_pos;

                for (DemString* ds = m->detected_types.data + last_meta.detected_types.length;
                     ds < m->detected_types.data + m->detected_types.length;
                     ds++) {
                    dem_string_deinit (ds);
                }

                m->detected_types.length = last_meta.detected_types.length;

                UNUSED (vec_deinit (&second_last_meta.detected_types));
                UNUSED (vec_deinit (&last_meta.detected_types));

                break;
            }
        }

        APPEND_TYPE (pfx);

        dem_string_concat (dem, pfx);
        dem_string_deinit (pfx);
        dem_string_deinit (last_name);
        dem_string_deinit (second_last_name);

        return dem;
    }

    // fix mutual-recursions
    MATCH_AND_DO (RULE (prefix_X) && APPEND_TYPE (dem), {
        prefix__template_prefix__closure_prefix__T();
    });

    MATCH_AND_DO (RULE (template_prefix_Y) && RULE (prefix_b) && APPEND_TYPE (dem), {
        prefix__template_prefix__closure_prefix__T();
    });

    MATCH_AND_DO (RULE (closure_prefix_Z) && RULE (prefix_c) && APPEND_TYPE (dem), {
        prefix__template_prefix__closure_prefix__T();
    });
    // });
    return NULL;
}

DEFN_RULE (abi_tags, { MATCH (RULE_ATLEAST_ONCE (abi_tag)); });

DEFN_RULE (abi_tag, {
    // will generate " \"<source_name>\","
    MATCH (READ ('B') && APPEND_STR (" \"") && RULE (source_name) && APPEND_STR ("\","));
})

DEFN_RULE (decltype, {
    MATCH (READ_STR ("Dt") && RULE (expression) && READ ('E'));
    MATCH (READ_STR ("DT") && RULE (expression) && READ ('E'));
});

DEFN_RULE (closure_prefix_Z_l, {
    MATCH_AND_DO (RULE (prefix_c), {
        prefix__template_prefix__closure_prefix__T();

        bool matched = false;
        MATCH (RULE (closure_prefix_m) && (matched = true));

        if (!matched) {
            MATCH_FAILED();
        }
    });
});

DEFN_RULE (closure_prefix_Z_k, { MATCH (RULE (template_args) && READ ('M')); })

DEFN_RULE (closure_prefix_Z, {
    MATCH (
        RULE (closure_prefix_Z_l) && RULE (closure_prefix_Z_k) && OPTIONAL (RULE (closure_prefix_Z))
    );
});

// DEFN_RULE (closure_prefix, {
//     MATCH (
//         OPTIONAL (RULE (prefix_X)) && RULE (prefix__template_prefix__closure_prefix__T) &&
//         RULE (closure_prefix_m)
//     );
//     MATCH (
//         RULE (template_prefix_Y) && RULE (prefix_b) &&
//         RULE (prefix__template_prefix__closure_prefix__T) && RULE (closure_prefix_m)
//     );
//     MATCH (
//         RULE (closure_prefix_Z) && RULE (prefix_c) &&
//         RULE (prefix__template_prefix__closure_prefix__T) && RULE (closure_prefix_m)
//     );
//     MATCH (RULE (closure_prefix_Z));
// });

DEFN_RULE (template_prefix_Y, {
    MATCH (RULE (template_unqualified_name));
    MATCH (RULE (template_param));
    MATCH (RULE (substitution));
});

DEFN_RULE (template_prefix, {
    MATCH_AND_DO (RULE (prefix_X) && APPEND_TYPE (dem), {
        prefix__template_prefix__closure_prefix__T();
    });

    MATCH_AND_DO (RULE (template_prefix_Y) && APPEND_TYPE (dem) && RULE (prefix_b), {
        prefix__template_prefix__closure_prefix__T();
    });

    MATCH_AND_DO (RULE (closure_prefix_Z) && APPEND_TYPE (dem) && RULE (prefix_c), {
        prefix__template_prefix__closure_prefix__T();
    });

    MATCH (RULE (template_prefix_Y) && APPEND_TYPE (dem));
});

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
            if (m->template_params.length > sid && vec_ptr_at (&m->template_params, sid)->buf) {
                FORCE_APPEND_TYPE (vec_ptr_at (&m->template_params, sid));
            }
            return SUBSTITUTE_TPARAM (sid);
        } else if (READ ('_')) {
            size_t sid = m->template_idx_start;
            if (m->template_params.length > sid && vec_ptr_at (&m->template_params, sid)->buf) {
                FORCE_APPEND_TYPE (vec_ptr_at (&m->template_params, sid));
            }
            return SUBSTITUTE_TPARAM (sid);
        }
    }
    RESTORE_POS();
});

DEFN_RULE (template_template_param, {
    MATCH (RULE (template_param));
    MATCH (RULE (substitution));
});

DEFN_RULE (substitution, {
    // HACK(brightprogrammer): This is not in original grammar, but this works!
    // Because having a "7__cxx11" just after a substitution "St" does not make sense to original grammar
    // Placing it here is also important, the order matters!
    MATCH (READ_STR ("St7__cxx11") && APPEND_STR ("std::__cxx11"));

    MATCH (READ_STR ("St") && APPEND_STR ("std"));
    MATCH (READ_STR ("Sa") && APPEND_STR ("std::allocator"));
    MATCH (READ_STR ("Sb") && APPEND_STR ("std::basic_string"));
    MATCH (
        READ_STR ("Ss") &&
        // APPEND_STR ("std::basic_string<char, std::char_traits<char>, std::allocator<char>>")
        APPEND_STR ("std::string")
    );
    MATCH (
        READ_STR ("Si") && APPEND_STR ("std::istream")
        // APPEND_STR ("std::basic_istream<char, std::char_traits<char>>")
    );
    MATCH (
        READ_STR ("So") && APPEND_STR ("std::ostream")
        // APPEND_STR ("std::basic_ostream<char, std::char_traits<char>>")
    );
    MATCH (
        READ_STR ("Sd") && APPEND_STR ("std::iostream")
        // APPEND_STR ("std::basic_iostream<char, std::char_traits<char>>")
    );

    MATCH (READ ('S') && RULE (seq_id) && READ ('_'));
});

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
        return SUBSTITUTE_TYPE (sid);
    } else if (PEEK() == '_') {
        return SUBSTITUTE_TYPE (0);
    }
});

DEFN_RULE (unqualified_name, {
// NOTE(brightprogrammer):
// Manual replacements, this is not in original grammar
#if REPLACE_GLOBAL_N_WITH_ANON_NAMESPACE
    MATCH (READ_STR ("12_GLOBAL__N_1") && APPEND_STR ("(anonymous namespace)"));
#endif

    MATCH (RULE (operator_name) && OPTIONAL (RULE (abi_tags)));
    MATCH (RULE (ctor_dtor_name));
    MATCH (RULE (source_name));
    MATCH (RULE (unnamed_type_name));
    /* MATCH (RULE (expr_primary)); */
    MATCH (READ_STR ("DC") && RULE_ATLEAST_ONCE (source_name) && READ ('E'));
});

DEFN_RULE (unnamed_type_name, {
    if (READ_STR ("Ut")) {
        st64 tidx = -1;
        READ_NUMBER (tidx);
        if (tidx >= 0) {
            // do something
        } else {
            return NULL;
        }

        if (READ ('_')) {
            return dem;
        }
    }
});

DEFN_RULE (ctor_dtor_name, {
    // NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
    MATCH (READ_STR ("C1") && SET_CTOR()); // gnu complete object ctor
    MATCH (READ_STR ("C2") && SET_CTOR()); // gnu base object ctor
    MATCH (READ_STR ("C3") && SET_CTOR()); // gnu complete object allocating ctor
    MATCH (READ_STR ("C4") && SET_CTOR()); // gnu unified ctor
    MATCH (READ_STR ("C5") && SET_CTOR()); // gnu object ctor group
    MATCH (READ_STR ("CI1") && SET_CTOR());
    MATCH (READ_STR ("CI2") && SET_CTOR());
    MATCH (READ_STR ("D0") && SET_DTOR()); // gnu deleting dtor
    MATCH (READ_STR ("D1") && SET_DTOR()); // gnu complete object dtor
    MATCH (READ_STR ("D2") && SET_DTOR()); // gnu base object dtor
    // 3 is not used
    MATCH (READ_STR ("D4") && SET_DTOR()); // gnu unified dtor
    MATCH (READ_STR ("D5") && SET_DTOR()); // gnu object dtor group
});

DEFN_RULE (operator_name, {
    MATCH (READ_STR ("nw") && APPEND_STR ("operator new"));
    MATCH (READ_STR ("na") && APPEND_STR ("operator new[]"));
    MATCH (READ_STR ("dl") && APPEND_STR ("operator delete"));
    MATCH (READ_STR ("da") && APPEND_STR ("operator delete[]"));
    MATCH (READ_STR ("aw") && APPEND_STR ("operator co_await"));
    MATCH (READ_STR ("ps") && APPEND_STR ("operator+"));
    MATCH (READ_STR ("ng") && APPEND_STR ("operator-"));
    MATCH (READ_STR ("ad") && APPEND_STR ("operator&"));
    MATCH (READ_STR ("de") && APPEND_STR ("operator*"));
    MATCH (READ_STR ("co") && APPEND_STR ("operator~"));
    MATCH (READ_STR ("pl") && APPEND_STR ("operator+"));
    MATCH (READ_STR ("mi") && APPEND_STR ("operator-"));
    MATCH (READ_STR ("ml") && APPEND_STR ("operator*"));
    MATCH (READ_STR ("dv") && APPEND_STR ("operator/"));
    MATCH (READ_STR ("rm") && APPEND_STR ("operator%"));
    MATCH (READ_STR ("an") && APPEND_STR ("operator&"));
    MATCH (READ_STR ("or") && APPEND_STR ("operator|"));
    MATCH (READ_STR ("eo") && APPEND_STR ("operator^"));
    MATCH (READ_STR ("aS") && APPEND_STR ("operator="));
    MATCH (READ_STR ("pL") && APPEND_STR ("operator+="));
    MATCH (READ_STR ("mI") && APPEND_STR ("operator-="));
    MATCH (READ_STR ("mL") && APPEND_STR ("operator*="));
    MATCH (READ_STR ("dV") && APPEND_STR ("operator/="));
    MATCH (READ_STR ("rM") && APPEND_STR ("operator%="));
    MATCH (READ_STR ("aN") && APPEND_STR ("operator&="));
    MATCH (READ_STR ("oR") && APPEND_STR ("operator|="));
    MATCH (READ_STR ("eO") && APPEND_STR ("operator^="));
    MATCH (READ_STR ("ls") && APPEND_STR ("operator<<"));
    MATCH (READ_STR ("rs") && APPEND_STR ("operator>>"));
    MATCH (READ_STR ("lS") && APPEND_STR ("operator<<="));
    MATCH (READ_STR ("rS") && APPEND_STR ("operator>>="));
    MATCH (READ_STR ("eq") && APPEND_STR ("operator=="));
    MATCH (READ_STR ("ne") && APPEND_STR ("operator!="));
    MATCH (READ_STR ("lt") && APPEND_STR ("operator<"));
    MATCH (READ_STR ("gt") && APPEND_STR ("operator>"));
    MATCH (READ_STR ("le") && APPEND_STR ("operator<="));
    MATCH (READ_STR ("ge") && APPEND_STR ("operator>="));
    MATCH (READ_STR ("ss") && APPEND_STR ("operator<=>"));
    MATCH (READ_STR ("nt") && APPEND_STR ("operator!"));
    MATCH (READ_STR ("aa") && APPEND_STR ("operator&&"));
    MATCH (READ_STR ("oo") && APPEND_STR ("operator||"));
    MATCH (READ_STR ("pp") && APPEND_STR ("operator++"));
    MATCH (READ_STR ("mm") && APPEND_STR ("operator--"));
    MATCH (READ_STR ("cm") && APPEND_STR ("operator,"));
    MATCH (READ_STR ("pm") && APPEND_STR ("operator->*"));
    MATCH (READ_STR ("pt") && APPEND_STR ("operator->"));
    MATCH (READ_STR ("cl") && APPEND_STR ("operator()"));
    MATCH (READ_STR ("ix") && APPEND_STR ("operator[]"));
    MATCH (READ_STR ("qu") && APPEND_STR ("operator?"));

    /* will generate " (type)" */
    MATCH (READ_STR ("cv") && APPEND_STR ("operator (") && RULE (type) && APPEND_STR (")"));

    /* operator-name ::= li <source-name>          # operator ""*/
    MATCH (
        READ_STR ("li") && RULE (source_name)
    ); // TODO(brightprogrammer): How to generate for this operator?

    MATCH (READ ('v') && RULE (digit) && RULE (source_name));
});

DEFN_RULE (type, {
    // must be at the top before any other type is matched
    MATCH (
        RULE (array_type) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );

    // HACK(brightprogrammer): Template substitutions need to be forcefully appended to
    // list of detected types for future substitutions. This is even if they're already
    // detected.
    // NOTE: This needs to be above the hack for RULE(type) below
    MATCH (
        READ_STR ("PKPK") && RULE (template_param) && APPEND_STR (" const") &&
        FORCE_APPEND_TYPE (dem) && APPEND_STR ("*") && FORCE_APPEND_TYPE (dem) &&
        APPEND_STR (" const") && FORCE_APPEND_TYPE (dem) && APPEND_STR ("*") &&
        FORCE_APPEND_TYPE (dem)
    );
    MATCH (
        READ_STR ("PK") && RULE (template_param) && APPEND_STR (" const") &&
        FORCE_APPEND_TYPE (dem) && APPEND_STR ("*") && FORCE_APPEND_TYPE (dem)
    );
    MATCH (
        READ_STR ("PR") && RULE (template_param) && APPEND_STR (" const") &&
        FORCE_APPEND_TYPE (dem) && APPEND_STR ("&") && FORCE_APPEND_TYPE (dem)
    );

    // HACK(brightprogrammer): Current parsing method makes it hard to parse and demangle
    // this correctly. Must be parsed before parsing P or O or R
    MATCH (
        READ_STR ("PKPK") && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem) &&
        APPEND_STR ("*") && APPEND_TYPE (dem) && APPEND_STR (" const") && APPEND_TYPE (dem) &&
        APPEND_STR ("*") && APPEND_TYPE (dem)
    );
    MATCH (
        READ_STR ("PK") && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem) &&
        APPEND_STR ("*") && APPEND_TYPE (dem)
    );
    MATCH (
        READ_STR ("PR") && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem) &&
        APPEND_STR ("&") && APPEND_TYPE (dem)
    );

    MATCH (RULE (builtin_type));
    MATCH (
        RULE (function_type) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );
    MATCH (
        RULE (class_enum_type) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );
    MATCH (
        RULE (pointer_to_member_type) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );
    MATCH (
        RULE (template_param) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );
    MATCH (
        RULE (template_template_param) && RULE (template_args) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );
    MATCH (
        RULE (decltype) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );

    MATCH (READ ('K') && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem)); // pointer
    MATCH (READ ('P') && RULE (type) && APPEND_CHR ('*') && APPEND_TYPE (dem));      // pointer
    MATCH (READ ('R') && RULE (type) && APPEND_CHR ('&') && APPEND_TYPE (dem)); // l-value reference
    MATCH (
        READ ('O') && RULE (type) && APPEND_STR ("&&") && APPEND_TYPE (dem)
    );                                 // r-value reference (C++11)
    MATCH (READ ('C') && RULE (type)); // complex pair (C99)
    MATCH (READ ('G') && RULE (type)); // imaginary (C99)
    MATCH (
        RULE (substitution) && OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );                                 // Names that've already been substituted don't get numbered
    MATCH (
        RULE (qualified_type) && APPEND_TYPE (dem) &&
        OPTIONAL (IS_CONST() && APPEND_STR (" const") && UNSET_CONST())
    );
});

DEFN_RULE (class_enum_type, {
    MATCH (OPTIONAL (READ_STR ("Ts") || READ_STR ("Tu") || READ_STR ("Te")) && RULE (name));
});

DEFN_RULE (array_type, {
    DEFER_VAR (array_num);
    DEFER_VAR (etype);

    bool is_ref = false;

    // pointer type
    // MATCH_AND_DO (
    //     OPTIONAL (is_ref = READ ('R')) && READ ('A') && READ ('_') && RULE (element_type) &&
    //         APPEND_STR (" *") && APPEND_TYPE (dem),
    //     {
    //         DemString dt = {0};
    //         dem_string_concat (&dt, etype);
    //         dem_string_append (&dt, " [");
    //         dem_string_concat (&dt, array_num);
    //         dem_string_append (&dt, "]");
    //
    //         APPEND_TYPE (&dt);
    //
    //         if (is_ref) {
    //             dem_string_deinit (&dt);
    //
    //             dem_string_concat (&dt, etype);
    //             dem_string_append (&dt, " (&) [");
    //             dem_string_concat (&dt, array_num);
    //             dem_string_append (&dt, "]");
    //
    //             APPEND_TYPE (&dt);
    //         } else {
    //             dem_string_concat (dem, &dt);
    //             dem_string_deinit (&dt);
    //         }
    //     }
    // );

    MATCH_AND_DO (
        OPTIONAL (is_ref = READ ('R')) && READ ('A') &&
            OPTIONAL (
                RULE_DEFER (array_num, array_bound_number) ||
                RULE_DEFER (array_num, instantiation_dependent_array_bound_expression)
            ) &&
            READ ('_') && RULE_DEFER (etype, element_type),
        {
            DemString dt = {0};
            dem_string_concat (&dt, etype);
            dem_string_append (&dt, " [");
            dem_string_concat (&dt, array_num);
            dem_string_append (&dt, "]");

            // TODO: Do we really force append here?
            FORCE_APPEND_TYPE (&dt);

            if (is_ref) {
                dem_string_deinit (&dt);

                dem_string_concat (&dt, etype);
                dem_string_append (&dt, " (&) [");
                dem_string_concat (&dt, array_num);
                dem_string_append (&dt, "]");

                // TODO: Do we really force append here?
                FORCE_APPEND_TYPE (&dt);

                dem_string_concat (dem, &dt);
                dem_string_deinit (&dt);
            } else {
                dem_string_concat (dem, &dt);
                dem_string_deinit (&dt);
            }
        }
    );
    dem_string_deinit (array_num);
    dem_string_deinit (etype);
});

DEFN_RULE (pointer_to_member_type, {
    DEFER_VAR (ctype);
    DEFER_VAR (rtype);
    DEFER_VAR (args);
    MATCH (
        READ ('M') && RULE_DEFER (ctype, class_type) && READ ('F') && RULE_DEFER (rtype, type) &&
        RULE_DEFER (args, bare_function_type) && APPEND_DEFER_VAR (rtype) &&

        APPEND_STR (" (") && APPEND_DEFER_VAR (ctype) && APPEND_STR ("::*)") &&

        APPEND_CHR ('(') && APPEND_DEFER_VAR (args) && APPEND_CHR (')')
    );
});

DEFN_RULE (function_type, {
    bool is_const   = false;
    bool is_functor = false;
    MATCH (
        OPTIONAL (READ ('P') && (is_functor = true)) &&
        OPTIONAL (RULE (cv_qualifiers) && IS_CONST() && (is_const = true) && UNSET_CONST()) &&
        OPTIONAL (RULE (exception_spec)) && READ_STR_OPTIONAL ("Dx") && READ ('F') &&
        READ_OPTIONAL ('Y') && RULE (signature_type) &&
        (is_functor ? APPEND_STR (" (*)(") : APPEND_STR (" (")) && RULE_MANY (bare_function_type) &&
        APPEND_CHR (')') && OPTIONAL (is_const && APPEND_STR (" const")) &&
        OPTIONAL (RULE (ref_qualifier)) && READ ('E')
    );
});

DEFN_RULE (exception_spec, {
    MATCH (READ_STR ("Do"));
    MATCH (READ_STR ("DO") && RULE (expression) && READ ('E'));
    MATCH (READ_STR ("Dw") && RULE_ATLEAST_ONCE (type) && READ ('E'));
});

DEFN_RULE (qualified_type, { MATCH (RULE (qualifiers) && RULE (type)); });

DEFN_RULE (qualifiers, { MATCH (RULE_MANY (extended_qualifier) && RULE (cv_qualifiers)); });

DEFN_RULE (extended_qualifier, {
    MATCH (READ ('U') && RULE (source_name) && RULE (template_args));
    MATCH (READ ('U') && RULE (source_name));
})

DEFN_RULE (builtin_type, {
    MATCH (READ ('v') && APPEND_STR ("void"));
    MATCH (READ ('w') && APPEND_STR ("wchar_t"));
    MATCH (READ ('b') && APPEND_STR ("bool"));
    MATCH (READ ('c') && APPEND_STR ("char"));
    MATCH (READ ('a') && APPEND_STR ("signed char"));
    MATCH (READ ('h') && APPEND_STR ("unsigned char"));
    MATCH (READ ('s') && APPEND_STR ("short"));
    MATCH (READ ('t') && APPEND_STR ("unsigned short"));
    MATCH (READ ('i') && APPEND_STR ("int"));
    MATCH (READ ('j') && APPEND_STR ("unsigned int"));
    MATCH (READ ('l') && APPEND_STR ("long"));
    MATCH (READ ('m') && APPEND_STR ("unsigned long"));
    MATCH (READ ('x') && APPEND_STR ("int64_t"));
    MATCH (READ ('y') && APPEND_STR ("uint64_t"));
    MATCH (READ ('n') && APPEND_STR ("__int128"));
    MATCH (READ ('o') && APPEND_STR ("unsigned __int128"));
    MATCH (READ ('f') && APPEND_STR ("float"));
    MATCH (READ ('d') && APPEND_STR ("double"));
    MATCH (READ ('e') && APPEND_STR ("long double, __float80"));
    MATCH (READ ('g') && APPEND_STR ("__float128"));
    MATCH (READ ('z') && APPEND_STR ("..."));
    MATCH (
        READ_STR ("Dd") && APPEND_STR ("decimal64")
    ); // NOTE(brightprogrammer): IDK what type is used for this case, this is just an assumption
    MATCH (
        READ_STR ("De") && APPEND_STR ("decimal128")
    ); // NOTE(brightprogrammer): IDK what type is used for this case
    MATCH (
        READ_STR ("Df") && APPEND_STR ("decimal32")
    ); // NOTE(brightprogrammer): IDK what type is used for this case
    MATCH (
        READ_STR ("Dh") && APPEND_STR ("decimal16")
    ); // NOTE(brightprogrammer): IDK what type is used for this case
    MATCH (READ_STR ("DF") && APPEND_STR ("_Float") && RULE (number) && READ ('_'));
    MATCH (
        READ_STR ("DF") && APPEND_STR ("_Float") && RULE (number) && READ ('x') && APPEND_STR ("x")
    );
    MATCH (
        READ_STR ("DF") && APPEND_STR ("std::bfloat") && RULE (number) && READ ('b') &&
        APPEND_STR ("_t")
    );
    MATCH (
        READ_STR ("DB") && APPEND_STR ("signed _BitInt(") && RULE (number) && APPEND_STR (")") &&
        READ ('_')
    );
    MATCH (
        READ_STR ("DB") && APPEND_STR ("signed _BitInt(") &&
        RULE (instantiation_dependent_expression) && APPEND_STR (")") && READ ('_')
    );
    MATCH (
        READ_STR ("DU") && APPEND_STR ("unsigned _BitInt(") && RULE (number) && APPEND_STR (")") &&
        READ ('_')
    );
    MATCH (
        READ_STR ("DU") && APPEND_STR ("unsigned _BitInt(") &&
        RULE (instantiation_dependent_expression) && APPEND_STR (")") && READ ('_')
    );
    MATCH (READ_STR ("Di") && APPEND_STR ("char32_t"));
    MATCH (READ_STR ("Ds") && APPEND_STR ("char16_t"));
    MATCH (READ_STR ("Du") && APPEND_STR ("char8_t"));
    MATCH (READ_STR ("Da") && APPEND_STR ("auto"));
    MATCH (READ_STR ("Dc") && APPEND_STR ("decltype(auto)"));
    // MATCH (READ_STR ("Dn") && APPEND_STR ("std::nullptr_t"));
    MATCH (READ_STR ("Dn") && APPEND_STR ("decltype(nullptr)"));
    MATCH (
        ((READ_STR ("DSDA") && APPEND_STR ("_Sat")) || READ_STR ("DA")) && APPEND_STR (" T _Accum")
    ); // NOTE(brightprogrammer): I'm unsure why there is a T in the middle of _Sat and _Accum
       // Do we have to match for a type again?
    MATCH (
        ((READ_STR ("DSDR") && APPEND_STR ("_Sat")) || READ_STR ("DR")) && APPEND_STR (" T _Fract")
    ); // NOTE(brightprogrammer): I'm unsure why there is a T in the middle of _Sat and _Fract
       // Do we have to match for a type again?
    MATCH (
        READ_STR ("DSDA") && APPEND_STR ("_Sat T _Accum")
    ); // NOTE(brightprogrammer): I'm unsure why there is a T in the middle of _Sat and _Accum
       // Do we have to match for a type again?
    MATCH (
        READ ('u') && RULE (source_name) && APPEND_TYPE (dem) && RULE (template_args) &&
        APPEND_TYPE (dem)
    );
});

DEFN_RULE (expression, {
    /* unary operators */
    MATCH (READ_STR ("ps") && APPEND_CHR ('+') && RULE (expression));
    MATCH (READ_STR ("ng") && APPEND_CHR ('-') && RULE (expression));
    MATCH (READ_STR ("ad") && APPEND_CHR ('&') && RULE (expression));
    MATCH (READ_STR ("de") && APPEND_CHR ('*') && RULE (expression));
    MATCH (READ_STR ("co") && APPEND_STR ("~") && RULE (expression));

    /* binary operators */
    MATCH (READ_STR ("pl") && RULE (expression) && APPEND_STR ("+") && RULE (expression));
    MATCH (READ_STR ("mi") && RULE (expression) && APPEND_STR ("-") && RULE (expression));
    MATCH (READ_STR ("ml") && RULE (expression) && APPEND_STR ("*") && RULE (expression));
    MATCH (READ_STR ("dv") && RULE (expression) && APPEND_STR ("/") && RULE (expression));
    MATCH (READ_STR ("rm") && RULE (expression) && APPEND_STR ("%") && RULE (expression));
    MATCH (READ_STR ("an") && RULE (expression) && APPEND_STR ("&") && RULE (expression));
    MATCH (READ_STR ("or") && RULE (expression) && APPEND_STR ("|") && RULE (expression));
    MATCH (READ_STR ("eo") && RULE (expression) && APPEND_STR ("^") && RULE (expression));
    MATCH (READ_STR ("aS") && RULE (expression) && APPEND_STR ("=") && RULE (expression));
    MATCH (READ_STR ("pL") && RULE (expression) && APPEND_STR ("+=") && RULE (expression));
    MATCH (READ_STR ("mI") && RULE (expression) && APPEND_STR ("-=") && RULE (expression));
    MATCH (READ_STR ("mL") && RULE (expression) && APPEND_STR ("*=") && RULE (expression));
    MATCH (READ_STR ("dV") && RULE (expression) && APPEND_STR ("/=") && RULE (expression));
    MATCH (READ_STR ("rM") && RULE (expression) && APPEND_STR ("%=") && RULE (expression));
    MATCH (READ_STR ("aN") && RULE (expression) && APPEND_STR ("&=") && RULE (expression));
    MATCH (READ_STR ("oR") && RULE (expression) && APPEND_STR ("|=") && RULE (expression));
    MATCH (READ_STR ("eO") && RULE (expression) && APPEND_STR ("^=") && RULE (expression));
    MATCH (READ_STR ("ls") && RULE (expression) && APPEND_STR ("<<") && RULE (expression));
    MATCH (READ_STR ("rs") && RULE (expression) && APPEND_STR (">>") && RULE (expression));
    MATCH (READ_STR ("lS") && RULE (expression) && APPEND_STR ("<<=") && RULE (expression));
    MATCH (READ_STR ("rS") && RULE (expression) && APPEND_STR (">>=") && RULE (expression));
    MATCH (READ_STR ("eq") && RULE (expression) && APPEND_STR ("==") && RULE (expression));
    MATCH (READ_STR ("ne") && RULE (expression) && APPEND_STR ("!=") && RULE (expression));
    MATCH (READ_STR ("lt") && RULE (expression) && APPEND_STR ("<") && RULE (expression));
    MATCH (READ_STR ("gt") && RULE (expression) && APPEND_STR (">") && RULE (expression));
    MATCH (READ_STR ("le") && RULE (expression) && APPEND_STR ("<=") && RULE (expression));
    MATCH (READ_STR ("ge") && RULE (expression) && APPEND_STR (">=") && RULE (expression));
    MATCH (READ_STR ("ss") && RULE (expression) && APPEND_STR ("<=>") && RULE (expression));
    MATCH (READ_STR ("nt") && RULE (expression) && APPEND_STR ("!") && RULE (expression));
    MATCH (READ_STR ("aa") && RULE (expression) && APPEND_STR ("&&") && RULE (expression));
    MATCH (READ_STR ("oo") && RULE (expression) && APPEND_STR ("||") && RULE (expression));

    /* ternary operator */
    MATCH (
        READ_STR ("qu") && RULE (expression) && APPEND_STR ("?") && RULE (expression) &&
        APPEND_STR (":") && RULE (expression)
    );

    /* type casting */
    /* will generate " (type)" */
    MATCH (
        READ_STR ("cv") && APPEND_STR ("(") && RULE (type) && APPEND_STR (")") && RULE (expression)
    );

    /* prefix operators */
    MATCH (READ_STR ("pp_") && APPEND_STR ("++") && RULE (expression));
    MATCH (READ_STR ("mm_") && APPEND_STR ("--") && RULE (expression));

    /* expression (expr-list), call */
    MATCH (
        READ_STR ("cl") && RULE (expression) && APPEND_STR ("(") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (")") && READ ('E')
    );

    /* (name) (expr-list), call that would use argument-dependent lookup but for the parentheses*/
    MATCH (
        READ_STR ("cp") && APPEND_STR ("(") && RULE (base_unresolved_name) && APPEND_STR (")") &&
        APPEND_STR ("(") && RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (")") && READ ('E')
    );

    /* type (expression), conversion with one argument */
    MATCH (
        READ_STR ("cv") && RULE (type) && APPEND_STR ("(") && RULE (expression) && APPEND_STR (")")
    );

    /* type (expr-list), conversion with other than one argument */
    MATCH (
        READ_STR ("cv") && RULE (type) && READ ('_') && APPEND_STR ("(") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (")") && READ ('E')
    );

    /* type {expr-list}, conversion with braced-init-list argument */
    MATCH (
        READ_STR ("tl") && RULE (type) && APPEND_STR ("{") &&
        RULE_MANY_WITH_SEP (braced_expression, ", ") && APPEND_STR ("}") && READ ('E')
    );

    /* {expr-list}, braced-init-list in any other context */
    MATCH (
        READ_STR ("il") && APPEND_STR ("{") && RULE_MANY_WITH_SEP (braced_expression, ", ") &&
        APPEND_STR ("}") && READ ('E')
    );

    /* new (expr-list) type */
    MATCH (
        (READ_STR ("gsnw") || READ_STR ("nw")) && APPEND_STR ("new (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        READ ('E')
    );

    /* new (expr-list) type (init) */
    MATCH (
        (READ_STR ("gsnw") || READ_STR ("nw")) && APPEND_STR ("new (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        RULE (initializer)
    );

    /* new[] (expr-list) type */
    MATCH (
        (READ_STR ("gsna") || READ_STR ("na")) && APPEND_STR ("new[] (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        READ ('E')
    );

    /* new[] (expr-list) type (init) */
    MATCH (
        (READ_STR ("gsna") || READ_STR ("na")) && APPEND_STR ("new[] (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        RULE (initializer)
    );

    /* delete expression */
    MATCH ((READ_STR ("gsdl") || READ_STR ("dl")) && APPEND_STR ("delete ") && RULE (expression));

    /* delete [] expression */
    MATCH ((READ_STR ("gsda") || READ_STR ("da")) && APPEND_STR ("delete[] ") && RULE (expression));

    // dc <type> <expression>                               # dynamic_cast<type> (expression)
    MATCH (
        READ_STR ("dc") && APPEND_STR ("dynamic_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );
    // sc <type> <expression>                               # static_cast<type> (expression)
    MATCH (
        READ_STR ("sc") && APPEND_STR ("static_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );
    // cc <type> <expression>                               # const_cast<type> (expression)
    MATCH (
        READ_STR ("cc") && APPEND_STR ("const_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );
    // rc <type> <expression>                               # reinterpret_cast<type> (expression)
    MATCH (
        READ_STR ("rc") && APPEND_STR ("reinterpret_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );

    // ti <type>                                            # typeid (type)
    MATCH (READ_STR ("ti") && APPEND_STR ("typeid(") && RULE (type) && APPEND_STR (")"));
    // te <expression>                                      # typeid (expression)
    MATCH (READ_STR ("te") && APPEND_STR ("typeid(") && RULE (expression) && APPEND_STR (")"));
    // st <type>                                            # sizeof (type)
    MATCH (READ_STR ("st") && APPEND_STR ("sizeof(") && RULE (type) && APPEND_STR (")"));
    // sz <expression>                                      # sizeof (expression)
    MATCH (READ_STR ("sz") && APPEND_STR ("sizeof(") && RULE (expression) && APPEND_STR (")"));
    // at <type>                                            # alignof (type)
    MATCH (READ_STR ("at") && APPEND_STR ("alignof(") && RULE (type) && APPEND_STR (")"));
    // az <expression>                                      # alignof (expression)
    MATCH (READ_STR ("az") && APPEND_STR ("alignof(") && RULE (expression) && APPEND_STR (")"));
    // nx <expression>                                      # noexcept (expression)
    MATCH (READ_STR ("nx") && APPEND_STR ("noexcept(") && RULE (expression) && APPEND_STR (")"));

    MATCH (RULE (template_param));
    MATCH (RULE (function_param));

    MATCH (READ_STR ("dt") && RULE (expression) && APPEND_CHR ('.') && RULE (unresolved_name));
    MATCH (READ_STR ("pt") && RULE (expression) && APPEND_STR ("->") && RULE (unresolved_name));
    MATCH (READ_STR ("ds") && RULE (expression) && APPEND_STR (".*") && RULE (expression));

    MATCH (
        READ_STR ("sZ") && APPEND_STR ("sizeof...(") && RULE (template_param) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("sZ") && APPEND_STR ("sizeof...(") && RULE (function_param) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("sP") && APPEND_STR ("sizeof...(") && RULE_MANY (template_arg) &&
        APPEND_CHR (')') && READ ('E')
    );
    MATCH (READ_STR ("sp") && RULE (expression) && APPEND_STR ("..."));

    /* unary left fold */
    MATCH (READ_STR ("flpl") && APPEND_STR ("(... +") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flmi") && APPEND_STR ("(... -") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flml") && APPEND_STR ("(... *") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fldv") && APPEND_STR ("(... /") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrm") && APPEND_STR ("(... %") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flan") && APPEND_STR ("(... &") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flor") && APPEND_STR ("(... |") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fleo") && APPEND_STR ("(... ^") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flaS") && APPEND_STR ("(... =") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flpL") && APPEND_STR ("(... +=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flmI") && APPEND_STR ("(... -=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flmL") && APPEND_STR ("(... *=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fldV") && APPEND_STR ("(... /=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrM") && APPEND_STR ("(... %=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flaN") && APPEND_STR ("(... &=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("floR") && APPEND_STR ("(... |=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fleO") && APPEND_STR ("(... ^=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flls") && APPEND_STR ("(... <<") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrs") && APPEND_STR ("(... >>") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fllS") && APPEND_STR ("(... <<=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrS") && APPEND_STR ("(... >>=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fleq") && APPEND_STR ("(... ==") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flne") && APPEND_STR ("(... !=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fllt") && APPEND_STR ("(... <") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flgt") && APPEND_STR ("(... >") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flle") && APPEND_STR ("(... <=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flge") && APPEND_STR ("(... >=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flss") && APPEND_STR ("(... <=>") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flnt") && APPEND_STR ("(... !") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flaa") && APPEND_STR ("(... &&") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("floo") && APPEND_STR ("(... ||") && RULE (expression) && APPEND_CHR (')'));

    /* unary fold right */
    MATCH (READ_STR ("frpl") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" + ...)"));
    MATCH (READ_STR ("frmi") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" - ...)"));
    MATCH (READ_STR ("frml") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" * ...)"));
    MATCH (READ_STR ("frdv") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" / ...)"));
    MATCH (READ_STR ("frrm") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" % ...)"));
    MATCH (READ_STR ("fran") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" & ...)"));
    MATCH (READ_STR ("fror") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" | ...)"));
    MATCH (READ_STR ("freo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^ ...)"));
    MATCH (READ_STR ("fraS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" = ...)"));
    MATCH (READ_STR ("frpL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" += ...)"));
    MATCH (READ_STR ("frmI") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" -= ...)"));
    MATCH (READ_STR ("frmL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" *= ...)"));
    MATCH (READ_STR ("frdV") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" /= ...)"));
    MATCH (READ_STR ("frrM") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" %= ...)"));
    MATCH (READ_STR ("fraN") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" &= ...)"));
    MATCH (READ_STR ("froR") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" |= ...)"));
    MATCH (READ_STR ("freO") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^= ...)"));
    MATCH (READ_STR ("frls") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" << ...)"));
    MATCH (READ_STR ("frrs") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >> ...)"));
    MATCH (READ_STR ("frlS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <<= ...)"));
    MATCH (READ_STR ("frrS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >>= ...)"));
    MATCH (READ_STR ("freq") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" == ...)"));
    MATCH (READ_STR ("frne") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" != ...)"));
    MATCH (READ_STR ("frlt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" < ...)"));
    MATCH (READ_STR ("frgt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" > ...)"));
    MATCH (READ_STR ("frle") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <= ...)"));
    MATCH (READ_STR ("frge") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >= ...)"));
    MATCH (READ_STR ("frss") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <=>...)"));
    MATCH (READ_STR ("frnt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ! ...)"));
    MATCH (READ_STR ("fraa") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" && ...)"));
    MATCH (READ_STR ("froo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" || ...)"));

    /* binary left fold */
    // clang-format off
    MATCH (READ_STR ("fLpl") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" + ... + ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLmi") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" - ... - ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLml") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" * ... * ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLdv") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" / ... / ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLrm") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" % ... % ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLan") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" & ... & ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLor") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" | ... | ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLeo") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" ^ ... ^ ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLaS") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" = ... = ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLpL") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" += ... += ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLmI") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" -= ... -= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLmL") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" *= ... *= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLdV") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" /= ... /= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLrM") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" %= ... %= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLaN") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" &= ... &= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLoR") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" |= ... |= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLeO") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" ^= ... ^= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLls") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" << ... << ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLrs") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" >> ... >> ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLlS") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" <<= ... <<= ") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLrS") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" >>= ... >>= ") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLeq") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" == ... == ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLne") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" != ... != ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLlt") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" < ... < ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLgt") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" > ... > ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLle") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" <= ... <= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLge") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" >= ... >= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLss") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" <=> ... <=> ") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLnt") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" ! ... ! ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLaa") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" && ... && ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fLoo") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" || ... || ")   && RULE (expression) && APPEND_CHR (')'));

    /* binary fold right */
    MATCH (READ_STR ("fRpl") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" + ... + ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRmi") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" - ... - ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRml") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" * ... * ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRdv") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" / ... / ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRrm") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" % ... % ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRan") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" & ... & ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRor") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" | ... | ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fReo") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" ^ ... ^ ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRaS") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" = ... = ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRpL") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" += ... += ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRmI") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" -= ... -= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRmL") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" *= ... *= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRdV") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" /= ... /= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRrM") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" %= ... %= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRaN") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" &= ... &= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRoR") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" |= ... |= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fReO") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" ^= ... ^= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRls") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" << ... << ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRrs") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" >> ... >> ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRlS") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" <<= ... <<= ") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRrS") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" >>= ... >>= ") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fReq") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" == ... == ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRne") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" != ... != ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRlt") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" < ... < ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRgt") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" > ... > ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRle") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" <= ... <= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRge") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" >= ... >= ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRss") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" <=> ... <=> ") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRnt") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" ! ... ! ")     && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRaa") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" && ... && ")   && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fRoo") && APPEND_CHR ('(') && RULE(expression) && APPEND_STR (" || ... || ")   && RULE (expression) && APPEND_CHR (')'));
    // clang-format on

    // tw <expression>                                      # throw expression
    MATCH (READ_STR ("tw") && APPEND_STR ("throw ") && RULE (expression));
    // tr                                                   # throw with no operand (rethrow)
    MATCH (READ_STR ("tr") && APPEND_STR ("throw"));

    // u <source-name> <template-arg>* E                    # vendor extended expression
    MATCH (
        READ ('u') && RULE (source_name) && RULE_MANY_WITH_SEP (template_arg, ", ") && READ ('E')
    );

    MATCH (RULE (unresolved_name));
    MATCH (RULE (expr_primary));
});

DEFN_RULE (braced_expression, {
    MATCH (RULE (expression));
    MATCH (
        READ_STR ("di") && APPEND_STR (" .") && RULE (field_source_name) && APPEND_STR (" = ") &&
        RULE (braced_expression)
    );
    MATCH (
        READ_STR ("dx") && APPEND_STR (" [") && RULE (index_expression) && APPEND_STR ("] = ") &&
        RULE (braced_expression)
    );
    MATCH (
        READ_STR ("dX") && APPEND_STR (" [") && RULE (range_begin_expression) &&
        APPEND_STR (" ... ") && RULE (range_end_expression) && APPEND_STR ("] = ") &&
        RULE (braced_expression)
    );
});

DEFN_RULE (initializer, {
    MATCH (
        READ_STR ("pi") && APPEND_STR (" (") && RULE_MANY_WITH_SEP (expression, ", ") &&
        APPEND_CHR (')') && READ ('E')
    );
});

DEFN_RULE (base_unresolved_name, {
    MATCH (RULE (simple_id));
    MATCH (READ_STR ("on") && RULE (operator_name) && OPTIONAL (RULE (template_args)));
    MATCH (READ_STR ("dn") && RULE (destructor_name));
});

DEFN_RULE (simple_id, {
    MATCH (
        RULE (source_name) && APPEND_TYPE (dem) &&
        OPTIONAL (RULE (template_args) && APPEND_TYPE (dem))
    );
});

DEFN_RULE (unresolved_type, {
    MATCH (RULE (template_param) && APPEND_STR ("::") && OPTIONAL (RULE (template_args)));
    MATCH (RULE (decltype));
    MATCH (RULE (substitution));
});

DEFN_RULE (unresolved_name, {
    MATCH (READ_STR ("gs") && APPEND_STR (" ::") && RULE (base_unresolved_name));
    MATCH (RULE (base_unresolved_name));
    MATCH (READ_STR ("sr") && RULE (unresolved_type) && RULE (base_unresolved_name));
    MATCH (
        READ_STR ("srN") && RULE (unresolved_type) &&
        RULE_ATLEAST_ONCE_WITH_SEP (unresolved_qualifier_level, ", ") && READ ('E') &&
        RULE (base_unresolved_name)
    );
    MATCH (READ_STR ("gs")); // TODO: come back here
});

DEFN_RULE (function_param, {
    MATCH (READ_STR ("fp") && RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && READ ('_'));
    MATCH (
        READ_STR ("fp") && RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') &&
        RULE (non_negative_number) && READ ('_')
    );
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && READ ('_')
    );
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && RULE (non_negative_number) &&
        READ ('_')
    );
    MATCH (READ_STR ("fPT"));
});

DEFN_RULE (unresolved_qualifier_level, { MATCH (RULE (simple_id)); })

DEFN_RULE (destructor_name, {
    MATCH (RULE (unresolved_type));
    MATCH (RULE (simple_id));
});

/* NOTE(brightprogrammer): The rule is modified. I've removed reading of 'E' from end.
 * The original grammar for some reason has no way to reach <expr-primary> rule and because
 * of that some matchings were failing.
 *
 * For this I manually added one alternative matching for this rule in the rule <unqualified-name>.
 * This branches from the original grammar here.
 */
DEFN_RULE (expr_primary, {
    MATCH (READ_STR ("LDnE") && APPEND_STR ("decltype(nullptr)0"));
    MATCH (READ_STR ("LDn0E") && APPEND_STR ("(decltype(nullptr))0"));
    MATCH (
        READ ('L') && APPEND_STR ("(") && (PEEK() == 'P') && RULE (pointer_type) &&
        APPEND_STR (")") && READ ('0') && APPEND_CHR ('0') && READ ('E')
    );

    // HACK: "(bool)0" is converted to "true"
    //       "(bool)1" is converted to "false"
    //       "(unsigned int)N" to "Nu"
    /* MATCH ( */
    /*     READ ('L') && RULE_DEFER (tn, type) && RULE_DEFER (n, value_number) && APPEND_STR ("(") && */
    /*     APPEND_DEFER_VAR (tn) && APPEND_STR (")") && APPEND_DEFER_VAR (n) && READ ('E') */
    /* ); */
    DEFER_VAR (t);
    DEFER_VAR (n);
    MATCH (
        READ ('L') && RULE_DEFER (t, type) && RULE_DEFER (n, value_number) &&
        OPTIONAL (
            // change to bool
            !strcmp (t->buf, "bool") ?
                (!strcmp (n->buf, "0") ? (dem_string_deinit (t),
                                          dem_string_deinit (n),
                                          dem_string_append_n (dem, "false", 5)) :
                                         (dem_string_deinit (t),
                                          dem_string_deinit (n),
                                          dem_string_append_n (dem, "true", 4))) :
                // shorten unsigned int typecast
                !strcmp (t->buf, "unsigned int") ?
                (dem_string_deinit (t), APPEND_DEFER_VAR (n) && dem_string_append_char (dem, 'u')) :
                true
        ) &&
        READ ('E')
    );
    dem_string_deinit (t);
    dem_string_deinit (n);
    MATCH (READ ('L') && RULE (type) && RULE (value_float) && READ ('E'));
    MATCH (READ ('L') && RULE (string_type) && READ ('E'));
    MATCH (
        READ ('L') && RULE (type) && RULE (real_part_float) && READ ('_') &&
        RULE (imag_part_float) && READ ('E')
    );
    MATCH (READ_STR ("L_Z") && RULE (encoding) && READ ('E'));
});

DEFN_RULE (float, {
    bool r = false;
    while (IS_DIGIT (PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
        r = true;
        ADV();
    }
    return r ? dem : NULL;
});

DEFN_RULE (source_name, {
    /* positive number providing length of name followed by it */
    st64 name_len = 0;
    READ_NUMBER (name_len);

    if (name_len > 0) {
        /* identifiers don't start with digits or any other special characters */
        if (name_len-- && (IS_ALPHA (PEEK()) || PEEK() == '_')) {
            APPEND_CHR (PEEK());
            ADV();

            /* keep matching while length remains and a valid character is found*/
            while (name_len-- && (IS_ALPHA (PEEK()) || IS_DIGIT (PEEK()) || PEEK() == '_')) {
                APPEND_CHR (PEEK());
                ADV();
            }

            /* if length is non-zero after reading, then the name is invalid. */
            /* NOTE(brightprogrammer): for correct cases length actually goes "-1" here */
            if (name_len > 0) {
                return NULL;
            }

            /* if atleast one character matches */
            return dem;
        }
    }
});

DEFN_RULE (digit, {
    if (IS_DIGIT (PEEK())) {
        APPEND_CHR (PEEK());
        ADV();
        return dem;
    }
});

DEFN_RULE (number, { MATCH (OPTIONAL (READ ('n')) && RULE_ATLEAST_ONCE (digit)); });

// DEFN_RULE (identifier, {
//     if (IS_ALPHA (PEEK()) || PEEK() == '_') {
//         dem_string_append_char (dem, PEEK());
//         ADV();
//         while (IS_ALPHA (PEEK()) || IS_DIGIT (PEEK()) || PEEK() == '_') {
//             dem_string_append_char (dem, PEEK());
//             ADV();
//         }
//         return dem;
//     }
// });

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
        rz_sys_breakpoint();
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
                rz_sys_breakpoint();
            }

            if (is_const) {
                SET_CONST();
            }
        }
    );

    m->t_level--;
});

DEFN_RULE (template_arg, {
    // HACK: even though RULE(type) automatically checks for a RULE(builtin_type), this hack
    // prevents the detected RULE(builtin_type) from being added as a detected template param
    // by making the check inside RULE(type) redundant
    MATCH (RULE (builtin_type) && APPEND_TPARAM (dem));

    MATCH (RULE (type) && APPEND_TPARAM (dem));

    MATCH (
        READ ('X') && RULE (expression) && READ ('E') && APPEND_TPARAM (dem) &&
        FORCE_APPEND_TYPE (dem)
    );
    MATCH (RULE (expr_primary) && APPEND_TPARAM (dem));
    MATCH (
        READ ('J') && RULE_MANY (template_arg) && READ ('E') && APPEND_TPARAM (dem) &&
        FORCE_APPEND_TYPE (dem)
    );
});

// DEFN_RULE (unscoped_template_name, {
//     MATCH (RULE (unscoped_name));
//     MATCH (RULE (substitution));
// })

DEFN_RULE (bare_function_type, {
    MATCH (
        RULE_ATLEAST_ONCE_WITH_SEP (signature_type, ", ") &&
        OPTIONAL (
            !strcmp (dem->buf, "void") && (dem_string_deinit (dem), dem_string_append (dem, ""))
        )
    );
});
