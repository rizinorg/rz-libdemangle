// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_MACROS_H
#define V3_IMPL_MACROS_H

#include "../../demangler_util.h"
#include "../vec.h"
#include "first.h"

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

#define PEEK_AT(p) (IN_RANGE (msi->cur + p) ? msi->cur[p] : 0)

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
 * \b Call a rule.
 *
 * \p x Rule name.
 *
 * \return DemString containing demangled string generated by the called rule.
 * \return NULL if rule match fails for any reason.
 */
#define RULE(x) (first_of_rule_##x (CUR()) ? rule_##x (dem, msi, m) : NULL)

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
#define RULE_DEFER(var, x) (first_of_rule_##x (CUR()) ? rule_##x ((var), msi, m) : NULL)
#define DEFER_VAR(var)                                                                             \
    DemString  tmp_defer_var_##var = {};                                                           \
    DemString* var                 = &tmp_defer_var_##var;                                         \
    dem_string_init (var);

#define APPEND_DEFER_VAR(var)                                                                      \
    ((var)->len ? (dem_string_concat (dem, (var)), dem_string_deinit (var), 1) : true)

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
#define RULE_ATLEAST_ONCE(x)                                                                       \
    match_one_or_more_rules (first_of_rule_##x, rule_##x, NULL, dem, msi, m)
#define RULE_ATLEAST_ONCE_WITH_SEP(x, sep)                                                         \
    match_one_or_more_rules (first_of_rule_##x, rule_##x, sep, dem, msi, m)

/**
 * \b Match given rule name any number of times.
 *
 * \p x Rule name
 *
 * \return DemString containing demangled string generated by the called rule.
 * \return NULL if rule match fails for any reason.
 */
#define RULE_MANY(x) match_zero_or_more_rules (first_of_rule_##x, rule_##x, NULL, dem, msi, m)
#define RULE_MANY_WITH_SEP(x, sep)                                                                 \
    match_zero_or_more_rules (first_of_rule_##x, rule_##x, sep, dem, msi, m)
#define RULE_DEFER_MANY(var, x)                                                                    \
    match_zero_or_more_rules (first_of_rule_##x, rule_##x, NULL, (var), msi, m)

/**
 * \b Declare a new rule so that it can be used with RULE(...) macro later on.
 *
 * \p x Rule name
 */
#define DECL_RULE(x) DemString* rule_##x (DemString* dem, StrIter* msi, Meta* m)

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
        if (!dem || !msi || !m) {                                                                  \
            return NULL;                                                                           \
        }                                                                                          \
        if (m->trace) {                                                                            \
            printf (                                                                               \
                "[TRACE] Entering rule '" #x "' at position %zu (remaining: '%.*s')\n",            \
                (size_t)(msi->cur - msi->beg),                                                     \
                (int)(msi->end - msi->cur > 20 ? 20 : msi->end - msi->cur),                        \
                msi->cur                                                                           \
            );                                                                                     \
        }                                                                                          \
        const char* _rule_start_pos = msi->cur;                                                    \
        ((void)_rule_start_pos);                                                                   \
        { rule_body }                                                                              \
        if (m->trace) {                                                                            \
            printf (                                                                               \
                "[TRACE] Rule '" #x "' FAILED at position %zu\n",                                  \
                (size_t)(msi->cur - msi->beg)                                                      \
            );                                                                                     \
        }                                                                                          \
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
            if (_og_meta->trace) {                                                                 \
                printf (                                                                           \
                    "[TRACE] Rule %s succeeded, consumed %zu chars, result: '%.*s'\n",             \
                    __func__ + 5,                                                                  \
                    (size_t)(msi->cur - _____trial_start_pos),                                     \
                    (int)(_tmp_dem.len > 50 ? 50 : _tmp_dem.len),                                  \
                    _tmp_dem.buf ? _tmp_dem.buf : ""                                               \
                );                                                                                 \
            }                                                                                      \
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

#define APPEND_TYPE(tname)       append_type (m, (tname), false)
#define FORCE_APPEND_TYPE(tname) append_type (m, (tname), true)

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

#endif // V3_IMPL_MACROS_H
