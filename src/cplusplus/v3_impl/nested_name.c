// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include "types.h"

DECL_RULE (nested_name_with_substitution_only);

// NOTE: Prefix parsing does not work well with multiple unqualified names
// We can create a new rule named second_last_unqualified_name and perform a trick
// to get the second last unqualified name always.

DEFN_RULE (nested_name, {
    DEFER_VAR (ref);
    DEFER_VAR (pfx);
    DEFER_VAR (uname);

    bool is_ctor = false;
    bool is_dtor = false;

    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <ctor-name> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <dtor-name> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) &&
            OPTIONAL (RULE_DEFER (ref, ref_qualifier)) && RULE_DEFER (pfx, prefix) &&
            ((is_ctor = !!RULE (ctor_name)) || (is_dtor = !!RULE (dtor_name)) ||
             RULE_DEFER (uname, unqualified_name)) &&
            READ ('E'),
        {
            if (is_ctor || is_dtor) {
                const char* cname = strrchr (pfx->buf, ':');
                if (!cname) {
                    cname = pfx->buf;
                } else {
                    cname += 1;
                }
                dem_string_concat (dem, pfx);
                APPEND_TYPE (dem);
                if (is_ctor) {
                    dem_string_append_n (dem, "::", 2);
                } else {
                    dem_string_append_n (dem, "::~", 3);
                }
                const char* e = strchr (cname, '<');
                dem_string_append_n (dem, cname, e ? e - cname : pfx->buf + pfx->len - cname);
            } else {
                dem_string_concat (dem, pfx);
                APPEND_TYPE (dem);
                dem_string_append_n (dem, "::", 2);
                dem_string_concat (dem, uname);
            }

            dem_string_deinit (pfx);
            dem_string_deinit (uname);
            if (ref->len) {
                APPEND_STR (" ");
                (void)APPEND_DEFER_VAR (ref);
                APPEND_TYPE (dem);
            }
        }
    );

    dem_string_deinit (pfx);
    dem_string_deinit (ref);
    dem_string_deinit (uname);
    is_ctor = is_dtor = false;

    if (m->trace) {
        printf (
            "[TRACE] -- nested-name -- Parsing with <prefix> failed in nested-name, now trying "
            "with <template-prefix>\n"
        );
    }

    DEFER_VAR (targs);

    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <ctor-name> <template-args> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <dtor-name> <template-args> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <unqualified-name> <template-args> E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) &&
            OPTIONAL (RULE_DEFER (ref, ref_qualifier)) && RULE_DEFER (pfx, template_prefix) &&
            ((is_ctor = !!RULE (ctor_name)) || (is_dtor = !!RULE (dtor_name)) ||
             RULE_DEFER (uname, unqualified_name)),
        {
            if (is_ctor || is_dtor) {
                const char* cname = strrchr (pfx->buf, ':');
                if (!cname) {
                    cname = pfx->buf;
                } else {
                    cname += 1;
                }
                dem_string_concat (dem, pfx);
                APPEND_TYPE (dem);
                if (is_ctor) {
                    dem_string_append_n (dem, "::", 2);
                } else {
                    dem_string_append_n (dem, "::~", 3);
                }
                const char* e = strchr (cname, '<');
                dem_string_append_n (dem, cname, e ? e - cname : pfx->buf + pfx->len - cname);
            } else {
                dem_string_concat (dem, pfx);
                APPEND_TYPE (dem);
                dem_string_append_n (dem, "::", 2);
                dem_string_concat (dem, uname);
                APPEND_TYPE (dem);
            }

            dem_string_deinit (pfx);
            dem_string_deinit (uname);

            if (RULE_DEFER (targs, template_args) && READ ('E')) {
                dem_string_concat (dem, targs);
                APPEND_TYPE (dem);
                dem_string_deinit (targs);
            } else {
                dem_string_deinit (targs);
                MATCH_FAILED();
            }

            if (ref->len) {
                APPEND_STR (" ");
                (void)APPEND_DEFER_VAR (ref);
                APPEND_TYPE (dem);
            }
        }
    );

    dem_string_deinit (pfx);
    dem_string_deinit (ref);
    dem_string_deinit (targs);
    dem_string_deinit (uname);



    MATCH (RULE (nested_name_with_substitution_only));
});
DEFN_RULE (nested_name_with_substitution_only, {
    DEFER_VAR (ref);
    DEFER_VAR (targs);
    Name*  substituted_name = NULL;
    size_t sid              = 0;

    // N [<CV-qualifiers>] [<ref-qualifier>] S<seq-id>_ [I<template-args>E] E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) &&
            OPTIONAL (RULE_DEFER (ref, ref_qualifier)) && READ ('S') &&
            (sid = parse_sequence_id (msi, m)) && (m->detected_types.length > sid - 1) &&
            (substituted_name = vec_ptr_at (&m->detected_types, sid - 1)) &&
            (substituted_name->num_parts > 1) && OPTIONAL (RULE_DEFER (targs, template_args)) &&
            READ ('E'),
        {
            dem_string_concat (dem, &substituted_name->name);

            if (targs->len) {
                (void)APPEND_DEFER_VAR (targs);
                APPEND_TYPE (dem);
            }

            // Add ref-qualifier if present
            if (ref->len) {
                APPEND_STR (" ");
                (void)APPEND_DEFER_VAR (ref);
                APPEND_TYPE (dem);
            }
        }
    );

    dem_string_deinit (ref);
    dem_string_deinit (targs);
});
