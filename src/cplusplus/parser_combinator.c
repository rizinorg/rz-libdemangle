// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "parser_combinator.h"

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
bool match_one_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemAstNode*  ast_node,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
) {
    if (!match_zero_or_more_rules (first, rule, sep, ast_node, msi, m, graph, parent_node_id)) {
        return false;
    }
    if (!ast_node->dem.buf) {
        return false;
    }
    return true;
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
bool match_zero_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemAstNode*  ast_node,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
) {
    if (!rule || !ast_node || !msi || !m) {
        return false;
    }

    size_t count = 0;
    while (true) {
        DemAstNode tmp = {0};
        SAVE_POS (0);
        if (first (CUR()) && rule (&tmp, msi, m, graph, parent_node_id)) {
            DemAstNode_append (ast_node, &tmp);
            if (sep) {
                dem_string_append (&ast_node->dem, sep);
            }
            count++;
        } else {
            RESTORE_POS (0);
            DemAstNode_deinit (&tmp);
            break;
        }
    }

    /* remove last sep */
    if (sep && ast_node->dem.buf && count > 0) {
        for (int l = 0; l < strlen (sep); l++) {
            ast_node->dem.buf[--ast_node->dem.len] = 0;
        }
    }

    /* we always match, even if nothing matches */
    return true;
}
