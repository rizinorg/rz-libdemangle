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
DemString* match_one_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
) {
    if (!first || !rule || !dem || !msi || !m) {
        return NULL;
    }

    // NOTE(brightprogrammer): Just here to check the current iteration in debugger
    // No special use
    ut32 iter_for_dbg = 0;

    SAVE_POS(0);
    /* match atleast once, and then */
    if (first (CUR()) && rule (dem, msi, m, graph, parent_node_id) && ++iter_for_dbg) {
        /* match as many as possible */
        while (first (CUR())) {
            DemString tmp = {0};
            SAVE_POS(1);
            if (rule (&tmp, msi, m, graph, parent_node_id) && ++iter_for_dbg) {
                /* add separator before appending demangled string */
                if (sep) {
                    dem_string_append_prefix_n (&tmp, sep, strlen (sep));
                }

                /* append the demangled string and deinit tmp */
                dem_string_concat (dem, &tmp);
                dem_string_deinit (&tmp);
            } else {
                RESTORE_POS(1);
                dem_string_deinit (&tmp);
                break;
            }
        }

        return dem;
    }

    RESTORE_POS(0);
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
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
) {
    if (!rule || !dem || !msi || !m) {
        return NULL;
    }

    ut32 match_count = 0;
    while (true) {
        DemString tmp = {0};
        SAVE_POS(0);
        if (first (CUR()) && rule (&tmp, msi, m, graph, parent_node_id)) {
            match_count++;
            if (sep) {
                dem_string_append (&tmp, sep);
            }
            dem_string_concat (dem, &tmp);
            dem_string_deinit (&tmp);
        } else {
            RESTORE_POS(0);
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
