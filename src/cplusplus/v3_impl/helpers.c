// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

bool meta_tmp_init (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return false;
    }

    vec_concat (&tmp->detected_types, &og->detected_types);
    vec_concat (&tmp->template_params, &og->template_params);
    vec_concat (&tmp->parent_type_kinds, &og->parent_type_kinds);;
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
    vec_move(&og->detected_types, &tmp->detected_types);
    vec_move(&og->template_params, &tmp->template_params);
    vec_move(&og->parent_type_kinds, &tmp->parent_type_kinds);

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
 * \b Parse sequence ID from mangled string iterator.
 *
 * Parses a sequence ID following the Itanium ABI specification:
 * - Empty (just '_'): returns 0
 * - Base-36 digits followed by '_': returns parsed value + 1
 *
 * \p msi   Mangled string iterator positioned at the sequence ID
 * \p m     Meta context (used for tracing if enabled)
 *
 * \return Parsed sequence ID (1 for empty, 2+ for base-36 values) on success
 * \return 0 on failure (invalid format)
 */
size_t parse_sequence_id (StrIter* msi, Meta* m) {
    if (!msi || !m) {
        return 0;
    }

    size_t sid           = 1; // Start at 1 for empty sequence
    bool   parsed_seq_id = false;

    if (IS_DIGIT (PEEK()) || IS_UPPER (PEEK())) {
        char*  base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
        char*  pos  = NULL;
        size_t pow  = 1;
        sid         = 2; // Start at 2 for base-36 sequences (1 + parsed value)
        while ((pos = strchr (base, PEEK()))) {
            size_t based_val  = (size_t)(pos - base);
            sid              += based_val * pow;
            pow              *= 36;
            ADV();
        }
        parsed_seq_id = true;
    } else if (PEEK() == '_') {
        sid           = 1; // Empty sequence maps to 1
        parsed_seq_id = true;
    }

    if (!parsed_seq_id || !READ ('_')) {
        return 0;
    }

    return sid;
}

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

    SAVE_POS();
    /* match atleast once, and then */
    if (first (CUR()) && rule (dem, msi, m, graph, parent_node_id) && ++iter_for_dbg) {
        /* match as many as possible */
        while (first (CUR())) {
            DemString tmp = {0};
            SAVE_POS();
            if (rule (&tmp, msi, m, graph, parent_node_id) && ++iter_for_dbg) {
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
        SAVE_POS();
        if (first (CUR()) && rule (&tmp, msi, m, graph, parent_node_id)) {
            match_count++;
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

// counts the number of :: in a name and adds 1 to it
// but ignores :: inside template arguments (between < and >)
static ut32 count_name_parts (Name* n) {
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

// Graphviz trace helper functions implementation
void trace_graph_init (TraceGraph* graph) {
    if (!graph) {
        return;
    }

    vec_init (&graph->nodes);
    graph->next_node_id    = 0;
    graph->current_node_id = -1;
    // Don't reset enabled flag - it should be set by caller
}

// Helper function to check if any ancestor node is failed
static bool has_failed_ancestor (TraceGraph* graph, int parent_id) {
    if (parent_id < 0) {
        return false; // No parent, so no failed ancestor
    }

    // Find the parent node
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* parent = vec_ptr_at (&graph->nodes, i);
        if (parent->id == parent_id) {
            if (parent->status == 2) { // parent is failed
                return true;
            }
            // Recursively check parent's ancestors
            return has_failed_ancestor (graph, parent->parent_id);
        }
    }

    return false; // Parent not found (shouldn't happen)
}

int trace_graph_add_node (
    TraceGraph* graph,
    const char* rule_name,
    size_t      pos,
    const char* input,
    int         parent_id
) {
    if (!graph || !graph->enabled || !rule_name) {
        return -1;
    }

    // Ensure vector has space
    if (vec_reserve (&graph->nodes, graph->nodes.length + 1)) {
        TraceNode* node = vec_ptr_at (&graph->nodes, graph->nodes.length);

        node->id        = graph->next_node_id++;
        node->parent_id = parent_id;
        node->rule_name = strdup (rule_name);
        node->start_pos = pos;
        node->end_pos   = pos; // Will be updated on completion

        // Create input snippet
        if (input) {
            size_t snippet_len  = strlen (input);
            node->input_snippet = malloc (snippet_len + 4);
            strncpy (node->input_snippet, input, snippet_len);
            node->input_snippet[snippet_len] = '\0';
        } else {
            node->input_snippet = strdup ("");
        }

        node->result        = NULL;
        node->attempt_order = 0;     // Will be set by caller if needed
        node->final_path    = false; // Initialize as not part of final path

        // Check if any ancestor is failed - if so, this node should be failed too
        if (has_failed_ancestor (graph, parent_id)) {
            node->status = 2; // failed
        } else {
            node->status = 0; // running
        }

        graph->nodes.length++;
        return node->id;
    }

    return -1;
}

// Helper function to recursively propagate failure to all descendants
static void propagate_failure_to_descendants (TraceGraph* graph, int parent_id) {
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* child = vec_ptr_at (&graph->nodes, i);
        if (child->parent_id == parent_id) {
            // Mark child as failed if it's not already failed
            if (child->status != 2) {
                child->status     = 2;     // failed
                child->final_path = false; // Can't be part of final path if failed

                // Recursively propagate to this child's descendants
                propagate_failure_to_descendants (graph, child->id);
            }
        }
    }
}

void trace_graph_set_result_impl (
    TraceGraph* graph,
    int         node_id,
    size_t      pos,
    const char* result,
    int         status
) {
    if (!graph || !graph->enabled || node_id < 0) {
        return;
    }

    // Find the node
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->id == node_id) {
            // Detect backtracking: if node was previously successful (status 1) and is now being marked as failed (status 2)
            if (node->status == 1 && status == 2) {
                status = 3; // Mark as backtracked instead of failed
            }

            node->status = status;
            if (result && strlen (result) > 0) {
                // Limit result length for readability
                size_t result_len = strlen (result);
                node->result      = malloc (result_len + 4);
                strncpy (node->result, result, result_len);
                node->result[result_len] = '\0';
            }

            if (pos - node->start_pos > 0) {
                node->end_pos = pos;
            }

            // If this node is being marked as failed, propagate failure to all descendants
            if (status == 2) {            // failed
                node->final_path = false; // Can't be part of final path if failed
                propagate_failure_to_descendants (graph, node_id);
            } else if (status == 3) {     // backtracked
                node->final_path = false; // Can't be part of final path if backtracked
                // Don't propagate failure for backtracked nodes - their children might still be valid
            }

            break;
        }
    }
}

void trace_graph_output_dot (TraceGraph* graph, const char* filename, Meta* meta) {
    if (!graph || !filename) {
        return;
    }

    char  buf[256] = {0};
    FILE* f        = fopen (filename, "w");
    if (!f) {
        return;
    }

    fprintf (f, "digraph DemangleTrace {\n");
    fprintf (f, "  rankdir=TB;\n");
    fprintf (f, "  node [shape=box, fontname=\"Courier\", fontsize=10];\n");
    fprintf (f, "  edge [fontname=\"Arial\", fontsize=8];\n\n");


    // Output nodes
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode*  node = vec_ptr_at (&graph->nodes, i);
        const char* color;
        const char* style;
        const char* penwidth = "1";

        if (node->final_path) {
            // Final path nodes get special highlighting
            switch (node->status) {
                case 1 : // success
                    color    = "gold";
                    style    = "filled,bold";
                    penwidth = "3";
                    break;
                default :
                    color    = "lightyellow";
                    style    = "filled,bold";
                    penwidth = "2";
                    break;
            }
        } else {
            // Regular nodes
            switch (node->status) {
                case 1 : // success
                    color = "lightgreen";
                    style = "filled";
                    break;
                case 2 : // failed
                    color = "lightcoral";
                    style = "filled";
                    break;
                case 3 : // backtracked
                    color = "orange";
                    style = "filled,dashed";
                    break;
                default : // running
                    color = "lightblue";
                    style = "filled";
                    break;
            }
        }

        buf[0]    = '\0';
        size_t sz = node->end_pos - node->start_pos > sizeof (buf) - 1 ?
                        sizeof (buf) - 1 :
                        node->end_pos - node->start_pos;
        memcpy (buf, node->input_snippet, sz);
        buf[sz] = '\0';


        fprintf (
            f,
            "  n%d [label=\"%s@pos:%zu\\n'%s'",
            node->id,
            node->rule_name,
            node->start_pos,
            buf
        );

        if (node->result && strlen (node->result) > 0) {
            fprintf (f, "\\n→ '%s'", node->result);
        }

        fprintf (f, "\", fillcolor=%s, style=\"%s\", penwidth=%s];\n", color, style, penwidth);
    }

    fprintf (f, "\n");

    // Output edges
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->parent_id >= 0) {
            const char* edge_color = "black";
            const char* edge_style = "solid";
            const char* penwidth   = "1";

            // Check if both parent and child are in final path
            bool parent_in_final_path = false;
            for (size_t j = 0; j < graph->nodes.length; j++) {
                TraceNode* parent = vec_ptr_at (&graph->nodes, j);
                if (parent->id == node->parent_id) {
                    parent_in_final_path = parent->final_path;
                    break;
                }
            }

            if (node->final_path && parent_in_final_path) {
                // Final path edges
                edge_color = "gold";
                edge_style = "solid";
                penwidth   = "3";
            } else {
                // Regular edges
                if (node->status == 2) {        // failed
                    edge_color = "red";
                } else if (node->status == 3) { // backtracked
                    edge_color = "orange";
                    edge_style = "dashed";
                } else if (node->status == 1) { // success
                    edge_color = "green";
                }
            }

            fprintf (
                f,
                "  n%d -> n%d [color=%s, style=%s, penwidth=%s];\n",
                node->parent_id,
                node->id,
                edge_color,
                edge_style,
                penwidth
            );
        }
    }

    fprintf (f, "\n  // Legend\n");
    fprintf (f, "  subgraph cluster_legend {\n");
    fprintf (f, "    label=\"Legend\";\n");
    fprintf (f, "    style=filled;\n");
    fprintf (f, "    fillcolor=white;\n");
    fprintf (
        f,
        "    legend_final_path [label=\"Final Path\", fillcolor=gold, style=\"filled,bold\", "
        "penwidth=3];\n"
    );
    fprintf (f, "    legend_success [label=\"Success\", fillcolor=lightgreen, style=filled];\n");
    fprintf (f, "    legend_failed [label=\"Failed\", fillcolor=lightcoral, style=filled];\n");
    fprintf (
        f,
        "    legend_backtrack [label=\"Backtracked\", fillcolor=orange, style=\"filled,dashed\"];\n"
    );
    fprintf (f, "    legend_running [label=\"Running\", fillcolor=lightblue, style=filled];\n");
    fprintf (f, "  }\n");

    // Add substitution table if meta is provided and has detected types
    if (meta && meta->detected_types.length > 0) {
        fprintf (f, "\n  // Substitution Table\n");
        fprintf (f, "  subgraph cluster_substitutions {\n");
        fprintf (f, "    label=\"Detected Substitutable Types\";\n");
        fprintf (f, "    style=filled;\n");
        fprintf (f, "    fillcolor=lightyellow;\n");
        fprintf (f, "    pencolor=black;\n");
        fprintf (f, "    fontname=\"Arial\";\n");
        fprintf (f, "    fontsize=12;\n");

        // Create table header
        fprintf (f, "    substitution_table [shape=plaintext, label=<\n");
        fprintf (
            f,
            "      <TABLE BORDER=\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\" BGCOLOR=\"white\">\n"
        );
        fprintf (f, "        <TR>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Index</B></TD>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Substitution</B></TD>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Type</B></TD>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Parts</B></TD>\n");
        fprintf (f, "        </TR>\n");

        // Add each detected type
        for (size_t i = 0; i < meta->detected_types.length; i++) {
            Name*       type = vec_ptr_at (&meta->detected_types, i);
            const char* sub_notation;

            if (i == 0) {
                sub_notation = "S_";
            } else {
                sub_notation = dem_str_newf ("S%zu_", i - 1);
            }

            fprintf (f, "        <TR>\n");
            fprintf (f, "          <TD>%zu</TD>\n", i);
            fprintf (f, "          <TD><FONT FACE=\"Courier\">%s</FONT></TD>\n", sub_notation);

            // Escape HTML characters in the type name
            char* escaped_name = NULL;
            if (type->name.buf && type->name.len > 0) {
                size_t escaped_len = type->name.len * 6 + 1; // worst case: all chars become &xxxx;
                escaped_name       = calloc (escaped_len, sizeof (char));
                if (escaped_name) {
                    const char* src = type->name.buf;
                    char*       dst = escaped_name;
                    for (size_t j = 0; j < type->name.len && src[j]; j++) {
                        switch (src[j]) {
                            case '<' :
                                strcpy (dst, "&lt;");
                                dst += 4;
                                break;
                            case '>' :
                                strcpy (dst, "&gt;");
                                dst += 4;
                                break;
                            case '&' :
                                strcpy (dst, "&amp;");
                                dst += 5;
                                break;
                            case '"' :
                                strcpy (dst, "&quot;");
                                dst += 6;
                                break;
                            case '\'' :
                                strcpy (dst, "&#39;");
                                dst += 5;
                                break;
                            default :
                                *dst++ = src[j];
                                break;
                        }
                    }
                    *dst = '\0';
                }
            }

            fprintf (
                f,
                "          <TD><FONT FACE=\"Courier\">%s</FONT></TD>\n",
                escaped_name ? escaped_name : "(empty)"
            );
            fprintf (f, "          <TD>%u</TD>\n", type->num_parts);
            fprintf (f, "        </TR>\n");

            if (escaped_name) {
                free (escaped_name);
            }
            if (i > 0) {
                free ((void*)sub_notation);
            }
        }

        fprintf (f, "      </TABLE>\n");
        fprintf (f, "    >];\n");
        fprintf (f, "  }\n");
    }

    fprintf (f, "}\n");
    fclose (f);
}

void trace_graph_cleanup (TraceGraph* graph) {
    if (!graph) {
        return;
    }

    // Free all allocated strings
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->rule_name) {
            free (node->rule_name);
        }
        if (node->input_snippet) {
            free (node->input_snippet);
        }
        if (node->result) {
            free (node->result);
        }
    }

    vec_deinit (&graph->nodes);
    graph->next_node_id    = 0;
    graph->current_node_id = -1;
    graph->enabled         = false;
}

// Helper function for marking final path recursively
static void mark_path_recursive (TraceGraph* graph, int node_id) {
    // Mark current node
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->id == node_id) {
            node->final_path = true;
            break;
        }
    }

    // Find ALL successful children and mark them too
    // In a recursive descent parser, all successful children contribute to the final result
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* child = vec_ptr_at (&graph->nodes, i);
        if (child->parent_id == node_id && child->status == 1) {
            mark_path_recursive (graph, child->id);
        }
    }
}

void trace_graph_mark_final_path (TraceGraph* graph) {
    if (!graph || !graph->enabled) {
        return;
    }

    // Better approach: A node is part of the final path if:
    // 1. It's successful (status == 1)
    // 2. It doesn't have any later siblings that also succeeded (indicating backtracking)
    // 3. All its ancestors are also part of the final path

    // For each successful node, check if it's the latest successful sibling
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);

        if (node->status != 1) {
            continue; // Only consider successful nodes
        }

        // Check if this node is the latest successful sibling
        bool is_final_choice              = true;
        int  latest_successful_sibling_id = node->id;

        for (size_t j = 0; j < graph->nodes.length; j++) {
            TraceNode* sibling = vec_ptr_at (&graph->nodes, j);
            if (sibling->parent_id == node->parent_id && sibling->status == 1 &&
                sibling->id > latest_successful_sibling_id) {
                latest_successful_sibling_id = sibling->id;
                is_final_choice              = false;
            }
        }

        // If this is the latest successful sibling, it's part of the final path
        if (is_final_choice) {
            node->final_path = true;
        }
    }

    // Now propagate the final_path marking up the tree
    // A node should only be marked final if it has at least one final child
    // (except for leaf nodes which we already marked above)
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < graph->nodes.length; i++) {
            TraceNode* node = vec_ptr_at (&graph->nodes, i);

            if (node->status != 1 || node->final_path) {
                continue; // Skip non-successful or already marked nodes
            }

            // Check if this node has any final_path children
            bool has_final_child = false;
            for (size_t j = 0; j < graph->nodes.length; j++) {
                TraceNode* child = vec_ptr_at (&graph->nodes, j);
                if (child->parent_id == node->id && child->final_path) {
                    has_final_child = true;
                    break;
                }
            }

            if (has_final_child) {
                node->final_path = true;
                changed          = true;
            }
        }
    }
}
