// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_TRACE_GRAPH_H
#define RZ_LIBDEMANGLE_TRACE_GRAPH_H

#include "demangler_util.h"
#include "vec.h"

// Graphviz trace node for visual debugging
typedef struct TraceNode {
    int    id;            // Unique node ID
    int    parent_id;     // Parent node ID (-1 for root)
    char*  rule_name;     // Rule name
    size_t start_pos;     // Start position in input
    size_t end_pos;       // End position in input
    char*  input_snippet; // Input snippet at this position
    char*  result;        // Partial result (if successful)
    int    status;        // 0=running, 1=success, 2=failed, 3=backtracked
    int    attempt_order; // Order of attempt within parent
    bool   final_path;    // True if this node is part of the final successful path
} TraceNode;

typedef Vec (TraceNode) TraceNodes;

// Separate graph structure for tracing
typedef struct TraceGraph {
    TraceNodes nodes;           // All trace nodes
    int        next_node_id;    // Next available node ID
    int        current_node_id; // Current active node ID
    bool       enabled;         // Whether tracing is enabled
} TraceGraph;

void trace_graph_set_result_impl (
    TraceGraph* graph,
    int         node_id,
    size_t      pos,
    const char* result,
    int         status
);

struct Meta;

// Graphviz trace helper functions
void trace_graph_init (TraceGraph* graph);
int  trace_graph_add_node (
     TraceGraph* graph,
     const char* rule_name,
     size_t      pos,
     const char* input,
     int         parent_id
 );
void trace_graph_mark_final_path (TraceGraph* graph);
void trace_graph_output_dot (TraceGraph* graph, const char* filename, struct Meta* meta);
void trace_graph_cleanup (TraceGraph* graph);

#endif //RZ_LIBDEMANGLE_TRACE_GRAPH_H
