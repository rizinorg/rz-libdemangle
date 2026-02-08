// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DOT_GRAPH_H
#define DOT_GRAPH_H

#include "types.h"
#include "v3_pp.h"

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

typedef struct DotGraph {
	FILE *file;
	int node_counter;
	bool enabled;
	char filename[256]; // Max filename length (255 + null terminator)

	PPContext pp_ctx;
} DotGraph;

/**
 * Initialize a DOT graph for AST visualization
 * @param dot DotGraph structure to initialize
 * @param pp_context Pretty-printing context
 * @param mangled_name The mangled symbol name (input)
 * @param demangled_name The demangled symbol name (output)
 */
void dot_graph_init(DotGraph *dot, PPContext pp_context, const char *mangled_name, const char *demangled_name);

/**
 * Add a node to the DOT graph
 * @param dot DotGraph context
 * @param node AST node to represent
 * @param node_id Unique identifier for the node
 */
void dot_graph_add_node(DotGraph *dot, DemNode *node, int node_id);

/**
 * Add an edge between two nodes in the DOT graph
 * @param dot DotGraph context
 * @param parent_id Parent node ID
 * @param child_id Child node ID
 * @param label Optional edge label (can be NULL)
 * @param style Optional edge style ("solid", "dashed", "dotted")
 */
void dot_graph_add_edge(DotGraph *dot, int parent_id, int child_id, const char *label, const char *style);

/**
 * Recursively traverse AST and generate DOT graph
 * @param dot DotGraph context
 * @param node Current AST node
 * @param parent_id Parent node ID (-1 for root)
 * @return Current node ID
 */
int dot_graph_traverse_ast(DotGraph *dot, DemNode *node, int parent_id, const char *parent_label, const char *style);

/**
 * Generate DOT graph for entire AST
 * @param dot DotGraph context
 * @param root Root AST node
 */
void dot_graph_generate(DotGraph *dot, DemNode *root);

/**
 * Finish and close the DOT graph file
 * @param dot DotGraph context
 */
void dot_graph_finish(DotGraph *dot);

/**
 * Clean up DotGraph resources
 * @param dot DotGraph context
 */
void dot_graph_cleanup(DotGraph *dot);

#endif // DOT_GRAPH_H