// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "trace_graph.h"
#include "types.h"

// Graphviz trace helper functions implementation
void trace_graph_init(TraceGraph *graph) {
	if (!graph) {
		return;
	}

	vec_init(&graph->nodes);
	graph->next_node_id = 0;
	graph->current_node_id = -1;
	// Don't reset enabled flag - it should be set by caller
}

// Helper function to check if any ancestor node is failed
static bool has_failed_ancestor(TraceGraph *graph, int parent_id) {
	if (parent_id < 0) {
		return false; // No parent, so no failed ancestor
	}

	// Find the parent node
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *parent = vec_ptr_at(&graph->nodes, i);
		if (parent->id == parent_id) {
			if (parent->status == 2) { // parent is failed
				return true;
			}
			// Recursively check parent's ancestors
			return has_failed_ancestor(graph, parent->parent_id);
		}
	}

	return false; // Parent not found (shouldn't happen)
}

int trace_graph_add_node(
	TraceGraph *graph,
	const char *rule_name,
	size_t pos,
	const char *input,
	int parent_id) {
	if (!graph || !graph->enabled || !rule_name) {
		return -1;
	}

	// Ensure vector has space
	if (vec_reserve(&graph->nodes, graph->nodes.length + 1)) {
		TraceNode *node = vec_ptr_at(&graph->nodes, graph->nodes.length);

		node->id = graph->next_node_id++;
		node->parent_id = parent_id;
		node->rule_name = strdup(rule_name);
		node->start_pos = pos;
		node->end_pos = pos; // Will be updated on completion

		// Create input snippet
		if (input) {
			size_t snippet_len = strlen(input);
			node->input_snippet = malloc(snippet_len + 4);
			strncpy(node->input_snippet, input, snippet_len);
			node->input_snippet[snippet_len] = '\0';
		} else {
			node->input_snippet = strdup("");
		}

		node->result = NULL;
		node->attempt_order = 0; // Will be set by caller if needed
		node->final_path = false; // Initialize as not part of final path

		// Check if any ancestor is failed - if so, this node should be failed too
		if (has_failed_ancestor(graph, parent_id)) {
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
static void propagate_failure_to_descendants(TraceGraph *graph, int parent_id) {
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *child = vec_ptr_at(&graph->nodes, i);
		if (child->parent_id == parent_id) {
			// Mark child as failed if it's not already failed
			if (child->status != 2) {
				child->status = 2; // failed
				child->final_path = false; // Can't be part of final path if failed

				// Recursively propagate to this child's descendants
				propagate_failure_to_descendants(graph, child->id);
			}
		}
	}
}

void trace_graph_set_result_impl(
	TraceGraph *graph,
	int node_id,
	size_t pos,
	const char *result,
	int status) {
	if (!graph || !graph->enabled || node_id < 0) {
		return;
	}

	// Find the node
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *node = vec_ptr_at(&graph->nodes, i);
		if (node->id == node_id) {
			// Detect backtracking: if node was previously successful (status 1) and is now being marked as failed (status 2)
			if (node->status == 1 && status == 2) {
				status = 3; // Mark as backtracked instead of failed
			}

			node->status = status;
			if (result && strlen(result) > 0) {
				// Limit result length for readability
				size_t result_len = strlen(result);
				node->result = malloc(result_len + 4);
				strncpy(node->result, result, result_len);
				node->result[result_len] = '\0';
			}

			if (pos - node->start_pos > 0) {
				node->end_pos = pos;
			}

			// If this node is being marked as failed, propagate failure to all descendants
			if (status == 2) { // failed
				node->final_path = false; // Can't be part of final path if failed
				propagate_failure_to_descendants(graph, node_id);
			} else if (status == 3) { // backtracked
				node->final_path = false; // Can't be part of final path if backtracked
				// Don't propagate failure for backtracked nodes - their children might still be valid
			}

			break;
		}
	}
}

void trace_graph_output_dot(TraceGraph *graph, const char *filename, Meta *meta) {
	if (!graph || !filename) {
		return;
	}

	char buf[256] = { 0 };
	FILE *f = fopen(filename, "w");
	if (!f) {
		return;
	}

	fprintf(f, "digraph DemangleTrace {\n");
	fprintf(f, "  rankdir=TB;\n");
	fprintf(f, "  node [shape=box, fontname=\"Courier\", fontsize=10];\n");
	fprintf(f, "  edge [fontname=\"Arial\", fontsize=8];\n\n");

	// Output nodes
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *node = vec_ptr_at(&graph->nodes, i);
		const char *color;
		const char *style;
		const char *penwidth = "1";

		if (node->final_path) {
			// Final path nodes get special highlighting
			switch (node->status) {
			case 1: // success
				color = "gold";
				style = "filled,bold";
				penwidth = "3";
				break;
			default:
				color = "lightyellow";
				style = "filled,bold";
				penwidth = "2";
				break;
			}
		} else {
			// Regular nodes
			switch (node->status) {
			case 1: // success
				color = "lightgreen";
				style = "filled";
				break;
			case 2: // failed
				color = "lightcoral";
				style = "filled";
				break;
			case 3: // backtracked
				color = "orange";
				style = "filled,dashed";
				break;
			default: // running
				color = "lightblue";
				style = "filled";
				break;
			}
		}

		buf[0] = '\0';
		size_t sz = node->end_pos - node->start_pos > sizeof(buf) - 1 ? sizeof(buf) - 1 : node->end_pos - node->start_pos;
		memcpy(buf, node->input_snippet, sz);
		buf[sz] = '\0';

		fprintf(
			f,
			"  n%d [label=\"%s@pos:%zu\\n'%s'",
			node->id,
			node->rule_name,
			node->start_pos,
			buf);

		if (node->result && strlen(node->result) > 0) {
			fprintf(f, "\\n→ '%s'", node->result);
		}

		fprintf(f, "\", fillcolor=%s, style=\"%s\", penwidth=%s];\n", color, style, penwidth);
	}

	fprintf(f, "\n");

	// Output edges
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *node = vec_ptr_at(&graph->nodes, i);
		if (node->parent_id >= 0) {
			const char *edge_color = "black";
			const char *edge_style = "solid";
			const char *penwidth = "1";

			// Check if both parent and child are in final path
			bool parent_in_final_path = false;
			for (size_t j = 0; j < graph->nodes.length; j++) {
				TraceNode *parent = vec_ptr_at(&graph->nodes, j);
				if (parent->id == node->parent_id) {
					parent_in_final_path = parent->final_path;
					break;
				}
			}

			if (node->final_path && parent_in_final_path) {
				// Final path edges
				edge_color = "gold";
				edge_style = "solid";
				penwidth = "3";
			} else {
				// Regular edges
				if (node->status == 2) { // failed
					edge_color = "red";
				} else if (node->status == 3) { // backtracked
					edge_color = "orange";
					edge_style = "dashed";
				} else if (node->status == 1) { // success
					edge_color = "green";
				}
			}

			fprintf(
				f,
				"  n%d -> n%d [color=%s, style=%s, penwidth=%s];\n",
				node->parent_id,
				node->id,
				edge_color,
				edge_style,
				penwidth);
		}
	}

	fprintf(f, "\n  // Legend\n");
	fprintf(f, "  subgraph cluster_legend {\n");
	fprintf(f, "    label=\"Legend\";\n");
	fprintf(f, "    style=filled;\n");
	fprintf(f, "    fillcolor=white;\n");
	fprintf(
		f,
		"    legend_final_path [label=\"Final Path\", fillcolor=gold, style=\"filled,bold\", "
		"penwidth=3];\n");
	fprintf(f, "    legend_success [label=\"Success\", fillcolor=lightgreen, style=filled];\n");
	fprintf(f, "    legend_failed [label=\"Failed\", fillcolor=lightcoral, style=filled];\n");
	fprintf(
		f,
		"    legend_backtrack [label=\"Backtracked\", fillcolor=orange, style=\"filled,dashed\"];\n");
	fprintf(f, "    legend_running [label=\"Running\", fillcolor=lightblue, style=filled];\n");
	fprintf(f, "  }\n");

	// Add substitution table if meta is provided and has detected types
	if (meta && meta->detected_types.length > 0) {
		fprintf(f, "\n  // Substitution Table\n");
		fprintf(f, "  subgraph cluster_substitutions {\n");
		fprintf(f, "    label=\"Detected Substitutable Types\";\n");
		fprintf(f, "    style=filled;\n");
		fprintf(f, "    fillcolor=lightyellow;\n");
		fprintf(f, "    pencolor=black;\n");
		fprintf(f, "    fontname=\"Arial\";\n");
		fprintf(f, "    fontsize=12;\n");

		// Create table header
		fprintf(f, "    substitution_table [shape=plaintext, label=<\n");
		fprintf(
			f,
			"      <TABLE BORDER=\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\" BGCOLOR=\"white\">\n");
		fprintf(f, "        <TR>\n");
		fprintf(f, "          <TD BGCOLOR=\"lightgray\"><B>Index</B></TD>\n");
		fprintf(f, "          <TD BGCOLOR=\"lightgray\"><B>Substitution</B></TD>\n");
		fprintf(f, "          <TD BGCOLOR=\"lightgray\"><B>Type</B></TD>\n");
		fprintf(f, "          <TD BGCOLOR=\"lightgray\"><B>Parts</B></TD>\n");
		fprintf(f, "        </TR>\n");

		// Add each detected type
		for (size_t i = 0; i < meta->detected_types.length; i++) {
			Name *type = vec_ptr_at(&meta->detected_types, i);
			const char *sub_notation;

			if (i == 0) {
				sub_notation = "S_";
			} else {
				sub_notation = dem_str_newf("S%zu_", i - 1);
			}

			fprintf(f, "        <TR>\n");
			fprintf(f, "          <TD>%zu</TD>\n", i);
			fprintf(f, "          <TD><FONT FACE=\"Courier\">%s</FONT></TD>\n", sub_notation);

			// Escape HTML characters in the type name
			char *escaped_name = NULL;
			if (type->name.buf && type->name.len > 0) {
				size_t escaped_len = type->name.len * 6 + 1; // worst case: all chars become &xxxx;
				escaped_name = calloc(escaped_len, sizeof(char));
				if (escaped_name) {
					const char *src = type->name.buf;
					char *dst = escaped_name;
					for (size_t j = 0; j < type->name.len && src[j]; j++) {
						switch (src[j]) {
						case '<':
							strcpy(dst, "&lt;");
							dst += 4;
							break;
						case '>':
							strcpy(dst, "&gt;");
							dst += 4;
							break;
						case '&':
							strcpy(dst, "&amp;");
							dst += 5;
							break;
						case '"':
							strcpy(dst, "&quot;");
							dst += 6;
							break;
						case '\'':
							strcpy(dst, "&#39;");
							dst += 5;
							break;
						default:
							*dst++ = src[j];
							break;
						}
					}
					*dst = '\0';
				}
			}

			fprintf(
				f,
				"          <TD><FONT FACE=\"Courier\">%s</FONT></TD>\n",
				escaped_name ? escaped_name : "(empty)");
			fprintf(f, "          <TD>%u</TD>\n", type->num_parts);
			fprintf(f, "        </TR>\n");

			if (escaped_name) {
				free(escaped_name);
			}
			if (i > 0) {
				free((void *)sub_notation);
			}
		}

		fprintf(f, "      </TABLE>\n");
		fprintf(f, "    >];\n");
		fprintf(f, "  }\n");
	}

	fprintf(f, "}\n");
	fclose(f);
}

void trace_graph_cleanup(TraceGraph *graph) {
	if (!graph) {
		return;
	}

	// Free all allocated strings
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *node = vec_ptr_at(&graph->nodes, i);
		if (node->rule_name) {
			free(node->rule_name);
		}
		if (node->input_snippet) {
			free(node->input_snippet);
		}
		if (node->result) {
			free(node->result);
		}
	}

	vec_deinit(&graph->nodes);
	graph->next_node_id = 0;
	graph->current_node_id = -1;
	graph->enabled = false;
}

// Helper function for marking final path recursively
static void mark_path_recursive(TraceGraph *graph, int node_id) {
	// Mark current node
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *node = vec_ptr_at(&graph->nodes, i);
		if (node->id == node_id) {
			node->final_path = true;
			break;
		}
	}

	// Find ALL successful children and mark them too
	// In a recursive descent parser, all successful children contribute to the final result
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *child = vec_ptr_at(&graph->nodes, i);
		if (child->parent_id == node_id && child->status == 1) {
			mark_path_recursive(graph, child->id);
		}
	}
}

void trace_graph_mark_final_path(TraceGraph *graph) {
	if (!graph || !graph->enabled) {
		return;
	}

	// Better approach: A node is part of the final path if:
	// 1. It's successful (status == 1)
	// 2. It doesn't have any later siblings that also succeeded (indicating backtracking)
	// 3. All its ancestors are also part of the final path

	// For each successful node, check if it's the latest successful sibling
	for (size_t i = 0; i < graph->nodes.length; i++) {
		TraceNode *node = vec_ptr_at(&graph->nodes, i);

		if (node->status != 1) {
			continue; // Only consider successful nodes
		}

		// Check if this node is the latest successful sibling
		bool is_final_choice = true;
		int latest_successful_sibling_id = node->id;

		for (size_t j = 0; j < graph->nodes.length; j++) {
			TraceNode *sibling = vec_ptr_at(&graph->nodes, j);
			if (sibling->parent_id == node->parent_id && sibling->status == 1 &&
				sibling->id > latest_successful_sibling_id) {
				latest_successful_sibling_id = sibling->id;
				is_final_choice = false;
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
			TraceNode *node = vec_ptr_at(&graph->nodes, i);

			if (node->status != 1 || node->final_path) {
				continue; // Skip non-successful or already marked nodes
			}

			// Check if this node has any final_path children
			bool has_final_child = false;
			for (size_t j = 0; j < graph->nodes.length; j++) {
				TraceNode *child = vec_ptr_at(&graph->nodes, j);
				if (child->parent_id == node->id && child->final_path) {
					has_final_child = true;
					break;
				}
			}

			if (has_final_child) {
				node->final_path = true;
				changed = true;
			}
		}
	}
}
