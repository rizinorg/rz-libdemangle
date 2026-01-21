// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dot_graph.h"
#include "demangle.h"
#include "demangler_util.h"
#include <ctype.h>

// Forward declaration for ast_pp function
void ast_pp(DemNode *node, DemString *out);

static const char *get_node_type_name(CpDemTypeKind tag) {
	// Extract the type name without the CP_DEM_TYPE_KIND_ prefix
	switch (tag) {
	case CP_DEM_TYPE_KIND_primitive_ty: return "primitive_ty";
	case CP_DEM_TYPE_KIND_function_type: return "function_type";
	case CP_DEM_TYPE_KIND_template_args: return "template_args";
	case CP_DEM_TYPE_KIND_template_param: return "template_param";
	case CP_DEM_TYPE_KIND_name: return "name";
	case CP_DEM_TYPE_KIND_nested_name: return "nested_name";
	case CP_DEM_TYPE_KIND_unqualified_name: return "unqualified_name";
	case CP_DEM_TYPE_KIND_source_name: return "source_name";
	case CP_DEM_TYPE_KIND_expression: return "expression";
	case CP_DEM_TYPE_KIND_type: return "type";
	case CP_DEM_TYPE_KIND_builtin_type: return "builtin_type";
	case CP_DEM_TYPE_KIND_substitution: return "substitution";
	case CP_DEM_TYPE_KIND_array_type: return "array_type";
	case CP_DEM_TYPE_KIND_pointer_to_member_type: return "ptr_member_type";
	case CP_DEM_TYPE_KIND_qualified_type: return "qualified_type";
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type: return "vendor_ext_qualified";
	case CP_DEM_TYPE_KIND_many: return "many";
	case CP_DEM_TYPE_KIND_encoding: return "encoding";
	case CP_DEM_TYPE_KIND_mangled_name: return "mangled_name";
	default: return "unknown";
	}
}

static const char *get_node_shape(CpDemTypeKind tag) {
	switch (tag) {
	case CP_DEM_TYPE_KIND_primitive_ty: return "oval";
	case CP_DEM_TYPE_KIND_function_type: return "box";
	case CP_DEM_TYPE_KIND_template_args: return "hexagon";
	case CP_DEM_TYPE_KIND_template_param: return "hexagon";
	case CP_DEM_TYPE_KIND_name: return "ellipse";
	case CP_DEM_TYPE_KIND_nested_name: return "ellipse";
	case CP_DEM_TYPE_KIND_unqualified_name: return "ellipse";
	case CP_DEM_TYPE_KIND_source_name: return "ellipse";
	case CP_DEM_TYPE_KIND_expression: return "diamond";
	case CP_DEM_TYPE_KIND_type: return "parallelogram";
	case CP_DEM_TYPE_KIND_builtin_type: return "oval";
	case CP_DEM_TYPE_KIND_substitution: return "triangle";
	case CP_DEM_TYPE_KIND_array_type: return "box3d";
	case CP_DEM_TYPE_KIND_pointer_to_member_type: return "cds";
	case CP_DEM_TYPE_KIND_qualified_type: return "house";
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type: return "house";
	case CP_DEM_TYPE_KIND_many: return "note";
	case CP_DEM_TYPE_KIND_encoding: return "component";
	case CP_DEM_TYPE_KIND_mangled_name: return "component";
	default: return "ellipse";
	}
}

static const char *get_node_color(CpDemTypeKind tag) {
	switch (tag) {
	case CP_DEM_TYPE_KIND_primitive_ty: return "lightblue";
	case CP_DEM_TYPE_KIND_function_type: return "lightgreen";
	case CP_DEM_TYPE_KIND_template_args: return "yellow";
	case CP_DEM_TYPE_KIND_template_param: return "yellow";
	case CP_DEM_TYPE_KIND_name: return "orange";
	case CP_DEM_TYPE_KIND_nested_name: return "orange";
	case CP_DEM_TYPE_KIND_unqualified_name: return "orange";
	case CP_DEM_TYPE_KIND_source_name: return "orange";
	case CP_DEM_TYPE_KIND_expression: return "pink";
	case CP_DEM_TYPE_KIND_type: return "lightgray";
	case CP_DEM_TYPE_KIND_builtin_type: return "lightblue";
	case CP_DEM_TYPE_KIND_substitution: return "red";
	case CP_DEM_TYPE_KIND_array_type: return "cyan";
	case CP_DEM_TYPE_KIND_pointer_to_member_type: return "purple";
	case CP_DEM_TYPE_KIND_qualified_type: return "brown";
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type: return "brown";
	case CP_DEM_TYPE_KIND_many: return "gold";
	case CP_DEM_TYPE_KIND_encoding: return "darkgreen";
	case CP_DEM_TYPE_KIND_mangled_name: return "darkgreen";
	default: return "white";
	}
}

__attribute__((unused)) static char *sanitize_label(const char *str, size_t len) {
	if (!str || len == 0) {
		return strdup("\"\"");
	}

	// Allocate buffer for escaped string (worst case: every char needs escaping)
	char *escaped = malloc(len * 2 + 3); // +2 for quotes, +1 for null terminator
	if (!escaped) {
		return strdup("\"\"");
	}

	int j = 0;
	escaped[j++] = '"';

	for (size_t i = 0; i < len && str[i]; i++) {
		char c = str[i];
		if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') {
			escaped[j++] = '\\';
		}
		escaped[j++] = c;

		// Limit label length to avoid huge graphs
		if (j > 100) {
			strcpy(escaped + j, "...\"");
			return escaped;
		}
	}

	escaped[j++] = '"';
	escaped[j] = '\0';

	return escaped;
}

void dot_graph_init(DotGraph *dot, const char *mangled_name) {
	if (!dot || !mangled_name) {
		return;
	}

	dot->node_counter = 0;
	dot->enabled = true;

	// Generate filename with timestamp and mangled name hash
	time_t now = time(NULL);
	unsigned int hash = 0;
	for (const char *p = mangled_name; *p; p++) {
		hash = hash * 31 + *p;
	}

	dot->filename = malloc(256);
	if (dot->filename) {
		snprintf(dot->filename, 256, "demangle_trace_%ld_%u.dot", (long)now, hash);
	} else {
		dot->filename = strdup("demangle_trace.dot");
	}

	dot->file = fopen(dot->filename, "w");
	if (!dot->file) {
		fprintf(stderr, "[DOT] Failed to create file: %s\n", dot->filename);
		dot->enabled = false;
		return;
	}

	// Write DOT graph header
	fprintf(dot->file, "digraph AST {\n");
	fprintf(dot->file, "    rankdir=TB;\n");
	fprintf(dot->file, "    node [fontname=\"Courier\", fontsize=10];\n");
	fprintf(dot->file, "    edge [fontname=\"Courier\", fontsize=9];\n");
	fprintf(dot->file, "\n");
	fprintf(dot->file, "    // Graph generated by rz-libdemangle C++ v3 demangler\n");
	fprintf(dot->file, "    // Mangled name: %s\n", mangled_name);
	fprintf(dot->file, "\n");

	fprintf(stderr, "[DOT] Generating trace file: %s\n", dot->filename);
}

void dot_graph_add_node(DotGraph *dot, DemNode *node, int node_id) {
	if (!dot || !dot->enabled || !dot->file || !node) {
		return;
	}

	const char *shape = get_node_shape(node->tag);
	const char *color = get_node_color(node->tag);
	const char *type_name = get_node_type_name(node->tag);

	// Create label with type-specific field information
	char label[1024];
	int len = snprintf(label, sizeof(label), "%s", type_name);

	// Add field-specific information based on node tag
	switch (node->tag) {
	case CP_DEM_TYPE_KIND_primitive_ty:
		if (node->primitive_ty.name.buf) {
			len += snprintf(label + len, sizeof(label) - len, "\\n%s", node->primitive_ty.name.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_function_type:
		if (node->fn_ty.cv_qualifiers.is_const) {
			len += snprintf(label + len, sizeof(label) - len, "\\nconst");
		}
		if (node->fn_ty.ref_qualifiers.is_l_value) {
			len += snprintf(label + len, sizeof(label) - len, "\\n&");
		}
		if (node->fn_ty.ref_qualifiers.is_r_value) {
			len += snprintf(label + len, sizeof(label) - len, "\\n&&");
		}
		break;

	case CP_DEM_TYPE_KIND_qualified_type:
		if (node->qualified_ty.qualifiers.is_const) {
			len += snprintf(label + len, sizeof(label) - len, "\\nconst");
		}
		if (node->qualified_ty.qualifiers.is_volatile) {
			len += snprintf(label + len, sizeof(label) - len, "\\nvolatile");
		}
		if (node->qualified_ty.qualifiers.is_restrict) {
			len += snprintf(label + len, sizeof(label) - len, "\\nrestrict");
		}
		break;

	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type:
		if (node->vendor_ext_qualified_ty.vendor_ext.buf) {
			len += snprintf(label + len, sizeof(label) - len, "\\n%s", node->vendor_ext_qualified_ty.vendor_ext.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_many:
		if (node->many_ty.sep) {
			len += snprintf(label + len, sizeof(label) - len, "\\nsep: %s", node->many_ty.sep);
		}
		if (node->children) {
			len += snprintf(label + len, sizeof(label) - len, "\\nchildren: %zu", VecPDemNode_len(node->children));
		}
		break;

	case CP_DEM_TYPE_KIND_template_args:
		if (node->children) {
			len += snprintf(label + len, sizeof(label) - len, "\\nargs: %zu", VecPDemNode_len(node->children));
		}
		break;

	default:
		// For other types, show basic value if available
		if (node->val.buf && node->val.len > 0) {
			char val_str[64];
			size_t copy_len = node->val.len < sizeof(val_str) - 1 ? node->val.len : sizeof(val_str) - 1;
			strncpy(val_str, node->val.buf, copy_len);
			val_str[copy_len] = '\0';
			len += snprintf(label + len, sizeof(label) - len, "\\n%s", val_str);
		}
		break;
	}

	// Write node to DOT file
	fprintf(dot->file, "\tnode%d [shape=%s, style=filled, fillcolor=%s, label=\"%s\"];\n",
		node_id, shape, color, label);
}

void dot_graph_add_edge(DotGraph *dot, int parent_id, int child_id, const char *label, const char *style) {
	if (!dot || !dot->enabled || !dot->file) {
		return;
	}

	fprintf(dot->file, "    node%d -> node%d", parent_id, child_id);

	bool has_style = (style && strcmp(style, "solid") != 0);
	bool has_label = (label && strlen(label) > 0);

	if (has_style || has_label) {
		fprintf(dot->file, " [");
		if (has_style) {
			fprintf(dot->file, "style=%s", style);
			if (has_label) {
				fprintf(dot->file, ", ");
			}
		}
		if (has_label) {
			fprintf(dot->file, "label=\"%s\"", label);
		}
		fprintf(dot->file, "]");
	}

	fprintf(dot->file, ";\n");
}

int dot_graph_traverse_ast(DotGraph *dot, DemNode *node, int parent_id, const char *parent_label, const char *style) {
	if (!dot || !dot->enabled || !node) {
		return -1;
	}

	int current_id = dot->node_counter++;

	// Add current node
	dot_graph_add_node(dot, node, current_id);

	// Add edge from parent if not root
	if (parent_id >= 0) {
		dot_graph_add_edge(dot, parent_id, current_id, parent_label, style);
	}

	// Process children based on node tag, similar to ast_pp logic
	switch (node->tag) {
	case CP_DEM_TYPE_KIND_primitive_ty:
		// Primitive types have no additional fields to traverse
		break;

	case CP_DEM_TYPE_KIND_function_type:
		if (node->fn_ty.ret) {
			dot_graph_traverse_ast(dot, node->fn_ty.ret, current_id, "ret", "solid");
		}
		if (node->fn_ty.name) {
			dot_graph_traverse_ast(dot, node->fn_ty.name, current_id, "name", "solid");
		}
		if (node->fn_ty.params) {
			dot_graph_traverse_ast(dot, node->fn_ty.params, current_id, "params", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_qualified_type:
		if (node->qualified_ty.inner_type) {
			dot_graph_traverse_ast(dot, node->qualified_ty.inner_type, current_id, "inner_type", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type:
		if (node->vendor_ext_qualified_ty.inner_type) {
			dot_graph_traverse_ast(dot, node->vendor_ext_qualified_ty.inner_type, current_id, "inner_type", "solid");
		}
		if (node->vendor_ext_qualified_ty.template_args) {
			dot_graph_traverse_ast(dot, node->vendor_ext_qualified_ty.template_args, current_id, "template_args", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_many:
	case CP_DEM_TYPE_KIND_nested_name:
	case CP_DEM_TYPE_KIND_template_args:
		// These types use the generic children vector
		if (node->children) {
			size_t child_count = VecPDemNode_len(node->children);
			for (size_t i = 0; i < child_count; i++) {
				PDemNode *child_ptr = VecPDemNode_at(node->children, i);
				if (child_ptr && *child_ptr) {
					char label[32];
					snprintf(label, sizeof(label), "child%zu", i);
					dot_graph_traverse_ast(dot, *child_ptr, current_id, label, "solid");
				}
			}
		}
		break;

	case CP_DEM_TYPE_KIND_type:
		// Type nodes use children vector, but may have subtag for pointers
		if (node->children) {
			size_t child_count = VecPDemNode_len(node->children);
			for (size_t i = 0; i < child_count; i++) {
				PDemNode *child_ptr = VecPDemNode_at(node->children, i);
				if (child_ptr && *child_ptr) {
					char label[32];
					if (node->subtag == POINTER_TYPE) {
						snprintf(label, sizeof(label), "*");
					} else if (node->subtag == REFERENCE_TYPE) {
						snprintf(label, sizeof(label), "&");
					} else if (node->subtag == RVALUE_REFERENCE_TYPE) {
						snprintf(label, sizeof(label), "&&");
					} else {
						snprintf(label, sizeof(label), "child%zu", i);
					}
					dot_graph_traverse_ast(dot, *child_ptr, current_id, label, "solid");
				}
			}
		}
		break;

	case CP_DEM_TYPE_KIND_fwd_template_ref:
		if (node->fwd_template_ref && node->fwd_template_ref->node) {
			dot_graph_traverse_ast(dot, node->fwd_template_ref->node, current_id, "resolved", "dashed");
		}
		break;

	default:
		// For all other nodes, traverse generic children if they exist
		if (node->children) {
			size_t child_count = VecPDemNode_len(node->children);
			for (size_t i = 0; i < child_count; i++) {
				PDemNode *child_ptr = VecPDemNode_at(node->children, i);
				if (child_ptr && *child_ptr) {
					char label[32];
					snprintf(label, sizeof(label), "child%zu", i);
					dot_graph_traverse_ast(dot, *child_ptr, current_id, label, "solid");
				}
			}
		}
		break;
	}

	return current_id;
}

void dot_graph_generate(DotGraph *dot, DemNode *root) {
	if (!dot || !dot->enabled || !root) {
		return;
	}

	fprintf(stderr, "[DOT] Generating AST graph with %d nodes...\n", dot->node_counter);
	dot_graph_traverse_ast(dot, root, -1, NULL, NULL);
}

void dot_graph_finish(DotGraph *dot) {
	if (!dot || !dot->enabled || !dot->file) {
		return;
	}

	fprintf(dot->file, "}\n");
	fclose(dot->file);
	dot->file = NULL;

	fprintf(stderr, "[DOT] AST graph saved to: %s\n", dot->filename);
	fprintf(stderr, "[DOT] Convert to image: dot -Tpng %s -o ast.png\n", dot->filename);
}

void dot_graph_cleanup(DotGraph *dot) {
	if (!dot) {
		return;
	}

	if (dot->file) {
		fclose(dot->file);
	}

	if (dot->filename) {
		free(dot->filename);
	}

	dot->file = NULL;
	dot->filename = NULL;
	dot->enabled = false;
}