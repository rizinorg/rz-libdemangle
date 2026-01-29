// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dot_graph.h"
#include "demangle.h"
#include "demangler_util.h"
#include "macros.h"
#include "v3_pp.h"

#include <ctype.h>

static const char *get_node_type_name(CpDemTypeKind tag) {
	// Extract the type name without the CP_DEM_TYPE_KIND_ prefix
	switch (tag) {
	// Basic types
	case CP_DEM_TYPE_KIND_primitive_ty: return "primitive_ty";
	case CP_DEM_TYPE_KIND_builtin_type: return "builtin_type";
	case CP_DEM_TYPE_KIND_type: return "type";
	case CP_DEM_TYPE_KIND_class_type: return "class_type";
	case CP_DEM_TYPE_KIND_pointer_type: return "pointer_type";
	case CP_DEM_TYPE_KIND_string_type: return "string_type";
	case CP_DEM_TYPE_KIND_signature_type: return "signature_type";

	// Function related
	case CP_DEM_TYPE_KIND_function_type: return "function_type";
	case CP_DEM_TYPE_KIND_bare_function_type: return "bare_function_type";
	case CP_DEM_TYPE_KIND_function_param: return "function_param";
	case CP_DEM_TYPE_KIND_function_encoding: return "function_encoding";
	case CP_DEM_TYPE_KIND_exception_spec: return "exception_spec";

	// Template related
	case CP_DEM_TYPE_KIND_template_args: return "template_args";
	case CP_DEM_TYPE_KIND_template_param: return "template_param";
	case CP_DEM_TYPE_KIND_template_arg: return "template_arg";
	case CP_DEM_TYPE_KIND_template_param_decl: return "template_param_decl";
	case CP_DEM_TYPE_KIND_template_template_param: return "template_template_param";
	case CP_DEM_TYPE_KIND_fwd_template_ref: return "fwd_template_ref";
	case CP_DEM_TYPE_KIND_name_with_template_args: return "name_w_tpl_args";
	case CP_DEM_TYPE_KIND_unscoped_template_name: return "unscoped_template_name";

	// Names
	case CP_DEM_TYPE_KIND_name: return "name";
	case CP_DEM_TYPE_KIND_nested_name: return "nested_name";
	case CP_DEM_TYPE_KIND_unqualified_name: return "unqualified_name";
	case CP_DEM_TYPE_KIND_unscoped_name: return "unscoped_name";
	case CP_DEM_TYPE_KIND_source_name: return "source_name";
	case CP_DEM_TYPE_KIND_field_source_name: return "field_source_name";
	case CP_DEM_TYPE_KIND_operator_name: return "operator_name";
	case CP_DEM_TYPE_KIND_special_name: return "special_name";
	case CP_DEM_TYPE_KIND_local_name: return "local_name";
	case CP_DEM_TYPE_KIND_unnamed_type_name: return "unnamed_type_name";
	case CP_DEM_TYPE_KIND_data_name: return "data_name";
	case CP_DEM_TYPE_KIND_entity_name: return "entity_name";
	case CP_DEM_TYPE_KIND_function_name: return "function_name";

	// Constructor/Destructor
	case CP_DEM_TYPE_KIND_ctor_dtor_name: return "ctor_dtor_name";
	case CP_DEM_TYPE_KIND_ctor_name: return "ctor_name";
	case CP_DEM_TYPE_KIND_dtor_name: return "dtor_name";
	case CP_DEM_TYPE_KIND_destructor_name: return "destructor_name";

	// Expression related
	case CP_DEM_TYPE_KIND_expression: return "expression";
	case CP_DEM_TYPE_KIND_expr_primary: return "expr_primary";
	case CP_DEM_TYPE_KIND_braced_expression: return "braced_expression";
	case CP_DEM_TYPE_KIND_braced_range_expression: return "braced_range_expression";
	case CP_DEM_TYPE_KIND_init_list_expression: return "init_list_expression";
	case CP_DEM_TYPE_KIND_fold_expression: return "fold_expression";
	case CP_DEM_TYPE_KIND_prefix_expression: return "prefix_expression";
	case CP_DEM_TYPE_KIND_binary_expression: return "binary_expression";
	case CP_DEM_TYPE_KIND_member_expression: return "member_expression";
	case CP_DEM_TYPE_KIND_new_expression: return "new_expression";
	case CP_DEM_TYPE_KIND_index_expression: return "index_expression";
	case CP_DEM_TYPE_KIND_range_begin_expression: return "range_begin_expression";
	case CP_DEM_TYPE_KIND_range_end_expression: return "range_end_expression";
	case CP_DEM_TYPE_KIND_instantiation_dependent_expression: return "inst_dep_expression";
	case CP_DEM_TYPE_KIND_instantiation_dependent_array_bound_expression: return "inst_dep_array_bound_expr";
	case CP_DEM_TYPE_KIND_initializer: return "initializer";

	// Qualifiers
	case CP_DEM_TYPE_KIND_qualified_type: return "qualified_type";
	case CP_DEM_TYPE_KIND_qualifiers: return "qualifiers";
	case CP_DEM_TYPE_KIND_top_level_cv_qualifiers: return "top_level_cv_qualifiers";
	case CP_DEM_TYPE_KIND_extended_qualifier: return "extended_qualifier";
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type: return "vendor_ext_qualified";

	// Array/Pointer types
	case CP_DEM_TYPE_KIND_vector_type: return "vector_type";
	case CP_DEM_TYPE_KIND_array_type: return "array_type";
	case CP_DEM_TYPE_KIND_array_bound_number: return "array_bound_number";
	case CP_DEM_TYPE_KIND_element_type: return "element_type";
	case CP_DEM_TYPE_KIND_pointer_to_member_type: return "ptr_member_type";

	// Numbers and values
	case CP_DEM_TYPE_KIND_number: return "number";
	case CP_DEM_TYPE_KIND_non_negative_number: return "non_negative_number";
	case CP_DEM_TYPE_KIND_non_neg_number: return "non_neg_number";
	case CP_DEM_TYPE_KIND_offset_number: return "offset_number";
	case CP_DEM_TYPE_KIND_digit: return "digit";
	case CP_DEM_TYPE_KIND_nv_digit: return "nv_digit";
	case CP_DEM_TYPE_KIND_nv_offset: return "nv_offset";
	case CP_DEM_TYPE_KIND_v_offset: return "v_offset";
	case CP_DEM_TYPE_KIND_virtual_offset_number: return "virtual_offset_number";
	case CP_DEM_TYPE_KIND_seq_id: return "seq_id";

	// Float related
	case CP_DEM_TYPE_KIND_float: return "float";
	case CP_DEM_TYPE_KIND_value_float: return "value_float";
	case CP_DEM_TYPE_KIND_real_part_float: return "real_part_float";
	case CP_DEM_TYPE_KIND_imag_part_float: return "imag_part_float";
	case CP_DEM_TYPE_KIND_value_number: return "value_number";

	// Unresolved names
	case CP_DEM_TYPE_KIND_unresolved_name: return "unresolved_name";
	case CP_DEM_TYPE_KIND_unresolved_type: return "unresolved_type";
	case CP_DEM_TYPE_KIND_unresolved_qualifier_level: return "unresolved_qualifier_level";
	case CP_DEM_TYPE_KIND_base_unresolved_name: return "base_unresolved_name";
	case CP_DEM_TYPE_KIND_simple_id: return "simple_id";

	// ABI and special
	case CP_DEM_TYPE_KIND_call_offset: return "call_offset";
	case CP_DEM_TYPE_KIND_discriminator: return "discriminator";
	case CP_DEM_TYPE_KIND_vendor_specific_suffix: return "vendor_specific_suffix";

	// Misc
	case CP_DEM_TYPE_KIND_substitution: return "substitution";
	case CP_DEM_TYPE_KIND_many: return "many";
	case CP_DEM_TYPE_KIND_encoding: return "encoding";
	case CP_DEM_TYPE_KIND_base_encoding: return "base_encoding";
	case CP_DEM_TYPE_KIND_mangled_name: return "mangled_name";
	case CP_DEM_TYPE_KIND_closure_ty_name: return "closure_ty_name";
	case CP_DEM_TYPE_KIND_module_name: return "module_name";
	case CP_DEM_TYPE_KIND_class_enum_type: return "class_enum_type";
	case CP_DEM_TYPE_KIND_decltype: return "decltype";
	case CP_DEM_TYPE_KIND_conv_op_ty: return "conv_op_ty";
	case CP_DEM_TYPE_KIND_abi_tag_ty: return "abi_tag_ty";
	case CP_DEM_TYPE_KIND_parameter_pack_expansion: return "parameter_pack_expansion";
	case CP_DEM_TYPE_KIND_template_parameter_pack: return "template_parameter_pack";
	case CP_DEM_TYPE_KIND_special_substitution: return "special_substitution";
	case CP_DEM_TYPE_KIND_expanded_special_substitution: return "expanded_special_substitution";

	default: return "unknown";
	}
}

static const char *get_node_shape(CpDemTypeKind tag) {
	switch (tag) {
	// Basic types - oval
	case CP_DEM_TYPE_KIND_primitive_ty: return "oval";
	case CP_DEM_TYPE_KIND_builtin_type: return "oval";
	case CP_DEM_TYPE_KIND_class_type: return "oval";
	case CP_DEM_TYPE_KIND_pointer_type: return "oval";
	case CP_DEM_TYPE_KIND_string_type: return "oval";
	case CP_DEM_TYPE_KIND_signature_type: return "oval";

	// Function related - box
	case CP_DEM_TYPE_KIND_function_type: return "box";
	case CP_DEM_TYPE_KIND_bare_function_type: return "box";
	case CP_DEM_TYPE_KIND_function_param: return "box";
	case CP_DEM_TYPE_KIND_function_encoding: return "box";
	case CP_DEM_TYPE_KIND_exception_spec: return "box";

	// Template related - hexagon
	case CP_DEM_TYPE_KIND_template_args: return "hexagon";
	case CP_DEM_TYPE_KIND_template_param: return "hexagon";
	case CP_DEM_TYPE_KIND_template_arg: return "hexagon";
	case CP_DEM_TYPE_KIND_template_param_decl: return "hexagon";
	case CP_DEM_TYPE_KIND_template_template_param: return "hexagon";
	case CP_DEM_TYPE_KIND_fwd_template_ref: return "doublecircle";
	case CP_DEM_TYPE_KIND_name_with_template_args: return "tab";
	case CP_DEM_TYPE_KIND_unscoped_template_name: return "hexagon";

	// Names - ellipse
	case CP_DEM_TYPE_KIND_name: return "ellipse";
	case CP_DEM_TYPE_KIND_nested_name: return "ellipse";
	case CP_DEM_TYPE_KIND_unqualified_name: return "ellipse";
	case CP_DEM_TYPE_KIND_unscoped_name: return "ellipse";
	case CP_DEM_TYPE_KIND_source_name: return "ellipse";
	case CP_DEM_TYPE_KIND_field_source_name: return "ellipse";
	case CP_DEM_TYPE_KIND_operator_name: return "ellipse";
	case CP_DEM_TYPE_KIND_special_name: return "ellipse";
	case CP_DEM_TYPE_KIND_local_name: return "ellipse";
	case CP_DEM_TYPE_KIND_unnamed_type_name: return "ellipse";
	case CP_DEM_TYPE_KIND_data_name: return "ellipse";
	case CP_DEM_TYPE_KIND_entity_name: return "ellipse";
	case CP_DEM_TYPE_KIND_function_name: return "ellipse";

	// Constructor/Destructor - octagon
	case CP_DEM_TYPE_KIND_ctor_dtor_name: return "octagon";
	case CP_DEM_TYPE_KIND_ctor_name: return "octagon";
	case CP_DEM_TYPE_KIND_dtor_name: return "octagon";
	case CP_DEM_TYPE_KIND_destructor_name: return "octagon";

	// Expression related - diamond
	case CP_DEM_TYPE_KIND_expression: return "diamond";
	case CP_DEM_TYPE_KIND_expr_primary: return "diamond";
	case CP_DEM_TYPE_KIND_braced_expression: return "diamond";
	case CP_DEM_TYPE_KIND_braced_range_expression: return "diamond";
	case CP_DEM_TYPE_KIND_init_list_expression: return "diamond";
	case CP_DEM_TYPE_KIND_fold_expression: return "diamond";
	case CP_DEM_TYPE_KIND_prefix_expression: return "diamond";
	case CP_DEM_TYPE_KIND_binary_expression: return "diamond";
	case CP_DEM_TYPE_KIND_member_expression: return "diamond";
	case CP_DEM_TYPE_KIND_new_expression: return "diamond";
	case CP_DEM_TYPE_KIND_index_expression: return "diamond";
	case CP_DEM_TYPE_KIND_range_begin_expression: return "diamond";
	case CP_DEM_TYPE_KIND_range_end_expression: return "diamond";
	case CP_DEM_TYPE_KIND_instantiation_dependent_expression: return "diamond";
	case CP_DEM_TYPE_KIND_instantiation_dependent_array_bound_expression: return "diamond";
	case CP_DEM_TYPE_KIND_initializer: return "diamond";

	// Qualifiers - house
	case CP_DEM_TYPE_KIND_qualified_type: return "house";
	case CP_DEM_TYPE_KIND_qualifiers: return "house";
	case CP_DEM_TYPE_KIND_top_level_cv_qualifiers: return "house";
	case CP_DEM_TYPE_KIND_extended_qualifier: return "house";
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type: return "house";

	// Array/Pointer types - box3d/cds
	case CP_DEM_TYPE_KIND_array_type: return "box3d";
	case CP_DEM_TYPE_KIND_array_bound_number: return "box3d";
	case CP_DEM_TYPE_KIND_element_type: return "box3d";
	case CP_DEM_TYPE_KIND_pointer_to_member_type: return "cds";

	// Numbers and values - plain box
	case CP_DEM_TYPE_KIND_number: return "plaintext";
	case CP_DEM_TYPE_KIND_non_negative_number: return "plaintext";
	case CP_DEM_TYPE_KIND_non_neg_number: return "plaintext";
	case CP_DEM_TYPE_KIND_offset_number: return "plaintext";
	case CP_DEM_TYPE_KIND_digit: return "plaintext";
	case CP_DEM_TYPE_KIND_nv_digit: return "plaintext";
	case CP_DEM_TYPE_KIND_nv_offset: return "plaintext";
	case CP_DEM_TYPE_KIND_v_offset: return "plaintext";
	case CP_DEM_TYPE_KIND_virtual_offset_number: return "plaintext";
	case CP_DEM_TYPE_KIND_seq_id: return "plaintext";
	case CP_DEM_TYPE_KIND_value_number: return "plaintext";

	// Float related - circle
	case CP_DEM_TYPE_KIND_float: return "circle";
	case CP_DEM_TYPE_KIND_value_float: return "circle";
	case CP_DEM_TYPE_KIND_real_part_float: return "circle";
	case CP_DEM_TYPE_KIND_imag_part_float: return "circle";

	// Unresolved names - trapezium
	case CP_DEM_TYPE_KIND_unresolved_name: return "trapezium";
	case CP_DEM_TYPE_KIND_unresolved_type: return "trapezium";
	case CP_DEM_TYPE_KIND_unresolved_qualifier_level: return "trapezium";
	case CP_DEM_TYPE_KIND_base_unresolved_name: return "trapezium";
	case CP_DEM_TYPE_KIND_simple_id: return "trapezium";

	// Type - parallelogram
	case CP_DEM_TYPE_KIND_type: return "parallelogram";

	// ABI and special - note/triangle
	case CP_DEM_TYPE_KIND_call_offset: return "triangle";
	case CP_DEM_TYPE_KIND_discriminator: return "triangle";
	case CP_DEM_TYPE_KIND_vendor_specific_suffix: return "note";

	// Misc
	case CP_DEM_TYPE_KIND_substitution: return "triangle";
	case CP_DEM_TYPE_KIND_many: return "note";
	case CP_DEM_TYPE_KIND_encoding: return "component";
	case CP_DEM_TYPE_KIND_base_encoding: return "component";
	case CP_DEM_TYPE_KIND_mangled_name: return "component";
	case CP_DEM_TYPE_KIND_closure_ty_name: return "invhouse";
	case CP_DEM_TYPE_KIND_module_name: return "folder";
	case CP_DEM_TYPE_KIND_class_enum_type: return "oval";
	case CP_DEM_TYPE_KIND_decltype: return "parallelogram";
	case CP_DEM_TYPE_KIND_conv_op_ty: return "doubleoctagon";
	case CP_DEM_TYPE_KIND_abi_tag_ty: return "tab";
	case CP_DEM_TYPE_KIND_parameter_pack_expansion: return "septagon";
	case CP_DEM_TYPE_KIND_template_parameter_pack: return "septagon";
	case CP_DEM_TYPE_KIND_special_substitution: return "invtriangle";
	case CP_DEM_TYPE_KIND_expanded_special_substitution: return "invtrapezium";

	default: return "ellipse";
	}
}

static const char *get_node_color(CpDemTypeKind tag) {
	switch (tag) {
	// Basic types - lightblue
	case CP_DEM_TYPE_KIND_primitive_ty: return "lightblue";
	case CP_DEM_TYPE_KIND_builtin_type: return "lightblue";
	case CP_DEM_TYPE_KIND_class_type: return "lightblue";
	case CP_DEM_TYPE_KIND_pointer_type: return "lightcyan";
	case CP_DEM_TYPE_KIND_string_type: return "lightblue";
	case CP_DEM_TYPE_KIND_signature_type: return "lightblue";
	case CP_DEM_TYPE_KIND_type: return "lightgray";

	// Function related - lightgreen
	case CP_DEM_TYPE_KIND_function_type: return "lightgreen";
	case CP_DEM_TYPE_KIND_bare_function_type: return "lightgreen";
	case CP_DEM_TYPE_KIND_function_param: return "lightgreen";
	case CP_DEM_TYPE_KIND_function_encoding: return "green";
	case CP_DEM_TYPE_KIND_exception_spec: return "lightgreen";

	// Template related - yellow
	case CP_DEM_TYPE_KIND_template_args: return "yellow";
	case CP_DEM_TYPE_KIND_template_param: return "yellow";
	case CP_DEM_TYPE_KIND_template_arg: return "yellow";
	case CP_DEM_TYPE_KIND_template_param_decl: return "yellow";
	case CP_DEM_TYPE_KIND_template_template_param: return "yellow";
	case CP_DEM_TYPE_KIND_fwd_template_ref: return "greenyellow";
	case CP_DEM_TYPE_KIND_name_with_template_args: return "lightcyan";
	case CP_DEM_TYPE_KIND_unscoped_template_name: return "yellow";

	// Names - orange
	case CP_DEM_TYPE_KIND_name: return "orange";
	case CP_DEM_TYPE_KIND_nested_name: return "orange";
	case CP_DEM_TYPE_KIND_unqualified_name: return "orange";
	case CP_DEM_TYPE_KIND_unscoped_name: return "orange";
	case CP_DEM_TYPE_KIND_source_name: return "orange";
	case CP_DEM_TYPE_KIND_field_source_name: return "orange";
	case CP_DEM_TYPE_KIND_operator_name: return "orange";
	case CP_DEM_TYPE_KIND_special_name: return "orange";
	case CP_DEM_TYPE_KIND_local_name: return "orange";
	case CP_DEM_TYPE_KIND_unnamed_type_name: return "orange";
	case CP_DEM_TYPE_KIND_data_name: return "orange";
	case CP_DEM_TYPE_KIND_entity_name: return "orange";
	case CP_DEM_TYPE_KIND_function_name: return "orange";

	// Constructor/Destructor - coral
	case CP_DEM_TYPE_KIND_ctor_dtor_name: return "coral";
	case CP_DEM_TYPE_KIND_ctor_name: return "coral";
	case CP_DEM_TYPE_KIND_dtor_name: return "coral";
	case CP_DEM_TYPE_KIND_destructor_name: return "coral";

	// Expression related - pink
	case CP_DEM_TYPE_KIND_expression: return "pink";
	case CP_DEM_TYPE_KIND_expr_primary: return "pink";
	case CP_DEM_TYPE_KIND_braced_expression: return "pink";
	case CP_DEM_TYPE_KIND_braced_range_expression: return "pink";
	case CP_DEM_TYPE_KIND_init_list_expression: return "pink";
	case CP_DEM_TYPE_KIND_fold_expression: return "pink";
	case CP_DEM_TYPE_KIND_prefix_expression: return "pink";
	case CP_DEM_TYPE_KIND_binary_expression: return "pink";
	case CP_DEM_TYPE_KIND_member_expression: return "pink";
	case CP_DEM_TYPE_KIND_new_expression: return "pink";
	case CP_DEM_TYPE_KIND_index_expression: return "pink";
	case CP_DEM_TYPE_KIND_range_begin_expression: return "pink";
	case CP_DEM_TYPE_KIND_range_end_expression: return "pink";
	case CP_DEM_TYPE_KIND_instantiation_dependent_expression: return "pink";
	case CP_DEM_TYPE_KIND_instantiation_dependent_array_bound_expression: return "pink";
	case CP_DEM_TYPE_KIND_initializer: return "pink";

	// Qualifiers - brown
	case CP_DEM_TYPE_KIND_qualified_type: return "brown";
	case CP_DEM_TYPE_KIND_qualifiers: return "brown";
	case CP_DEM_TYPE_KIND_top_level_cv_qualifiers: return "brown";
	case CP_DEM_TYPE_KIND_extended_qualifier: return "brown";
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type: return "brown";

	// Array/Pointer types - cyan/purple
	case CP_DEM_TYPE_KIND_array_type: return "cyan";
	case CP_DEM_TYPE_KIND_array_bound_number: return "cyan";
	case CP_DEM_TYPE_KIND_element_type: return "cyan";
	case CP_DEM_TYPE_KIND_pointer_to_member_type: return "purple";

	// Numbers and values - wheat
	case CP_DEM_TYPE_KIND_number: return "wheat";
	case CP_DEM_TYPE_KIND_non_negative_number: return "wheat";
	case CP_DEM_TYPE_KIND_non_neg_number: return "wheat";
	case CP_DEM_TYPE_KIND_offset_number: return "wheat";
	case CP_DEM_TYPE_KIND_digit: return "wheat";
	case CP_DEM_TYPE_KIND_nv_digit: return "wheat";
	case CP_DEM_TYPE_KIND_nv_offset: return "wheat";
	case CP_DEM_TYPE_KIND_v_offset: return "wheat";
	case CP_DEM_TYPE_KIND_virtual_offset_number: return "wheat";
	case CP_DEM_TYPE_KIND_seq_id: return "wheat";
	case CP_DEM_TYPE_KIND_value_number: return "wheat";

	// Float related - lightyellow
	case CP_DEM_TYPE_KIND_float: return "lightyellow";
	case CP_DEM_TYPE_KIND_value_float: return "lightyellow";
	case CP_DEM_TYPE_KIND_real_part_float: return "lightyellow";
	case CP_DEM_TYPE_KIND_imag_part_float: return "lightyellow";

	// Unresolved names - salmon
	case CP_DEM_TYPE_KIND_unresolved_name: return "salmon";
	case CP_DEM_TYPE_KIND_unresolved_type: return "salmon";
	case CP_DEM_TYPE_KIND_unresolved_qualifier_level: return "salmon";
	case CP_DEM_TYPE_KIND_base_unresolved_name: return "salmon";
	case CP_DEM_TYPE_KIND_simple_id: return "salmon";

	// ABI and special - gold/khaki
	case CP_DEM_TYPE_KIND_call_offset: return "khaki";
	case CP_DEM_TYPE_KIND_discriminator: return "khaki";
	case CP_DEM_TYPE_KIND_vendor_specific_suffix: return "gold";

	// Misc
	case CP_DEM_TYPE_KIND_substitution: return "red";
	case CP_DEM_TYPE_KIND_many: return "gold";
	case CP_DEM_TYPE_KIND_encoding: return "darkgreen";
	case CP_DEM_TYPE_KIND_base_encoding: return "darkgreen";
	case CP_DEM_TYPE_KIND_mangled_name: return "darkgreen";
	case CP_DEM_TYPE_KIND_closure_ty_name: return "violet";
	case CP_DEM_TYPE_KIND_module_name: return "khaki";
	case CP_DEM_TYPE_KIND_class_enum_type: return "lightblue";
	case CP_DEM_TYPE_KIND_decltype: return "lightgray";
	case CP_DEM_TYPE_KIND_conv_op_ty: return "mediumpurple";
	case CP_DEM_TYPE_KIND_abi_tag_ty: return "plum";
	case CP_DEM_TYPE_KIND_parameter_pack_expansion: return "palegreen";
	case CP_DEM_TYPE_KIND_template_parameter_pack: return "paleturquoise";
	case CP_DEM_TYPE_KIND_special_substitution: return "orangered";
	case CP_DEM_TYPE_KIND_expanded_special_substitution: return "tomato";

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
	char label[1024] = { 0 };
	int len = snprintf(label, sizeof(label), "%s", type_name);
	if (node->val.buf && node->val.len > 0) {
		const int max_len = 256;
		int copy_len = node->val.len < max_len ? node->val.len : max_len;
		len += snprintf(label + len, sizeof(label) - len, "\\n%.*s", copy_len, node->val.buf);
		if (node->val.len > max_len) {
			len += snprintf(label + len, sizeof(label) - len, "...");
		}
	}

	// Add ast_pp output to show the pretty-printed representation
	DemString pp_output;
	dem_string_init(&pp_output);
	ast_pp(node, &pp_output);
	if (pp_output.buf && pp_output.len > 0) {
		// Escape special characters and limit length
		len += snprintf(label + len, sizeof(label) - len, "\\n=> ");
		size_t remaining = sizeof(label) - len;
		size_t pp_len = pp_output.len < remaining - 1 ? pp_output.len : remaining - 1;
		for (size_t i = 0; i < pp_len && len < sizeof(label) - 1; i++) {
			char ch = pp_output.buf[i];
			// Escape special DOT characters
			if (ch == '"' || ch == '\\' || ch == '\n') {
				if (len < sizeof(label) - 2) {
					label[len++] = '\\';
					label[len++] = (ch == '\n') ? 'n' : ch;
				}
			} else if (ch >= 32 && ch < 127) { // Only printable ASCII
				label[len++] = ch;
			}
		}
	} else {
		len += snprintf(label + len, sizeof(label) - len, "\\n: <empty>");
	}
	dem_string_deinit(&pp_output);

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

	case CP_DEM_TYPE_KIND_closure_ty_name:
		if (node->closure_ty_name.count.buf && node->closure_ty_name.count.len > 0) {
			len += snprintf(label + len, sizeof(label) - len, "\\ncount: %.*s",
				(int)node->closure_ty_name.count.len, node->closure_ty_name.count.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_module_name:
		if (node->module_name_ty.IsPartition) {
			len += snprintf(label + len, sizeof(label) - len, "\\npartition");
		}
		break;

	case CP_DEM_TYPE_KIND_abi_tag_ty:
		if (node->abi_tag_ty.tag.buf && node->abi_tag_ty.tag.len > 0) {
			len += snprintf(label + len, sizeof(label) - len, "\\ntag: %.*s",
				(int)node->abi_tag_ty.tag.len, node->abi_tag_ty.tag.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_member_expression:
		if (node->member_expr.op.buf && node->member_expr.op.len > 0) {
			len += snprintf(label + len, sizeof(label) - len, "\\nop: %.*s",
				(int)node->member_expr.op.len, node->member_expr.op.buf);
		}
		break;

	default:
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
		if (node->fn_ty.requires_node) {
			dot_graph_traverse_ast(dot, node->fn_ty.requires_node, current_id, "requires", "solid");
		}
		if (node->fn_ty.exception_spec) {
			dot_graph_traverse_ast(dot, node->fn_ty.exception_spec, current_id, "exception_spec", "solid");
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

	case CP_DEM_TYPE_KIND_closure_ty_name:
		if (node->closure_ty_name.template_params) {
			dot_graph_traverse_ast(dot, node->closure_ty_name.template_params, current_id, "template_params", "solid");
		}
		if (node->closure_ty_name.params) {
			dot_graph_traverse_ast(dot, node->closure_ty_name.params, current_id, "params", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_module_name:
		if (node->module_name_ty.pare) {
			dot_graph_traverse_ast(dot, node->module_name_ty.pare, current_id, "parent", "solid");
		}
		if (node->module_name_ty.name) {
			dot_graph_traverse_ast(dot, node->module_name_ty.name, current_id, "name", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_name_with_template_args:
		if (node->name_with_template_args.name) {
			dot_graph_traverse_ast(dot, node->name_with_template_args.name, current_id, "name", "solid");
		}
		if (node->name_with_template_args.template_args) {
			dot_graph_traverse_ast(dot, node->name_with_template_args.template_args, current_id, "template_args", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_nested_name:
		if (node->nested_name.qual) {
			dot_graph_traverse_ast(dot, node->nested_name.qual, current_id, "qualifier", "solid");
		}
		if (node->nested_name.name) {
			dot_graph_traverse_ast(dot, node->nested_name.name, current_id, "name", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_local_name:
		if (node->local_name.encoding) {
			dot_graph_traverse_ast(dot, node->local_name.encoding, current_id, "encoding", "solid");
		}
		if (node->local_name.entry) {
			dot_graph_traverse_ast(dot, node->local_name.entry, current_id, "entry", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_ctor_dtor_name:
		if (node->ctor_dtor_name.name) {
			dot_graph_traverse_ast(dot, node->ctor_dtor_name.name, current_id, "name", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_conv_op_ty:
		if (node->conv_op_ty.ty) {
			dot_graph_traverse_ast(dot, node->conv_op_ty.ty, current_id, "type", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_parameter_pack_expansion:
		if (node->parameter_pack_expansion.ty) {
			dot_graph_traverse_ast(dot, node->parameter_pack_expansion.ty, current_id, "type", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_abi_tag_ty:
		if (node->abi_tag_ty.ty) {
			dot_graph_traverse_ast(dot, node->abi_tag_ty.ty, current_id, "type", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_vector_type:
	case CP_DEM_TYPE_KIND_array_type:
		if (node->array_ty.inner_ty) {
			dot_graph_traverse_ast(dot, node->array_ty.inner_ty, current_id, "inner_type", "solid");
		}
		if (node->array_ty.dimension) {
			dot_graph_traverse_ast(dot, node->array_ty.dimension, current_id, "dimension", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_member_expression:
		if (node->member_expr.lhs) {
			dot_graph_traverse_ast(dot, node->member_expr.lhs, current_id, "lhs", "solid");
		}
		if (node->member_expr.rhs) {
			dot_graph_traverse_ast(dot, node->member_expr.rhs, current_id, "rhs", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_fold_expression:
		if (node->fold_expr.pack) {
			dot_graph_traverse_ast(dot, node->fold_expr.pack, current_id, "pack", "solid");
		}
		if (node->fold_expr.init) {
			dot_graph_traverse_ast(dot, node->fold_expr.init, current_id, "init", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_braced_expression:
		if (node->braced_expr.elem) {
			dot_graph_traverse_ast(dot, node->braced_expr.elem, current_id, "elem", "solid");
		}
		if (node->braced_expr.init) {
			dot_graph_traverse_ast(dot, node->braced_expr.init, current_id, "init", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_braced_range_expression:
		if (node->braced_range_expr.first) {
			dot_graph_traverse_ast(dot, node->braced_range_expr.first, current_id, "first", "solid");
		}
		if (node->braced_range_expr.last) {
			dot_graph_traverse_ast(dot, node->braced_range_expr.last, current_id, "last", "solid");
		}
		if (node->braced_range_expr.init) {
			dot_graph_traverse_ast(dot, node->braced_range_expr.init, current_id, "init", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_init_list_expression:
		if (node->init_list_expr.ty) {
			dot_graph_traverse_ast(dot, node->init_list_expr.ty, current_id, "ty", "solid");
		}
		if (node->init_list_expr.inits) {
			dot_graph_traverse_ast(dot, node->init_list_expr.inits, current_id, "inits", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_binary_expression:
		if (node->binary_expr.lhs) {
			dot_graph_traverse_ast(dot, node->binary_expr.lhs, current_id, "lhs", "solid");
		}
		if (node->binary_expr.rhs) {
			dot_graph_traverse_ast(dot, node->binary_expr.rhs, current_id, "rhs", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_prefix_expression:
		if (node->prefix_expr.inner) {
			dot_graph_traverse_ast(dot, node->prefix_expr.inner, current_id, "inner", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_new_expression:
		if (node->new_expr.expr_list) {
			dot_graph_traverse_ast(dot, node->new_expr.expr_list, current_id, "expr_list", "solid");
		}
		if (node->new_expr.ty) {
			dot_graph_traverse_ast(dot, node->new_expr.ty, current_id, "ty", "solid");
		}
		if (node->new_expr.init_list) {
			dot_graph_traverse_ast(dot, node->new_expr.init_list, current_id, "init_list", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_many:
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

	case CP_DEM_TYPE_KIND_fwd_template_ref:
		DEM_UNREACHABLE;
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
	fprintf(stderr, "[DOT] Convert to image:\ndot -Tpng %s -o ast.png\n\n", dot->filename);
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