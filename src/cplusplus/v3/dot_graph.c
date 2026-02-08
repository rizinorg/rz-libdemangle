// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dot_graph.h"
#include "../demangle.h"
#include "demangler_util.h"
#include "macros.h"
#include "v3_pp.h"

#include <ctype.h>

static const char *get_node_type_name(CpDemTypeKind tag) {
	// Extract the type name without the CP_DEM_TYPE_KIND_ prefix
	switch (tag) {
	// Basic types
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY: return "primitive_ty";
	case CP_DEM_TYPE_KIND_BUILTIN_TYPE: return "builtin_type";
	case CP_DEM_TYPE_KIND_TYPE: return "type";
	case CP_DEM_TYPE_KIND_CLASS_TYPE: return "class_type";
	case CP_DEM_TYPE_KIND_POINTER_TYPE: return "pointer_type";
	case CP_DEM_TYPE_KIND_STRING_TYPE: return "string_type";
	case CP_DEM_TYPE_KIND_SIGNATURE_TYPE: return "signature_type";

	// Function related
	case CP_DEM_TYPE_KIND_FUNCTION_TYPE: return "function_type";
	case CP_DEM_TYPE_KIND_BARE_FUNCTION_TYPE: return "bare_function_type";
	case CP_DEM_TYPE_KIND_FUNCTION_PARAM: return "function_param";
	case CP_DEM_TYPE_KIND_FUNCTION_ENCODING: return "function_encoding";
	case CP_DEM_TYPE_KIND_EXCEPTION_SPEC: return "exception_spec";
	case CP_DEM_TYPE_KIND_NOEXCEPT_SPEC: return "noexcept_spec";
	case CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC: return "dynamic_exception_spec";

	// Template related
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGS: return "template_args";
	case CP_DEM_TYPE_KIND_TEMPLATE_PARAM: return "template_param";
	case CP_DEM_TYPE_KIND_TEMPLATE_ARG: return "template_arg";
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK: return "template_argument_pack";
	case CP_DEM_TYPE_KIND_TEMPLATE_PARAM_DECL: return "template_param_decl";
	case CP_DEM_TYPE_KIND_TEMPLATE_TEMPLATE_PARAM: return "template_template_param";
	case CP_DEM_TYPE_KIND_FWD_TEMPLATE_REF: return "fwd_template_ref";
	case CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS: return "name_w_tpl_args";
	case CP_DEM_TYPE_KIND_UNSCOPED_TEMPLATE_NAME: return "unscoped_template_name";

	// Names
	case CP_DEM_TYPE_KIND_NAME: return "name";
	case CP_DEM_TYPE_KIND_NESTED_NAME: return "nested_name";
	case CP_DEM_TYPE_KIND_UNQUALIFIED_NAME: return "unqualified_name";
	case CP_DEM_TYPE_KIND_UNSCOPED_NAME: return "unscoped_name";
	case CP_DEM_TYPE_KIND_SOURCE_NAME: return "source_name";
	case CP_DEM_TYPE_KIND_FIELD_SOURCE_NAME: return "field_source_name";
	case CP_DEM_TYPE_KIND_OPERATOR_NAME: return "operator_name";
	case CP_DEM_TYPE_KIND_SPECIAL_NAME: return "special_name";
	case CP_DEM_TYPE_KIND_LOCAL_NAME: return "local_name";
	case CP_DEM_TYPE_KIND_UNNAMED_TYPE_NAME: return "unnamed_type_name";
	case CP_DEM_TYPE_KIND_DATA_NAME: return "data_name";
	case CP_DEM_TYPE_KIND_ENTITY_NAME: return "entity_name";
	case CP_DEM_TYPE_KIND_FUNCTION_NAME: return "function_name";

	// Constructor/Destructor
	case CP_DEM_TYPE_KIND_CTOR_DTOR_NAME: return "ctor_dtor_name";
	case CP_DEM_TYPE_KIND_CTOR_NAME: return "ctor_name";
	case CP_DEM_TYPE_KIND_DTOR_NAME: return "dtor_name";
	case CP_DEM_TYPE_KIND_DESTRUCTOR_NAME: return "destructor_name";

	// Expression related
	case CP_DEM_TYPE_KIND_EXPRESSION: return "expression";
	case CP_DEM_TYPE_KIND_EXPR_PRIMARY: return "expr_primary";
	case CP_DEM_TYPE_KIND_INTEGER_LITERAL: return "integer_literal";
	case CP_DEM_TYPE_KIND_BRACED_EXPRESSION: return "braced_expression";
	case CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION: return "braced_range_expression";
	case CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION: return "init_list_expression";
	case CP_DEM_TYPE_KIND_FOLD_EXPRESSION: return "fold_expression";
	case CP_DEM_TYPE_KIND_PREFIX_EXPRESSION: return "prefix_expression";
	case CP_DEM_TYPE_KIND_BINARY_EXPRESSION: return "binary_expression";
	case CP_DEM_TYPE_KIND_MEMBER_EXPRESSION: return "member_expression";
	case CP_DEM_TYPE_KIND_NEW_EXPRESSION: return "new_expression";
	case CP_DEM_TYPE_KIND_INDEX_EXPRESSION: return "index_expression";
	case CP_DEM_TYPE_KIND_RANGE_BEGIN_EXPRESSION: return "range_begin_expression";
	case CP_DEM_TYPE_KIND_RANGE_END_EXPRESSION: return "range_end_expression";
	case CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_EXPRESSION: return "inst_dep_expression";
	case CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_ARRAY_BOUND_EXPRESSION: return "inst_dep_array_bound_expr";
	case CP_DEM_TYPE_KIND_INITIALIZER: return "initializer";

	// Qualifiers
	case CP_DEM_TYPE_KIND_QUALIFIED_TYPE: return "qualified_type";
	case CP_DEM_TYPE_KIND_QUALIFIERS: return "qualifiers";
	case CP_DEM_TYPE_KIND_TOP_LEVEL_CV_QUALIFIERS: return "top_level_cv_qualifiers";
	case CP_DEM_TYPE_KIND_EXTENDED_QUALIFIER: return "extended_qualifier";
	case CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE: return "vendor_ext_qualified";

	// Array/Pointer types
	case CP_DEM_TYPE_KIND_VECTOR_TYPE: return "vector_type";
	case CP_DEM_TYPE_KIND_ARRAY_TYPE: return "array_type";
	case CP_DEM_TYPE_KIND_ARRAY_BOUND_NUMBER: return "array_bound_number";
	case CP_DEM_TYPE_KIND_ELEMENT_TYPE: return "element_type";
	case CP_DEM_TYPE_KIND_POINTER_TO_MEMBER_TYPE: return "ptr_member_type";

	// Numbers and values
	case CP_DEM_TYPE_KIND_NUMBER: return "number";
	case CP_DEM_TYPE_KIND_NON_NEGATIVE_NUMBER: return "non_negative_number";
	case CP_DEM_TYPE_KIND_NON_NEG_NUMBER: return "non_neg_number";
	case CP_DEM_TYPE_KIND_OFFSET_NUMBER: return "offset_number";
	case CP_DEM_TYPE_KIND_DIGIT: return "digit";
	case CP_DEM_TYPE_KIND_NV_DIGIT: return "nv_digit";
	case CP_DEM_TYPE_KIND_NV_OFFSET: return "nv_offset";
	case CP_DEM_TYPE_KIND_V_OFFSET: return "v_offset";
	case CP_DEM_TYPE_KIND_VIRTUAL_OFFSET_NUMBER: return "virtual_offset_number";
	case CP_DEM_TYPE_KIND_SEQ_ID: return "seq_id";

	// Float related
	case CP_DEM_TYPE_KIND_FLOAT: return "float";
	case CP_DEM_TYPE_KIND_VALUE_FLOAT: return "value_float";
	case CP_DEM_TYPE_KIND_REAL_PART_FLOAT: return "real_part_float";
	case CP_DEM_TYPE_KIND_IMAG_PART_FLOAT: return "imag_part_float";
	case CP_DEM_TYPE_KIND_VALUE_NUMBER: return "value_number";

	// Unresolved names
	case CP_DEM_TYPE_KIND_UNRESOLVED_NAME: return "unresolved_name";
	case CP_DEM_TYPE_KIND_UNRESOLVED_TYPE: return "unresolved_type";
	case CP_DEM_TYPE_KIND_UNRESOLVED_QUALIFIER_LEVEL: return "unresolved_qualifier_level";
	case CP_DEM_TYPE_KIND_BASE_UNRESOLVED_NAME: return "base_unresolved_name";
	case CP_DEM_TYPE_KIND_SIMPLE_ID: return "simple_id";

	// ABI and special
	case CP_DEM_TYPE_KIND_CALL_OFFSET: return "call_offset";
	case CP_DEM_TYPE_KIND_DISCRIMINATOR: return "discriminator";
	case CP_DEM_TYPE_KIND_VENDOR_SPECIFIC_SUFFIX: return "vendor_specific_suffix";

	// Misc
	case CP_DEM_TYPE_KIND_SUBSTITUTION: return "substitution";
	case CP_DEM_TYPE_KIND_MANY: return "many";
	case CP_DEM_TYPE_KIND_ENCODING: return "encoding";
	case CP_DEM_TYPE_KIND_BASE_ENCODING: return "base_encoding";
	case CP_DEM_TYPE_KIND_MANGLED_NAME: return "mangled_name";
	case CP_DEM_TYPE_KIND_CLOSURE_TY_NAME: return "closure_ty_name";
	case CP_DEM_TYPE_KIND_MODULE_NAME: return "module_name";
	case CP_DEM_TYPE_KIND_CLASS_ENUM_TYPE: return "class_enum_type";
	case CP_DEM_TYPE_KIND_DECLTYPE: return "decltype";
	case CP_DEM_TYPE_KIND_CONV_OP_TY: return "conv_op_ty";
	case CP_DEM_TYPE_KIND_ABI_TAG_TY: return "abi_tag_ty";
	case CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION: return "parameter_pack_expansion";
	case CP_DEM_TYPE_KIND_PARAMETER_PACK: return "template_parameter_pack";
	case CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION: return "special_substitution";
	case CP_DEM_TYPE_KIND_EXPANDED_SPECIAL_SUBSTITUTION: return "expanded_special_substitution";

	default: return "unknown";
	}
}

static const char *get_node_shape(CpDemTypeKind tag) {
	switch (tag) {
	// Basic types - oval
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY: return "oval";
	case CP_DEM_TYPE_KIND_BUILTIN_TYPE: return "oval";
	case CP_DEM_TYPE_KIND_CLASS_TYPE: return "oval";
	case CP_DEM_TYPE_KIND_POINTER_TYPE: return "oval";
	case CP_DEM_TYPE_KIND_STRING_TYPE: return "oval";
	case CP_DEM_TYPE_KIND_SIGNATURE_TYPE: return "oval";

	// Function related - box
	case CP_DEM_TYPE_KIND_FUNCTION_TYPE: return "box";
	case CP_DEM_TYPE_KIND_BARE_FUNCTION_TYPE: return "box";
	case CP_DEM_TYPE_KIND_FUNCTION_PARAM: return "box";
	case CP_DEM_TYPE_KIND_FUNCTION_ENCODING: return "box";
	case CP_DEM_TYPE_KIND_EXCEPTION_SPEC: return "box";
	case CP_DEM_TYPE_KIND_NOEXCEPT_SPEC: return "box";
	case CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC: return "box";

	// Template related - hexagon
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGS: return "hexagon";
	case CP_DEM_TYPE_KIND_TEMPLATE_PARAM: return "hexagon";
	case CP_DEM_TYPE_KIND_TEMPLATE_ARG: return "hexagon";
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK: return "hexagon";
	case CP_DEM_TYPE_KIND_TEMPLATE_PARAM_DECL: return "hexagon";
	case CP_DEM_TYPE_KIND_TEMPLATE_TEMPLATE_PARAM: return "hexagon";
	case CP_DEM_TYPE_KIND_FWD_TEMPLATE_REF: return "doublecircle";
	case CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS: return "tab";
	case CP_DEM_TYPE_KIND_UNSCOPED_TEMPLATE_NAME: return "hexagon";

	// Names - ellipse
	case CP_DEM_TYPE_KIND_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_NESTED_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_UNQUALIFIED_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_UNSCOPED_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_SOURCE_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_FIELD_SOURCE_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_OPERATOR_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_SPECIAL_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_LOCAL_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_UNNAMED_TYPE_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_DATA_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_ENTITY_NAME: return "ellipse";
	case CP_DEM_TYPE_KIND_FUNCTION_NAME: return "ellipse";

	// Constructor/Destructor - octagon
	case CP_DEM_TYPE_KIND_CTOR_DTOR_NAME: return "octagon";
	case CP_DEM_TYPE_KIND_CTOR_NAME: return "octagon";
	case CP_DEM_TYPE_KIND_DTOR_NAME: return "octagon";
	case CP_DEM_TYPE_KIND_DESTRUCTOR_NAME: return "octagon";

	// Expression related - diamond
	case CP_DEM_TYPE_KIND_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_EXPR_PRIMARY: return "diamond";
	case CP_DEM_TYPE_KIND_INTEGER_LITERAL: return "diamond";
	case CP_DEM_TYPE_KIND_BRACED_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_FOLD_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_PREFIX_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_BINARY_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_MEMBER_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_NEW_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_INDEX_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_RANGE_BEGIN_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_RANGE_END_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_ARRAY_BOUND_EXPRESSION: return "diamond";
	case CP_DEM_TYPE_KIND_INITIALIZER: return "diamond";

	// Qualifiers - house
	case CP_DEM_TYPE_KIND_QUALIFIED_TYPE: return "house";
	case CP_DEM_TYPE_KIND_QUALIFIERS: return "house";
	case CP_DEM_TYPE_KIND_TOP_LEVEL_CV_QUALIFIERS: return "house";
	case CP_DEM_TYPE_KIND_EXTENDED_QUALIFIER: return "house";
	case CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE: return "house";

	// Array/Pointer types - box3d/cds
	case CP_DEM_TYPE_KIND_ARRAY_TYPE: return "box3d";
	case CP_DEM_TYPE_KIND_ARRAY_BOUND_NUMBER: return "box3d";
	case CP_DEM_TYPE_KIND_ELEMENT_TYPE: return "box3d";
	case CP_DEM_TYPE_KIND_POINTER_TO_MEMBER_TYPE: return "cds";

	// Numbers and values - plain box
	case CP_DEM_TYPE_KIND_NUMBER: return "plaintext";
	case CP_DEM_TYPE_KIND_NON_NEGATIVE_NUMBER: return "plaintext";
	case CP_DEM_TYPE_KIND_NON_NEG_NUMBER: return "plaintext";
	case CP_DEM_TYPE_KIND_OFFSET_NUMBER: return "plaintext";
	case CP_DEM_TYPE_KIND_DIGIT: return "plaintext";
	case CP_DEM_TYPE_KIND_NV_DIGIT: return "plaintext";
	case CP_DEM_TYPE_KIND_NV_OFFSET: return "plaintext";
	case CP_DEM_TYPE_KIND_V_OFFSET: return "plaintext";
	case CP_DEM_TYPE_KIND_VIRTUAL_OFFSET_NUMBER: return "plaintext";
	case CP_DEM_TYPE_KIND_SEQ_ID: return "plaintext";
	case CP_DEM_TYPE_KIND_VALUE_NUMBER: return "plaintext";

	// Float related - circle
	case CP_DEM_TYPE_KIND_FLOAT: return "circle";
	case CP_DEM_TYPE_KIND_VALUE_FLOAT: return "circle";
	case CP_DEM_TYPE_KIND_REAL_PART_FLOAT: return "circle";
	case CP_DEM_TYPE_KIND_IMAG_PART_FLOAT: return "circle";

	// Unresolved names - trapezium
	case CP_DEM_TYPE_KIND_UNRESOLVED_NAME: return "trapezium";
	case CP_DEM_TYPE_KIND_UNRESOLVED_TYPE: return "trapezium";
	case CP_DEM_TYPE_KIND_UNRESOLVED_QUALIFIER_LEVEL: return "trapezium";
	case CP_DEM_TYPE_KIND_BASE_UNRESOLVED_NAME: return "trapezium";
	case CP_DEM_TYPE_KIND_SIMPLE_ID: return "trapezium";

	// Type - parallelogram
	case CP_DEM_TYPE_KIND_TYPE: return "parallelogram";

	// ABI and special - note/triangle
	case CP_DEM_TYPE_KIND_CALL_OFFSET: return "triangle";
	case CP_DEM_TYPE_KIND_DISCRIMINATOR: return "triangle";
	case CP_DEM_TYPE_KIND_VENDOR_SPECIFIC_SUFFIX: return "note";

	// Misc
	case CP_DEM_TYPE_KIND_SUBSTITUTION: return "triangle";
	case CP_DEM_TYPE_KIND_MANY: return "note";
	case CP_DEM_TYPE_KIND_ENCODING: return "component";
	case CP_DEM_TYPE_KIND_BASE_ENCODING: return "component";
	case CP_DEM_TYPE_KIND_MANGLED_NAME: return "component";
	case CP_DEM_TYPE_KIND_CLOSURE_TY_NAME: return "invhouse";
	case CP_DEM_TYPE_KIND_MODULE_NAME: return "folder";
	case CP_DEM_TYPE_KIND_CLASS_ENUM_TYPE: return "oval";
	case CP_DEM_TYPE_KIND_DECLTYPE: return "parallelogram";
	case CP_DEM_TYPE_KIND_CONV_OP_TY: return "doubleoctagon";
	case CP_DEM_TYPE_KIND_ABI_TAG_TY: return "tab";
	case CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION: return "septagon";
	case CP_DEM_TYPE_KIND_PARAMETER_PACK: return "septagon";
	case CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION: return "invtriangle";
	case CP_DEM_TYPE_KIND_EXPANDED_SPECIAL_SUBSTITUTION: return "invtrapezium";

	default: return "ellipse";
	}
}

static const char *get_node_color(CpDemTypeKind tag) {
	switch (tag) {
	// Basic types - lightblue
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY: return "lightblue";
	case CP_DEM_TYPE_KIND_BUILTIN_TYPE: return "lightblue";
	case CP_DEM_TYPE_KIND_CLASS_TYPE: return "lightblue";
	case CP_DEM_TYPE_KIND_POINTER_TYPE: return "lightcyan";
	case CP_DEM_TYPE_KIND_STRING_TYPE: return "lightblue";
	case CP_DEM_TYPE_KIND_SIGNATURE_TYPE: return "lightblue";
	case CP_DEM_TYPE_KIND_TYPE: return "lightgray";

	// Function related - lightgreen
	case CP_DEM_TYPE_KIND_FUNCTION_TYPE: return "lightgreen";
	case CP_DEM_TYPE_KIND_BARE_FUNCTION_TYPE: return "lightgreen";
	case CP_DEM_TYPE_KIND_FUNCTION_PARAM: return "lightgreen";
	case CP_DEM_TYPE_KIND_FUNCTION_ENCODING: return "green";
	case CP_DEM_TYPE_KIND_EXCEPTION_SPEC: return "lightgreen";
	case CP_DEM_TYPE_KIND_NOEXCEPT_SPEC: return "lightgreen";
	case CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC: return "lightgreen";

	// Template related - yellow
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGS: return "yellow";
	case CP_DEM_TYPE_KIND_TEMPLATE_PARAM: return "yellow";
	case CP_DEM_TYPE_KIND_TEMPLATE_ARG: return "yellow";
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK: return "yellow";
	case CP_DEM_TYPE_KIND_TEMPLATE_PARAM_DECL: return "yellow";
	case CP_DEM_TYPE_KIND_TEMPLATE_TEMPLATE_PARAM: return "yellow";
	case CP_DEM_TYPE_KIND_FWD_TEMPLATE_REF: return "greenyellow";
	case CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS: return "lightcyan";
	case CP_DEM_TYPE_KIND_UNSCOPED_TEMPLATE_NAME: return "yellow";

	// Names - orange
	case CP_DEM_TYPE_KIND_NAME: return "orange";
	case CP_DEM_TYPE_KIND_NESTED_NAME: return "orange";
	case CP_DEM_TYPE_KIND_UNQUALIFIED_NAME: return "orange";
	case CP_DEM_TYPE_KIND_UNSCOPED_NAME: return "orange";
	case CP_DEM_TYPE_KIND_SOURCE_NAME: return "orange";
	case CP_DEM_TYPE_KIND_FIELD_SOURCE_NAME: return "orange";
	case CP_DEM_TYPE_KIND_OPERATOR_NAME: return "orange";
	case CP_DEM_TYPE_KIND_SPECIAL_NAME: return "orange";
	case CP_DEM_TYPE_KIND_LOCAL_NAME: return "orange";
	case CP_DEM_TYPE_KIND_UNNAMED_TYPE_NAME: return "orange";
	case CP_DEM_TYPE_KIND_DATA_NAME: return "orange";
	case CP_DEM_TYPE_KIND_ENTITY_NAME: return "orange";
	case CP_DEM_TYPE_KIND_FUNCTION_NAME: return "orange";

	// Constructor/Destructor - coral
	case CP_DEM_TYPE_KIND_CTOR_DTOR_NAME: return "coral";
	case CP_DEM_TYPE_KIND_CTOR_NAME: return "coral";
	case CP_DEM_TYPE_KIND_DTOR_NAME: return "coral";
	case CP_DEM_TYPE_KIND_DESTRUCTOR_NAME: return "coral";

	// Expression related - pink
	case CP_DEM_TYPE_KIND_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_EXPR_PRIMARY: return "pink";
	case CP_DEM_TYPE_KIND_INTEGER_LITERAL: return "pink";
	case CP_DEM_TYPE_KIND_BRACED_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_FOLD_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_PREFIX_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_BINARY_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_MEMBER_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_NEW_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_INDEX_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_RANGE_BEGIN_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_RANGE_END_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_ARRAY_BOUND_EXPRESSION: return "pink";
	case CP_DEM_TYPE_KIND_INITIALIZER: return "pink";

	// Qualifiers - brown
	case CP_DEM_TYPE_KIND_QUALIFIED_TYPE: return "brown";
	case CP_DEM_TYPE_KIND_QUALIFIERS: return "brown";
	case CP_DEM_TYPE_KIND_TOP_LEVEL_CV_QUALIFIERS: return "brown";
	case CP_DEM_TYPE_KIND_EXTENDED_QUALIFIER: return "brown";
	case CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE: return "brown";

	// Array/Pointer types - cyan/purple
	case CP_DEM_TYPE_KIND_ARRAY_TYPE: return "cyan";
	case CP_DEM_TYPE_KIND_ARRAY_BOUND_NUMBER: return "cyan";
	case CP_DEM_TYPE_KIND_ELEMENT_TYPE: return "cyan";
	case CP_DEM_TYPE_KIND_POINTER_TO_MEMBER_TYPE: return "purple";

	// Numbers and values - wheat
	case CP_DEM_TYPE_KIND_NUMBER: return "wheat";
	case CP_DEM_TYPE_KIND_NON_NEGATIVE_NUMBER: return "wheat";
	case CP_DEM_TYPE_KIND_NON_NEG_NUMBER: return "wheat";
	case CP_DEM_TYPE_KIND_OFFSET_NUMBER: return "wheat";
	case CP_DEM_TYPE_KIND_DIGIT: return "wheat";
	case CP_DEM_TYPE_KIND_NV_DIGIT: return "wheat";
	case CP_DEM_TYPE_KIND_NV_OFFSET: return "wheat";
	case CP_DEM_TYPE_KIND_V_OFFSET: return "wheat";
	case CP_DEM_TYPE_KIND_VIRTUAL_OFFSET_NUMBER: return "wheat";
	case CP_DEM_TYPE_KIND_SEQ_ID: return "wheat";
	case CP_DEM_TYPE_KIND_VALUE_NUMBER: return "wheat";

	// Float related - lightyellow
	case CP_DEM_TYPE_KIND_FLOAT: return "lightyellow";
	case CP_DEM_TYPE_KIND_VALUE_FLOAT: return "lightyellow";
	case CP_DEM_TYPE_KIND_REAL_PART_FLOAT: return "lightyellow";
	case CP_DEM_TYPE_KIND_IMAG_PART_FLOAT: return "lightyellow";

	// Unresolved names - salmon
	case CP_DEM_TYPE_KIND_UNRESOLVED_NAME: return "salmon";
	case CP_DEM_TYPE_KIND_UNRESOLVED_TYPE: return "salmon";
	case CP_DEM_TYPE_KIND_UNRESOLVED_QUALIFIER_LEVEL: return "salmon";
	case CP_DEM_TYPE_KIND_BASE_UNRESOLVED_NAME: return "salmon";
	case CP_DEM_TYPE_KIND_SIMPLE_ID: return "salmon";

	// ABI and special - gold/khaki
	case CP_DEM_TYPE_KIND_CALL_OFFSET: return "khaki";
	case CP_DEM_TYPE_KIND_DISCRIMINATOR: return "khaki";
	case CP_DEM_TYPE_KIND_VENDOR_SPECIFIC_SUFFIX: return "gold";

	// Misc
	case CP_DEM_TYPE_KIND_SUBSTITUTION: return "red";
	case CP_DEM_TYPE_KIND_MANY: return "gold";
	case CP_DEM_TYPE_KIND_ENCODING: return "darkgreen";
	case CP_DEM_TYPE_KIND_BASE_ENCODING: return "darkgreen";
	case CP_DEM_TYPE_KIND_MANGLED_NAME: return "darkgreen";
	case CP_DEM_TYPE_KIND_CLOSURE_TY_NAME: return "violet";
	case CP_DEM_TYPE_KIND_MODULE_NAME: return "khaki";
	case CP_DEM_TYPE_KIND_CLASS_ENUM_TYPE: return "lightblue";
	case CP_DEM_TYPE_KIND_DECLTYPE: return "lightgray";
	case CP_DEM_TYPE_KIND_CONV_OP_TY: return "mediumpurple";
	case CP_DEM_TYPE_KIND_ABI_TAG_TY: return "plum";
	case CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION: return "palegreen";
	case CP_DEM_TYPE_KIND_PARAMETER_PACK: return "paleturquoise";
	case CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION: return "orangered";
	case CP_DEM_TYPE_KIND_EXPANDED_SPECIAL_SUBSTITUTION: return "tomato";

	default: return "white";
	}
}

// Helper function to sanitize filename - replace invalid characters with underscore
static void sanitize_filename(char *str) {
	if (!str) {
		return;
	}
	for (char *p = str; *p; p++) {
		// Replace filesystem-unsafe and problematic characters
		if (*p == '/' || *p == '\\' || *p == ':' || *p == '*' ||
			*p == '?' || *p == '"' || *p == '<' || *p == '>' ||
			*p == '|' || *p == '\n' || *p == '\r' || *p == '\t' ||
			*p == ' ' || *p == '(' || *p == ')' || *p == ',' ||
			*p == '[' || *p == ']' || *p == '{' || *p == '}') {
			*p = '_';
		}
	}
}

void dot_graph_init(DotGraph *dot, PPContext pp_context, const char *mangled_name, const char *demangled_name) {
	if (!dot || !mangled_name) {
		return;
	}

	dot->node_counter = 0;
	dot->enabled = true;
	dot->pp_ctx = pp_context;

	// Build filename: <mangled>-<demangled>.dot (or just <mangled>.dot if no demangled)
	// Maximum filename length is 254 chars (255 bytes including null terminator)

	// Copy and sanitize the mangled name
	char *safe_mangled = strdup(mangled_name);
	if (!safe_mangled) {
		snprintf(dot->filename, sizeof(dot->filename), "demangle.dot");
		dot->enabled = false;
		return;
	}
	sanitize_filename(safe_mangled);

	// Copy and sanitize the demangled name if present
	char *safe_demangled = NULL;
	if (demangled_name && demangled_name[0] != '\0') {
		safe_demangled = strdup(demangled_name);
		if (safe_demangled) {
			sanitize_filename(safe_demangled);
		}
	}

	// Build filename using snprintf, which handles truncation automatically
	// Maximum filename is 255 bytes (including null), so 254 visible chars
	int ret;
	if (safe_demangled) {
		// Try full format first
		ret = snprintf(dot->filename, sizeof(dot->filename), "%s-%s.dot", safe_mangled, safe_demangled);

		// If truncated, use precision specifiers to fit within limit
		// Format: "mangled-demangled.dot" should be <= 254 chars
		// Reserve 5 chars for "-.dot", leaving 249 for the two names
		if (ret >= (int)sizeof(dot->filename)) {
			// Split 249 chars evenly: 124 + 125 = 249
			snprintf(dot->filename, sizeof(dot->filename), "%.124s-%.125s.dot", safe_mangled, safe_demangled);
		}
	} else {
		// Only mangled name: format is "mangled.dot"
		ret = snprintf(dot->filename, sizeof(dot->filename), "%s.dot", safe_mangled);

		// If truncated, limit mangled name to fit
		// Reserve 4 chars for ".dot", leaving 250 for the name
		if (ret >= (int)sizeof(dot->filename)) {
			snprintf(dot->filename, sizeof(dot->filename), "%.250s.dot", safe_mangled);
		}
	}

	free(safe_mangled);
	free(safe_demangled);

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996) // 'fopen': This function or variable may be unsafe
#endif
	dot->file = fopen(dot->filename, "w");
#ifdef _MSC_VER
#pragma warning(pop)
#endif
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

	// Create label with type-specific field information using DemString
	DemString label;
	dem_string_init(&label);
	dem_string_append(&label, type_name);

	// Add node value if present
	if (node->val.buf && node->val.len > 0) {
		const size_t max_len = 256;
		size_t copy_len = node->val.len < max_len ? node->val.len : max_len;
		dem_string_append(&label, "\\n");
		dem_string_append_n(&label, node->val.buf, copy_len);
		if (node->val.len > max_len) {
			dem_string_append(&label, "...");
		}
	}

	// Add ast_pp output to show the pretty-printed representation
	DemString pp_output = { 0 };
	dem_string_init(&pp_output);
	dot->pp_ctx.inside_template = false;
	dot->pp_ctx.paren_depth = 0;
	ast_pp(node, &pp_output, &dot->pp_ctx);
	if (pp_output.buf && pp_output.len > 0) {
		dem_string_append(&label, "\\n=> ");
		// Escape special DOT characters
		for (size_t i = 0; i < pp_output.len; i++) {
			char ch = pp_output.buf[i];
			if (ch == '"' || ch == '\\' || ch == '\n') {
				dem_string_append_n(&label, "\\", 1);
				dem_string_append_n(&label, (ch == '\n') ? "n" : &ch, 1);
			} else if (ch >= 32 && ch < 127) {
				dem_string_append_n(&label, &ch, 1);
			}
		}
	} else {
		dem_string_append(&label, "\\n: <empty>");
	}
	dem_string_deinit(&pp_output);

	// Add field-specific information based on node tag
	switch (node->tag) {
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY:
		if (node->primitive_ty.name.buf) {
			dem_string_append(&label, "\\n");
			dem_string_append(&label, node->primitive_ty.name.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_FUNCTION_TYPE:
		if (node->fn_ty.cv_qualifiers.is_const) {
			dem_string_append(&label, "\\nconst");
		}
		if (node->fn_ty.ref_qualifiers.is_l_value) {
			dem_string_append(&label, "\\n&");
		}
		if (node->fn_ty.ref_qualifiers.is_r_value) {
			dem_string_append(&label, "\\n&&");
		}
		break;

	case CP_DEM_TYPE_KIND_QUALIFIED_TYPE:
		if (node->qualified_ty.qualifiers.is_const) {
			dem_string_append(&label, "\\nconst");
		}
		if (node->qualified_ty.qualifiers.is_volatile) {
			dem_string_append(&label, "\\nvolatile");
		}
		if (node->qualified_ty.qualifiers.is_restrict) {
			dem_string_append(&label, "\\nrestrict");
		}
		break;

	case CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE:
		if (node->vendor_ext_qualified_ty.vendor_ext.buf) {
			dem_string_append(&label, "\\n");
			dem_string_append(&label, node->vendor_ext_qualified_ty.vendor_ext.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_MANY:
		if (node->many_ty.sep) {
			dem_string_append(&label, "\\nsep: ");
			dem_string_append(&label, node->many_ty.sep);
		}
		if (node->children) {
			char buf[32];
			snprintf(buf, sizeof(buf), "\\nchildren: %zu", VecPDemNode_len(node->children));
			dem_string_append(&label, buf);
		}
		break;

	case CP_DEM_TYPE_KIND_CLOSURE_TY_NAME:
		if (node->closure_ty_name.count.buf && node->closure_ty_name.count.len > 0) {
			dem_string_append(&label, "\\ncount: ");
			dem_string_append_n(&label, node->closure_ty_name.count.buf, node->closure_ty_name.count.len);
		}
		break;

	case CP_DEM_TYPE_KIND_MODULE_NAME:
		if (node->module_name_ty.IsPartition) {
			dem_string_append(&label, "\\npartition");
		}
		break;

	case CP_DEM_TYPE_KIND_ABI_TAG_TY:
		if (node->abi_tag_ty.tag.buf && node->abi_tag_ty.tag.len > 0) {
			dem_string_append(&label, "\\ntag: ");
			dem_string_append_n(&label, node->abi_tag_ty.tag.buf, node->abi_tag_ty.tag.len);
		}
		break;

	case CP_DEM_TYPE_KIND_MEMBER_EXPRESSION:
		if (node->member_expr.op.buf && node->member_expr.op.len > 0) {
			dem_string_append(&label, "\\nop: ");
			dem_string_append_n(&label, node->member_expr.op.buf, node->member_expr.op.len);
		}
		break;

	default:
		break;
	}

	// Write node to DOT file
	fprintf(dot->file, "\tnode%d [shape=%s, style=filled, fillcolor=%s, label=\"%s\"];\n",
		node_id, shape, color, label.buf ? label.buf : "");

	dem_string_deinit(&label);
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
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY:
		// Primitive types have no additional fields to traverse
		break;

	case CP_DEM_TYPE_KIND_INTEGER_LITERAL:
		// Integer literals have only DemStringView fields (type, value), no child nodes
		break;

	case CP_DEM_TYPE_KIND_FUNCTION_TYPE:
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

	case CP_DEM_TYPE_KIND_QUALIFIED_TYPE:
		if (node->qualified_ty.inner_type) {
			dot_graph_traverse_ast(dot, node->qualified_ty.inner_type, current_id, "inner_type", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE:
		if (node->vendor_ext_qualified_ty.inner_type) {
			dot_graph_traverse_ast(dot, node->vendor_ext_qualified_ty.inner_type, current_id, "inner_type", "solid");
		}
		if (node->vendor_ext_qualified_ty.template_args) {
			dot_graph_traverse_ast(dot, node->vendor_ext_qualified_ty.template_args, current_id, "template_args", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_CLOSURE_TY_NAME:
		if (node->closure_ty_name.template_params) {
			dot_graph_traverse_ast(dot, node->closure_ty_name.template_params, current_id, "template_params", "solid");
		}
		if (node->closure_ty_name.params) {
			dot_graph_traverse_ast(dot, node->closure_ty_name.params, current_id, "params", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_MODULE_NAME:
		if (node->module_name_ty.pare) {
			dot_graph_traverse_ast(dot, node->module_name_ty.pare, current_id, "parent", "solid");
		}
		if (node->module_name_ty.name) {
			dot_graph_traverse_ast(dot, node->module_name_ty.name, current_id, "name", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS:
		if (node->name_with_template_args.name) {
			dot_graph_traverse_ast(dot, node->name_with_template_args.name, current_id, "name", "solid");
		}
		if (node->name_with_template_args.template_args) {
			dot_graph_traverse_ast(dot, node->name_with_template_args.template_args, current_id, "template_args", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_NESTED_NAME:
		if (node->nested_name.qual) {
			dot_graph_traverse_ast(dot, node->nested_name.qual, current_id, "qualifier", "solid");
		}
		if (node->nested_name.name) {
			dot_graph_traverse_ast(dot, node->nested_name.name, current_id, "name", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_LOCAL_NAME:
		if (node->local_name.encoding) {
			dot_graph_traverse_ast(dot, node->local_name.encoding, current_id, "encoding", "solid");
		}
		if (node->local_name.entry) {
			dot_graph_traverse_ast(dot, node->local_name.entry, current_id, "entry", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_CTOR_DTOR_NAME:
		if (node->ctor_dtor_name.name) {
			dot_graph_traverse_ast(dot, node->ctor_dtor_name.name, current_id, "name", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_CONV_OP_TY:
		if (node->conv_op_ty.ty) {
			dot_graph_traverse_ast(dot, node->conv_op_ty.ty, current_id, "type", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_TEMPLATE_ARGS:
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK:
	case CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION:
	case CP_DEM_TYPE_KIND_NOEXCEPT_SPEC:
	case CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC:
		// These types use child pointer
		if (node->child) {
			dot_graph_traverse_ast(dot, node->child, current_id, "child", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_PARAMETER_PACK:
		// parameter_pack uses child_ref (const pointer to many node)
		if (node->child_ref) {
			dot_graph_traverse_ast(dot, (DemNode *)node->child_ref, current_id, "pack_ref", "dashed");
		}
		break;

	case CP_DEM_TYPE_KIND_ABI_TAG_TY:
		if (node->abi_tag_ty.ty) {
			dot_graph_traverse_ast(dot, node->abi_tag_ty.ty, current_id, "type", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_VECTOR_TYPE:
	case CP_DEM_TYPE_KIND_ARRAY_TYPE:
		if (node->array_ty.inner_ty) {
			dot_graph_traverse_ast(dot, node->array_ty.inner_ty, current_id, "inner_type", "solid");
		}
		if (node->array_ty.dimension) {
			dot_graph_traverse_ast(dot, node->array_ty.dimension, current_id, "dimension", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_MEMBER_EXPRESSION:
		if (node->member_expr.lhs) {
			dot_graph_traverse_ast(dot, node->member_expr.lhs, current_id, "lhs", "solid");
		}
		if (node->member_expr.rhs) {
			dot_graph_traverse_ast(dot, node->member_expr.rhs, current_id, "rhs", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_FOLD_EXPRESSION:
		if (node->fold_expr.pack) {
			dot_graph_traverse_ast(dot, node->fold_expr.pack, current_id, "pack", "solid");
		}
		if (node->fold_expr.init) {
			dot_graph_traverse_ast(dot, node->fold_expr.init, current_id, "init", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_BRACED_EXPRESSION:
		if (node->braced_expr.elem) {
			dot_graph_traverse_ast(dot, node->braced_expr.elem, current_id, "elem", "solid");
		}
		if (node->braced_expr.init) {
			dot_graph_traverse_ast(dot, node->braced_expr.init, current_id, "init", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION:
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

	case CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION:
		if (node->init_list_expr.ty) {
			dot_graph_traverse_ast(dot, node->init_list_expr.ty, current_id, "ty", "solid");
		}
		if (node->init_list_expr.inits) {
			dot_graph_traverse_ast(dot, node->init_list_expr.inits, current_id, "inits", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_BINARY_EXPRESSION:
		if (node->binary_expr.lhs) {
			dot_graph_traverse_ast(dot, node->binary_expr.lhs, current_id, "lhs", "solid");
		}
		if (node->binary_expr.rhs) {
			dot_graph_traverse_ast(dot, node->binary_expr.rhs, current_id, "rhs", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_PREFIX_EXPRESSION:
		if (node->prefix_expr.inner) {
			dot_graph_traverse_ast(dot, node->prefix_expr.inner, current_id, "inner", "solid");
		}
		break;

	case CP_DEM_TYPE_KIND_NEW_EXPRESSION:
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

	case CP_DEM_TYPE_KIND_MANY:
		// This type uses the generic children vector
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

	case CP_DEM_TYPE_KIND_FWD_TEMPLATE_REF:
		// Forward template reference: traverse fwd->ref as its child
		if (node->fwd_template_ref && node->fwd_template_ref->ref) {
			DemNode *ref_node = (DemNode *)node->fwd_template_ref->ref;
			dot_graph_traverse_ast(dot, ref_node, current_id, "ref", "dashed");
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

	// Only convert to SVG if DEMANGLE_TRACE_SVG environment variable is set
	if (getenv("DEMANGLE_TRACE_SVG")) {
		// Filename is guaranteed to be <= 255 chars by dot_graph_init()
		// Command format: "dot -Tsvg -O \"<filename>\" 2>/dev/null"
		// Max length: 30 + 255 = 285 bytes (well within safe limits)
		char cmd[512];
		snprintf(cmd, sizeof(cmd), "dot -Tsvg -O \"%s\" 2>/dev/null", dot->filename);

		fprintf(stderr, "[DOT] Converting to SVG...\n");
		int ret = system(cmd);

		if (ret == 0) {
			fprintf(stderr, "[DOT] Successfully converted to: %s.svg\n", dot->filename);
		} else {
			fprintf(stderr, "[DOT] Failed to convert to SVG (is 'dot' installed?)\n");
			fprintf(stderr, "[DOT] Manual conversion: dot -Tsvg -O \"%s\"\n", dot->filename);
		}
	} else {
		fprintf(stderr, "[DOT] SVG conversion skipped (set DEMANGLE_TRACE_SVG=1 to enable)\n");
	}
}

void dot_graph_cleanup(DotGraph *dot) {
	if (!dot) {
		return;
	}

	if (dot->file) {
		fclose(dot->file);
	}

	// filename is now a stack array, no need to free
	dot->filename[0] = '\0';

	dot->file = NULL;
	dot->enabled = false;
}