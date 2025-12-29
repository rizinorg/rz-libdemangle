// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_TYPES_H
#define V3_IMPL_TYPES_H

#include "../demangler_util.h"
#include "macros.h"
#include "trace_graph.h"
#include "vec.h"

#define DBG_PRINT_DETECTED_TYPES   0
#define DBG_PRINT_DETECTED_TPARAMS 0

/**
 * \b String iterator
 **/
typedef struct StrIter {
	const char *beg; /**< \b Beginning position of string. */
	const char *end; /**< \b Ending of string (usually points to the null-terminator char). */
	const char *cur; /**< \b Current read position. */
} StrIter;

typedef enum CpDemTypeKind_t {
	CP_DEM_TYPE_KIND_unknown,
	CP_DEM_TYPE_KIND_mangled_name,
	CP_DEM_TYPE_KIND_encoding,
	CP_DEM_TYPE_KIND_name,
	CP_DEM_TYPE_KIND_unscoped_name,
	CP_DEM_TYPE_KIND_nested_name,
	CP_DEM_TYPE_KIND_cv_qualifiers,
	CP_DEM_TYPE_KIND_ref_qualifier,
	CP_DEM_TYPE_KIND_prefix,
	CP_DEM_TYPE_KIND_prefix_start,
	CP_DEM_TYPE_KIND_prefix_suffix,
	CP_DEM_TYPE_KIND_prefix_tail,
	CP_DEM_TYPE_KIND_closure_prefix,
	CP_DEM_TYPE_KIND_template_prefix,
	CP_DEM_TYPE_KIND_template_param,
	CP_DEM_TYPE_KIND_decltype,
	CP_DEM_TYPE_KIND_unqualified_name,
	CP_DEM_TYPE_KIND_ctor_name,
	CP_DEM_TYPE_KIND_dtor_name,
	CP_DEM_TYPE_KIND_ctor_dtor_name,
	CP_DEM_TYPE_KIND_source_name,
	CP_DEM_TYPE_KIND_number,
	CP_DEM_TYPE_KIND_unnamed_type_name,
	CP_DEM_TYPE_KIND_abi_tag,
	CP_DEM_TYPE_KIND_abi_tags,
	CP_DEM_TYPE_KIND_operator_name,
	CP_DEM_TYPE_KIND_type,
	CP_DEM_TYPE_KIND_builtin_type,
	CP_DEM_TYPE_KIND_expression,
	CP_DEM_TYPE_KIND_unresolved_name,
	CP_DEM_TYPE_KIND_function_param,
	CP_DEM_TYPE_KIND_expr_primary,
	CP_DEM_TYPE_KIND_float,
	CP_DEM_TYPE_KIND_initializer,
	CP_DEM_TYPE_KIND_braced_expression,
	CP_DEM_TYPE_KIND_base_unresolved_name,
	CP_DEM_TYPE_KIND_simple_id,
	CP_DEM_TYPE_KIND_destructor_name,
	CP_DEM_TYPE_KIND_unresolved_type,
	CP_DEM_TYPE_KIND_unresolved_qualifier_level,
	CP_DEM_TYPE_KIND_qualified_type,
	CP_DEM_TYPE_KIND_qualifiers,
	CP_DEM_TYPE_KIND_extended_qualifier,
	CP_DEM_TYPE_KIND_function_type,
	CP_DEM_TYPE_KIND_exception_spec,
	CP_DEM_TYPE_KIND_class_enum_type,
	CP_DEM_TYPE_KIND_array_type,
	CP_DEM_TYPE_KIND_pointer_to_member_type,
	CP_DEM_TYPE_KIND_template_template_param,
	CP_DEM_TYPE_KIND_digit,
	CP_DEM_TYPE_KIND_template_args,
	CP_DEM_TYPE_KIND_template_arg,
	CP_DEM_TYPE_KIND_substitution,
	CP_DEM_TYPE_KIND_seq_id,
	CP_DEM_TYPE_KIND_local_name,
	CP_DEM_TYPE_KIND_discriminator,
	CP_DEM_TYPE_KIND_vendor_specific_suffix,
	CP_DEM_TYPE_KIND_special_name,
	CP_DEM_TYPE_KIND_call_offset,
	CP_DEM_TYPE_KIND_nv_offset,
	CP_DEM_TYPE_KIND_v_offset,
	CP_DEM_TYPE_KIND_bare_function_type,
	CP_DEM_TYPE_KIND_unscoped_template_name,
	CP_DEM_TYPE_KIND_top_level_cv_qualifiers,
	CP_DEM_TYPE_KIND_non_negative_number,
	CP_DEM_TYPE_KIND_value_number,
	CP_DEM_TYPE_KIND_value_float,
	CP_DEM_TYPE_KIND_string_type,
	CP_DEM_TYPE_KIND_pointer_type,
	CP_DEM_TYPE_KIND_real_part_float,
	CP_DEM_TYPE_KIND_imag_part_float,
	CP_DEM_TYPE_KIND_field_source_name,
	CP_DEM_TYPE_KIND_index_expression,
	CP_DEM_TYPE_KIND_range_begin_expression,
	CP_DEM_TYPE_KIND_range_end_expression,
	CP_DEM_TYPE_KIND_instantiation_dependent_expression,
	CP_DEM_TYPE_KIND_element_type,
	CP_DEM_TYPE_KIND_instantiation_dependent_array_bound_expression,
	CP_DEM_TYPE_KIND_array_bound_number,
	CP_DEM_TYPE_KIND_class_type,
	CP_DEM_TYPE_KIND_function_encoding,
	CP_DEM_TYPE_KIND_entity_name,
	CP_DEM_TYPE_KIND_base_encoding,
	CP_DEM_TYPE_KIND_offset_number,
	CP_DEM_TYPE_KIND_virtual_offset_number,
	CP_DEM_TYPE_KIND_function_name,
	CP_DEM_TYPE_KIND_data_name,
	CP_DEM_TYPE_KIND_signature_type,
	CP_DEM_TYPE_KIND_nested_name_with_substitution_only,
	CP_DEM_TYPE_KIND_nv_digit,
	CP_DEM_TYPE_KIND_non_neg_number,
} CpDemTypeKind;

typedef Vec(CpDemTypeKind) CpDemTypeKinds;

typedef struct {
	const char *buf;
	size_t len;
} DemStringView;

struct Vec_t(DemAstNode);

typedef struct DemAstNode_t {
	struct Vec_t(DemAstNode) * children;
	DemString dem;
	DemStringView val;
	CpDemTypeKind tag;
} DemAstNode;

DemAstNode* DemAstNode_new();
DemAstNode *DemAstNode_ctor(DemString *dem, DemStringView *val, CpDemTypeKind tag);
void DemAstNode_dtor(DemAstNode *dan);
bool DemAstNode_init(DemAstNode *dan);
void DemAstNode_deinit(DemAstNode *dan);
DemAstNode *DemAstNode_append(DemAstNode *xs, DemAstNode *x);
DemAstNode *DemAstNode_children_at(DemAstNode *xs, size_t idx);
bool DemAstNode_is_empty(DemAstNode *x);
void DemAstNode_copy(DemAstNode *dst, const DemAstNode *src);
void DemAstNode_init_clone(DemAstNode *dst, const DemAstNode *src);
#define DemAstNode_non_empty(X) (!DemAstNode_is_empty(X))

VecIMPL(DemAstNode, DemAstNode_deinit);

typedef struct Name {
	DemString name;
	ut32 num_parts; // if part count greater than 1 then a nested name
} Name;

void name_deinit(Name *x);

VecIMPL(Name, name_deinit);

typedef struct Meta {
	VecT(DemAstNode) detected_types;
	VecT(Name) template_params;
	bool is_ctor;
	bool is_dtor;
	bool is_const;
	bool trace; // Debug tracing flag (now just for compatibility)

	// detected templates are reset everytime a new template argument list starts at the same level
	// instead of taking care of that, we just rebase from where we start our substitution
	// this way we just keep adding templates and incrementing this idx_start on every reset
	// so a T_ (index = 0) can actually refer to index = 5
	int template_idx_start;
	int last_reset_idx;

	// Index of the prefix entry in detected_types that prefix_tail should append to
	// This is set before entering prefix parsing and used by prefix_tail
	ut64 prefix_base_idx;

	// Current prefix string that prefix_tail should use when building full paths
	// This is needed when the base is a special substitution like "std" which is not
	// added to the substitution table
	DemAstNode current_prefix;

	// template level, detects the depth of RULE(template_args) expansion
	// if we expand above level 1 (starts at level 1), then we stop appending parameters to template
	// parameter list
	int t_level;
	bool template_reset;

	bool is_ctor_or_dtor_at_l0;
} Meta;

struct TraceGraph;

/**
 * Type of rules.
 *
 * \p dem Demangled string.
 * \p msi Mangled string iter.
 * \p m   Meta context.
 * \p graph Trace graph for debugging.
 * \p parent_node_id Parent node ID in the trace graph (-1 for root).
 *
 * \return dem on success.
 * \return NULL otherwise.
 */
typedef bool (*DemRule)(
	DemAstNode *ast_node,
	StrIter *msi,
	Meta *m,
	struct TraceGraph *graph,
	int parent_node_id);

typedef bool (*DemRuleFirst)(const char *input);

// Meta helper functions
bool meta_copy(Meta *dst, Meta *src);
void meta_move(Meta *dst, Meta *src);
void meta_deinit(Meta *m);

// Helper functions
size_t parse_sequence_id(StrIter *msi, Meta *m);
bool append_type(Meta *m, const DemAstNode *x, bool force_append);
bool append_tparam(Meta *m, DemString *t);
bool meta_substitute_type(Meta *m, ut64 id, DemString *dem);
bool meta_substitute_tparam(Meta *m, ut64 id, DemString *dem);
st64 find_type_index(Meta *m, const char *type_str);

ut32 count_name_parts(const DemString *x);
bool is_builtin_type(const char *t);

#endif // V3_IMPL_TYPES_H
