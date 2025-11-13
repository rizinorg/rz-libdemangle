// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_TYPES_H
#define V3_IMPL_TYPES_H

#include "../../demangler_util.h"
#include "../vec.h"
#include "macros.h"

#define DBG_PRINT_DETECTED_TYPES   0
#define DBG_PRINT_DETECTED_TPARAMS 0

#define REPLACE_GLOBAL_N_WITH_ANON_NAMESPACE 1

/**
 * \b String iterator
 **/
typedef struct StrIter {
    const char* beg; /**< \b Beginning position of string. */
    const char* end; /**< \b Ending of string (usually points to the null-terminator char). */
    const char* cur; /**< \b Current read position. */
} StrIter;

typedef struct Name {
    DemString name;
    ut32      num_parts; // if part count greater than 1 then a nested name
} Name;

typedef Vec (Name) Names;

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

enum CpDemTypeKind_t;
typedef Vec (enum CpDemTypeKind_t) CpDemTypeKinds;

typedef struct Meta {
    Names detected_types;
    Names template_params;
    bool  is_ctor;
    bool  is_dtor;
    bool  is_const;
    bool  trace; // Debug tracing flag (now just for compatibility)

    // detected templates are reset everytime a new template argument list starts at the same level
    // instead of taking care of that, we just rebase from where we start our substitution
    // this way we just keep adding templates and incrementing this idx_start on every reset
    // so a T_ (index = 0) can actually refer to index = 5
    int template_idx_start;
    int last_reset_idx;

    // template level, detects the depth of RULE(template_args) expansion
    // if we expand above level 1 (starts at level 1), then we stop appending parameters to template
    // parameter list
    int  t_level;
    bool template_reset;

    bool is_ctor_or_dtor_at_l0;
   CpDemTypeKinds parent_type_kinds;
} Meta;

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
typedef DemString* (*DemRule) (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
);

typedef bool (*DemRuleFirst) (const char* input);

/* TODO: what to do with this? */
typedef enum CpDemOptions {
    x,
    y
} CpDemOptions;

// Meta helper functions
bool meta_tmp_init (Meta* og, Meta* tmp);
void meta_tmp_apply (Meta* og, Meta* tmp);
void meta_tmp_fini (Meta* og, Meta* tmp);

// Helper functions
size_t     parse_sequence_id (StrIter* msi, Meta* m);
bool       append_type (Meta* m, DemString* t, bool force_append);
bool       append_tparam (Meta* m, DemString* t);
DemString* match_one_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
);
DemString* match_zero_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
);

// Graphviz trace helper functions
void trace_graph_init (TraceGraph* graph);
int  trace_graph_add_node (
     TraceGraph* graph,
     const char* rule_name,
     size_t      pos,
     const char* input,
     int         parent_id
 );
void trace_graph_set_result_impl (TraceGraph* graph, int node_id, size_t pos, const char* result, int status);
void trace_graph_mark_final_path (TraceGraph* graph);

void trace_graph_output_dot (TraceGraph* graph, const char* filename, Meta* meta);
void trace_graph_cleanup (TraceGraph* graph);

typedef enum CpDemTypeKind_t {
    CP_DEM_TYPE_KIND_mangled_name,
    CP_DEM_TYPE_KIND_encoding,
    CP_DEM_TYPE_KIND_name,
    CP_DEM_TYPE_KIND_unscoped_name,
    CP_DEM_TYPE_KIND_nested_name,
    CP_DEM_TYPE_KIND_cv_qualifiers,
    CP_DEM_TYPE_KIND_ref_qualifier,
    CP_DEM_TYPE_KIND_prefix,
    CP_DEM_TYPE_KIND_template_param,
    CP_DEM_TYPE_KIND_decltype,
    CP_DEM_TYPE_KIND_template_prefix,
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
    CP_DEM_TYPE_KIND_prefix_or_template_prefix_start,
    CP_DEM_TYPE_KIND_prefix_start_unit,
    CP_DEM_TYPE_KIND_prefix_start_rr,
    CP_DEM_TYPE_KIND_prefix_start,
    CP_DEM_TYPE_KIND_prefix_nested_class_or_namespace,
    CP_DEM_TYPE_KIND_closure_prefix_unit,
    CP_DEM_TYPE_KIND_closure_prefix_rr,
    CP_DEM_TYPE_KIND_closure_prefix,
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

// Rule declarations
DECL_RULE (mangled_name);
DECL_RULE (encoding);
DECL_RULE (name);
DECL_RULE (unscoped_name);
DECL_RULE (nested_name);
DECL_RULE (cv_qualifiers);
DECL_RULE (ref_qualifier);
DECL_RULE (prefix);
DECL_RULE (template_param);
DECL_RULE (decltype);
DECL_RULE (template_prefix);
DECL_RULE (unqualified_name);
DECL_RULE (ctor_name);
DECL_RULE (dtor_name);
DECL_RULE (ctor_dtor_name);
DECL_RULE (source_name);
DECL_RULE (number);
DECL_RULE (unnamed_type_name);
DECL_RULE (abi_tag);
DECL_RULE (abi_tags);
DECL_RULE (operator_name);
DECL_RULE (type);
DECL_RULE (builtin_type);
DECL_RULE (expression);
DECL_RULE (unresolved_name);
DECL_RULE (function_param);
DECL_RULE (expr_primary);
DECL_RULE (float);
DECL_RULE (initializer);
DECL_RULE (braced_expression);
DECL_RULE (base_unresolved_name);
DECL_RULE (simple_id);
DECL_RULE (destructor_name);
DECL_RULE (unresolved_type);
DECL_RULE (unresolved_qualifier_level);
DECL_RULE (qualified_type);
DECL_RULE (qualifiers);
DECL_RULE (extended_qualifier);
DECL_RULE (function_type);
DECL_RULE (exception_spec);
DECL_RULE (class_enum_type);
DECL_RULE (array_type);
DECL_RULE (pointer_to_member_type);
DECL_RULE (template_template_param);
DECL_RULE (digit);
DECL_RULE (template_args);
DECL_RULE (template_arg);
DECL_RULE (substitution);
DECL_RULE (seq_id);
DECL_RULE (local_name);
DECL_RULE (discriminator);
DECL_RULE (vendor_specific_suffix);
DECL_RULE (special_name);
DECL_RULE (call_offset);
DECL_RULE (nv_offset);
DECL_RULE (v_offset);
DECL_RULE (bare_function_type);

// Helper rules for new grammar implementation
DECL_RULE (prefix_or_template_prefix_start);
DECL_RULE (prefix_start_unit);
DECL_RULE (prefix_start_rr);
DECL_RULE (prefix_start);
DECL_RULE (prefix_nested_class_or_namespace);
DECL_RULE (closure_prefix_unit);
DECL_RULE (closure_prefix_rr);
DECL_RULE (closure_prefix);

DECL_RULE (unscoped_template_name);

// Rule aliases
DECL_RULE_ALIAS (top_level_cv_qualifiers, cv_qualifiers);
DECL_RULE_ALIAS (non_negative_number, number);
DECL_RULE_ALIAS (value_number, number);
DECL_RULE_ALIAS (value_float, float);
DECL_RULE_ALIAS (string_type, type);
DECL_RULE_ALIAS (pointer_type, type);
DECL_RULE_ALIAS (real_part_float, float);
DECL_RULE_ALIAS (imag_part_float, float);
DECL_RULE_ALIAS (field_source_name, source_name);
DECL_RULE_ALIAS (index_expression, expression);
DECL_RULE_ALIAS (range_begin_expression, expression);
DECL_RULE_ALIAS (range_end_expression, expression);
DECL_RULE_ALIAS (instantiation_dependent_expression, expression);
DECL_RULE_ALIAS (element_type, type);
DECL_RULE_ALIAS (instantiation_dependent_array_bound_expression, expression);
DECL_RULE_ALIAS (array_bound_number, number);
DECL_RULE_ALIAS (class_type, type);
DECL_RULE_ALIAS (function_encoding, encoding);
DECL_RULE_ALIAS (entity_name, name);
DECL_RULE_ALIAS (base_encoding, encoding);
DECL_RULE_ALIAS (offset_number, number);
DECL_RULE_ALIAS (virtual_offset_number, number);
DECL_RULE_ALIAS (function_name, name);
DECL_RULE_ALIAS (data_name, name);
DECL_RULE_ALIAS (signature_type, type);


#endif // V3_IMPL_TYPES_H
