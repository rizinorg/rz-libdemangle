// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_TYPES_H
#define V3_IMPL_TYPES_H

#include "../demangler_util.h"
#include "demangle.h"
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
	CP_DEM_TYPE_KIND_primitive_ty,
	CP_DEM_TYPE_KIND_mangled_name,
	CP_DEM_TYPE_KIND_encoding,
	CP_DEM_TYPE_KIND_name,
	CP_DEM_TYPE_KIND_unscoped_name,
	CP_DEM_TYPE_KIND_nested_name,
	CP_DEM_TYPE_KIND_cv_qualifiers,
	CP_DEM_TYPE_KIND_ref_qualifier,
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
	CP_DEM_TYPE_KIND_fold_expression,
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
	CP_DEM_TYPE_KIND_vendor_ext_qualified_type,
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
	CP_DEM_TYPE_KIND_template_param_decl,
	CP_DEM_TYPE_KIND_non_neg_number,
	CP_DEM_TYPE_KIND_fwd_template_ref,
	CP_DEM_TYPE_KIND_many,
	CP_DEM_TYPE_KIND_module_name,
	CP_DEM_TYPE_KIND_name_with_template_args,
	CP_DEM_TYPE_KIND_closure_ty_name,
} CpDemTypeKind;

typedef Vec(CpDemTypeKind) CpDemTypeKinds;

typedef struct {
	const char *buf;
	size_t len;
} DemStringView;

struct Vec_t(DemNode);

enum {
	INVALID_TYPE,
	POINTER_TYPE,
	REFERENCE_TYPE,
	RVALUE_REFERENCE_TYPE,
	QUALIFIED_TYPE,
	ARRAY_TYPE,
	TEMPLATE_PARAMETER_PACK,
};

struct DemNode_t;

// Forward template reference: stores a reference to T_ that needs resolution later
typedef struct ForwardTemplateRef {
	struct DemNode_t *node; // The AST node
	ut64 level; // Template parameter level
	ut64 index; // Template parameter index
} ForwardTemplateRef;

typedef ForwardTemplateRef *PForwardTemplateRef;

typedef struct DemNode_t *PDemNode;

typedef struct {
	DemString name;
} PrimitiveTy;

typedef struct {
	const char *sep; // Separator string (e.g., ", " for parameters)
} ManyTy;

typedef struct {
	bool is_const : 1;
	bool is_volatile : 1;
	bool is_restrict : 1;
} CvQualifiers;

typedef struct {
	bool is_l_value : 1;
	bool is_r_value : 1;
} RefQualifiers;

typedef struct {
	PDemNode params; // Points to a node with tag=many containing parameter nodes
	PDemNode ret;
	PDemNode name;
	PDemNode requires_node;
	PDemNode exception_spec;
	CvQualifiers cv_qualifiers;
	RefQualifiers ref_qualifiers;
} FunctionTy;

typedef struct {
	PDemNode inner_type; // The type being qualified (e.g., "QString")
	CvQualifiers qualifiers; // The CV qualifiers (const, volatile, restrict)
} QualifiedTy;

typedef struct {
	PDemNode inner_type; // The type being qualified (e.g., "QString")
	DemStringView vendor_ext;
	PDemNode template_args; // Template arguments node
} VendorExtQualifiedTy;

typedef struct {
	bool IsPartition;
	PDemNode name;
	PDemNode pare;
} ModuleNameTy;

typedef struct {
	PDemNode name;
	PDemNode template_args;
} NameWithTemplateArgs;

typedef struct {
	PDemNode template_params;
	PDemNode params;
	DemStringView count;
} ClosureTyName;

typedef struct DemNode_t {
	struct DemNode_t *parent;
	DemStringView val;
	CpDemTypeKind tag;
	ut32 subtag;
	struct Vec_t(PDemNode) * children; // Moved outside union, used by all types

	union {
		PForwardTemplateRef fwd_template_ref;
		PrimitiveTy primitive_ty;
		QualifiedTy qualified_ty;
		VendorExtQualifiedTy vendor_ext_qualified_ty;
		FunctionTy fn_ty;
		ManyTy many_ty;
		ModuleNameTy module_name_ty;
		NameWithTemplateArgs name_with_template_args;
		ClosureTyName closure_ty_name;
	};
} DemNode;

DemNode *DemNode_new();
DemNode *DemNode_ctor_inplace(DemNode *asm_node, CpDemTypeKind tag, const char *val_begin, size_t val_len);
DemNode *DemNode_ctor(CpDemTypeKind tag, const char *val_begin, size_t val_len);
void DemNode_dtor(DemNode *dan);
bool DemNode_init(DemNode *dan);
void DemNode_deinit(DemNode *dan);
bool DemNode_is_empty(DemNode *x);
void DemNode_copy(DemNode *dst, const DemNode *src);
void DemNode_move(DemNode *dst, DemNode *src);
void DemNode_init_clone(DemNode *dst, const DemNode *src);
DemNode *DemNode_clone(const DemNode *src);
#define DemNode_non_empty(X) (!DemNode_is_empty(X))

DemNode *make_primitive_type_inplace(DemNode *x, const char *begin, const char *end, const char *name, size_t name_len);
DemNode *make_primitive_type(const char *begin, const char *end, const char *name, size_t name_len);
DemNode *make_name_with_template_args(const char *begin, const char *end, DemNode *name_node, DemNode *template_args_node);

static inline void PDemNode_free(void *ptr) {
	if (ptr) {
		DemNode *node = *(DemNode **)ptr;
		if (node) {
			DemNode_dtor(node);
		}
	}
}

VecIMPL(PDemNode, PDemNode_free);

typedef VecT(PDemNode) NodeList;
void NodeList_copy(NodeList *dst, const NodeList *src);

static inline void PNodeList_free(void *self) {
}

typedef NodeList *PNodeList;
VecIMPL(PNodeList, PNodeList_free);

static inline void ForwardTemplateRef_free(void *ref) {
	(void)ref; // Node is owned by AST, don't free
}

VecIMPL(PForwardTemplateRef, ForwardTemplateRef_free);

/**
 * Parser context that deeply contains string iterator, metadata, and trace graph.
 * This is the main context passed to all rule functions.
 */
typedef struct DemParser {
	const char *beg;
	const char *end;
	const char *cur;

	NodeList detected_types;
	NodeList names;
	PNodeList outer_template_params;
	VecT(PNodeList) template_params;
	VecT(PForwardTemplateRef) forward_template_refs;
	bool is_ctor;
	bool is_dtor;
	bool is_conversion_operator;
	bool not_parse_template_args;
	bool pack_expansion;
	bool trace;
} DemParser;

/**
 * Error codes for parsing failures
 */
typedef enum DemErrorCode {
	DEM_ERR_OK = 0,
	DEM_ERR_UNEXPECTED_END,
	DEM_ERR_OUT_OF_MEMORY,
	DEM_ERR_INVALID_SYNTAX,
	DEM_ERR_UNKNOWN
} DemErrorCode;

/**
 * Result of a parsing rule.
 * Contains either the output node (on success) or error code (on failure).
 */
typedef struct DemResult {
	DemNode *output; /**< Output node (allocated on success) */
	DemErrorCode error; /**< Error code (on failure) */
} DemResult;

typedef struct {
	DemParser parser;
	DemResult result;
	DemString output;
} DemContext;

void DemContext_deinit(DemContext *ctx);

/**
 * Type of rules.
 * @param p Parser context
 * @param parent Parent node (read-only, can be NULL for root)
 * @param r Result structure to fill
 * @return true on success (r->output set), false on failure (r->error may be set)
 */
typedef bool (*DemRule)(DemParser *p, const DemNode *parent, DemResult *r);

// DemParser helper functions
void DemParser_init(DemParser *p, const char *input);
void DemParser_deinit(DemParser *p);
void DemResult_deinit(DemResult *r);
bool parse_rule(DemContext *ctx, const char *mangled, DemRule rule, CpDemOptions opts);

// Helper functions
bool append_type(DemParser *p, const DemNode *x);
DemNode *substitute_get(DemParser *p, ut64 id);
DemNode *template_param_get(DemParser *p, ut64 level, ut64 index);
bool resolve_forward_template_refs(DemParser *p, DemNode *dan);

#endif // V3_IMPL_TYPES_H
