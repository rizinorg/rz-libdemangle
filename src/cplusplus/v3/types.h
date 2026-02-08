// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_TYPES_H
#define V3_IMPL_TYPES_H

#include "../../demangler_util.h"
#include "../demangle.h"
#include "../vec.h"

typedef enum CpDemTypeKind_t {
	CP_DEM_TYPE_KIND_UNKNOWN,
	CP_DEM_TYPE_KIND_PRIMITIVE_TY,
	CP_DEM_TYPE_KIND_MANGLED_NAME,
	CP_DEM_TYPE_KIND_ENCODING,
	CP_DEM_TYPE_KIND_NAME,
	CP_DEM_TYPE_KIND_UNSCOPED_NAME,
	CP_DEM_TYPE_KIND_NESTED_NAME,
	CP_DEM_TYPE_KIND_TEMPLATE_PARAM,
	CP_DEM_TYPE_KIND_DECLTYPE,
	CP_DEM_TYPE_KIND_UNQUALIFIED_NAME,
	CP_DEM_TYPE_KIND_CTOR_NAME,
	CP_DEM_TYPE_KIND_DTOR_NAME,
	CP_DEM_TYPE_KIND_CTOR_DTOR_NAME,
	CP_DEM_TYPE_KIND_SOURCE_NAME,
	CP_DEM_TYPE_KIND_NUMBER,
	CP_DEM_TYPE_KIND_UNNAMED_TYPE_NAME,
	CP_DEM_TYPE_KIND_OPERATOR_NAME,
	CP_DEM_TYPE_KIND_TYPE,
	CP_DEM_TYPE_KIND_BUILTIN_TYPE,
	CP_DEM_TYPE_KIND_EXPRESSION,
	CP_DEM_TYPE_KIND_FOLD_EXPRESSION,
	CP_DEM_TYPE_KIND_BRACED_EXPRESSION,
	CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION,
	CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION,
	CP_DEM_TYPE_KIND_PREFIX_EXPRESSION,
	CP_DEM_TYPE_KIND_BINARY_EXPRESSION,
	CP_DEM_TYPE_KIND_MEMBER_EXPRESSION,
	CP_DEM_TYPE_KIND_NEW_EXPRESSION,

	CP_DEM_TYPE_KIND_UNRESOLVED_NAME,
	CP_DEM_TYPE_KIND_FUNCTION_PARAM,
	CP_DEM_TYPE_KIND_EXPR_PRIMARY,
	CP_DEM_TYPE_KIND_INTEGER_LITERAL,
	CP_DEM_TYPE_KIND_FLOAT,
	CP_DEM_TYPE_KIND_INITIALIZER,

	CP_DEM_TYPE_KIND_BASE_UNRESOLVED_NAME,
	CP_DEM_TYPE_KIND_SIMPLE_ID,
	CP_DEM_TYPE_KIND_DESTRUCTOR_NAME,
	CP_DEM_TYPE_KIND_UNRESOLVED_TYPE,
	CP_DEM_TYPE_KIND_UNRESOLVED_QUALIFIER_LEVEL,
	CP_DEM_TYPE_KIND_QUALIFIED_TYPE,
	CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE,
	CP_DEM_TYPE_KIND_QUALIFIERS,
	CP_DEM_TYPE_KIND_EXTENDED_QUALIFIER,
	CP_DEM_TYPE_KIND_FUNCTION_TYPE,
	CP_DEM_TYPE_KIND_EXCEPTION_SPEC,
	CP_DEM_TYPE_KIND_CLASS_ENUM_TYPE,
	CP_DEM_TYPE_KIND_ARRAY_TYPE,
	CP_DEM_TYPE_KIND_VECTOR_TYPE,
	CP_DEM_TYPE_KIND_POINTER_TO_MEMBER_TYPE,
	CP_DEM_TYPE_KIND_TEMPLATE_TEMPLATE_PARAM,
	CP_DEM_TYPE_KIND_DIGIT,
	CP_DEM_TYPE_KIND_TEMPLATE_ARGS,
	CP_DEM_TYPE_KIND_TEMPLATE_ARG,
	CP_DEM_TYPE_KIND_SUBSTITUTION,
	CP_DEM_TYPE_KIND_SEQ_ID,
	CP_DEM_TYPE_KIND_LOCAL_NAME,
	CP_DEM_TYPE_KIND_DISCRIMINATOR,
	CP_DEM_TYPE_KIND_VENDOR_SPECIFIC_SUFFIX,
	CP_DEM_TYPE_KIND_SPECIAL_NAME,
	CP_DEM_TYPE_KIND_CALL_OFFSET,
	CP_DEM_TYPE_KIND_NV_OFFSET,
	CP_DEM_TYPE_KIND_V_OFFSET,
	CP_DEM_TYPE_KIND_BARE_FUNCTION_TYPE,
	CP_DEM_TYPE_KIND_UNSCOPED_TEMPLATE_NAME,
	CP_DEM_TYPE_KIND_TOP_LEVEL_CV_QUALIFIERS,
	CP_DEM_TYPE_KIND_NON_NEGATIVE_NUMBER,
	CP_DEM_TYPE_KIND_VALUE_NUMBER,
	CP_DEM_TYPE_KIND_VALUE_FLOAT,
	CP_DEM_TYPE_KIND_STRING_TYPE,
	CP_DEM_TYPE_KIND_POINTER_TYPE,
	CP_DEM_TYPE_KIND_REAL_PART_FLOAT,
	CP_DEM_TYPE_KIND_IMAG_PART_FLOAT,
	CP_DEM_TYPE_KIND_FIELD_SOURCE_NAME,
	CP_DEM_TYPE_KIND_INDEX_EXPRESSION,
	CP_DEM_TYPE_KIND_RANGE_BEGIN_EXPRESSION,
	CP_DEM_TYPE_KIND_RANGE_END_EXPRESSION,
	CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_EXPRESSION,
	CP_DEM_TYPE_KIND_ELEMENT_TYPE,
	CP_DEM_TYPE_KIND_INSTANTIATION_DEPENDENT_ARRAY_BOUND_EXPRESSION,
	CP_DEM_TYPE_KIND_ARRAY_BOUND_NUMBER,
	CP_DEM_TYPE_KIND_CLASS_TYPE,
	CP_DEM_TYPE_KIND_FUNCTION_ENCODING,
	CP_DEM_TYPE_KIND_ENTITY_NAME,
	CP_DEM_TYPE_KIND_BASE_ENCODING,
	CP_DEM_TYPE_KIND_OFFSET_NUMBER,
	CP_DEM_TYPE_KIND_VIRTUAL_OFFSET_NUMBER,
	CP_DEM_TYPE_KIND_FUNCTION_NAME,
	CP_DEM_TYPE_KIND_DATA_NAME,
	CP_DEM_TYPE_KIND_SIGNATURE_TYPE,
	CP_DEM_TYPE_KIND_NV_DIGIT,
	CP_DEM_TYPE_KIND_TEMPLATE_PARAM_DECL,
	CP_DEM_TYPE_KIND_PARAMETER_PACK,
	CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK,
	CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION,
	CP_DEM_TYPE_KIND_NON_NEG_NUMBER,
	CP_DEM_TYPE_KIND_FWD_TEMPLATE_REF,
	CP_DEM_TYPE_KIND_MANY,
	CP_DEM_TYPE_KIND_MODULE_NAME,
	CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS,
	CP_DEM_TYPE_KIND_CLOSURE_TY_NAME,
	CP_DEM_TYPE_KIND_CONV_OP_TY,
	CP_DEM_TYPE_KIND_ABI_TAG_TY,
	CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION,
	CP_DEM_TYPE_KIND_EXPANDED_SPECIAL_SUBSTITUTION,
	CP_DEM_TYPE_KIND_NOEXCEPT_SPEC,
	CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC,
} CpDemTypeKind;

typedef struct {
	const char *buf;
	size_t len;
} DemStringView;

static inline bool dem_string_append_sv(DemString *dst, const DemStringView src) {
	if (!dst || !src.buf) {
		return false;
	}
	return dem_string_append_n(dst, src.buf, src.len);
}

static inline bool sv_form_cstr(DemStringView *dst, const char *src) {
	if (!dst || !src) {
		return false;
	}
	dst->buf = src;
	dst->len = strlen(src);
	return true;
}

static inline bool sv_eq_cstr(DemStringView *dst, const char *src) {
	if (!dst || !src) {
		return false;
	}
	return dst->len == strlen(src) && strncmp(dst->buf, src, dst->len) == 0;
}

struct Vec_t(DemNode);

enum {
	SUB_TAG_INVALID,
	POINTER_TYPE,
	REFERENCE_TYPE,
	RVALUE_REFERENCE_TYPE,
	QUALIFIED_TYPE,
	ARRAY_TYPE,
	SPECIAL_SUBSTITUTION_ALLOCATOR,
	SPECIAL_SUBSTITUTION_BASIC_STRING,
	SPECIAL_SUBSTITUTION_STRING,
	SPECIAL_SUBSTITUTION_ISTREAM,
	SPECIAL_SUBSTITUTION_OSTREAM,
	SPECIAL_SUBSTITUTION_IOSTREAM,
	TEMPLATE_PARAM_DECL_TYPE, // Ty - type parameter
	TEMPLATE_PARAM_DECL_NON_TYPE, // Tn <type> - non-type parameter
	TEMPLATE_PARAM_DECL_TEMPLATE, // Tt <template-param-decl>* E - template template parameter
	TEMPLATE_PARAM_DECL_PACK, // Tp <template-param-decl> - parameter pack
	TEMPLATE_PARAM_DECL_CONSTRAINED, // Tk <name> [<template-args>] - constrained parameter
};

struct DemNode_t;

// Forward template reference: stores a reference to T_ that needs resolution later
typedef struct ForwardTemplateRef {
	ut64 level; // Template parameter level
	ut64 index; // Template parameter index
	struct DemNode_t *ref;
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

typedef struct {
	PDemNode qual;
	PDemNode name;
} NestedName;

typedef struct {
	PDemNode encoding;
	PDemNode entry;
} LocalName;

typedef struct {
	PDemNode name;
	bool is_dtor;
} CtorDtorName;

typedef struct {
	PDemNode ty;
} ConvOpTy;

typedef struct {
	PDemNode ty;
	DemStringView tag;
} AbiTagTy;

typedef struct {
	PDemNode inner_ty;
	PDemNode dimension;
} ArrayTy;

typedef struct {
	PDemNode lhs;
	DemStringView op;
	PDemNode rhs;
} MemberExpr;

typedef struct {
	PDemNode lhs;
	DemStringView op;
	PDemNode rhs;
} BinaryExpr;

typedef struct {
	DemStringView prefix;
	PDemNode inner;
} PrefixExpr;

typedef struct {
	PDemNode pack, init;
	DemStringView op;
	bool is_left_fold;
} FoldExpr;

typedef struct {
	PDemNode elem, init;
	bool is_array;
} BracedExpr;

typedef struct {
	PDemNode first, last, init;
} BracedRangeExpr;

typedef struct {
	PDemNode ty;
	PDemNode inits; // many node
} InitListExpr;

typedef struct {
	PDemNode expr_list, ty, init_list;
	bool is_global;
	DemStringView op;
} NewExpr;

typedef struct {
	DemStringView type;
	DemStringView value;
} IntegerLiteralExpr;

typedef enum {
	PRIMARY,
	PPOSTFIX,
	UNARY,
	CAST,
	PTRMEM,
	MULTIPLICATIVE,
	ADDITIVE,
	SHIFT,
	SPACESHIP,
	RELATIONAL,
	EQUALITY,
	AND,
	XOR,
	IOR,
	ANDIF,
	ORIF,
	PCONDITIONAL,
	ASSIGN,
	COMMA,
	DEFAULT,
} Prec;

typedef struct DemNode_t {
	DemStringView val;
	CpDemTypeKind tag;
	Prec prec;
	ut32 subtag;
	struct Vec_t(PDemNode) * children; // Moved outside union, used by all types

	union {
		struct {
			const struct DemNode_t *child_ref;
		};

		struct {
			struct DemNode_t *child;
		};

		const ForwardTemplateRef *fwd_template_ref;
		PrimitiveTy primitive_ty;
		QualifiedTy qualified_ty;
		VendorExtQualifiedTy vendor_ext_qualified_ty;
		FunctionTy fn_ty;
		ManyTy many_ty;
		ModuleNameTy module_name_ty;
		NameWithTemplateArgs name_with_template_args;
		ClosureTyName closure_ty_name;
		NestedName nested_name;
		LocalName local_name;
		CtorDtorName ctor_dtor_name;
		ConvOpTy conv_op_ty;
		AbiTagTy abi_tag_ty;
		ArrayTy array_ty;
		MemberExpr member_expr;
		FoldExpr fold_expr;
		BracedExpr braced_expr;
		BracedRangeExpr braced_range_expr;
		InitListExpr init_list_expr;
		BinaryExpr binary_expr;
		PrefixExpr prefix_expr;
		NewExpr new_expr;
		IntegerLiteralExpr integer_literal_expr;
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

static inline void ForwardTemplateRef_free(void *pfwd) {
	if (pfwd && *(void **)pfwd) {
		free(*(void **)pfwd);
	}
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
	bool not_parse_template_args;
	bool trace;

	CpDemOptions options;
} DemParser;

typedef struct {
	bool is_conversion_ctor_dtor;
	bool end_with_template_args;
	size_t fwd_template_ref_begin;
	CvQualifiers cv_qualifiers;
	RefQualifiers ref_qualifiers;
} NameState;

void NameState_init(NameState *ns, const DemParser *p);

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
 * @param r Result structure to fill
 * @return true on success (r->output set), false on failure (r->error may be set)
 */
typedef bool (*DemRule)(DemParser *p, DemResult *r);

// DemParser helper functions
void DemParser_init(DemParser *p, CpDemOptions options, const char *input);
void DemParser_deinit(DemParser *p);
void DemResult_deinit(DemResult *r);
bool parse_rule(DemContext *ctx, const char *mangled, DemRule rule, CpDemOptions opts);

// Helper functions
bool append_type(DemParser *p, const DemNode *x);
DemNode *substitute_get(DemParser *p, ut64 id);
DemNode *template_param_get(DemParser *p, ut64 level, ut64 index);
bool resolve_forward_template_refs(DemParser *p, DemNode *dan);

#endif // V3_IMPL_TYPES_H
