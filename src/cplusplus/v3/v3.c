// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
/**
 * Documentation for used grammar can be found at either of
 * - https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling
 */

// Disable unused-value warning for the macros in this file
// The CALL_RULE* macros use comma expressions where intermediate results are intentionally discarded
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wunused-value"
#endif

#include "v3.h"
#include "v3_pp.h"
#include "../demangle.h"
#include "demangler_util.h"
#include "macros.h"
#include "parser_combinator.h"
#include "types.h"
#include "../vec.h"
#include <ctype.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

void pp_cv_qualifiers(CvQualifiers qualifiers, DemString *out, PPContext *ctx) {
	if (ctx && !(ctx->opts & DEM_OPT_ANSI)) {
		return;
	}
	if (qualifiers.is_const) {
		dem_string_append(out, " const");
	}
	if (qualifiers.is_volatile) {
		dem_string_append(out, " volatile");
	}
	if (qualifiers.is_restrict) {
		dem_string_append(out, " restrict");
	}
}

void pp_ref_qualifiers(RefQualifiers qualifiers, DemString *out, PPContext *ctx) {
	if (qualifiers.is_l_value) {
		dem_string_append(out, " &");
	}
	if (qualifiers.is_r_value) {
		dem_string_append(out, " &&");
	}
}

void pp_array_type_dimension(DemNode *node, DemString *out, PDemNode *pbase_ty, PPContext *ctx) {
	if (!node || !(node->tag == CP_DEM_TYPE_KIND_ARRAY_TYPE || node->tag == CP_DEM_TYPE_KIND_VECTOR_TYPE)) {
		return;
	}
	size_t count = 0;
	PDemNode base_ty = node;
	do {
		ArrayTy array_ty = base_ty->array_ty;
		dem_string_appends(out, "[");
		ast_pp(array_ty.dimension, out, ctx);
		dem_string_appends(out, "]");
		base_ty = array_ty.inner_ty;
		count++;
	} while (base_ty && (base_ty->tag == CP_DEM_TYPE_KIND_ARRAY_TYPE || base_ty->tag == CP_DEM_TYPE_KIND_VECTOR_TYPE));
	if (count == 0) {
		dem_string_append(out, "[]");
	}
	if (pbase_ty) {
		*pbase_ty = base_ty;
	}
}

static void pp_array_type(PDemNode node, DemString *out, PPContext *ctx) {
	DemString dim_string = { 0 };
	dem_string_init(&dim_string);
	PDemNode base_node = NULL;
	pp_array_type_dimension(node, &dim_string, &base_node, ctx);
	ast_pp(base_node, out, ctx);
	if (dem_string_non_empty(&dim_string)) {
		dem_string_append(out, " ");
		dem_string_concat(out, &dim_string);
	}
	dem_string_deinit(&dim_string);
}

static bool pp_init_list_as_string(PDemNode node, DemString *out, PPContext *ctx, PDemNode elems) {
	PDemNode base_node = node->array_ty.inner_ty;
	if ((base_node->tag == CP_DEM_TYPE_KIND_PRIMITIVE_TY &&
		    strncmp(base_node->primitive_ty.name.buf, "char", base_node->primitive_ty.name.len) == 0) ||
		(base_node->tag == CP_DEM_TYPE_KIND_BUILTIN_TYPE && AST_(base_node, 0) &&
			strncmp(AST_(base_node, 0)->primitive_ty.name.buf, "char", AST_(base_node, 0)->primitive_ty.name.len) == 0)) {
		dem_string_append(out, "\"");
		// Reconstruct string content from IntegerLiteral children
		if (elems && elems->children) {
			size_t count = VecPDemNode_len(elems->children);
			for (size_t i = 0; i < count; i++) {
				PDemNode *child_ptr = VecPDemNode_at(elems->children, i);
				if (!child_ptr || !*child_ptr) {
					continue;
				}
				PDemNode child = *child_ptr;
				if (child->tag != CP_DEM_TYPE_KIND_INTEGER_LITERAL) {
					continue;
				}
				// Parse the integer value from the mangled representation
				DemStringView val = child->integer_literal_expr.value;
				ut64 num = 0;
				const char *vp = val.buf;
				const char *ve = val.buf + val.len;
				if (vp < ve && *vp == 'n') {
					vp++; // skip negative sign (shouldn't happen for chars, but handle it)
				}
				while (vp < ve && *vp >= '0' && *vp <= '9') {
					num = num * 10 + (ut64)(*vp - '0');
					vp++;
				}
				if (num > 0 && num < 128) {
					char ch = (char)num;
					dem_string_append_n(out, &ch, 1);
				}
			}
		}
		dem_string_append(out, "\"");

		return true;
	}
	pp_array_type(node, out, ctx);
	return false;
}

// Helper to print pointer/reference/qualifier decorators
static void pp_type_quals(PDemNode node, DemString *out, CpDemTypeKind target_tag, PDemNode *pbase_ty, PPContext *ctx) {
	if (!node || !out) {
		return;
	}

	if (node->tag == target_tag) {
		// Reached the target type - stop recursion
		if (pbase_ty) {
			*pbase_ty = node;
		}
		return;
	}

	if (node->tag == CP_DEM_TYPE_KIND_TYPE && node->subtag != SUB_TAG_INVALID) {
		// Recurse first to get inner decorators
		if (AST(0)) {
			pp_type_quals(AST(0), out, target_tag, pbase_ty, ctx);
		}

		// Then add our decorator
		switch (node->subtag) {
		case POINTER_TYPE:
			dem_string_append(out, "*");
			break;
		case REFERENCE_TYPE:
			dem_string_append(out, "&");
			break;
		case RVALUE_REFERENCE_TYPE:
			dem_string_append(out, "&&");
			break;
		default:
			DEM_UNREACHABLE;
			break;
		}
		return;
	}
	if (node->tag == CP_DEM_TYPE_KIND_QUALIFIED_TYPE) {
		// Check if this qualified type wraps an array - if so, stop here
		// and return the qualified_type node as the base (qualifiers apply to array elements)
		if (node->qualified_ty.inner_type &&
			node->qualified_ty.inner_type->tag == CP_DEM_TYPE_KIND_ARRAY_TYPE) {
			if (pbase_ty) {
				*pbase_ty = node;
			}
			return;
		}

		if (node->qualified_ty.inner_type) {
			pp_type_quals(node->qualified_ty.inner_type, out, target_tag, pbase_ty, ctx);
		}
		pp_cv_qualifiers(node->qualified_ty.qualifiers, out, ctx);
		return;
	}

	if (pbase_ty) {
		*pbase_ty = node;
	}
}

// Helper to reorder qualifiers for array/function references
// Transforms " const&" to "const &" for arrays, or "*const&" to "* const&" for function pointers
static void reorder_qualifiers_for_array_fn_ref(DemString *quals) {
	if (!quals || !quals->buf || quals->len < 2) {
		return;
	}

	// Look for pattern: [*][ cv-qualifiers][&|&&]
	// We need to move cv-qualifiers before & but after *, with proper spacing

	char *ref_pos = NULL;
	bool is_rvalue_ref = false;

	// Find reference marker from the end
	if (quals->len >= 2 && quals->buf[quals->len - 2] == '&' && quals->buf[quals->len - 1] == '&') {
		ref_pos = &quals->buf[quals->len - 2];
		is_rvalue_ref = true;
	} else if (quals->len >= 1 && quals->buf[quals->len - 1] == '&') {
		ref_pos = &quals->buf[quals->len - 1];
	}

	if (!ref_pos) {
		return; // No reference found
	}

	// Find where cv-qualifiers start (after last * or from beginning)
	char *cv_start = NULL;
	char *ptr = quals->buf;
	char *last_star = NULL;

	while (ptr < ref_pos) {
		if (*ptr == '*') {
			last_star = ptr;
		}
		ptr++;
	}

	// Determine start of prefix and cv-qualifiers
	char *prefix_end = last_star ? (last_star + 1) : quals->buf;
	cv_start = prefix_end;
	while (cv_start < ref_pos && *cv_start == ' ') {
		cv_start++;
	}

	if (cv_start >= ref_pos) {
		return; // No cv-qualifiers before reference
	}

	// Extract parts
	size_t prefix_len = prefix_end - quals->buf;
	size_t cv_len = ref_pos - cv_start;
	size_t ref_len = is_rvalue_ref ? 2 : 1;

	// Build reordered string: prefix + " " + cv-quals + ref (no space before ref for function pointers)
	// For arrays: "const &", for function pointers: "* const&"
	DemString reordered = { 0 };
	dem_string_init(&reordered);

	if (prefix_len > 0) {
		dem_string_append_n(&reordered, quals->buf, prefix_len);
		// Add space after * for function pointers
		if (last_star && cv_start < ref_pos) {
			dem_string_append(&reordered, " ");
		}
	}
	dem_string_append_n(&reordered, cv_start, cv_len);
	dem_string_append_n(&reordered, ref_pos, ref_len);

	// Replace original
	dem_string_deinit(quals);
	*quals = reordered;
}

static void pp_type_with_quals(PDemNode node, DemString *out, PPContext *ctx) {
	DemString qualifiers_string = { 0 };
	dem_string_init(&qualifiers_string);
	PDemNode base_node = NULL;
	pp_type_quals(node, &qualifiers_string, CP_DEM_TYPE_KIND_UNKNOWN, &base_node, ctx);

	if (base_node && base_node->tag == CP_DEM_TYPE_KIND_ARRAY_TYPE) {
		DemString array_dem_string = { 0 };
		dem_string_init(&array_dem_string);
		PDemNode array_inner_base = NULL;
		pp_array_type_dimension(base_node, &array_dem_string, &array_inner_base, ctx);
		ast_pp(array_inner_base, out, ctx);
		if (dem_string_non_empty(&qualifiers_string)) {
			reorder_qualifiers_for_array_fn_ref(&qualifiers_string);
			dem_string_append(out, " (");
			dem_string_concat(out, &qualifiers_string);
			dem_string_append(out, ")");
		}
		if (dem_string_non_empty(&array_dem_string)) {
			dem_string_append(out, " ");
			dem_string_concat(out, &array_dem_string);
		}
		dem_string_deinit(&array_dem_string);
	} else if (base_node && base_node->tag == CP_DEM_TYPE_KIND_QUALIFIED_TYPE &&
		base_node->qualified_ty.inner_type &&
		base_node->qualified_ty.inner_type->tag == CP_DEM_TYPE_KIND_ARRAY_TYPE) {
		// Handle qualified array: print element type with qualifiers, then ref, then array dimension
		DemString array_dem_string = { 0 };
		dem_string_init(&array_dem_string);
		PDemNode array_inner_base = NULL;
		pp_array_type_dimension(base_node->qualified_ty.inner_type, &array_dem_string, &array_inner_base, ctx);
		ast_pp(array_inner_base, out, ctx);
		pp_cv_qualifiers(base_node->qualified_ty.qualifiers, out, ctx);
		if (dem_string_non_empty(&qualifiers_string)) {
			reorder_qualifiers_for_array_fn_ref(&qualifiers_string);
			dem_string_append(out, " (");
			dem_string_concat(out, &qualifiers_string);
			dem_string_append(out, ")");
		}
		if (dem_string_non_empty(&array_dem_string)) {
			dem_string_append(out, " ");
			dem_string_concat(out, &array_dem_string);
		}
		dem_string_deinit(&array_dem_string);
	} else {
		ast_pp(base_node, out, ctx);
		if (dem_string_non_empty(&qualifiers_string)) {
			// Reference collapsing (C++ rules):
			// When a reference qualifier is about to be appended and the base type
			// already ends with a reference (e.g., from a pack expansion element),
			// apply collapsing: & + & = &, & + && = &, && + & = &, && + && = &&.
			size_t out_len = dem_string_length(out);
			size_t q_len = qualifiers_string.len;
			bool out_ends_with_ref = (out_len >= 1 && out->buf[out_len - 1] == '&');
			bool quals_is_ref = (q_len >= 1 && qualifiers_string.buf[0] == '&');
			if (out_ends_with_ref && quals_is_ref) {
				// Determine inner and outer ref types
				bool inner_is_rvalue = (out_len >= 2 && out->buf[out_len - 2] == '&');
				bool outer_is_rvalue = (q_len >= 2 && qualifiers_string.buf[1] == '&');
				if (inner_is_rvalue && outer_is_rvalue) {
					// && + && = &&: already have &&, don't append
				} else if (inner_is_rvalue) {
					// && + & = &: trim trailing & from out
					out->len--;
					out->buf[out->len] = '\0';
				} else {
					// & + & = & or & + && = &: already have &, don't append
				}
			} else {
				dem_string_concat(out, &qualifiers_string);
			}
		}
	}

	dem_string_deinit(&qualifiers_string);
}

bool pp_parameter_pack(PDemNode node, DemString *out, PPContext *pp_ctx) {
	if (!(node->tag == CP_DEM_TYPE_KIND_PARAMETER_PACK && node->child_ref && node->child_ref->tag == CP_DEM_TYPE_KIND_MANY)) {
		return false;
	}
	const DemNode *many_node = node->child_ref;
	if (pp_ctx->current_pack_index == UT32_MAX) {
		pp_ctx->current_pack_index = 0;
		pp_ctx->current_pack_max = VecPDemNode_len(many_node->children);
	}

	if (pp_ctx->current_pack_index < VecPDemNode_len(many_node->children)) {
		PDemNode *child = VecPDemNode_at(many_node->children, pp_ctx->current_pack_index);
		if (child && *child) {
			ast_pp(*child, out, pp_ctx);
		} else {
			dem_string_append(out, "<null pack element>");
		}
	}
	return true;
}

// Print all elements of a parameter_pack comma-separated (for fold expressions)
static void pp_pack_all_elements(PDemNode node, DemString *out, PPContext *pp_ctx) {
	if (node->tag == CP_DEM_TYPE_KIND_PARAMETER_PACK && node->child_ref && node->child_ref->tag == CP_DEM_TYPE_KIND_MANY) {
		const DemNode *many_node = node->child_ref;
		size_t count = VecPDemNode_len(many_node->children);
		for (size_t i = 0; i < count; i++) {
			if (i > 0) {
				dem_string_append(out, ", ");
			}
			PDemNode *child = VecPDemNode_at(many_node->children, i);
			if (child && *child) {
				ast_pp(*child, out, pp_ctx);
			}
		}
	} else {
		ast_pp(node, out, pp_ctx);
	}
}

bool pp_pack_expansion(PDemNode node, DemString *out, PPContext *pp_ctx) {
	ut32 saved_pack_index = pp_ctx->current_pack_index;
	ut32 saved_pack_max = pp_ctx->current_pack_max;
	pp_ctx->current_pack_index = UT32_MAX;
	pp_ctx->current_pack_max = UT32_MAX;

	size_t saved_pos = dem_string_length(out);
	ast_pp(node->child, out, pp_ctx);

	if (pp_ctx->current_pack_index == UT32_MAX) {
		dem_string_append(out, "...");
		goto beach;
	}

	if (pp_ctx->current_pack_max == 0 && out->len != saved_pos) {
		// Empty pack expansion - remove previously appended content
		out->len = saved_pos;
		out->buf[out->len] = '\0';
		goto beach;
	}

	for (size_t i = 1; i < pp_ctx->current_pack_max; i++) {
		dem_string_append(out, ", ");
		pp_ctx->current_pack_index = i;
		ast_pp(node->child, out, pp_ctx);
	}

beach:
	pp_ctx->current_pack_index = saved_pack_index;
	pp_ctx->current_pack_max = saved_pack_max;
	return true;
}

// Helper function to extract the base class name from a ctor/dtor name
// Recursively unwraps name_with_template_args and nested_name to get the final primitive name
static bool node_base_name(PDemNode node, DemStringView *out) {
	if (!node) {
		return false;
	}

	switch (node->tag) {
	case CP_DEM_TYPE_KIND_ABI_TAG_TY:
		// Unwrap abi_tag_ty to get the inner type
		if (node->abi_tag_ty.ty) {
			return node_base_name(node->abi_tag_ty.ty, out);
		}
		break;
	case CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS:
		// Unwrap template args to get the base name
		if (node->name_with_template_args.name) {
			return node_base_name(node->name_with_template_args.name, out);
		}
		break;

	case CP_DEM_TYPE_KIND_NESTED_NAME:
		// Get the final name component (not the qualifier)
		if (node->nested_name.name) {
			return node_base_name(node->nested_name.name, out);
		}
		break;

	case CP_DEM_TYPE_KIND_EXPANDED_SPECIAL_SUBSTITUTION:
		switch (node->subtag) {
		case SPECIAL_SUBSTITUTION_ALLOCATOR:
			return sv_form_cstr(out, "allocator");
		case SPECIAL_SUBSTITUTION_BASIC_STRING:
			return sv_form_cstr(out, "basic_string");
		case SPECIAL_SUBSTITUTION_STRING:
			return sv_form_cstr(out, "basic_string");
		case SPECIAL_SUBSTITUTION_IOSTREAM:
			return sv_form_cstr(out, "basic_iostream");
		case SPECIAL_SUBSTITUTION_ISTREAM:
			return sv_form_cstr(out, "basic_istream");
		case SPECIAL_SUBSTITUTION_OSTREAM:
			return sv_form_cstr(out, "basic_ostream");
		default:
			return sv_form_cstr(out, "<unknown special substitution>");
		}
		return false;

	case CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION:
		switch (node->subtag) {
		case SPECIAL_SUBSTITUTION_ALLOCATOR:
			return sv_form_cstr(out, "allocator");
		case SPECIAL_SUBSTITUTION_BASIC_STRING:
			return sv_form_cstr(out, "basic_string");
		case SPECIAL_SUBSTITUTION_STRING:
			return sv_form_cstr(out, "string");
		case SPECIAL_SUBSTITUTION_IOSTREAM:
			return sv_form_cstr(out, "iostream");
		case SPECIAL_SUBSTITUTION_ISTREAM:
			return sv_form_cstr(out, "istream");
		case SPECIAL_SUBSTITUTION_OSTREAM:
			return sv_form_cstr(out, "ostream");
		default:
			return sv_form_cstr(out, "<unknown special substitution>");
		}
		return false;

	case CP_DEM_TYPE_KIND_PRIMITIVE_TY:
		return sv_form_cstr(out, node->primitive_ty.name.buf);
	default:
		return node_base_name(node, out);
	}
	return false;
}

static bool pp_base_name(PDemNode node, DemString *out) {
	DemStringView base_name = { 0 };
	if (!node_base_name(node, &base_name)) {
		return false;
	}
	return dem_string_append_sv(out, base_name);
}

// Helper to check if a type node ultimately wraps a function type
// This walks through type wrappers (pointer, reference, qualified) to find the innermost type
struct PPFnContext_t;

typedef void (*AST_PP_FN)(struct PPFnContext_t *, DemString *);

typedef struct PPFnContext_t {
	DemNode *fn;
	DemNode *mod;
	AST_PP_FN pp_mod;
	DemNode *quals;
	AST_PP_FN pp_quals;
	PPContext *pp_ctx;
} PPFnContext;

static bool extract_function_type(DemNode *node, DemNode **out_func_node) {
	if (!node) {
		return false;
	}

	if (node->tag == CP_DEM_TYPE_KIND_FUNCTION_TYPE) {
		if (out_func_node) {
			*out_func_node = node;
		}
		return true;
	}

	if (node->tag == CP_DEM_TYPE_KIND_TYPE && AST(0)) {
		return extract_function_type(AST(0), out_func_node);
	}

	if (node->tag == CP_DEM_TYPE_KIND_QUALIFIED_TYPE && node->qualified_ty.inner_type) {
		return extract_function_type(node->qualified_ty.inner_type, out_func_node);
	}

	return false;
}

static void pp_function_ty_mod_return_fn(PPFnContext *, DemString *);
static void pp_function_ty_quals(PPFnContext *ctx, DemString *out);

static void pp_function_ty_with_context(PPFnContext *ctx, DemString *out) {
	if (!ctx || !ctx->fn || !out) {
		return;
	}

	DemNode *node = ctx->fn;
	FunctionTy *ft = &node->fn_ty;

	// Print return type
	DemNode *ret_fn_ty = NULL;
	if (ft->ret && extract_function_type(ft->ret, &ret_fn_ty)) {
		DemNode *saved_ret = ft->ret;
		ft->ret = NULL;
		PPFnContext inner_ctx = {
			.fn = ret_fn_ty,
			.quals = saved_ret,
			.pp_quals = pp_function_ty_quals,
			.mod = node,
			.pp_mod = pp_function_ty_mod_return_fn,
			.pp_ctx = ctx->pp_ctx,
		};
		pp_function_ty_with_context(&inner_ctx, out);
		ft->ret = saved_ret;
		return;
	}

	if (ft->ret) {
		ast_pp(ft->ret, out, ctx->pp_ctx);
		dem_string_append(out, " ");
	}

	bool has_mod = ctx && ctx->mod && ctx->pp_mod;
	bool has_quals = ctx && ctx->quals && ctx->pp_quals;
	bool has_mod_or_quals = has_mod || has_quals;
	if (has_mod_or_quals) {
		dem_string_append(out, "(");
	}
	if (ft->name) {
		ast_pp(ft->name, out, ctx->pp_ctx);
		if (has_mod_or_quals) {
			dem_string_append(out, " ");
		}
	}
	if (has_quals) {
		ctx->pp_quals(ctx, out);
	}
	if (has_mod) {
		ctx->pp_mod(ctx, out);
	}
	if (has_mod_or_quals) {
		dem_string_append(out, ")");
	}

	// Print parameters
	dem_string_append(out, "(");
	if (ft->params && (ctx->pp_ctx->opts & DEM_OPT_PARAMS)) {
		ast_pp(ft->params, out, ctx->pp_ctx);
	}
	dem_string_append(out, ")");

	// Print cv and ref qualifiers
	pp_cv_qualifiers(ft->cv_qualifiers, out, ctx->pp_ctx);
	pp_ref_qualifiers(ft->ref_qualifiers, out, ctx->pp_ctx);

	// Print exception spec
	if (ft->exception_spec) {
		dem_string_append(out, " ");
		ast_pp(ft->exception_spec, out, ctx->pp_ctx);
	}
}

static void pp_function_ty(PDemNode node, DemString *out, PPContext *pp_ctx) {
	PPFnContext ctx = { 0 };
	ctx.fn = node;
	ctx.pp_ctx = pp_ctx;
	pp_function_ty_with_context(&ctx, out);
}

static void pp_function_ty_mod_return_fn(PPFnContext *ctx, DemString *out) {
	PPFnContext inner_ctx = {
		.fn = ctx->mod,
		.pp_ctx = ctx->pp_ctx
	};
	pp_function_ty_with_context(&inner_ctx, out);
}

static void pp_function_ty_quals(PPFnContext *ctx, DemString *out) {
	if (!ctx || !ctx->quals) {
		return;
	}
	DemString quals_str = { 0 };
	dem_string_init(&quals_str);
	pp_type_quals(ctx->quals, &quals_str, CP_DEM_TYPE_KIND_FUNCTION_TYPE, NULL, ctx->pp_ctx);
	reorder_qualifiers_for_array_fn_ref(&quals_str);
	dem_string_concat(out, &quals_str);
	dem_string_deinit(&quals_str);
}

static void pp_function_ty_mod_pointer_to_member_type(PPFnContext *ctx, DemString *out) {
	if (ctx && ctx->mod) {
		ast_pp(ctx->mod, out, ctx->pp_ctx);
	}
	dem_string_append(out, "::*");
}

void pp_expanded_special_substitution(DemNode *node, DemString *out, PPContext *ctx) {
	dem_string_append(out, "std::");
	pp_base_name(node, out);
	if (node->subtag >= SPECIAL_SUBSTITUTION_STRING) {
		dem_string_append(out, "<char, std::char_traits<char>");
		if (node->subtag == SPECIAL_SUBSTITUTION_STRING) {
			dem_string_append(out, ", std::allocator<char>");
		}
		dem_string_append(out, ">");
	}
}

void pp_special_substitution(DemNode *node, DemString *out) {
	dem_string_append(out, "std::");
	pp_base_name(node, out);
}

// Helper functions for printing parentheses with depth tracking
static inline void print_open(DemString *out, PPContext *ctx) {
	dem_string_append(out, "(");
	ctx->paren_depth++;
}

static inline void print_close(DemString *out, PPContext *ctx) {
	dem_string_append(out, ")");
	ctx->paren_depth--;
}

static inline void pp_as_operand_ex(DemNode *node, DemString *out, Prec prec, bool strictly_worse, PPContext *ctx) {
	if (!node || !out) {
		return;
	}
	bool need_parens = (size_t)node->prec >= (size_t)prec + (size_t)strictly_worse;
	if (need_parens) {
		print_open(out, ctx);
	}
	ast_pp(node, out, ctx);
	if (need_parens) {
		print_close(out, ctx);
	}
}

static void pp_template_param_decl(DemNode *node, DemString *out, PPContext *ctx) {
	if (!node || !out) {
		return;
	}

}

void ast_pp(DemNode *node, DemString *out, PPContext *ctx) {
	if (!node || !out || !ctx) {
		return;
	}

	switch (node->tag) {
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY:
		// Primitive type nodes contain literal strings
		if (node->primitive_ty.name.buf) {
			dem_string_append(out, node->primitive_ty.name.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION:
		pp_special_substitution(node, out);
		break;
	case CP_DEM_TYPE_KIND_EXPANDED_SPECIAL_SUBSTITUTION:
		pp_expanded_special_substitution(node, out, ctx);
		break;

	case CP_DEM_TYPE_KIND_ABI_TAG_TY:
		ast_pp(node->abi_tag_ty.ty, out, ctx);
		dem_string_append(out, "[abi:");
		dem_string_append_n(out,
			node->abi_tag_ty.tag.buf,
			node->abi_tag_ty.tag.len);
		dem_string_append(out, "]");
		break;

	case CP_DEM_TYPE_KIND_NOEXCEPT_SPEC:
		dem_string_append(out, "noexcept");
		print_open(out, ctx);
		ast_pp(node->child, out, ctx);
		print_close(out, ctx);
		break;
	case CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC:
		dem_string_append(out, "throw");
		print_open(out, ctx);
		ast_pp(node->child, out, ctx);
		print_close(out, ctx);
		break;
	case CP_DEM_TYPE_KIND_FUNCTION_TYPE: {
		pp_function_ty(node, out, ctx);
		break;
	}
	case CP_DEM_TYPE_KIND_MODULE_NAME:
		if (node->module_name_ty.pare) {
			ast_pp(node->module_name_ty.pare, out, ctx);
		}
		if (node->module_name_ty.pare || node->module_name_ty.IsPartition) {
			dem_string_append(out, node->module_name_ty.IsPartition ? ":" : ".");
		}
		if (node->module_name_ty.name) {
			ast_pp(node->module_name_ty.name, out, ctx);
		}
		break;
	case CP_DEM_TYPE_KIND_TEMPLATE_ARGS:
		dem_string_append(out, "<");

		// Set inside_template flag when printing template arguments
		bool old_inside_template = ctx->inside_template;
		ctx->inside_template = true;
		ast_pp(node->child, out, ctx);
		ctx->inside_template = old_inside_template;

		dem_string_append(out, ">");
		break;
	case CP_DEM_TYPE_KIND_TEMPLATE_PARAM_DECL:
		pp_template_param_decl(node, out, ctx);
		break;
	case CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS:
		if (node->name_with_template_args.name) {
			ast_pp(node->name_with_template_args.name, out, ctx);
		}
		if (node->name_with_template_args.template_args) {
			ast_pp(node->name_with_template_args.template_args, out, ctx);
		}
		break;

	case CP_DEM_TYPE_KIND_QUALIFIED_TYPE:
		if (node->qualified_ty.inner_type) {
			ast_pp(node->qualified_ty.inner_type, out, ctx);
			pp_cv_qualifiers(node->qualified_ty.qualifiers, out, ctx);
		}
		break;

	case CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE:
		if (node->vendor_ext_qualified_ty.inner_type) {
			ast_pp(node->vendor_ext_qualified_ty.inner_type, out, ctx);
			if (node->vendor_ext_qualified_ty.vendor_ext.buf) {
				dem_string_append(out, " ");
				dem_string_append_n(out,
					node->vendor_ext_qualified_ty.vendor_ext.buf,
					node->vendor_ext_qualified_ty.vendor_ext.len);
			}
			if (node->vendor_ext_qualified_ty.template_args) {
				ast_pp(node->vendor_ext_qualified_ty.template_args, out, ctx);
			}
		}
		break;

	case CP_DEM_TYPE_KIND_CONV_OP_TY:
		dem_string_append(out, "operator ");
		ast_pp(node->conv_op_ty.ty, out, ctx);
		break;

	case CP_DEM_TYPE_KIND_MANY:
		// Print children with separator
		if (!node->children) {
			break;
		}
		bool first = true;
		vec_foreach_ptr(PDemNode, node->children, child_ptr, {
			DemNode *child = child_ptr ? *child_ptr : NULL;
			if (!child) {
				continue;
			}
			size_t saved_pos = dem_string_length(out);
			if (!first && node->many_ty.sep) {
				dem_string_append(out, node->many_ty.sep);
			}
			size_t pos_after_sep = dem_string_length(out);
			ast_pp(child, out, ctx);
			first = false;
			if (dem_string_length(out) == pos_after_sep && out->buf) {
				// No content was added after separator - remove it
				out->len = saved_pos;
				out->buf[out->len] = '\0';
			}
		});
		break;

	case CP_DEM_TYPE_KIND_NESTED_NAME:
		// Nested names are separated by "::"
		if (node->nested_name.qual) {
			ast_pp(node->nested_name.qual, out, ctx);
			dem_string_append(out, "::");
		}
		if (node->nested_name.name) {
			ast_pp(node->nested_name.name, out, ctx);
		}
		break;

	case CP_DEM_TYPE_KIND_LOCAL_NAME:
		ast_pp(node->local_name.encoding, out, ctx);
		dem_string_append(out, "::");
		ast_pp(node->local_name.entry, out, ctx);
		break;

	case CP_DEM_TYPE_KIND_CTOR_DTOR_NAME:
		if (node->ctor_dtor_name.is_dtor) {
			dem_string_append(out, "~");
		}
		// For constructor/destructor names, we only want the final class name,
		// not the full qualified name or template arguments. Extract the base name.
		if (node->ctor_dtor_name.name) {
			pp_base_name(node->ctor_dtor_name.name, out);
		}
		break;

	case CP_DEM_TYPE_KIND_CLOSURE_TY_NAME: {
		// Closure types are lambda expressions: 'lambda[count]'<template_params> [ requires expr ] (params) [ requires expr ]
		const ClosureTyName *ctn = &node->closure_ty_name;
		dem_string_append(out, "'lambda");
		if (ctn->count.buf && ctn->count.len > 0) {
			dem_string_append_sv(out, ctn->count);
		}
		dem_string_append(out, "'");

		if (ctn->template_params && ctn->template_params->children) {
			dem_string_append(out, "<");
			ast_pp(node->closure_ty_name.template_params, out, ctx);
			dem_string_append(out, ">");
		}
		if (ctn->requires1) {
			dem_string_append(out, " requires ");
			ast_pp(ctn->requires1, out, ctx);
		}

		print_open(out, ctx);
		if (node->closure_ty_name.params) {
			ast_pp(node->closure_ty_name.params, out, ctx);
		}
		print_close(out, ctx);
		if (ctn->requires2) {
			dem_string_append(out, " requires ");
			ast_pp(ctn->requires2, out, ctx);
		}
		break;
	}
	case CP_DEM_TYPE_KIND_TYPE: {
		// Check if this is a function pointer (or pointer/reference/qualified wrapping a function pointer)
		DemNode *func_node = NULL;
		if (extract_function_type(node, &func_node)) {
			// This is a function pointer - use special formatting
			PPFnContext pp_fn_context = {
				.fn = func_node,
				.quals = node,
				.pp_quals = pp_function_ty_quals,
				.pp_ctx = ctx,
			};
			pp_function_ty_with_context(&pp_fn_context, out);
		} else if (node->subtag != SUB_TAG_INVALID && AST(0)) {
			pp_type_with_quals(node, out, ctx);
		} else {
			// Regular type - print children and add decorator
			vec_foreach_ptr(PDemNode, node->children, child_ptr, {
				ast_pp(*child_ptr, out, ctx);
			});
		}
	} break;

	case CP_DEM_TYPE_KIND_ARRAY_TYPE:
		pp_array_type(node, out, ctx);
		break;

	case CP_DEM_TYPE_KIND_VECTOR_TYPE: {
		DemString dem = { 0 };
		dem_string_init(&dem);
		PDemNode inner_ty = NULL;
		pp_array_type_dimension(node, &dem, &inner_ty, ctx);
		if (inner_ty) {
			ast_pp(inner_ty, out, ctx);
			dem_string_append(out, " vector");
			dem_string_concat(out, &dem);
		}
		dem_string_deinit(&dem);
		break;
	}

	case CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK:
		ast_pp(node->child, out, ctx);
		break;
	case CP_DEM_TYPE_KIND_PARAMETER_PACK:
		pp_parameter_pack(node, out, ctx);
		break;
	case CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION:
		pp_pack_expansion(node, out, ctx);
		break;

	case CP_DEM_TYPE_KIND_FWD_TEMPLATE_REF:
		if (node->fwd_template_ref && node->fwd_template_ref->ref) {
			ast_pp(node->fwd_template_ref->ref, out, ctx);
		} else {
			dem_string_append(out, "T_?_?");
		}
		break;

	case CP_DEM_TYPE_KIND_POINTER_TO_MEMBER_TYPE:
		// Member pointer: M <class-type> <member-type>
		// For member function pointers: return_type (Class::*)(params) cv-qualifiers ref-qualifiers
		// For member data pointers: type Class::*
		if (AST(1) && AST(1)->tag == CP_DEM_TYPE_KIND_FUNCTION_TYPE) {
			PPFnContext pp_fn_context = {
				.pp_mod = pp_function_ty_mod_pointer_to_member_type,
				.mod = AST(0),
				.fn = AST(1),
				.pp_ctx = ctx,
			};
			pp_function_ty_with_context(&pp_fn_context, out);
		} else {
			// Member data pointer
			if (AST(1)) {
				ast_pp(AST(1), out, ctx);
				dem_string_append(out, " ");
			}
			if (AST(0)) {
				ast_pp(AST(0), out, ctx);
			}
			dem_string_append(out, "::*");
		}
		break;
	case CP_DEM_TYPE_KIND_MEMBER_EXPRESSION:
		pp_as_operand_ex(node->member_expr.lhs, out, node->prec, true, ctx);
		dem_string_append_sv(out, node->member_expr.op);
		pp_as_operand_ex(node->member_expr.rhs, out, node->prec, false, ctx);
		break;
	case CP_DEM_TYPE_KIND_FOLD_EXPRESSION: {
		print_open(out, ctx);
		if (!node->fold_expr.is_left_fold || node->fold_expr.init) {
			if (node->fold_expr.is_left_fold) {
				pp_as_operand_ex(node->fold_expr.init, out, CAST, true, ctx);
			} else {
				print_open(out, ctx);
				pp_pack_all_elements(node->fold_expr.pack, out, ctx);
				print_close(out, ctx);
			}
			dem_string_append(out, " ");
			dem_string_append_sv(out, node->fold_expr.op);
			dem_string_append(out, " ");
		}
		dem_string_append(out, "...");
		if (node->fold_expr.is_left_fold || node->fold_expr.init) {
			dem_string_append(out, " ");
			dem_string_append_sv(out, node->fold_expr.op);
			dem_string_append(out, " ");
			if (node->fold_expr.is_left_fold) {
				print_open(out, ctx);
				pp_pack_all_elements(node->fold_expr.pack, out, ctx);
				print_close(out, ctx);
			} else {
				pp_as_operand_ex(node->fold_expr.init, out, CAST, true, ctx);
			}
		}
		print_close(out, ctx);
		break;
	}
	case CP_DEM_TYPE_KIND_BRACED_EXPRESSION: {
		if (node->braced_expr.is_array) {
			dem_string_append(out, "[");
			ast_pp(node->braced_expr.elem, out, ctx);
			dem_string_append(out, "]");
		} else {
			dem_string_append(out, ".");
			ast_pp(node->braced_expr.elem, out, ctx);
		}
		if (node->braced_expr.init->tag != CP_DEM_TYPE_KIND_BRACED_EXPRESSION && node->braced_expr.init->tag != CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION) {
			dem_string_append(out, " = ");
		}
		ast_pp(node->braced_expr.init, out, ctx);
		break;
	}
	case CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION: {
		dem_string_append(out, "[");
		ast_pp(node->braced_range_expr.first, out, ctx);
		dem_string_append(out, "...");
		ast_pp(node->braced_range_expr.last, out, ctx);
		dem_string_append(out, "]");
		if (node->braced_expr.init->tag != CP_DEM_TYPE_KIND_BRACED_EXPRESSION && node->braced_expr.init->tag != CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION) {
			dem_string_append(out, " = ");
		}
		ast_pp(node->braced_expr.init, out, ctx);
		break;
	}
	case CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION: {
		DemNode *ty = node->init_list_expr.ty;
		if (ty) {
			if (ty->tag == CP_DEM_TYPE_KIND_ARRAY_TYPE && pp_init_list_as_string(ty, out, ctx, node->init_list_expr.inits)) {
				break;
			}
			ast_pp(ty, out, ctx);
		}
		dem_string_append(out, "{");
		ast_pp(node->init_list_expr.inits, out, ctx);
		dem_string_append(out, "}");
		break;
	}

	case CP_DEM_TYPE_KIND_BINARY_EXPRESSION: {
		// Don't add parentheses around > or >> when we're already inside template arguments
		bool paren_all = ctx->paren_depth <= 0 &&
			(sv_eq_cstr(&node->binary_expr.op, ">") || sv_eq_cstr(&node->binary_expr.op, ">>"));
		if (paren_all) {
			print_open(out, ctx);
		}
		bool is_assign = node->prec == ASSIGN;
		pp_as_operand_ex(node->binary_expr.lhs, out, is_assign ? ORIF : node->prec, !is_assign, ctx);
		if (!sv_eq_cstr(&node->binary_expr.op, ",")) {
			dem_string_append(out, " ");
		}
		dem_string_append_sv(out, node->binary_expr.op);
		dem_string_append(out, " ");
		pp_as_operand_ex(node->binary_expr.rhs, out, node->prec, is_assign, ctx);
		if (paren_all) {
			print_close(out, ctx);
		}
		break;
	}
	case CP_DEM_TYPE_KIND_PREFIX_EXPRESSION: {
		dem_string_append_sv(out, node->prefix_expr.prefix);
		pp_as_operand_ex(node->prefix_expr.inner, out, node->prec, false, ctx);
		break;
	}
	case CP_DEM_TYPE_KIND_NEW_EXPRESSION: {
		if (node->new_expr.is_global) {
			dem_string_append(out, "::");
		}
		dem_string_append_sv(out, node->new_expr.op);
		if (node->new_expr.expr_list && VecPDemNode_len(node->new_expr.expr_list->children) > 0) {
			print_open(out, ctx);
			ast_pp(node->new_expr.expr_list, out, ctx);
			print_close(out, ctx);
		}
		dem_string_append(out, " ");
		if (node->new_expr.ty) {
			ast_pp(node->new_expr.ty, out, ctx);
		}
		if (node->new_expr.init_list && VecPDemNode_len(node->new_expr.init_list->children) > 0) {
			print_open(out, ctx);
			ast_pp(node->new_expr.init_list, out, ctx);
			print_close(out, ctx);
		}
		break;
	}

	case CP_DEM_TYPE_KIND_INTEGER_LITERAL: {
		DemStringView ty = node->integer_literal_expr.type;
		DemStringView val = node->integer_literal_expr.value;
		// Determine if this type uses cast notation (e.g. "(char)104") or suffix notation (e.g. "5u")
		bool use_cast = false;
		const char *suffix = "";
		if (ty.len == 3 && strncmp(ty.buf, "int", 3) == 0) {
			// no suffix for int
		} else if (ty.len == 12 && strncmp(ty.buf, "unsigned int", 12) == 0) {
			suffix = "u";
		} else if (ty.len == 4 && strncmp(ty.buf, "long", 4) == 0) {
			suffix = "l";
		} else if (ty.len == 13 && strncmp(ty.buf, "unsigned long", 13) == 0) {
			suffix = "ul";
		} else if (ty.len == 9 && strncmp(ty.buf, "long long", 9) == 0) {
			suffix = "ll";
		} else if (ty.len == 18 && strncmp(ty.buf, "unsigned long long", 18) == 0) {
			suffix = "ull";
		} else {
			// char, signed char, unsigned char, etc. use cast notation
			use_cast = true;
		}
		if (use_cast) {
			dem_string_append(out, "(");
			dem_string_append_n(out, ty.buf, ty.len);
			dem_string_append(out, ")");
		}
		// Print the numeric value (interpreting 'n' prefix as '-')
		if (val.len > 0 && val.buf[0] == 'n') {
			dem_string_append(out, "-");
			dem_string_append_n(out, val.buf + 1, val.len - 1);
		} else {
			dem_string_append_n(out, val.buf, val.len);
		}
		if (!use_cast) {
			dem_string_append(out, suffix);
		}
		break;
	}

	default:
		// For all other nodes with children, recursively print all children
		if (node->children) {
			vec_foreach_ptr(PDemNode, node->children, child_ptr, {
				DemNode *child = child_ptr ? *child_ptr : NULL;
				if (child) {
					ast_pp(child, out, ctx);
				}
			});
		}
		break;
	}
}

typedef struct {
	const char *a;
	const char *b;
} DemSimpleEntry;

static const DemSimpleEntry simple_entries[] = {
	{ "basic_string<char, std::char_traits<char>, std::allocator<char>>", "string" },
	{ "basic_iostream<char, std::char_traits<char>, std::allocator<char>>", "iostream" },
	{ "basic_istream<char, std::char_traits<char>, std::allocator<char>>", "istream" },
	{ "basic_ostream<char, std::char_traits<char>, std::allocator<char>>", "ostream" },
	{ "basic_streambuf<char, std::char_traits<char>, std::allocator<char>>", "streambuf" },
	{ "basic_string<char, std::char_traits<char>>", "string" },
	{ "basic_iostream<char, std::char_traits<char>>", "iostream" },
	{ "basic_istream<char, std::char_traits<char>>", "istream" },
	{ "basic_ostream<char, std::char_traits<char>>", "ostream" },
	{ "basic_streambuf<char, std::char_traits<char>>", "streambuf" },
	{ "unsigned long long", "uint64_t" },
	{ "long long", "int64_t" },
};

static void dem_simplify(DemString *out) {
	for (size_t i = 0; i < sizeof(simple_entries) / sizeof(simple_entries[0]); i++) {
		dem_string_replace_all(
			out,
			&simple_entries[i].a[0],
			strlen(simple_entries[i].a),
			simple_entries[i].b,
			strlen(simple_entries[i].b));
	}
}

static bool parse_base36(DemParser *p, ut64 *px) {
	static const char *base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
	char *pos = NULL;
	ut64 x = 0;
	ut64 sz = 0;
	while ((pos = strchr(base, p->cur[sz]))) {
		st64 based_val = pos - base;
		if (x > 0) {
			x *= 36;
		}
		x += based_val;
		sz++;
	}
	*px = x;
	p->cur += sz;
	return true;
}

bool parse_number(
	DemParser *p, DemStringView *out, bool allow_negative) {
	const char *start = p->cur;
	if (allow_negative) {
		READ('n');
	}
	if (!IN_RANGE(CUR()) || !isdigit(PEEK())) {
		if (out) {
			out->buf = NULL;
			out->len = 0;
		}
		return true;
	}
	while (IN_RANGE(CUR()) && isdigit(PEEK())) {
		ADV();
	}
	if (out) {
		out->buf = start;
		out->len = p->cur - start;
	}
	return true;
}

bool parse_non_neg_integer(
	DemParser *p, ut64 *out) {
	*out = 0;
	if (PEEK() < '0' || PEEK() > '9') {
		return false;
	}
	while (PEEK() >= '0' && PEEK() <= '9' && IN_RANGE(CUR())) {
		*out *= 10;
		*out += (ut64)(PEEK() - '0');
		ADV();
	}
	return true;
}

bool parse_cv_qualifiers(DemParser *p, CvQualifiers *quals) {
	const char *start = p->cur;
	if (READ('r')) {
		quals->is_restrict = true;
	}
	if (READ('V')) {
		quals->is_volatile = true;
	}
	if (READ('K')) {
		quals->is_const = true;
	}
	return p->cur != start;
}

bool parse_ref_qualifiers(DemParser *p, RefQualifiers *quals) {
	const char *start = p->cur;
	if (READ('R')) {
		quals->is_l_value = true;
	}
	if (READ('O')) {
		quals->is_r_value = true;
	}
	return p->cur != start;
}

bool parse_discriminator(DemParser *p) {
	if (!(READ('_'))) {
		return false;
	}
	READ('_');
	parse_number(p, NULL, false);
	return true;
}

bool parse_base_source_name(DemParser *p, const char **pout, size_t *plen) {
	ut64 num = 0;
	if (!parse_non_neg_integer(p, &num)) {
		return false;
	}
	// Check if the length is valid and within bounds
	// Prevent overflow and ensure we stay within the input buffer
	if (num > (ut64)(END() - CUR())) {
		return false;
	}
	if (pout) {
		*pout = CUR();
	}
	if (plen) {
		*plen = (size_t)num;
	}
	CUR() += num;
	return true;
}

bool parse_seq_id(DemParser *p, DemNode **pp_out_node) {
	ut64 sid = 0;
	if (IS_DIGIT(PEEK()) || IS_UPPER(PEEK())) {
		if (!parse_base36(p, &sid)) {
			return false;
		}
		sid += 1;
	}
	if (!READ('_')) {
		return false;
	}
	DemNode *ref = substitute_get(p, sid);
	if (!ref) {
		return false;
	}
	// Return the reference directly without cloning.
	if (pp_out_node) {
		*pp_out_node = ref;
	}
	return true;
}

bool rule_vendor_specific_suffix(DemParser *p, DemResult *r) {
	RULE_HEAD(VENDOR_SPECIFIC_SUFFIX);
	// Handle _ptr suffix (should be ignored, not output)
	if (READ_STR("ptr")) {
		// Consume but don't output anything
		TRACE_RETURN_SUCCESS;
	}
	// Handle Apple/Objective-C block_invoke patterns
	// These appear as suffixes after the main symbol
	// Look for block_invoke followed by optional number
	if (READ_STR("block_invoke")) {
		AST_APPEND_STR(" block_invoke");
		if (READ('_')) {
			AST_APPEND_STR("_");
			DemStringView num_str = { 0 };
			if (parse_number(p, &num_str, false)) {
				// Append the number string as-is from the input
				AST_APPEND_STRN(num_str.buf, num_str.len);
			}
		}
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(vendor_specific_suffix);
}

bool rule_number(DemParser *p, DemResult *r) {
	RULE_HEAD(NUMBER);
	if (!(isdigit(PEEK()) || (PEEK() == 'n' && isdigit(PEEK_AT(1))))) {
		TRACE_RETURN_FAILURE();
	}
	bool is_negative = READ('n');
	ut64 num = 0;
	if (!parse_non_neg_integer(p, &num)) {
		TRACE_RETURN_FAILURE();
	}
	// Format and append the number
	char buf[64];
	snprintf(buf, sizeof(buf), "%s%llu", is_negative ? "-" : "", (unsigned long long)num);
	AST_APPEND_STR(buf);
	TRACE_RETURN_SUCCESS;
}

bool rule_ctor_dtor_name(DemParser *p, DemResult *r, NameState *ns, PDemNode scope) {
	RULE_HEAD(CTOR_DTOR_NAME);

	if (scope && scope->tag == CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION) {
		scope->tag = CP_DEM_TYPE_KIND_EXPANDED_SPECIAL_SUBSTITUTION;
	}

	// NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
	if (READ('C')) {
		bool IsInherited = READ('I');
		if (PEEK() < '1' && PEEK() > '5') {
			TRACE_RETURN_FAILURE();
		}
		ADV();
		if (IsInherited) {
			MUST_MATCH(CALL_RULE_VA(rule_name, ns));
		}
		if (ns) {
			ns->is_conversion_ctor_dtor = true;
		}
		node->ctor_dtor_name.name = scope;
		TRACE_RETURN_SUCCESS;
	}

	if (READ('D')) {
		if (PEEK() < '0' && PEEK() > '5') {
			TRACE_RETURN_FAILURE();
		}
		ADV();
		if (ns) {
			ns->is_conversion_ctor_dtor = true;
		}
		node->ctor_dtor_name.is_dtor = true;
		node->ctor_dtor_name.name = scope;
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(ctor_dtor_name);
}

bool parse_module_name(DemParser *p, PDemNode *pmodule) {
	const ParseContext ctx = context_save_inline(p, NULL);
	while (READ('W')) {
		bool IsPartition = READ('P');
		DemResult result = { 0 };
		if (!rule_source_name(p, &result)) {
			return true;
		}

		DemNode *Sub = result.output;
		result.output = NULL;
		DemNode *sub_module = DemNode_ctor(CP_DEM_TYPE_KIND_MODULE_NAME, ctx.saved_pos, CUR() - ctx.saved_pos);
		if (!sub_module) {
			DemResult_deinit(&result);
			return false;
		}
		sub_module->module_name_ty.pare = pmodule ? *pmodule : NULL;
		sub_module->module_name_ty.IsPartition = IsPartition;
		sub_module->module_name_ty.name = Sub;
		AST_APPEND_TYPE1(sub_module);
		if (pmodule) {
			*pmodule = sub_module;
		}
	}
	return true;
}

PDemNode parse_abi_tags(DemParser *p, PDemNode node) {
	while (READ('B')) {
		DemStringView tag = { 0 };
		if (!parse_base_source_name(p, &tag.buf, &tag.len)) {
			return NULL;
		}
		PDemNode tagged = DemNode_ctor(CP_DEM_TYPE_KIND_ABI_TAG_TY, tag.buf, tag.len);
		if (!tagged) {
			return NULL;
		}
		tagged->abi_tag_ty.tag = tag;
		tagged->abi_tag_ty.ty = node;
		node = tagged;
	}
	return node;
}

bool rule_unqualified_name(DemParser *p, DemResult *r,
	NameState *ns, DemNode *scope, DemNode *module) {
	RULE_HEAD(UNQUALIFIED_NAME);

	if (!parse_module_name(p, &module)) {
		TRACE_RETURN_FAILURE();
	}

	bool is_member_like_friend = scope && READ('F');
	READ('L');

	DemNode *result = NULL;
	if (READ_STR("DC")) {
		CALL_MANY1_N(result, rule_source_name, ", ", 'E');
		if (result) {
			// Wrap structured binding names in brackets: [a1, a2]
			DemNode *wrapper = DemNode_ctor(CP_DEM_TYPE_KIND_MANY, result->val.buf, result->val.len);
			if (!wrapper) {
				TRACE_RETURN_FAILURE();
			}
			wrapper->many_ty.sep = "";
			Node_append(wrapper, make_primitive_type(CUR(), CUR(), "[", 1));
			Node_append(wrapper, result);
			Node_append(wrapper, make_primitive_type(CUR(), CUR(), "]", 1));
			result = wrapper;
		}
	} else if (PEEK() == 'U') {
		CALL_RULE_N(result, rule_unnamed_type_name);
	} else if (PEEK() == 'D' || PEEK() == 'C') {
		if (scope == NULL || module != NULL) {
			TRACE_RETURN_FAILURE();
		}
		CALL_RULE_N_VA(result, rule_ctor_dtor_name, ns, scope);
	} else if (isdigit(PEEK())) {
		CALL_RULE_N(result, rule_source_name);
	} else {
		CALL_RULE_N_VA(result, rule_operator_name, ns);
	}

	if (result && module) {
		// Attach module name: name@module
		DemNode *wrapper = DemNode_ctor(CP_DEM_TYPE_KIND_MANY, result->val.buf, result->val.len);
		if (!wrapper) {
			DemNode_dtor(result);
			DemNode_dtor(module);
			TRACE_RETURN_FAILURE();
		}
		wrapper->many_ty.sep = "";
		Node_append(wrapper, result);
		Node_append(wrapper, make_primitive_type(CUR(), CUR(), "@", 1));
		Node_append(wrapper, module);
		result = wrapper;
	}
	if (result) {
		result = parse_abi_tags(p, result);
	}
	if (result && is_member_like_friend) {
		// TODO: MemberLikeFriendName
		DEM_UNREACHABLE;
	} else if (result && scope) {
		node->tag = CP_DEM_TYPE_KIND_NESTED_NAME;
		node->nested_name.qual = scope;
		node->nested_name.name = result;
		TRACE_RETURN_SUCCESS;
	}

	if (!result) {
		TRACE_RETURN_FAILURE();
	}
	RETURN_AND_OUTPUT_VAR(result);
}

bool rule_unresolved_name(DemParser *p, DemResult *r) {
	RULE_HEAD(UNRESOLVED_NAME);
	if (READ_STR("srN")) {
		MUST_MATCH((CALL_RULE(rule_unresolved_type)) &&
			(PEEK() == 'I' ? CALL_RULE(rule_template_args) : true));

		PDemNode qualifier_level = NULL;
		CALL_MANY_N(qualifier_level, rule_unresolved_qualifier_level, "::", 'E');
		if (qualifier_level && VecPDemNode_len(qualifier_level->children) > 0) {
			AST_APPEND_STR("::");
			AST_APPEND_NODE(qualifier_level);
		} else {
			DemNode_dtor(qualifier_level);
		}

		AST_APPEND_STR("::");
		MUST_MATCH(CALL_RULE(rule_base_unresolved_name));
		TRACE_RETURN_SUCCESS;
	}
	if (!(READ_STR("sr"))) {
		MUST_MATCH(CALL_RULE(rule_base_unresolved_name));
		TRACE_RETURN_SUCCESS
	}
	if (isdigit(PEEK())) {
		MUST_MATCH(CALL_MANY1(rule_unresolved_qualifier_level, "::", 'E'));
		AST_APPEND_STR("::");
	} else {
		MUST_MATCH(CALL_RULE(rule_unresolved_type));
		if (PEEK() == 'I') {
			MUST_MATCH(CALL_RULE(rule_template_args) && READ('E'));
		}
		AST_APPEND_STR("::");
	}
	MUST_MATCH(CALL_RULE(rule_base_unresolved_name));
	TRACE_RETURN_SUCCESS;
}

bool rule_unscoped_name(DemParser *p, DemResult *r, NameState *ns, bool *is_subst) {
	RULE_HEAD(UNSCOPED_NAME);

	DemNode *std_node = NULL;
	if (READ_STR("St")) {
		std_node = make_primitive_type(CUR(), CUR(), "std", 3);
		if (!std_node) {
			TRACE_RETURN_FAILURE();
		}
	}

	DemNode *result = NULL;
	DemNode *module = NULL;
	if (PEEK() == 'S') {
		DemNode *subst = NULL;
		MUST_MATCH(CALL_RULE_N(subst, rule_substitution));
		if (subst->tag == CP_DEM_TYPE_KIND_MODULE_NAME) {
			module = subst;
		} else if (is_subst && !std_node) {
			*is_subst = true;
			result = subst;
		} else {
			DemNode_dtor(std_node);
			DemNode_dtor(result);
			DemNode_dtor(module);
			DemNode_dtor(subst);
			TRACE_RETURN_FAILURE();
		}
	}

	if (!result || std_node) {
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_VA_REPLACE_NODE(rule_unqualified_name, ns, std_node, module));
	}
	if (result) {
		RETURN_AND_OUTPUT_VAR(result);
	}
	RULE_FOOT(unscoped_name);
}

bool rule_unresolved_type(DemParser *p, DemResult *r) {
	RULE_HEAD(UNRESOLVED_TYPE);
	TRY_MATCH((CALL_RULE(rule_template_param)) && (((CALL_RULE(rule_template_args))) || true) && AST_APPEND_TYPE);
	TRY_MATCH((CALL_RULE(rule_decltype)) && AST_APPEND_TYPE);
	TRY_MATCH(CALL_RULE(rule_substitution));
	RULE_FOOT(unresolved_type);
}

bool rule_unresolved_qualifier_level(DemParser *p, DemResult *r) {
	RULE_HEAD(UNRESOLVED_QUALIFIER_LEVEL);
	TRY_MATCH(CALL_RULE(rule_simple_id));
	RULE_FOOT(unresolved_qualifier_level);
}

bool rule_decltype(DemParser *p, DemResult *r) {
	RULE_HEAD(DECLTYPE);
	if (!(READ_STR("Dt") || READ_STR("DT"))) {
		TRACE_RETURN_FAILURE();
	}
	PDemNode expr = NULL;
	MUST_MATCH(CALL_RULE_N(expr, rule_expression) && READ('E'));
	AST_APPEND_STR("decltype(");
	AST_APPEND_NODE(expr);
	AST_APPEND_STR(")");
	TRACE_RETURN_SUCCESS;
}

bool rule_array_type(DemParser *p, DemResult *r) {
	RULE_HEAD(ARRAY_TYPE);
	MUST_MATCH(READ('A'));
	node->subtag = ARRAY_TYPE;
	if (PEEK() == '_') {
		// Empty dimension: A_<type> - just consume the '_' without creating a size node
		MUST_MATCH(READ('_'));
		DemNode_dtor(node->array_ty.dimension);
		node->array_ty.dimension = NULL;
	} else if (isdigit(PEEK())) {
		MUST_MATCH(CALL_RULE_N(node->array_ty.dimension, rule_number) && READ('_'));
	} else {
		MUST_MATCH(CALL_RULE_N(node->array_ty.dimension, rule_expression) && READ('_'));
	}
	MUST_MATCH(CALL_RULE_N(node->array_ty.inner_ty, rule_type));
	TRACE_RETURN_SUCCESS;
}

bool rule_vector_type(DemParser *p, DemResult *r) {
	RULE_HEAD(VECTOR_TYPE);
	MUST_MATCH(READ_STR("Dv"));
	if (isdigit(PEEK())) {
		MUST_MATCH(CALL_RULE_N(node->array_ty.dimension, rule_number) && READ('_'));
		if (READ('p')) {
			PDemNode dim = node->array_ty.dimension;
			node->array_ty.dimension = NULL;
			AST_APPEND_STR("pixel vector[");
			AST_APPEND_NODE(dim);
			AST_APPEND_STR("]");
			node->tag = CP_DEM_TYPE_KIND_TYPE;
			TRACE_RETURN_SUCCESS;
		}
	} else if (!READ('_')) {
		MUST_MATCH(CALL_RULE_N(node->array_ty.dimension, rule_expression) && READ('_'));
	}
	MUST_MATCH(CALL_RULE_N(node->array_ty.inner_ty, rule_type));
	TRACE_RETURN_SUCCESS;
}

typedef enum {
	Prefix, // Prefix unary: @ expr
	Postfix, // Postfix unary: expr @
	Binary, // Binary: lhs @ rhs
	Array, // Array index:  lhs [ rhs ]
	Member, // Member access: lhs @ rhs
	New, // New
	Del, // Delete
	Call, // Function call: expr (expr*)
	CCast, // C cast: (type)expr
	Conditional, // Conditional: expr ? expr : expr
	NameOnly, // Overload only, not allowed in expression.
	// Below do not have operator names
	NamedCast, // Named cast, @<type>(expr)
	OfIdOp, // alignof, sizeof, typeid
	Unnameable,
} OIKind;

typedef struct {
	char Enc[2]; // Encoding
	OIKind Kind; // Kind of operator
	bool Flag; // Entry-specific flag
	Prec Prec; // Precedence
	const char *Name; // Spelling
} OperatorInfo;

static const OperatorInfo Ops[] = {
	// Keep ordered by encoding
	{ "aN", Binary, false, ASSIGN, "operator&=" },
	{ "aS", Binary, false, ASSIGN, "operator=" },
	{ "aa", Binary, false, ANDIF, "operator&&" },
	{ "ad", Prefix, false, UNARY, "operator&" },
	{ "an", Binary, false, AND, "operator&" },
	{ "at", OfIdOp, /*Type*/ true, UNARY, "alignof " },
	{ "aw", NameOnly, false, PRIMARY,
		"operator co_await" },
	{ "az", OfIdOp, /*Type*/ false, UNARY, "alignof " },
	{ "cc", NamedCast, false, PPOSTFIX, "const_cast" },
	{ "cl", Call, /*Paren*/ false, PPOSTFIX,
		"operator()" },
	{ "cm", Binary, false, COMMA, "operator," },
	{ "co", Prefix, false, UNARY, "operator~" },
	{ "cp", Call, /*Paren*/ true, PPOSTFIX,
		"operator()" },
	{ "cv", CCast, false, CAST, "operator" }, // C CAST
	{ "dV", Binary, false, ASSIGN, "operator/=" },
	{ "da", Del, /*Ary*/ true, UNARY,
		"operator delete[]" },
	{ "dc", NamedCast, false, PPOSTFIX, "dynamic_cast" },
	{ "de", Prefix, false, UNARY, "operator*" },
	{ "dl", Del, /*Ary*/ false, UNARY,
		"operator delete" },
	{ "ds", Member, /*Named*/ false, PTRMEM,
		"operator.*" },
	{ "dt", Member, /*Named*/ false, PPOSTFIX,
		"operator." },
	{ "dv", Binary, false, ASSIGN, "operator/" },
	{ "eO", Binary, false, ASSIGN, "operator^=" },
	{ "eo", Binary, false, XOR, "operator^" },
	{ "eq", Binary, false, EQUALITY, "operator==" },
	{ "ge", Binary, false, RELATIONAL, "operator>=" },
	{ "gt", Binary, false, RELATIONAL, "operator>" },
	{ "ix", Array, false, PPOSTFIX, "operator[]" },
	{ "lS", Binary, false, ASSIGN, "operator<<=" },
	{ "le", Binary, false, RELATIONAL, "operator<=" },
	{ "ls", Binary, false, SHIFT, "operator<<" },
	{ "lt", Binary, false, RELATIONAL, "operator<" },
	{ "mI", Binary, false, ASSIGN, "operator-=" },
	{ "mL", Binary, false, ASSIGN, "operator*=" },
	{ "mi", Binary, false, ADDITIVE, "operator-" },
	{ "ml", Binary, false, MULTIPLICATIVE,
		"operator*" },
	{ "mm", Postfix, false, PPOSTFIX, "operator--" },
	{ "na", New, /*Ary*/ true, UNARY,
		"operator new[]" },
	{ "ne", Binary, false, EQUALITY, "operator!=" },
	{ "ng", Prefix, false, UNARY, "operator-" },
	{ "nt", Prefix, false, UNARY, "operator!" },
	{ "nw", New, /*Ary*/ false, UNARY, "operator new" },
	{ "oR", Binary, false, ASSIGN, "operator|=" },
	{ "oo", Binary, false, ORIF, "operator||" },
	{ "or", Binary, false, IOR, "operator|" },
	{ "pL", Binary, false, ASSIGN, "operator+=" },
	{ "pl", Binary, false, ADDITIVE, "operator+" },
	{ "pm", Member, /*Named*/ true, PTRMEM,
		"operator->*" },
	{ "pp", Postfix, false, PPOSTFIX, "operator++" },
	{ "ps", Prefix, false, UNARY, "operator+" },
	{ "pt", Member, /*Named*/ true, PPOSTFIX,
		"operator->" },
	{ "qu", Conditional, false, PCONDITIONAL,
		"operator?" },
	{ "rM", Binary, false, ASSIGN, "operator%=" },
	{ "rS", Binary, false, ASSIGN, "operator>>=" },
	{ "rc", NamedCast, false, PPOSTFIX,
		"reinterpret_cast" },
	{ "rm", Binary, false, MULTIPLICATIVE,
		"operator%" },
	{ "rs", Binary, false, SHIFT, "operator>>" },
	{ "sc", NamedCast, false, PPOSTFIX, "static_cast" },
	{ "ss", Binary, false, SPACESHIP, "operator<=>" },
	{ "st", OfIdOp, /*Type*/ true, UNARY, "sizeof " },
	{ "sz", OfIdOp, /*Type*/ false, UNARY, "sizeof " },
	{ "te", OfIdOp, /*Type*/ false, PPOSTFIX,
		"typeid " },
	{ "ti", OfIdOp, /*Type*/ true, PPOSTFIX, "typeid " },
};
static const size_t NumOps = sizeof(Ops) / sizeof(Ops[0]);

const OperatorInfo *parse_operator_info(DemParser *p) {
	if (P_SIZE() < 2) {
		return NULL;
	}

	size_t lower = 0u, upper = NumOps - 1;
	while (upper != lower) {
		size_t middle = (upper + lower) / 2;
		if (Ops[middle].Enc[0] < PEEK() || (Ops[middle].Enc[0] == PEEK() && Ops[middle].Enc[1] < PEEK_AT(1))) {
			lower = middle + 1;
		} else {
			upper = middle;
		}
	}
	if (!(Ops[lower].Enc[0] == PEEK() && Ops[lower].Enc[1] == PEEK_AT(1))) {
		return NULL;
	}

	ADV_BY(2);
	return &Ops[lower];
}

const char *opinfo_get_symbol(const OperatorInfo *opinfo) {
	if (opinfo->Kind < Unnameable) {
		if (strncmp(opinfo->Name, "operator", 8) != 0) {
			return opinfo->Name;
		}
		if (*(opinfo->Name + 8) == ' ') {
			return opinfo->Name + 9; // skip "operator "
		}
		return opinfo->Name + 8; // skip "operator"
	}
	return opinfo->Name;
}

bool rule_operator_name(DemParser *p, DemResult *r, NameState *ns) {
	RULE_HEAD(OPERATOR_NAME);
	const OperatorInfo *Op = parse_operator_info(p);
	if (Op) {
		if (Op->Kind == CCast) {
			bool saved_not_parse = p->not_parse_template_args;
			bool saved_permit_forward_template_refs = p->permit_forward_template_refs;
			p->not_parse_template_args = true;
			p->permit_forward_template_refs = saved_permit_forward_template_refs || ns != NULL;

			MUST_MATCH(CALL_RULE_N(node->conv_op_ty.ty, rule_type));

			if (ns) {
				ns->is_conversion_ctor_dtor = true;
			}
			node->tag = CP_DEM_TYPE_KIND_CONV_OP_TY;

			p->not_parse_template_args = saved_not_parse;
			p->permit_forward_template_refs = saved_permit_forward_template_refs;
			TRACE_RETURN_SUCCESS;
		}
		if (Op->Kind >= Unnameable) {
			TRACE_RETURN_FAILURE();
		}
		if (Op->Kind == Member && !Op->Flag) {
			TRACE_RETURN_FAILURE();
		}

		AST_APPEND_STR(Op->Name);
		TRACE_RETURN_SUCCESS;
	}

	if (READ_STR("li")) {
		// ::= li <source-name>  # operator ""
		PDemNode opname = NULL;
		MUST_MATCH(CALL_RULE_N(opname, rule_source_name));
		AST_APPEND_STR("operator\"\" ");
		AST_APPEND_NODE(opname);
		TRACE_RETURN_SUCCESS;
	}

	if (READ_STR("v")) {
		// ::= v <digit> <source-name>        # vendor extended operator
		ut64 num = 0;
		if (!parse_non_neg_integer(p, &num)) {
			TRACE_RETURN_FAILURE();
		}
		MUST_MATCH(CALL_RULE(rule_source_name));
		TRACE_RETURN_SUCCESS;
	}

	RULE_FOOT(operator_name);
}

bool rule_expr_primary(DemParser *p, DemResult *r) {
	RULE_HEAD(EXPR_PRIMARY);
	if (!READ('L')) {
		TRACE_RETURN_FAILURE();
	}
	TRY_MATCH(PEEK() == 'P' && AST_APPEND_STR("(") && (CALL_RULE(rule_type)) &&
		AST_APPEND_STR(")") && READ('0') && AST_APPEND_STR("0") && READ('E'));
	TRY_MATCH(READ_STR("_Z") && (CALL_RULE(rule_encoding)) && READ('E'));
	TRY_MATCH(READ_STR("Dn0E") && AST_APPEND_STR("nullptr"));

	// Non-type template parameter: L<type><value>E
	// For bool: Lb0E -> false, Lb1E -> true
	TRY_MATCH(READ_STR("b0E") && AST_APPEND_STR("false"));
	TRY_MATCH(READ_STR("b1E") && AST_APPEND_STR("true"));

	// For simple builtin integer types, build an IntegerLiteral node
	// Examples: Lj4E -> 4u, Li5E -> 5, Lm6E -> 6ul
	context_save(literal);
	char type_code = PEEK();
	const char *type_name = NULL;
	size_t type_name_len = 0;
	bool is_literal_int = false;

	switch (type_code) {
	case 'i': // int
		type_name = "int";
		type_name_len = 3;
		is_literal_int = true;
		break;
	case 'j': // unsigned int
		type_name = "unsigned int";
		type_name_len = 12;
		is_literal_int = true;
		break;
	case 'l': // long
		type_name = "long";
		type_name_len = 4;
		is_literal_int = true;
		break;
	case 'm': // unsigned long
		type_name = "unsigned long";
		type_name_len = 13;
		is_literal_int = true;
		break;
	case 'x': // long long
		type_name = "long long";
		type_name_len = 9;
		is_literal_int = true;
		break;
	case 'y': // unsigned long long
		type_name = "unsigned long long";
		type_name_len = 18;
		is_literal_int = true;
		break;
	case 'c': // char
		type_name = "char";
		type_name_len = 4;
		is_literal_int = true;
		break;
	case 'a': // signed char
		type_name = "signed char";
		type_name_len = 11;
		is_literal_int = true;
		break;
	case 'h': // unsigned char
		type_name = "unsigned char";
		type_name_len = 13;
		is_literal_int = true;
		break;
	case 's': // short
		// Use cast notation for short types
		is_literal_int = false;
		break;
	case 't': // unsigned short
		// Use cast notation for unsigned short types
		is_literal_int = false;
		break;
	default:
		break;
	}

	if (is_literal_int) {
		ADV(); // skip type code
		// Capture the value portion (including optional 'n' for negative)
		const char *value_begin = CUR();
		bool is_negative = READ('n');
		(void)is_negative;
		ut64 num = 0;
		if (parse_non_neg_integer(p, &num) && READ('E')) {
			const char *value_end = CUR() - 1; // exclude 'E'
			node->tag = CP_DEM_TYPE_KIND_INTEGER_LITERAL;
			node->integer_literal_expr.type.buf = type_name;
			node->integer_literal_expr.type.len = type_name_len;
			node->integer_literal_expr.value.buf = value_begin;
			node->integer_literal_expr.value.len = (size_t)(value_end - value_begin);
			TRACE_RETURN_SUCCESS;
		}
	}
	context_restore(literal);

	// For other types: L<type><number>E -> (<type>)<number>
	// We need to append: "(" type ")" number
	// First append "("
	AST_APPEND_STR("(");
	// Then parse and append the type
	if (CALL_RULE(rule_type)) {
		// Append ")"
		AST_APPEND_STR(")");
		// Now try to parse and append the number
		bool is_negative = READ('n');
		ut64 num = 0;
		if (parse_non_neg_integer(p, &num) && READ('E')) {
			// Format and append the number
			char buf[64];
			int len = snprintf(buf, sizeof(buf), "%s%llu",
				is_negative ? "-" : "", (unsigned long long)num);
			if (len > 0 && len < (int)sizeof(buf)) {
				AST_APPEND_STRN(buf, len);
			}
			TRACE_RETURN_SUCCESS;
		}
		// If number parsing failed, try float
		TRY_MATCH((CALL_RULE(rule_float)) && READ('E'));
		TRY_MATCH((CALL_RULE(rule_float)) && READ('_') && (CALL_RULE(rule_float)) && READ('E'));
	}
	RULE_FOOT(expr_primary);
}

bool rule_braced_expression(DemParser *p, DemResult *r) {
	RULE_HEAD(BRACED_EXPRESSION);
	if (PEEK() == 'd') {
		switch (PEEK_AT(1)) {
		case 'X':
			ADV_BY(2);
			node->tag = CP_DEM_TYPE_KIND_BRACED_RANGE_EXPRESSION;
			MUST_MATCH(CALL_RULE_N(node->braced_range_expr.first, rule_expression));
			MUST_MATCH(CALL_RULE_N(node->braced_range_expr.last, rule_expression));
			MUST_MATCH(CALL_RULE_N(node->braced_range_expr.init, rule_braced_expression));
			TRACE_RETURN_SUCCESS;
		case 'i':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE_N(node->braced_expr.elem, rule_source_name));
			MUST_MATCH(CALL_RULE_N(node->braced_expr.init, rule_braced_expression));
			node->braced_expr.is_array = false;
			TRACE_RETURN_SUCCESS;
		case 'x':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE_N(node->braced_expr.elem, rule_expression));
			MUST_MATCH(CALL_RULE_N(node->braced_expr.init, rule_braced_expression));
			node->braced_expr.is_array = true;
			TRACE_RETURN_SUCCESS;
		default:
			break;
		}
	}
	RETURN_SUCCESS_OR_FAIL(CALL_RULE_REPLACE_NODE(rule_expression));
}

static void swap(void **a, void **b) {
	void *temp = *a;
	*a = *b;
	*b = temp;
}

bool rule_fold_expression(DemParser *p, DemResult *r) {
	RULE_HEAD(FOLD_EXPRESSION);
	if (!READ('f')) {
		TRACE_RETURN_FAILURE();
	}
	bool IsLeftFold = false, HasInitializer = false;
	switch (PEEK()) {
	default:
		TRACE_RETURN_FAILURE();
	case 'L':
		IsLeftFold = true;
		HasInitializer = true;
		break;
	case 'R':
		HasInitializer = true;
		break;
	case 'l':
		IsLeftFold = true;
		break;
	case 'r':
		break;
	}
	ADV();

	const OperatorInfo *Op = parse_operator_info(p);
	if (!Op) {
		TRACE_RETURN_FAILURE();
	}
	if (!(Op->Kind == Binary || (Op->Kind == Member && *opinfo_get_symbol(Op) == '*'))) {
		TRACE_RETURN_FAILURE();
	}

	DemNode *Pack = NULL;
	MUST_MATCH(CALL_RULE_N(Pack, rule_expression));

	DemNode *init = NULL;
	if (HasInitializer) {
		MUST_MATCH(CALL_RULE_N(init, rule_expression));
	}
	if (init && IsLeftFold) {
		swap((void **)&Pack, (void **)&init);
	}

	node->fold_expr.pack = Pack;
	node->fold_expr.init = init;
	node->fold_expr.is_left_fold = IsLeftFold;
	sv_form_cstr(&node->fold_expr.op, opinfo_get_symbol(Op));
	TRACE_RETURN_SUCCESS;
}

bool rule_prefix_expression(DemParser *p, DemResult *r, const OperatorInfo *op) {
	RULE_HEAD(PREFIX_EXPRESSION);
	MUST_MATCH(CALL_RULE_N(node->prefix_expr.inner, rule_expression));
	sv_form_cstr(&node->prefix_expr.prefix, opinfo_get_symbol(op));
	node->prec = op->Prec;
	TRACE_RETURN_SUCCESS;
}

bool rule_binary_expression(DemParser *p, DemResult *r, const OperatorInfo *op) {
	RULE_HEAD(BINARY_EXPRESSION);
	MUST_MATCH(CALL_RULE_N(node->binary_expr.lhs, rule_expression));
	sv_form_cstr(&node->binary_expr.op, opinfo_get_symbol(op));
	MUST_MATCH(CALL_RULE_N(node->binary_expr.rhs, rule_expression));
	node->prec = op->Prec;
	TRACE_RETURN_SUCCESS;
}

bool rule_expression(DemParser *p, DemResult *r) {
	RULE_HEAD(EXPRESSION);

	bool is_global = READ_STR("gs");
	const OperatorInfo *Op = parse_operator_info(p);
	if (Op) {
		switch (Op->Kind) {
		case Prefix: RETURN_SUCCESS_OR_FAIL(CALL_RULE_VA_REPLACE_NODE(rule_prefix_expression, Op));
		case Postfix:
			if (READ('_')) {
				RETURN_SUCCESS_OR_FAIL(CALL_RULE_VA_REPLACE_NODE(rule_prefix_expression, Op));
			}
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(opinfo_get_symbol(Op));
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case Binary: RETURN_SUCCESS_OR_FAIL(CALL_RULE_VA_REPLACE_NODE(rule_binary_expression, Op));
		case Array: // ix: arr[idx]
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("[");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("]");
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case Member: // dt/pt: expr.name / expr->name
			MUST_MATCH(CALL_RULE_N(node->member_expr.lhs, rule_expression));
			sv_form_cstr(&node->member_expr.op, opinfo_get_symbol(Op));
			MUST_MATCH(CALL_RULE_N(node->member_expr.rhs, rule_expression));
			node->prec = Op->Prec;
			node->tag = CP_DEM_TYPE_KIND_MEMBER_EXPRESSION;
			TRACE_RETURN_SUCCESS;
		case New: // nw/na
			node->new_expr.is_global = is_global;
			sv_form_cstr(&node->new_expr.op, opinfo_get_symbol(Op));
			MUST_MATCH(CALL_MANY_N(node->new_expr.expr_list, rule_expression, ", ", '_'));
			MUST_MATCH(CALL_RULE_N(node->new_expr.ty, rule_type));

			bool has_inits = READ_STR("pi");
			if (PEEK() != 'E') {
				if (!has_inits) {
					TRACE_RETURN_FAILURE();
				}
				MUST_MATCH(CALL_MANY_N(node->new_expr.init_list, rule_expression, ", ", 'E'));
			}
			node->prec = Op->Prec;
			node->tag = CP_DEM_TYPE_KIND_NEW_EXPRESSION;
			TRACE_RETURN_SUCCESS;
		case Del: // dl/da
			if (is_global) {
				AST_APPEND_STR("::");
			}
			AST_APPEND_STR(opinfo_get_symbol(Op));
			AST_APPEND_STR(" ");
			MUST_MATCH(CALL_RULE(rule_expression));
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case Call: // cl: func(args)
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("(");
			MUST_MATCH(CALL_MANY(rule_expression, ", ", 'E'));
			AST_APPEND_STR(")");
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case CCast: // cv: (type)expr or (type)(args)
			AST_APPEND_STR("(");
			MUST_MATCH(CALL_RULE(rule_type));
			AST_APPEND_STR(")");
			if (READ('_')) {
				AST_APPEND_STR("(");
				MUST_MATCH(CALL_MANY(rule_expression, ", ", 'E'));
				AST_APPEND_STR(")");
			} else {
				AST_APPEND_STR("(");
				MUST_MATCH(CALL_RULE(rule_expression));
				AST_APPEND_STR(")");
			}
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case Conditional: // qu: cond ? then : else
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(" ? ");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(" : ");
			MUST_MATCH(CALL_RULE(rule_expression));
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case NameOnly:
			TRACE_RETURN_FAILURE();
		case NamedCast: // dc/sc/cc/rc: cast<type>(expr)
			AST_APPEND_STR(opinfo_get_symbol(Op));
			AST_APPEND_STR("<");
			MUST_MATCH(CALL_RULE(rule_type));
			AST_APPEND_STR(">(");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(")");
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case OfIdOp: // st/sz/at/az/ti/te: sizeof/alignof/typeid
			AST_APPEND_STR(opinfo_get_symbol(Op));
			AST_APPEND_STR("(");
			if (Op->Flag) {
				MUST_MATCH(CALL_RULE(rule_type));
			} else {
				MUST_MATCH(CALL_RULE(rule_expression));
			}
			AST_APPEND_STR(")");
			node->prec = Op->Prec;
			TRACE_RETURN_SUCCESS;
		case Unnameable:
			TRACE_RETURN_FAILURE();
		}
		DEM_UNREACHABLE;
	}

	// Non-operator expressions
	if (is_global) {
		AST_APPEND_STR("::");
	}
	if (PEEK() == 'L') {
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_REPLACE_NODE(rule_expr_primary));
	}
	if (PEEK() == 'T') {
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_REPLACE_NODE(rule_template_param));
	}
	if (PEEK() == 'f') {
		if (PEEK_AT(1) == 'p' || (PEEK_AT(1) == 'L' && isdigit(PEEK_AT(2)))) {
			RETURN_SUCCESS_OR_FAIL(CALL_RULE(rule_function_param));
		}
		RETURN_SUCCESS_OR_FAIL(CALL_RULE(rule_fold_expression));
	}
	if (READ_STR("il")) {
		node->tag = CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION;
		RETURN_SUCCESS_OR_FAIL(CALL_MANY_N(node->init_list_expr.inits, rule_expression, ", ", 'E'));
	}
	if (READ_STR("tl")) {
		node->tag = CP_DEM_TYPE_KIND_INIT_LIST_EXPRESSION;
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_N(node->init_list_expr.ty, rule_type) && CALL_MANY_N(node->init_list_expr.inits, rule_braced_expression, ", ", 'E'));
	}
	if (READ_STR("nx")) {
		RETURN_SUCCESS_OR_FAIL(AST_APPEND_STR("noexcept (") && CALL_RULE(rule_expression) && AST_APPEND_STR(")"));
	}
	if (READ_STR("tw")) {
		RETURN_SUCCESS_OR_FAIL(AST_APPEND_STR("throw ") && CALL_RULE(rule_expression));
	}
	if (READ_STR("tr")) {
		RETURN_SUCCESS_OR_FAIL(AST_APPEND_STR("throw"));
	}
	if (READ_STR("sZ")) {
		RETURN_SUCCESS_OR_FAIL(AST_APPEND_STR("sizeof...(") && (CALL_RULE(rule_template_param) || CALL_RULE(rule_function_param)) && AST_APPEND_STR(")"));
	}
	if (READ_STR("sP")) {
		RETURN_SUCCESS_OR_FAIL(AST_APPEND_STR("sizeof...(") && CALL_MANY(rule_template_arg, "", 'E') && AST_APPEND_STR(")"));
	}
	if (READ_STR("sp")) {
		MUST_MATCH(CALL_RULE_N(node->child, rule_expression));
		node->tag = CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION;
		TRACE_RETURN_SUCCESS;
	}
	if (READ('u')) {
		PDemNode name = NULL;
		MUST_MATCH(CALL_RULE_N(name, rule_source_name));

		bool is_uuid = false;
		PDemNode uuid = NULL;
		DemStringView base_name = { 0 };
		if (!node_base_name(name, &base_name)) {
			TRACE_RETURN_FAILURE();
		}
		if (sv_eq_cstr(&base_name, "__uuidof")) {
			if (READ('t')) {
				MUST_MATCH(CALL_RULE_N(uuid, rule_type));
				is_uuid = true;
			} else if (READ('z')) {
				MUST_MATCH(CALL_RULE_N(uuid, rule_expression));
				is_uuid = true;
			}
		}

		PDemNode args = NULL;
		if (is_uuid) {
			if (!uuid) {
				TRACE_RETURN_FAILURE();
			}
			args = DemNode_ctor(CP_DEM_TYPE_KIND_MANY, name->val.buf, CUR() - name->val.buf);
			if (!args) {
				TRACE_RETURN_FAILURE();
			}
			Node_append(args, uuid);
		} else {
			CALL_MANY_N(args, rule_template_arg, ", ", '\0');
		}
		AST_APPEND_NODE(name);
		AST_APPEND_STR("(");
		AST_APPEND_NODE(args);
		AST_APPEND_STR(")");
		TRACE_RETURN_SUCCESS;
	}

	RETURN_SUCCESS_OR_FAIL(CALL_RULE(rule_unresolved_name));
}

bool rule_simple_id(DemParser *p, DemResult *r) {
	RULE_HEAD(SIMPLE_ID);
	TRY_MATCH((CALL_RULE(rule_source_name)) && (((CALL_RULE(rule_template_args))) || true));
	RULE_FOOT(simple_id);
}

bool rule_template_param(DemParser *p, DemResult *r) {
	RULE_HEAD(TEMPLATE_PARAM);
	if (!(READ('T'))) {
		TRACE_RETURN_FAILURE();
	}
	ut64 level = 0;
	if (READ('L')) {
		if (!(parse_non_neg_integer(p, &level) && READ('_'))) {
			TRACE_RETURN_FAILURE();
		}
		level++;
	}
	ut64 index = 0;
	if (!READ('_')) {
		if (!(parse_non_neg_integer(p, &index) && READ('_'))) {
			TRACE_RETURN_FAILURE();
		}
		index++;
	}

	if (p->permit_forward_template_refs && level == 0) {
		PForwardTemplateRef fwd = calloc(sizeof(ForwardTemplateRef), 1);
		if (!fwd) {
			TRACE_RETURN_FAILURE();
		}
		fwd->level = level;
		fwd->index = index;
		PForwardTemplateRef *pfwd = VecF(PForwardTemplateRef, append)(&p->forward_template_refs, &fwd);
		if (!pfwd) {
			free(fwd);
			TRACE_RETURN_FAILURE();
		}

		node->fwd_template_ref = fwd;
		node->tag = CP_DEM_TYPE_KIND_FWD_TEMPLATE_REF;

		if (p->trace) {
			fprintf(stderr, "[template_param] Created forward ref L%" PRIu64 "_%" PRIu64 " to %p\n",
				level, index, (void *)node);
		}
		TRACE_RETURN_SUCCESS;
	}

	if (level >= VecPNodeList_len(&p->template_params) || VecPNodeList_at(&p->template_params, level) == NULL || index >= VecPDemNode_len(*VecPNodeList_at(&p->template_params, level))) {
		if (p->parse_lambda_params_at_level == level && level <= VecPNodeList_len(&p->template_params)) {
			if (level == VecPNodeList_len(&p->template_params)) {
				VecPNodeList_append(&p->template_params, NULL);
			}
			PRIMITIVE_TYPE("auto");
			TRACE_RETURN_FAILURE();
		}
		TRACE_RETURN_FAILURE();
	}

	DemNode *t = template_param_get(p, level, index);
	if (!t) {
		TRACE_RETURN_FAILURE();
	}
	DemNode_copy(node, t);
	TRACE_RETURN_SUCCESS;
}

bool rule_call_offset(DemParser *p, DemResult *r) {
	RULE_HEAD(CALL_OFFSET);
	if (READ('h')) {
		if (!READ('n')) {
			TRACE_RETURN_FAILURE();
		}
		ut64 x = 0;
		if (!parse_non_neg_integer(p, &x)) {
			TRACE_RETURN_FAILURE();
		}
		if (!READ('_')) {
			TRACE_RETURN_FAILURE();
		}
		AST_APPEND_STR("non-virtual thunk to ");
		TRACE_RETURN_SUCCESS;
	}
	if (READ('v')) {
		MUST_MATCH(parse_number(p, NULL, true) && READ('_') && parse_number(p, NULL, true) && READ('_'));
		AST_APPEND_STR("virtual thunk to ");
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(call_offset);
}

/*
 * NOTE: Taken from old c++v3 demangler code
 * Some of these are tested, others are not encountered yet.
 *
 * <special-name> ::= TV <type>
	  ::= TT <type>
	  ::= TI <type>
	  ::= TS <type>
	  ::= TA <template-arg>
	  ::= GV <(object) name>
	  ::= T <call-offset> <(base) encoding>
	  ::= Tc <call-offset> <call-offset> <(base) encoding>
   Also g++ extensions:
	  ::= TC <type> <(offset) number> _ <(base) type>
	  ::= TF <type>
	  ::= TJ <type>
	  ::= GR <name>
	  ::= GA <encoding>
	  ::= Gr <resource name>
	  ::= GTt <encoding>
	  ::= GTn <encoding>

	  ::= TW <object name> # Thread-local wrapper
	  ::= TH <object name> # Thread-local initialization
*/
bool rule_special_name(DemParser *p, DemResult *r) {
	RULE_HEAD(SPECIAL_NAME);
	switch (PEEK()) {
	case 'T':
		ADV();
		switch (PEEK()) {
		case 'C': {
			// TC <derived-type> <offset> _ <base-type>   # construction vtable
			ADV();
			DemNode *base_ty = NULL;
			DemNode *derived_ty = NULL;
			MUST_MATCH(CALL_RULE_N(base_ty, rule_type));
			ut64 offset = 0;
			MUST_MATCH(parse_non_neg_integer(p, &offset));
			AST_APPEND_STR("construction vtable for ");
			if (READ('_') && CALL_RULE_N(derived_ty, rule_type)) {
				AST_APPEND_NODE(derived_ty);
				AST_APPEND_STR("-in-");
				AST_APPEND_NODE(base_ty);
			} else {
				AST_APPEND_NODE(base_ty);
			}
			break;
		}
		case 'c':
			ADV();
			RETURN_SUCCESS_OR_FAIL(CALL_RULE(rule_call_offset) && CALL_RULE(rule_call_offset) && CALL_RULE(rule_encoding));
			break;
		case 'V':
			ADV();
			MUST_MATCH(AST_APPEND_STR("vtable for ") && CALL_RULE(rule_type));
			break;
		case 'T':
			ADV();
			MUST_MATCH(AST_APPEND_STR("VTT structure for ") && CALL_RULE(rule_type));
			break;
		case 'I':
			ADV();
			MUST_MATCH(AST_APPEND_STR("typeinfo for ") && CALL_RULE(rule_type));
			break;
		case 'S':
			ADV();
			MUST_MATCH(AST_APPEND_STR("typeinfo name for ") && CALL_RULE(rule_type));
			break;
		case 'A':
			ADV();
			MUST_MATCH(AST_APPEND_STR("template parameter object for ") && CALL_RULE(rule_template_arg));
			break;
		case 'W':
			ADV();
			MUST_MATCH(AST_APPEND_STR("thread-local wrapper routine for ") && CALL_RULE_VA(rule_name, NULL));
			break;
		case 'H':
			ADV();
			MUST_MATCH(AST_APPEND_STR("thread-local initialization routine for ") && CALL_RULE_VA(rule_name, NULL));
			break;
		default:
			MUST_MATCH(CALL_RULE(rule_call_offset) && CALL_RULE(rule_encoding));
			break;
		}
		break;
	case 'G':
		ADV();
		switch (PEEK()) {
		case 'I':
			ADV();
			PDemNode module_name = NULL;
			if (!parse_module_name(p, &module_name) || !module_name) {
				TRACE_RETURN_FAILURE();
			}
			MUST_MATCH(AST_APPEND_STR("initializer for module ") && AST_APPEND_NODE(module_name));
			break;
		case 'R':
			ADV();
			AST_APPEND_STR("reference temporary for ");
			MUST_MATCH(CALL_RULE_VA(rule_name, NULL));
			parse_seq_id(p, NULL);
			MUST_MATCH(READ('_'));
			break;
		case 'V':
			ADV();
			MUST_MATCH(AST_APPEND_STR("guard variable for ") && CALL_RULE_VA(rule_name, NULL));
			break;
		case 'A':
			ADV();
			MUST_MATCH(CALL_RULE(rule_encoding));
			break;
		case 'T':
			ADV();
			MUST_MATCH((READ('t') || READ('n')) && CALL_RULE(rule_encoding));
			break;
		default: break;
		};
		break;
	default:
		TRACE_RETURN_FAILURE();
		break;
	}
	TRACE_RETURN_SUCCESS;
}

bool rule_function_type(DemParser *p, DemResult *r) {
	RULE_HEAD(FUNCTION_TYPE);
	// This rule only handles F...E (bare function type)
	// P prefix is handled in the type rule, which properly inserts * for function pointers
	parse_cv_qualifiers(p, &node->fn_ty.cv_qualifiers);

	if (READ_STR("Do")) {
		node->fn_ty.exception_spec = MAKE_PRIMITIVE_TYPE(CUR() - 2, CUR(), "noexcept");
		if (!node->fn_ty.exception_spec) {
			TRACE_RETURN_FAILURE();
		}
	} else if (READ_STR("DO")) {
		PDemNode spec = NULL;
		MUST_MATCH(CALL_RULE_N(spec, rule_expression) && READ('E'));
		node->fn_ty.exception_spec = DemNode_ctor(CP_DEM_TYPE_KIND_NOEXCEPT_SPEC, saved_ctx_rule.saved_pos, CUR() - saved_ctx_rule.saved_pos);
		if (!node->fn_ty.exception_spec) {
			TRACE_RETURN_FAILURE();
		}
		node->fn_ty.exception_spec->child = spec;
	} else if (READ_STR("Dw")) {
		PDemNode spec = NULL;
		MUST_MATCH(CALL_MANY_N(spec, rule_type, ", ", 'E'));
		node->fn_ty.exception_spec = DemNode_ctor(CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC, saved_ctx_rule.saved_pos, CUR() - saved_ctx_rule.saved_pos);
		if (!node->fn_ty.exception_spec) {
			TRACE_RETURN_FAILURE();
		}
		node->fn_ty.exception_spec->child = spec;
	}

	READ_STR("Dx");
	MUST_MATCH(READ('F'));
	READ('Y');
	MUST_MATCH(CALL_RULE_N(node->fn_ty.ret, rule_type));

	node->fn_ty.params = DemNode_ctor(CP_DEM_TYPE_KIND_MANY, CUR(), 0);
	if (!node->fn_ty.params) {
		TRACE_RETURN_FAILURE();
	}
	node->fn_ty.params->many_ty.sep = ", ";
	while (true) {
		if (READ('E')) {
			break;
		}
		if (READ('v')) {
			continue;
		}
		if (READ_STR("RE")) {
			node->fn_ty.ref_qualifiers.is_l_value = true;
			break;
		}
		if (READ_STR("OE")) {
			node->fn_ty.ref_qualifiers.is_r_value = true;
			break;
		}
		PDemNode param = NULL;
		MUST_MATCH(CALL_RULE_N(param, rule_type));
		Node_append(node->fn_ty.params, param);
	}
	node->fn_ty.params->val.len = CUR() - node->fn_ty.params->val.buf;
	TRACE_RETURN_SUCCESS;
}

bool rule_function_param(DemParser *p, DemResult *r) {
	RULE_HEAD(FUNCTION_PARAM);
	if (READ_STR("PT")) {
		TRACE_RETURN_SUCCESS;
	}
	if (READ_STR("fpT")) {
		PRIMITIVE_TYPE("this");
		TRACE_RETURN_SUCCESS;
	}
	MUST_MATCH(READ('f'));
	CvQualifiers qualifiers = { 0 };
	if (READ('L')) {
		MUST_MATCH(CALL_RULE(rule_number));
	}
	MUST_MATCH(READ('p'));
	parse_cv_qualifiers(p, &qualifiers);
	AST_APPEND_STR(" ");
	CALL_RULE(rule_number);
	READ('_');
	TRACE_RETURN_SUCCESS;
}

bool rule_builtin_type(DemParser *p, DemResult *r) {
	RULE_HEAD(BUILTIN_TYPE);
	TRY_MATCH(READ_STR("DF") && AST_APPEND_STR("_Float") && (CALL_RULE(rule_number)) && READ('_'));
	TRY_MATCH(READ_STR("DF") && AST_APPEND_STR("_Float") && (CALL_RULE(rule_number)) && READ('x') && AST_APPEND_STR("x"));
	TRY_MATCH(READ_STR("DF") && AST_APPEND_STR("std::bfloat") && (CALL_RULE(rule_number)) && READ('b') && AST_APPEND_STR("_t"));
	TRY_MATCH(READ_STR("DB") && AST_APPEND_STR("signed _BitInt(") && (CALL_RULE(rule_number)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ_STR("DB") && AST_APPEND_STR("signed _BitInt(") && (CALL_RULE(rule_expression)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ_STR("DU") && AST_APPEND_STR("unsigned _BitInt(") && (CALL_RULE(rule_number)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ_STR("DU") && AST_APPEND_STR("unsigned _BitInt(") && (CALL_RULE(rule_expression)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ('u') && (CALL_RULE(rule_source_name)) && (((CALL_RULE(rule_template_args))) || true));
	TRY_MATCH(READ_STR("DS") && READ_STR("DA") && AST_APPEND_STR("_Sat _Accum"));
	TRY_MATCH(READ_STR("DS") && READ_STR("DR") && AST_APPEND_STR("_Sat _Fract"));
	TRY_MATCH(READ('v') && AST_APPEND_STR("void"));
	TRY_MATCH(READ('w') && AST_APPEND_STR("wchar_t"));
	TRY_MATCH(READ('b') && AST_APPEND_STR("bool"));
	TRY_MATCH(READ('c') && AST_APPEND_STR("char"));
	TRY_MATCH(READ('a') && AST_APPEND_STR("signed char"));
	TRY_MATCH(READ('h') && AST_APPEND_STR("unsigned char"));
	TRY_MATCH(READ('s') && AST_APPEND_STR("short"));
	TRY_MATCH(READ('t') && AST_APPEND_STR("unsigned short"));
	TRY_MATCH(READ('i') && AST_APPEND_STR("int"));
	TRY_MATCH(READ('j') && AST_APPEND_STR("unsigned int"));
	TRY_MATCH(READ('l') && AST_APPEND_STR("long"));
	TRY_MATCH(READ('m') && AST_APPEND_STR("unsigned long"));
	TRY_MATCH(READ('x') && AST_APPEND_STR("long long"));
	TRY_MATCH(READ('y') && AST_APPEND_STR("unsigned long long"));
	TRY_MATCH(READ('n') && AST_APPEND_STR("__int128"));
	TRY_MATCH(READ('o') && AST_APPEND_STR("unsigned __int128"));
	TRY_MATCH(READ('f') && AST_APPEND_STR("float"));
	TRY_MATCH(READ('d') && AST_APPEND_STR("double"));
	TRY_MATCH(READ('e') && AST_APPEND_STR("long double"));
	TRY_MATCH(READ('g') && AST_APPEND_STR("__float128"));
	TRY_MATCH(READ('z') && AST_APPEND_STR("..."));
	TRY_MATCH(READ_STR("Dd") && AST_APPEND_STR("decimal64"));
	TRY_MATCH(READ_STR("De") && AST_APPEND_STR("decimal128"));
	TRY_MATCH(READ_STR("Df") && AST_APPEND_STR("decimal32"));
	TRY_MATCH(READ_STR("Dh") && AST_APPEND_STR("half"));
	TRY_MATCH(READ_STR("Di") && AST_APPEND_STR("char32_t"));
	TRY_MATCH(READ_STR("Ds") && AST_APPEND_STR("char16_t"));
	TRY_MATCH(READ_STR("Du") && AST_APPEND_STR("char8_t"));
	TRY_MATCH(READ_STR("Da") && AST_APPEND_STR("auto"));
	TRY_MATCH(READ_STR("Dc") && AST_APPEND_STR("decltype(auto)"));
	TRY_MATCH(READ_STR("Dn") && AST_APPEND_STR("std::nullptr_t"));
	TRY_MATCH(READ_STR("DA") && AST_APPEND_STR("_Accum"));
	TRY_MATCH(READ_STR("DR") && AST_APPEND_STR("_Fract"));
	RULE_FOOT(builtin_type);
}

bool rule_source_name(DemParser *p, DemResult *r) {
	RULE_HEAD(SOURCE_NAME);
	/* positive number providing length of name followed by it */
	size_t name_len = 0;
	const char *name = NULL;
	if (!parse_base_source_name(p, &name, &name_len)) {
		TRACE_RETURN_FAILURE();
	}
	if (strncmp(name, "_GLOBAL__N", sizeof("_GLOBAL__N") - 1) == 0) {
		node = PRIMITIVE_TYPE("(anonymous namespace)");
	} else {
		PRIMITIVE_TYPEN(name, name_len);
	}
	TRACE_RETURN_SUCCESS;
}

bool rule_class_enum_type(DemParser *p, DemResult *r) {
	RULE_HEAD(CLASS_ENUM_TYPE);
	const char *elab_prefix = NULL;
	if (READ_STR("Ts")) {
		elab_prefix = "struct ";
	} else if (READ_STR("Tu")) {
		elab_prefix = "union ";
	} else if (READ_STR("Te")) {
		elab_prefix = "enum ";
	}
	DemNode *name = NULL;
	if (!CALL_RULE_N_VA(name, rule_name, NULL)) {
		TRACE_RETURN_FAILURE();
	}
	if (elab_prefix) {
		AST_APPEND_STR(elab_prefix);
		AST_APPEND_NODE(name);
	} else {
		DemNode_dtor(node);
		node = name;
	}
	TRACE_RETURN_SUCCESS;
}

bool rule_mangled_name(DemParser *p, DemResult *r) {
	RULE_HEAD(MANGLED_NAME);

	if (!READ_STR("_Z")) {
		TRACE_RETURN_FAILURE();
	}

	READ('L');
	MUST_MATCH(CALL_RULE(rule_encoding));

	// Try to match vendor-specific suffix
	READ('.');
	READ('_');
	CALL_RULE(rule_vendor_specific_suffix);
	TRACE_RETURN_SUCCESS;
}

bool rule_qualified_type(DemParser *p, DemResult *r) {
	RULE_HEAD(QUALIFIED_TYPE);
	if (PEEK() == 'U') {
		ADV();
		MUST_MATCH(parse_base_source_name(p, &node->vendor_ext_qualified_ty.vendor_ext.buf, &node->vendor_ext_qualified_ty.vendor_ext.len));
		if (PEEK() == 'I') {
			MUST_MATCH(CALL_RULE_N(node->vendor_ext_qualified_ty.template_args, rule_template_args));
		}
		MUST_MATCH(CALL_RULE_N(node->vendor_ext_qualified_ty.inner_type, rule_qualified_type));
		node->tag = CP_DEM_TYPE_KIND_VENDOR_EXT_QUALIFIED_TYPE;
		TRACE_RETURN_SUCCESS;
	}

	parse_cv_qualifiers(p, &node->qualified_ty.qualifiers);
	MUST_MATCH(CALL_RULE_N(node->qualified_ty.inner_type, rule_type));
	TRACE_RETURN_SUCCESS;
}

bool rule_type(DemParser *p, DemResult *r) {
	RULE_HEAD(TYPE);
	const char *before_builtin = CUR();
	if (CALL_RULE_REPLACE_NODE(rule_builtin_type)) {
		// Vendor-extended types (u<length><name>) should be added to substitution table
		// because they can be referenced by substitutions later
		if (*before_builtin == 'u') {
			goto beach;
		}
		TRACE_RETURN_SUCCESS;
	}
	if (CALL_RULE_REPLACE_NODE(rule_function_type)) {
		goto beach;
	}
	switch (PEEK()) {
	case 'r':
	case 'V':
	case 'K':
	case 'U': {
		MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_qualified_type));
		break;
	}
	case 'M':
		MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_pointer_to_member_type));
		break;
	case 'A':
		MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_array_type));
		break;
	case 'C':
		ADV();
		MUST_MATCH(CALL_RULE(rule_type));
		AST_APPEND_STR(" complex");
		break;
	case 'G':
		ADV();
		MUST_MATCH(CALL_RULE(rule_type));
		AST_APPEND_STR(" imaginary");
		break;
	case 'P':
	case 'R':
	case 'O': {
		ut32 subtag = 0;
		// Process pointer/reference types
		switch (PEEK()) {
		case 'P':
			subtag = POINTER_TYPE;
			break;
		case 'R':
			subtag = REFERENCE_TYPE;
			break;
		case 'O':
			subtag = RVALUE_REFERENCE_TYPE;
			break;
		default:
			DEM_UNREACHABLE;
		}
		ADV();
		MUST_MATCH(CALL_RULE(rule_type));
		// Reference collapsing (C++11 rules):
		// If the inner type is already a reference, apply collapsing:
		//   & + &  = &
		//   & + && = &
		//   && + & = &
		//   && + && = &&
		// In other words, if either is an lvalue ref, the result is lvalue ref.
		if (AST(0) && AST(0)->tag == CP_DEM_TYPE_KIND_TYPE &&
			(AST(0)->subtag == REFERENCE_TYPE || AST(0)->subtag == RVALUE_REFERENCE_TYPE)) {
			if (subtag == REFERENCE_TYPE || AST(0)->subtag == REFERENCE_TYPE) {
				// Collapse to lvalue reference: unwrap the inner ref
				// and set outer subtag to REFERENCE_TYPE
				subtag = REFERENCE_TYPE;
			}
			// else both are rvalue ref -> stays RVALUE_REFERENCE_TYPE
			// Unwrap the inner reference: promote its child to be our direct child
			PDemNode inner_child = AST(0);
			if (inner_child->children && inner_child->children->length > 0) {
				PDemNode *grandchild_ptr = VecPDemNode_at(inner_child->children, 0);
				if (grandchild_ptr && *grandchild_ptr) {
					PDemNode grandchild = *grandchild_ptr;
					*grandchild_ptr = NULL; // Prevent double-free
					// Replace inner_child with grandchild in node's children
					PDemNode *child_ptr = VecPDemNode_at(node->children, 0);
					if (child_ptr) {
						DemNode_dtor(*child_ptr);
						*child_ptr = grandchild;
					}
				}
			}
		}
		node->subtag = subtag;
		break;
	}
	case 'D':
		// Dp <type>       # pack expansion (C++0x)
		if (PEEK_AT(1) == 'p') {
			ADV_BY(2);
			MUST_MATCH(CALL_RULE_N(node->child, rule_type));
			node->tag = CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION;
			break;
		}
		if (PEEK_AT(1) == 'v') {
			MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_vector_type));
			break;
		}
		if (PEEK_AT(1) == 't' || PEEK_AT(1) == 'T') {
			MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_decltype));
			break;
		}
		// fallthrough
	case 'T': {
		if (strchr("sue", PEEK_AT(1)) != NULL) {
			MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_class_enum_type));
			break;
		}
		PDemNode template_param_node = NULL;
		PDemNode template_args_node = NULL;
		MUST_MATCH(CALL_RULE_N(template_param_node, rule_template_param));
		if (PEEK() == 'I' && !p->not_parse_template_args) {
			AST_APPEND_TYPE;
			CALL_RULE_N(template_args_node, rule_template_args);
			node->tag = CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS;
			node->name_with_template_args.name = template_param_node;
			node->name_with_template_args.template_args = template_args_node;
		} else {
			PDemNode saved_node = node;
			node = template_param_node;
			DemNode_dtor(saved_node);
		}
		break;
	}
	case 'S': {
		if (PEEK_AT(1) != 't') {
			bool is_subst = false;
			DemNode *result = NULL;
			CALL_RULE_N_VA(result, rule_unscoped_name, NULL, &is_subst);
			if (!result) {
				TRACE_RETURN_FAILURE();
			}
			if (PEEK() == 'I' && (!is_subst || !p->not_parse_template_args)) {
				if (!is_subst) {
					AST_APPEND_TYPE1(result);
				}
				DemNode *ta = NULL;
				CALL_RULE_N(ta, rule_template_args);
				if (!ta) {
					DemNode_dtor(result);
					TRACE_RETURN_FAILURE();
				}
				node->tag = CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS;
				node->name_with_template_args.name = result;
				node->name_with_template_args.template_args = ta;
			} else if (is_subst) {
				RETURN_AND_OUTPUT_VAR(result);
			} else {
				// Module-scoped name without template args:
				// replace node with result so it gets added to the
				// substitution table at beach: and returned properly.
				DemNode_dtor(node);
				node = result;
			}
			break;
		}
		// fallthrough
	}
	default:
		MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_class_enum_type));
		break;
	}

beach:
	if (CUR() > saved_ctx_rule.saved_pos) {
		AST_APPEND_TYPE;
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(type);
}

bool rule_base_unresolved_name(DemParser *p, DemResult *r) {
	RULE_HEAD(BASE_UNRESOLVED_NAME);
	TRY_MATCH((CALL_RULE(rule_simple_id)));
	if (READ_STR("dn")) {
		MUST_MATCH(CALL_RULE(rule_destructor_name));
		TRACE_RETURN_SUCCESS;
	}
	READ_STR("on");
	MUST_MATCH(CALL_RULE_VA(rule_operator_name, NULL));
	if (PEEK() == 'I') {
		MUST_MATCH(CALL_RULE(rule_template_args));
	}
	TRACE_RETURN_SUCCESS;
}

bool rule_local_name(DemParser *p, DemResult *r, NameState *ns) {
	RULE_HEAD(LOCAL_NAME);
	if (!READ('Z')) {
		TRACE_RETURN_FAILURE();
	}

	CALL_RULE_N(node->local_name.encoding, rule_encoding);
	if (!node->local_name.encoding || !READ('E')) {
		TRACE_RETURN_FAILURE();
	}

	const char *saved_pos = CUR();
	if (READ('s')) {
		parse_discriminator(p);
		DemNode *string_lit = make_primitive_type(saved_pos, CUR(), "string literal", strlen("string literal"));
		if (!string_lit) {
			TRACE_RETURN_FAILURE();
		}
		node->local_name.entry = string_lit;
		TRACE_RETURN_SUCCESS;
	}
	if (READ('d')) {
		CALL_RULE(rule_number);
		parse_number(p, NULL, true);
		if (!READ('_')) {
			TRACE_RETURN_FAILURE();
		}
		CALL_RULE_N_VA(node->local_name.entry, rule_name, ns);
		if (!node->local_name.entry) {
			TRACE_RETURN_FAILURE();
		}
		TRACE_RETURN_SUCCESS;
	}
	CALL_RULE_N_VA(node->local_name.entry, rule_name, ns);
	if (!node->local_name.entry) {
		TRACE_RETURN_FAILURE();
	}
	parse_discriminator(p);
	TRACE_RETURN_SUCCESS;
}

bool rule_substitution(DemParser *p, DemResult *r) {
	RULE_HEAD(SUBSTITUTION);
	if (!READ('S')) {
		TRACE_RETURN_FAILURE();
	}

	if (PEEK() >= 'a' && PEEK() <= 'z') {
		ut32 kind = 0;
		switch (PEEK()) {
		case 'a': kind = SPECIAL_SUBSTITUTION_ALLOCATOR; break;
		case 'b': kind = SPECIAL_SUBSTITUTION_BASIC_STRING; break;
		case 'd': kind = SPECIAL_SUBSTITUTION_IOSTREAM; break;
		case 'i': kind = SPECIAL_SUBSTITUTION_ISTREAM; break;
		case 'o': kind = SPECIAL_SUBSTITUTION_OSTREAM; break;
		case 's': kind = SPECIAL_SUBSTITUTION_STRING; break;
		default: TRACE_RETURN_FAILURE();
		}
		ADV();
		PDemNode special_subst = DemNode_ctor(CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION, saved_ctx_rule.saved_pos, CUR() - saved_ctx_rule.saved_pos);
		if (!special_subst) {
			TRACE_RETURN_FAILURE();
		}
		special_subst->subtag = kind;
		special_subst->tag = CP_DEM_TYPE_KIND_SPECIAL_SUBSTITUTION;

		PDemNode with_tags = parse_abi_tags(p, special_subst);
		if (with_tags && with_tags != special_subst) {
			AST_APPEND_TYPE1(with_tags);
			special_subst = with_tags;
		}

		RETURN_AND_OUTPUT_VAR(special_subst);
	}

	DemNode *child_node = NULL;
	if (!parse_seq_id(p, &child_node)) {
		TRACE_RETURN_FAILURE();
	}
	DemNode_copy(node, child_node);
	TRACE_RETURN_SUCCESS;
}

bool rule_float(DemParser *p, DemResult *r) {
	RULE_HEAD(FLOAT);
	while (IS_DIGIT(PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
		ADV();
	}
	RULE_FOOT(float);
}

bool rule_destructor_name(DemParser *p, DemResult *r) {
	RULE_HEAD(DESTRUCTOR_NAME);
	TRY_MATCH(CALL_RULE(rule_unresolved_type));
	TRY_MATCH(CALL_RULE(rule_simple_id));
	RULE_FOOT(destructor_name);
}

bool rule_name(DemParser *p, DemResult *r, NameState *ns) {
	RULE_HEAD(NAME);
	if (PEEK() == 'N') {
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_VA_REPLACE_NODE(rule_nested_name, ns));
	}
	if (PEEK() == 'Z') {
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_VA_REPLACE_NODE(rule_local_name, ns));
	}

	DemNode *result = NULL;
	bool is_subst = false;
	CALL_RULE_N_VA(result, rule_unscoped_name, ns, &is_subst);
	if (!result) {
		TRACE_RETURN_FAILURE();
	}

	// If unscoped_name parsed successfully, check for template_args
	if (PEEK() == 'I') {
		if (!is_subst) {
			AST_APPEND_TYPE1(result);
		}
		DemNode *ta = NULL;
		CALL_RULE_N_VA(ta, rule_template_args_ex, ns != NULL);
		if (!ta) {
			DemNode_dtor(result);
			TRACE_RETURN_FAILURE();
		}
		if (ns) {
			ns->end_with_template_args = true;
		}
		node->tag = CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS;
		node->name_with_template_args.name = result;
		node->name_with_template_args.template_args = ta;
		TRACE_RETURN_SUCCESS;
	}
	if (is_subst) {
		DemNode_dtor(result);
		TRACE_RETURN_FAILURE();
	}
	RETURN_AND_OUTPUT_VAR(result);
}

bool rule_nested_name(DemParser *p, DemResult *r, NameState *ns) {
	RULE_HEAD(NESTED_NAME);
	if (!READ('N')) {
		TRACE_RETURN_FAILURE();
	}
	CvQualifiers cv_quals = { 0 };
	RefQualifiers ref_qual = { 0 };
	if (parse_cv_qualifiers(p, &cv_quals) && ns) {
		ns->cv_qualifiers = cv_quals;
	}
	if (parse_ref_qualifiers(p, &ref_qual) && ns) {
		ns->ref_qualifiers = ref_qual;
	}

	DemNode *ast_node = NULL;
	while (!READ('E')) {
		if (ns) {
			ns->end_with_template_args = false;
		}
		if (PEEK() == 'T') {
			if (ast_node != NULL) {
				goto fail;
			}
			CALL_RULE_N(ast_node, rule_template_param);
		} else if (PEEK() == 'I') {
			if (ast_node == NULL) {
				TRACE_RETURN_FAILURE();
			}
			if (ast_node->tag == CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS) {
				goto fail;
			}
			DemNode *ta = NULL;
			MUST_MATCH(CALL_RULE_N_VA(ta, rule_template_args_ex, ns != NULL));
			if (ns) {
				ns->end_with_template_args = true;
			}
			ast_node = make_name_with_template_args(saved_ctx_rule.saved_pos, CUR(), ast_node, ta);
		} else if (PEEK() == 'D' && (PEEK_AT(1) == 't' || PEEK_AT(1) == 'T')) {
			if (ast_node != NULL) {
				goto fail;
			}
			CALL_RULE_N(ast_node, rule_decltype);
		} else {
			// Skip 'L' prefix for internal linkage
			if (PEEK() == 'L') {
				ADV();
			}
			DemNode *module = NULL;
			if (PEEK() == 'S') {
				DemNode *subst = NULL;
				if (PEEK_AT(1) == 't') {
					subst = make_primitive_type(CUR(), CUR() + 2, "std", 3);
					ADV_BY(2);
				} else {
					CALL_RULE_N(subst, rule_substitution);
				}
				if (subst->tag == CP_DEM_TYPE_KIND_MODULE_NAME) {
					module = subst;
				} else if (ast_node) {
					DemNode_dtor(subst);
					goto fail;
				} else {
					ast_node = subst;
					continue;
				}
			}
			DemNode *qual_name = NULL;
			CALL_RULE_N_VA(qual_name, rule_unqualified_name, ns, ast_node, module);
			if (!qual_name) {
				goto fail;
			}
			ast_node = qual_name;
		}
		if (ast_node == NULL) {
			TRACE_RETURN_FAILURE();
		}
		AST_APPEND_TYPE1(ast_node);
		READ('M');
	}
	if (ast_node == NULL || VecF(PDemNode, empty)(&p->detected_types)) {
		TRACE_RETURN_FAILURE();
	}
	DemNode **pop_node = VecF(PDemNode, pop)(&p->detected_types);
	if (pop_node) {
		DemNode_dtor(*pop_node);
	}
	RETURN_AND_OUTPUT_VAR(ast_node);
fail:
	DemNode_dtor(ast_node);
	TRACE_RETURN_FAILURE();
}

bool is_template_param_decl(DemParser *p) {
	return PEEK() == 'T' && strchr("yptnk", PEEK_AT(1)) != NULL;
}

bool rule_template_arg(DemParser *p, DemResult *r) {
	RULE_HEAD(TEMPLATE_ARG);
	switch (PEEK()) {
	case 'X': {
		ADV();
		MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_expression) && READ('E'));
		TRACE_RETURN_SUCCESS;
	}
	case 'J': {
		ADV();
		MUST_MATCH(CALL_MANY_N(node->child, rule_template_arg, ", ", 'E'));
		node->tag = CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK;
		TRACE_RETURN_SUCCESS;
	}
	case 'L': {
		if (PEEK_AT(1) == 'Z') {
			ADV_BY(2);
			MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_encoding) && READ('E'));
			TRACE_RETURN_SUCCESS;
		}
		MUST_MATCH(CALL_RULE_REPLACE_NODE(rule_expr_primary));
		TRACE_RETURN_SUCCESS;
		break;
	}
	case 'T': {
		if (!is_template_param_decl(p)) {
			RETURN_SUCCESS_OR_FAIL(CALL_RULE_REPLACE_NODE(rule_type));
		}
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_REPLACE_NODE(rule_template_param_decl));
	}
	default:
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_REPLACE_NODE(rule_type));
		break;
	}
	RULE_FOOT(template_arg);
}

bool rule_template_args(DemParser *p, DemResult *r) {
	return rule_template_args_ex(p, r, false);
}

bool rule_template_args_ex(DemParser *p, DemResult *r, bool tag_templates) {
	RULE_HEAD(TEMPLATE_ARGS);
	if (!READ('I')) {
		TRACE_RETURN_FAILURE();
	}
	if (tag_templates) {
		VecPNodeList_clear(&p->template_params);
		VecPNodeList_append(&p->template_params, &p->outer_template_params);
		VecPDemNode_clear(p->outer_template_params);
	}
	PDemNode many_node = DemNode_ctor(CP_DEM_TYPE_KIND_MANY, saved_ctx_rule.saved_pos, 1);
	if (!many_node) {
		TRACE_RETURN_FAILURE();
	}
	while (!READ('E')) {
		PDemNode arg = NULL;
		if (!CALL_RULE_N(arg, rule_template_arg)) {
			TRACE_RETURN_FAILURE();
		}
		if (tag_templates) {
			DemNode *entry = arg;
			if (arg->tag == CP_DEM_TYPE_KIND_TEMPLATE_ARGUMENT_PACK) {
				entry = DemNode_ctor(CP_DEM_TYPE_KIND_PARAMETER_PACK, arg->val.buf, arg->val.len);
				if (entry) {
					entry->child_ref = arg->child;
				}
			} else {
				entry = DemNode_clone(arg);
			}
			if (!entry) {
				DemNode_dtor(arg);
				TRACE_RETURN_FAILURE();
			}

			VecF(PDemNode, append)(p->outer_template_params, &entry);
		}
		Node_append(many_node, arg);
		if (READ('Q')) {
			// C++20 constraint expression attached to the template argument.
			// Minimal support: parse it as an expression and ignore it.
			// (Pretty-printing a per-argument constraint isn't currently supported.)
			PDemNode constraint_expr = NULL;
			if (!(CALL_RULE_N(constraint_expr, rule_expression) && READ('E'))) {
				TRACE_RETURN_FAILURE();
			}
			DemNode_dtor(constraint_expr);
		}
	}
	many_node->many_ty.sep = ", ";
	many_node->val.len = CUR() - many_node->val.buf;
	node->child = many_node;
	TRACE_RETURN_SUCCESS;
}

DemNode *parse_template_param_decl(DemParser *p, NodeList *params) {
	if (!READ('T')) {
		return NULL;
	}
	switch (PEEK()) {
	case 'y': {
		// Ty - type parameter
		ADV();

	}
	case 'n': {
		// Tn <type> - non-type parameter
		ADV();

	}
	case 't': {
		// Tt <template-param-decl>* E - template template parameter
		ADV();

	}
	case 'p': {
		// Tp <template-param-decl> - parameter pack
		ADV();
	}
	case 'k': {
		// Tk <name> [<template-args>] - constrained parameter (concept)
		ADV();
	}
	default:
		break;
	}
	return NULL;
}

bool rule_unnamed_type_name(DemParser *p, DemResult *r) {
	RULE_HEAD(UNNAMED_TYPE_NAME);
	if (READ_STR("Ut")) {
		ut64 tidx = 0;
		if (!parse_non_neg_integer(p, &tidx)) {
			tidx = 0;
		}
		if (!READ('_')) {
			TRACE_RETURN_FAILURE();
		}
		TRACE_RETURN_SUCCESS;
	}
	if (READ_STR("Ul")) {
		// Ul <template-param-decl>* [Q <constraint-expr> E] <lambda-sig> [Q <constraint-expr> E] E <number> _

		size_t saved_parse_lambda_params_at_level = p->parse_lambda_params_at_level;
		p->parse_lambda_params_at_level = VecPNodeList_len(&p->template_params);

		size_t saved_template_params_len = VecPNodeList_len(&p->template_params);
		PNodeList lambda_template_params = VecPDemNode_ctor();
		VecPNodeList_append(&p->template_params, &lambda_template_params);

		PDemNode temp_params = NULL;
		while (is_template_param_decl(p)) {
			// TODO:
			DEM_UNREACHABLE;
		}
		if (temp_params && VecPDemNode_empty(temp_params->children)) {
			VecPNodeList_pop(&p->template_params);
		}

		PDemNode requires1 = NULL;
		if (READ('Q')) {
			// C++20 constraint expression (templated lambda) - minimal support: parse & ignore.
			MUST_MATCH(CALL_RULE_N(requires1, rule_expression) && READ('E'));
			if (!requires1) {
				TRACE_RETURN_FAILURE();
			}
		}
		DemNode *params = NULL;
		if (!READ('v')) {
			CALL_MANY1_N(params, rule_type, ", ", '\0');
		}
		PDemNode requires2 = NULL;
		if (READ('Q')) {
			MUST_MATCH(CALL_RULE_N(requires2, rule_expression) && READ('E'));
			if (!requires2) {
				TRACE_RETURN_FAILURE();
			}
		}
		if (!READ('E')) {
			TRACE_RETURN_FAILURE();
		}
		if (!parse_number(p, &node->closure_ty_name.count, false)) {
			TRACE_RETURN_FAILURE();
		}
		if (!READ('_')) {
			TRACE_RETURN_FAILURE();
		}
		node->tag = CP_DEM_TYPE_KIND_CLOSURE_TY_NAME;
		node->closure_ty_name.template_params = temp_params;
		node->closure_ty_name.params = params;
		node->closure_ty_name.requires1 = requires1;
		node->closure_ty_name.requires2 = requires2;

		p->parse_lambda_params_at_level = saved_parse_lambda_params_at_level;
		VecPNodeList_resize(&p->template_params, saved_template_params_len);
		VecPDemNode_dtor(lambda_template_params);
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(unnamed_type_name);
}

bool rule_pointer_to_member_type(DemParser *p, DemResult *r) {
	RULE_HEAD(POINTER_TO_MEMBER_TYPE);
	if (!READ('M')) {
		TRACE_RETURN_FAILURE();
	}
	// Grammar: M <class-type> <member-type>
	// For member function pointers: M <class> <function-type>
	// For member data pointers: M <class> <data-type>
	MUST_MATCH(CALL_RULE(rule_type));
	MUST_MATCH(CALL_RULE(rule_type));
	TRACE_RETURN_SUCCESS;
}

// Helper function to parse reference qualifiers directly into a struct
// Returns true if at least one qualifier was parsed
bool parse_ref_qualifier(DemParser *p, RefQualifiers *quals) {
	const char *start = p->cur;
	if (READ('R')) {
		quals->is_l_value = true;
	}
	if (READ('O')) {
		quals->is_r_value = true;
	}
	return p->cur != start;
}

bool is_end_of_encoding(const DemParser *p) {
	// The set of chars that can potentially follow an <encoding> (none of which
	// can start a <type>). Enumerating these allows us to avoid speculative
	// parsing.
	return REMAIN_SIZE() == 0 || PEEK() == 'E' || PEEK() == '.' || PEEK() == '_';
};

bool rule_encoding(DemParser *p, DemResult *r) {
	RULE_HEAD(ENCODING);
	// Handle special names (G=guard variable, T=typeinfo/vtable)
	// These have different structure than function signatures
	if (PEEK() == 'G' || PEEK() == 'T') {
		RETURN_SUCCESS_OR_FAIL(CALL_RULE_REPLACE_NODE(rule_special_name));
	}
	// Override tag to function_type since encoding produces function signatures
	node->tag = CP_DEM_TYPE_KIND_FUNCTION_TYPE;
	// Parse: name, [return_type], parameters
	NameState ns = { 0 };
	NameState_init(&ns, p);
	MUST_MATCH(CALL_RULE_N_VA(node->fn_ty.name, rule_name, &ns));
	if (!resolve_forward_template_refs(p, node->fn_ty.name)) {
		TRACE_RETURN_FAILURE();
	}

	if (is_end_of_encoding(p)) {
		PDemNode name = node->fn_ty.name;
		node->fn_ty.name = NULL;
		RETURN_AND_OUTPUT_VAR(name);
	}

	if (ns.end_with_template_args && !ns.is_conversion_ctor_dtor) {
		// Template functions must have an explicit return type
		// Exception: conversion operators don't have explicit return types
		CALL_RULE_N(node->fn_ty.ret, rule_type);
	}

	// Parse function parameters using match_many to create a many node
	// 'v' means void (no parameters), otherwise parse parameter list
	if (!READ('v')) {
		if (!CALL_MANY1_N(node->fn_ty.params, rule_type, ", ", '\0')) {
			TRACE_RETURN_FAILURE();
		}
	}

	node->fn_ty.cv_qualifiers = ns.cv_qualifiers;
	node->fn_ty.ref_qualifiers = ns.ref_qualifiers;
	TRACE_RETURN_SUCCESS;
}

void DemContext_deinit(DemContext *ctx) {
	if (!ctx) {
		return;
	}
	DemParser_deinit(&ctx->parser);
	DemResult_deinit(&ctx->result);
	dem_string_deinit(&ctx->output);
}

bool parse_rule(DemContext *ctx, const char *mangled, DemRule rule, CpDemOptions opts) {
	if (!mangled || !rule || !ctx) {
		return false;
	}
	// Enable tracing via environment variable or compile-time flag
#ifdef ENABLE_GRAPHVIZ_TRACE
	bool trace = true;
#else
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996) // 'getenv': This function or variable may be unsafe
#endif
	bool trace = (getenv("DEMANGLE_TRACE") != NULL);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#endif
	// Initialize DemParser
	DemParser *p = &ctx->parser;
	DemParser_init(p, opts, mangled);
	ctx->parser.trace = trace;
	if (!rule(p, &ctx->result)) {
		return false;
	}
	PPContext pp_ctx = { 0 };
	if (ctx->parser.trace && VecPDemNode_len(&p->detected_types) > 0) {
		DemString buf = { 0 };
		vec_foreach_ptr_i(PDemNode, &p->detected_types, i, sub_ptr, {
			DemNode *sub = sub_ptr ? *sub_ptr : NULL;
			dem_string_appendf(&buf, "[%lu] = ", i);
			if (sub) {
				PPContext_init(&pp_ctx, opts);
				ast_pp(sub, &buf, &pp_ctx);
				dem_string_append(&buf, "\n");
			} else {
				dem_string_append(&buf, "(null)\n");
			}
		});
		char *buf_str = dem_string_drain_no_free(&buf);
		fprintf(stderr, "# substitutions:\n%s\n", buf_str ? buf_str : "(null)");
		free(buf_str);
	}
	DemNode *output_node = ctx->result.output;
	PPContext_init(&pp_ctx, opts);
	ast_pp(output_node, &ctx->output, &pp_ctx);
	if (ctx->parser.options & DEM_OPT_SIMPLE) {
		dem_simplify(&ctx->output);
	}

	return true;
}

/**
 *
 * @param mangled
 * @param opts
 * @return
 */
char *cp_demangle_v3(const char *mangled, CpDemOptions opts) {
	// Handle vendor-specific prefixes (Apple/Objective-C extensions)
	// These appear as multiple underscores before the actual _Z symbol
	const char *p = mangled;
	// Count leading underscores
	while (*p == '_') {
		p++;
	}
	// If we found a _Z after underscores, and there were underscores, process from the _Z
	if (*p == 'Z' && p > mangled) {
		// p points to 'Z', so p-1 points to '_', which is the start of "_Z"
		p = p - 1;
	}
	DemContext ctx = { 0 };
	if (!parse_rule(&ctx, p, rule_mangled_name, opts)) {
		DemContext_deinit(&ctx);
		return NULL;
	}
	char *result = dem_string_drain_no_free(&ctx.output);
	// Clear the output buffer so DemContext_deinit doesn't double-free it
	ctx.output = (DemString){ 0 };
	DemContext_deinit(&ctx);
	return result;
}
