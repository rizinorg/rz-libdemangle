// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
/**
 * Documentation for used grammar can be found at either of
 * - https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling
 */
#include "v3.h"
#include "v3_pp.h"
#include "demangle.h"
#include "demangler_util.h"
#include "dot_graph.h"
#include "macros.h"
#include "parser_combinator.h"
#include "types.h"
#include "vec.h"
#include <ctype.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

void pp_cv_qualifiers(CvQualifiers qualifiers, DemString *out) {
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

void pp_ref_qualifiers(RefQualifiers qualifiers, DemString *out) {
	if (qualifiers.is_l_value) {
		dem_string_append(out, " &");
	}
	if (qualifiers.is_r_value) {
		dem_string_append(out, " &&");
	}
}

typedef struct PPPackExpansionContext_t {
	DemNode *node;
	DemNode *pack;
	DemNode *outer;
} PPPackExpansionContext;

bool extract_pack_expansion(DemNode *node, PDemNode *outer_ty, PDemNode *inner_ty) {
	if (!node || (!outer_ty && !inner_ty)) {
		return false;
	}

	if (node->tag == CP_DEM_TYPE_KIND_parameter_pack_expansion && node->parameter_pack_expansion.ty && outer_ty) {
		PDemNode ty = node->parameter_pack_expansion.ty;
		if (ty->tag == CP_DEM_TYPE_KIND_type && ty->subtag != INVALID_TYPE) {
			*outer_ty = ty;
			return extract_pack_expansion(AST_(ty, 0), NULL, inner_ty);
		}
		if (ty->tag == CP_DEM_TYPE_KIND_qualified_type) {
			*outer_ty = ty;
			return extract_pack_expansion(ty->qualified_ty.inner_type, NULL, inner_ty);
		}
		return extract_pack_expansion(ty, outer_ty, inner_ty);
	}
	if (node->tag == CP_DEM_TYPE_KIND_template_parameter_pack && inner_ty) {
		*inner_ty = node;
		return true;
	}
	if (node->tag == CP_DEM_TYPE_KIND_type && node->subtag != INVALID_TYPE) {
		return extract_pack_expansion(AST_(node, 0), outer_ty, inner_ty);
	}
	if (node->tag == CP_DEM_TYPE_KIND_qualified_type) {
		return extract_pack_expansion(node->qualified_ty.inner_type, outer_ty, inner_ty);
	}

	return true;
}

// Helper to print pointer/reference/qualifier decorators
static void pp_type_quals(PDemNode node, DemString *out, CpDemTypeKind target_tag) {
	if (!node || !out) {
		return;
	}

	if (node->tag == target_tag) {
		// Reached the target type - stop recursion
		return;
	}

	if (node->tag == CP_DEM_TYPE_KIND_type) {
		// Recurse first to get inner decorators
		if (AST(0)) {
			pp_type_quals(AST(0), out, target_tag);
		}

		// Then add our decorator
		if (node->subtag == POINTER_TYPE) {
			dem_string_append(out, "*");
		} else if (node->subtag == REFERENCE_TYPE) {
			dem_string_append(out, "&");
		} else if (node->subtag == RVALUE_REFERENCE_TYPE) {
			dem_string_append(out, "&&");
		}
	} else if (node->tag == CP_DEM_TYPE_KIND_qualified_type) {
		// Recurse first
		if (node->qualified_ty.inner_type) {
			pp_type_quals(node->qualified_ty.inner_type, out, target_tag);
		}

		// Then add qualifiers
		pp_cv_qualifiers(node->qualified_ty.qualifiers, out);
	}
}

bool pp_pack_expansion(PPPackExpansionContext *ctx, DemString *out) {
	if (!ctx || !ctx->node || !out) {
		return false;
	}
	DemNode *node = ctx->node;
	if (node->parameter_pack_expansion.ty) {
		if (!extract_pack_expansion(node, &ctx->outer, &ctx->pack)) {
			dem_string_append(out, "<expansion error>");
			return true;
		}
		if (!ctx->pack) {
			return true;
		}
		PDemNode many_node = AST_(ctx->pack, 0);
		if (!many_node || many_node->tag != CP_DEM_TYPE_KIND_many) {
			dem_string_append(out, "<expansion error>");
			return true;
		}
		vec_foreach_ptr_i(many_node->children, idx, child, {
			if (idx > 0) {
				dem_string_append(out, many_node->many_ty.sep);
			}
			if (!child) {
				continue;
			}
			ast_pp(*child, out);
			pp_type_quals(ctx->outer, out, CP_DEM_TYPE_KIND_template_parameter_pack);
		});
	} else {
		dem_string_append(out, "expansion(?)");
	}
	return true;
}

// Helper function to extract the base class name from a ctor/dtor name
// Recursively unwraps name_with_template_args and nested_name to get the final primitive name
static bool extract_base_class_name(PDemNode node, PDemNode *out_name) {
	if (!node) {
		return false;
	}

	switch (node->tag) {
	case CP_DEM_TYPE_KIND_abi_tag_ty:
		// Unwrap abi_tag_ty to get the inner type
		if (node->abi_tag_ty.ty) {
			return extract_base_class_name(node->abi_tag_ty.ty, out_name);
		}
		break;
	case CP_DEM_TYPE_KIND_name_with_template_args:
		// Unwrap template args to get the base name
		if (node->name_with_template_args.name) {
			return extract_base_class_name(node->name_with_template_args.name, out_name);
		}
		break;

	case CP_DEM_TYPE_KIND_nested_name:
		// Get the final name component (not the qualifier)
		if (node->nested_name.name) {
			return extract_base_class_name(node->nested_name.name, out_name);
		}
		break;

	case CP_DEM_TYPE_KIND_primitive_ty:
	default:
		break;
	}

	// For other node types, just return as-is
	if (out_name) {
		*out_name = node;
	}
	return true;
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
} PPFnContext;

static bool extract_function_type(DemNode *node, DemNode **out_func_node) {
	if (!node) {
		return false;
	}

	if (node->tag == CP_DEM_TYPE_KIND_function_type) {
		if (out_func_node) {
			*out_func_node = node;
		}
		return true;
	}

	if (node->tag == CP_DEM_TYPE_KIND_type && AST(0)) {
		return extract_function_type(AST(0), out_func_node);
	}

	if (node->tag == CP_DEM_TYPE_KIND_qualified_type && node->qualified_ty.inner_type) {
		return extract_function_type(node->qualified_ty.inner_type, out_func_node);
	}

	return false;
}

static void pp_function_ty_mod_return_fn(PPFnContext *, DemString *);
static void pp_function_ty_quals(PPFnContext *ctx, DemString *out);

static void pp_function_ty(PPFnContext *ctx, DemString *out) {
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
		};
		pp_function_ty(&inner_ctx, out);
		ft->ret = saved_ret;
		return;
	}

	if (ft->ret) {
		ast_pp(ft->ret, out);
		dem_string_append(out, " ");
	}

	bool has_mod = ctx && ctx->mod && ctx->pp_mod;
	bool has_quals = ctx && ctx->quals && ctx->pp_quals;
	bool has_mod_or_quals = has_mod || has_quals;
	if (has_mod_or_quals) {
		dem_string_append(out, "(");
	}
	if (ft->name) {
		ast_pp(ft->name, out);
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
	if (ft->params) {
		ast_pp(ft->params, out);
	}
	dem_string_append(out, ")");

	// Print exception spec
	if (ft->exception_spec) {
		ast_pp(ft->exception_spec, out);
	}

	// Print cv and ref qualifiers
	pp_cv_qualifiers(ft->cv_qualifiers, out);
	pp_ref_qualifiers(ft->ref_qualifiers, out);
}

static void pp_function_ty_mod_return_fn(PPFnContext *ctx, DemString *out) {
	PPFnContext inner_ctx = {
		.fn = ctx->mod
	};
	pp_function_ty(&inner_ctx, out);
}

static void pp_function_ty_quals(PPFnContext *ctx, DemString *out) {
	if (!ctx || !ctx->quals) {
		return;
	}
	pp_type_quals(ctx->quals, out, CP_DEM_TYPE_KIND_function_type);
}

static void pp_function_ty_mod_pointer_to_member_type(PPFnContext *ctx, DemString *out) {
	if (ctx && ctx->mod) {
		ast_pp(ctx->mod, out);
	}
	dem_string_append(out, "::*");
}

void ast_pp(DemNode *node, DemString *out) {
	if (!node || !out) {
		return;
	}

	switch (node->tag) {
	case CP_DEM_TYPE_KIND_primitive_ty:
		// Primitive type nodes contain literal strings
		if (node->primitive_ty.name.buf) {
			dem_string_append(out, node->primitive_ty.name.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_abi_tag_ty:
		ast_pp(node->abi_tag_ty.ty, out);
		dem_string_append(out, "[abi:");
		dem_string_append_n(out,
			node->abi_tag_ty.tag.buf,
			node->abi_tag_ty.tag.len);
		dem_string_append(out, "]");
		break;

	case CP_DEM_TYPE_KIND_function_type: {
		PPFnContext ctx = {
			.fn = node,
		};
		pp_function_ty(&ctx, out);
		break;
	}
	case CP_DEM_TYPE_KIND_module_name:
		if (node->module_name_ty.pare) {
			ast_pp(node->module_name_ty.pare, out);
			dem_string_append(out, ".");
		}
		if (node->module_name_ty.name) {
			ast_pp(node->module_name_ty.name, out);
			if (node->module_name_ty.IsPartition) {
				dem_string_append(out, ":");
			} else if (node->parent && node->parent->tag == CP_DEM_TYPE_KIND_module_name) {
				dem_string_append(out, ".");
			}
		}
		break;
	case CP_DEM_TYPE_KIND_name_with_template_args:
		if (node->name_with_template_args.name) {
			ast_pp(node->name_with_template_args.name, out);
		}
		if (node->name_with_template_args.template_args) {
			ast_pp(node->name_with_template_args.template_args, out);
		}
		break;

	case CP_DEM_TYPE_KIND_qualified_type:
		if (node->qualified_ty.inner_type) {
			ast_pp(node->qualified_ty.inner_type, out);
			pp_cv_qualifiers(node->qualified_ty.qualifiers, out);
		}
		break;

	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type:
		if (node->vendor_ext_qualified_ty.inner_type) {
			ast_pp(node->vendor_ext_qualified_ty.inner_type, out);
			if (node->vendor_ext_qualified_ty.vendor_ext.buf) {
				dem_string_append(out, " ");
				dem_string_append_n(out,
					node->vendor_ext_qualified_ty.vendor_ext.buf,
					node->vendor_ext_qualified_ty.vendor_ext.len);
			}
			if (node->vendor_ext_qualified_ty.template_args) {
				ast_pp(node->vendor_ext_qualified_ty.template_args, out);
			}
		}
		break;

	case CP_DEM_TYPE_KIND_conv_op_ty:
		dem_string_append(out, "operator ");
		ast_pp(node->conv_op_ty.ty, out);
		break;

	case CP_DEM_TYPE_KIND_many:
		// Print children with separator
		if (node->children) {
			bool first = true;
			vec_foreach_ptr(node->children, child_ptr, {
				DemNode *child = child_ptr ? *child_ptr : NULL;
				if (child) {
					if (!first && node->many_ty.sep) {
						dem_string_append(out, node->many_ty.sep);
					}
					ast_pp(child, out);
					first = false;
				}
			});
		}
		break;

	case CP_DEM_TYPE_KIND_nested_name:
		// Nested names are separated by "::"
		if (node->nested_name.qual) {
			ast_pp(node->nested_name.qual, out);
			dem_string_append(out, "::");
		}
		if (node->nested_name.name) {
			ast_pp(node->nested_name.name, out);
		}
		break;

	case CP_DEM_TYPE_KIND_local_name:
		ast_pp(node->local_name.encoding, out);
		dem_string_append(out, "::");
		ast_pp(node->local_name.entry, out);
		break;

	case CP_DEM_TYPE_KIND_ctor_dtor_name:
		if (node->ctor_dtor_name.is_dtor) {
			dem_string_append(out, "~");
		}
		// For constructor/destructor names, we only want the final class name,
		// not the full qualified name or template arguments. Extract the base name.
		PDemNode base_name = NULL;
		if (node->ctor_dtor_name.name && extract_base_class_name(node->ctor_dtor_name.name, &base_name)) {
			ast_pp(base_name, out);
		}
		break;

	case CP_DEM_TYPE_KIND_closure_ty_name:
		// Closure types are lambda expressions: 'lambda'(params)#count
		dem_string_append(out, "'lambda");
		if (node->closure_ty_name.template_params) {
			dem_string_append(out, "<");
			ast_pp(node->closure_ty_name.template_params, out);
			dem_string_append(out, ">");
		}
		dem_string_append(out, "'(");
		if (node->closure_ty_name.params) {
			ast_pp(node->closure_ty_name.params, out);
		}
		dem_string_append(out, ")");
		if (node->closure_ty_name.count.buf && node->closure_ty_name.count.len > 0) {
			dem_string_append(out, "#");
			dem_string_append_n(out, node->closure_ty_name.count.buf, node->closure_ty_name.count.len);
		}
		break;

	case CP_DEM_TYPE_KIND_template_args:
		dem_string_append(out, "<");
		if (AST(0)) {
			ast_pp(AST(0), out);
		}
		dem_string_append(out, ">");
		break;

	case CP_DEM_TYPE_KIND_type: {
		// Check if this is a function pointer (or pointer/reference/qualified wrapping a function pointer)
		DemNode *func_node = NULL;
		if (extract_function_type(node, &func_node)) {
			// This is a function pointer - use special formatting
			PPFnContext ctx = {
				.fn = func_node,
				.quals = node,
				.pp_quals = pp_function_ty_quals,
			};
			pp_function_ty(&ctx, out);
		} else if ((node->subtag == POINTER_TYPE || node->subtag == REFERENCE_TYPE || node->subtag == RVALUE_REFERENCE_TYPE) &&
			AST(0) && AST(0)->tag == CP_DEM_TYPE_KIND_array_type) {
			// Special case: pointer/reference to array
			// Format as: element_type (*|&|&&) [dimension]
			DemNode *array_node = AST(0);
			// Print array element type (child 1 of array)
			if (array_node->children && VecPDemNode_len(array_node->children) > 1) {
				DemNode *element_type = *VecPDemNode_at(array_node->children, 1);
				if (element_type) {
					ast_pp(element_type, out);
				}
			}
			dem_string_append(out, " (");
			if (node->subtag == POINTER_TYPE) {
				dem_string_append(out, "*");
			} else if (node->subtag == REFERENCE_TYPE) {
				dem_string_append(out, "&");
			} else if (node->subtag == RVALUE_REFERENCE_TYPE) {
				dem_string_append(out, "&&");
			}
			dem_string_append(out, ") [");
			// Print array dimension (child 0 of array)
			if (array_node->children && VecPDemNode_len(array_node->children) > 0) {
				DemNode *dimension = *VecPDemNode_at(array_node->children, 0);
				if (dimension) {
					ast_pp(dimension, out);
				}
			}
			dem_string_append(out, "]");
		} else {
			// Regular type - print children and add decorator
			vec_foreach_ptr(node->children, child_ptr, {
				ast_pp(*child_ptr, out);
			});
			if (node->subtag == POINTER_TYPE) {
				dem_string_append(out, "*");
			} else if (node->subtag == REFERENCE_TYPE) {
				dem_string_append(out, "&");
			} else if (node->subtag == RVALUE_REFERENCE_TYPE) {
				dem_string_append(out, "&&");
			}
		}
	} break;

	case CP_DEM_TYPE_KIND_array_type:
		// Array type: element_type [dimension]
		// Child 0: dimension (optional), Child 1: element type
		if (AST(1)) {
			ast_pp(AST(1), out);
		}
		dem_string_append(out, " [");
		if (AST(0)) {
			ast_pp(AST(0), out);
		}
		dem_string_append(out, "]");
		break;

	case CP_DEM_TYPE_KIND_template_parameter_pack:
		if (AST(0)) {
			ast_pp(AST(0), out);
		}
		break;
	case CP_DEM_TYPE_KIND_parameter_pack_expansion: {
		PPPackExpansionContext ctx = {
			.node = node,
			.outer = NULL,
			.pack = NULL
		};
		pp_pack_expansion(&ctx, out);
		break;
	}

	case CP_DEM_TYPE_KIND_fwd_template_ref:
		if (node->fwd_template_ref) {
			dem_string_appendf(out, "T_%d_%d", node->fwd_template_ref->level, node->fwd_template_ref->index);
		} else {
			dem_string_append(out, "T_?_?");
		}
		break;

	case CP_DEM_TYPE_KIND_pointer_to_member_type:
		// Member pointer: M <class-type> <member-type>
		// For member function pointers: return_type (Class::*)(params) cv-qualifiers ref-qualifiers
		// For member data pointers: type Class::*
		if (AST(1) && AST(1)->tag == CP_DEM_TYPE_KIND_function_type) {
			PPFnContext ctx = {
				.pp_mod = pp_function_ty_mod_pointer_to_member_type,
				.mod = AST(0),
				.fn = AST(1),
			};
			pp_function_ty(&ctx, out);
		} else {
			// Member data pointer
			if (AST(1)) {
				ast_pp(AST(1), out);
				dem_string_append(out, " ");
			}
			if (AST(0)) {
				ast_pp(AST(0), out);
			}
			dem_string_append(out, "::*");
		}
		break;

	default:
		// For all other nodes with children, recursively print all children
		if (node->children) {
			vec_foreach_ptr(node->children, child_ptr, {
				DemNode *child = child_ptr ? *child_ptr : NULL;
				if (child) {
					ast_pp(child, out);
				}
			});
		}
		break;
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

bool parse_base_source_name(DemParser *p, const char **pout, ut64 *plen) {
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
		*plen = num;
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

bool rule_vendor_specific_suffix(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(vendor_specific_suffix);
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

bool rule_number(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(number);
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

bool rule_ctor_dtor_name(DemParser *p, const DemNode *parent, DemResult *r, NameState *ns, PDemNode scope) {
	RULE_HEAD(ctor_dtor_name);

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

bool rule_module_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(module_name);
	DemNode *Module = NULL;
	while (READ('W')) {
		bool IsPartition = READ('P');
		DemNode *Sub = NULL;
		CALL_RULE_N(Sub, rule_source_name);
		if (!Sub) {
			return true;
		}
		DemNode *sub_module = DemNode_ctor(CP_DEM_TYPE_KIND_module_name, saved_pos_rule, CUR() - saved_pos_rule);
		if (!sub_module) {
			TRACE_RETURN_FAILURE();
		}
		sub_module->module_name_ty.pare = Module;
		sub_module->module_name_ty.IsPartition = IsPartition;
		sub_module->module_name_ty.name = Sub;
		Module = sub_module;
		AST_APPEND_TYPE1(Module);
		Module->parent = node;
	}

	TRACE_RETURN_SUCCESS;
}

PDemNode parse_abi_tags(DemParser *p, PDemNode node) {
	while (READ('B')) {
		DemStringView tag = { 0 };
		if (!parse_base_source_name(p, &tag.buf, &tag.len)) {
			return NULL;
		}
		PDemNode tagged = DemNode_ctor(CP_DEM_TYPE_KIND_abi_tag_ty, tag.buf, tag.len);
		if (!tagged) {
			return NULL;
		}
		tagged->abi_tag_ty.tag = tag;
		tagged->abi_tag_ty.ty = node;
		node = tagged;
	}
	return node;
}

bool rule_unqualified_name(DemParser *p, const DemNode *parent, DemResult *r,
	NameState *ns, DemNode *scope, DemNode *module) {
	RULE_HEAD(unqualified_name);

	bool is_member_like_friend = scope && READ('F');
	READ('L');

	DemNode *result = NULL;
	if (READ_STR("DC")) {
		CALL_MANY1_N(result, rule_source_name, ", ");
		if (!READ('E')) {
			TRACE_RETURN_FAILURE();
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
		// TODO: handle module scoping
		DEM_UNREACHABLE;
	}
	if (result) {
		result = parse_abi_tags(p, result);
	}
	if (result && is_member_like_friend) {
		// TODO: MemberLikeFriendName
		DEM_UNREACHABLE;
	} else if (result && scope) {
		node->tag = CP_DEM_TYPE_KIND_nested_name;
		node->nested_name.qual = scope;
		node->nested_name.name = result;
		TRACE_RETURN_SUCCESS;
	}

	if (!result) {
		TRACE_RETURN_FAILURE();
	}
	DemNode_move(node, result);
	TRACE_RETURN_SUCCESS;
}

bool rule_unresolved_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unresolved_name);
	(void)READ_STR("gs");
	if (READ_STR("srN")) {
		RETURN_SUCCESS_OR_FAIL((CALL_RULE(rule_unresolved_type)) &&
			(PEEK() == 'I' ? CALL_RULE(rule_template_args) : true) &&
			AST_APPEND_STR("::") &&
			CALL_MANY1(rule_unresolved_qualifier_level, "::") && READ('E') &&
			AST_APPEND_STR("::") &&
			CALL_RULE(rule_base_unresolved_name));
	}
	if (!(READ_STR("sr"))) {
		MUST_MATCH(CALL_RULE(rule_base_unresolved_name));
		TRACE_RETURN_SUCCESS
	}
	if (isdigit(PEEK())) {
		MUST_MATCH(CALL_MANY1(rule_unresolved_qualifier_level, "::") && READ('E'));
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

bool rule_unscoped_name(DemParser *p, const DemNode *parent, DemResult *r, NameState *ns, bool *is_subst) {
	RULE_HEAD(unscoped_name);

	DemNode *std_node = NULL;
	if (READ_STR("St")) {
		std_node = make_primitive_type(CUR(), CUR(), "std", 3);
		if (!std_node) {
			TRACE_RETURN_FAILURE();
		}
	}

	DemNode *result = NULL;
	DemNode *module = NULL;
	DemNode *subst = NULL;
	if (PEEK() == 'S') {
		MUST_MATCH(CALL_RULE_N(subst, rule_substitution));
		if (subst->tag == CP_DEM_TYPE_KIND_module_name) {
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
		RETURN_SUCCESS_OR_FAIL(PASSTHRU_RULE_VA(rule_unqualified_name, ns, std_node, module));
	}
	if (result) {
		DemNode_move(node, result);
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(unscoped_name);
}

bool rule_unresolved_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unresolved_type);
	TRY_MATCH((CALL_RULE(rule_template_param)) && (((CALL_RULE(rule_template_args))) || true) && AST_APPEND_TYPE);
	TRY_MATCH((CALL_RULE(rule_decltype)) && AST_APPEND_TYPE);
	TRY_MATCH(CALL_RULE(rule_substitution));
	RULE_FOOT(unresolved_type);
}

bool rule_unresolved_qualifier_level(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unresolved_qualifier_level);
	TRY_MATCH(CALL_RULE(rule_simple_id));
	RULE_FOOT(unresolved_qualifier_level);
}

bool rule_decltype(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(decltype);
	if (!(READ_STR("Dt") || READ_STR("DT"))) {
		TRACE_RETURN_FAILURE();
	}
	PDemNode expr = NULL;
	MUST_MATCH(CALL_RULE_N(expr, rule_expression) && READ('E'));
	AST_APPEND_STR("decltype (");
	AST_APPEND_NODE(expr);
	AST_APPEND_STR(")");
	TRACE_RETURN_SUCCESS;
}

bool rule_exception_spec(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(exception_spec);
	TRY_MATCH(READ_STR("DO") && (CALL_RULE(rule_expression)) && READ('E'));
	TRY_MATCH(READ_STR("Dw") && (CALL_RULE(rule_type)) && READ('E'));
	TRY_MATCH(READ_STR("Do"));
	RULE_FOOT(exception_spec);
}

void pp_array_type(DemNode *node, DemString *out) {
	if (!node || node->tag != CP_DEM_TYPE_KIND_array_type) {
		return;
	}
	DemNode *type_node = node;
	DemNode *size_node = node;
	while (type_node->tag == CP_DEM_TYPE_KIND_array_type) {
		DemNode *parent_node = type_node;
		type_node = AST_(parent_node, 1);
		size_node = AST_(parent_node, 0);
		dem_string_appends(out, "[");
		ast_pp(size_node, out);
		dem_string_appends(out, "]");
	}
	dem_string_appends_prefix(out, " ");
	ast_pp(type_node, out);
}

bool rule_array_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(array_type);
	MUST_MATCH(READ('A'));
	node->subtag = ARRAY_TYPE;
	if (PEEK() == '_') {
		// Empty dimension: A_<type> - just consume the '_' without creating a size node
		MUST_MATCH(READ('_'));
	} else if (isdigit(PEEK())) {
		MUST_MATCH(CALL_RULE(rule_number) && READ('_'));
	} else {
		MUST_MATCH(CALL_RULE(rule_expression) && READ('_'));
	}
	MUST_MATCH(CALL_RULE(rule_type));
	AST_APPEND_TYPE;
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(array_type);
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

typedef enum {
	Primary,
	PPostfix,
	Unary,
	Cast,
	PtrMem,
	Multiplicative,
	Additive,
	Shift,
	Spaceship,
	Relational,
	Equality,
	And,
	Xor,
	Ior,
	AndIf,
	OrIf,
	PConditional,
	Assign,
	Comma,
	Default,
} Prec;

typedef struct {
	char Enc[2]; // Encoding
	OIKind Kind; // Kind of operator
	bool Flag; // Entry-specific flag
	Prec Prec; // Precedence
	const char *Name; // Spelling
} OperatorInfo;

static const OperatorInfo Ops[] = {
	// Keep ordered by encoding
	{ "aN", Binary, false, Assign, "operator&=" },
	{ "aS", Binary, false, Assign, "operator=" },
	{ "aa", Binary, false, AndIf, "operator&&" },
	{ "ad", Prefix, false, Unary, "operator&" },
	{ "an", Binary, false, And, "operator&" },
	{ "at", OfIdOp, /*Type*/ true, Unary, "alignof " },
	{ "aw", NameOnly, false, Primary,
		"operator co_await" },
	{ "az", OfIdOp, /*Type*/ false, Unary, "alignof " },
	{ "cc", NamedCast, false, PPostfix, "const_cast" },
	{ "cl", Call, /*Paren*/ false, PPostfix,
		"operator()" },
	{ "cm", Binary, false, Comma, "operator," },
	{ "co", Prefix, false, Unary, "operator~" },
	{ "cp", Call, /*Paren*/ true, PPostfix,
		"operator()" },
	{ "cv", CCast, false, Cast, "operator" }, // C Cast
	{ "dV", Binary, false, Assign, "operator/=" },
	{ "da", Del, /*Ary*/ true, Unary,
		"operator delete[]" },
	{ "dc", NamedCast, false, PPostfix, "dynamic_cast" },
	{ "de", Prefix, false, Unary, "operator*" },
	{ "dl", Del, /*Ary*/ false, Unary,
		"operator delete" },
	{ "ds", Member, /*Named*/ false, PtrMem,
		"operator.*" },
	{ "dt", Member, /*Named*/ false, PPostfix,
		"operator." },
	{ "dv", Binary, false, Assign, "operator/" },
	{ "eO", Binary, false, Assign, "operator^=" },
	{ "eo", Binary, false, Xor, "operator^" },
	{ "eq", Binary, false, Equality, "operator==" },
	{ "ge", Binary, false, Relational, "operator>=" },
	{ "gt", Binary, false, Relational, "operator>" },
	{ "ix", Array, false, PPostfix, "operator[]" },
	{ "lS", Binary, false, Assign, "operator<<=" },
	{ "le", Binary, false, Relational, "operator<=" },
	{ "ls", Binary, false, Shift, "operator<<" },
	{ "lt", Binary, false, Relational, "operator<" },
	{ "mI", Binary, false, Assign, "operator-=" },
	{ "mL", Binary, false, Assign, "operator*=" },
	{ "mi", Binary, false, Additive, "operator-" },
	{ "ml", Binary, false, Multiplicative,
		"operator*" },
	{ "mm", Postfix, false, PPostfix, "operator--" },
	{ "na", New, /*Ary*/ true, Unary,
		"operator new[]" },
	{ "ne", Binary, false, Equality, "operator!=" },
	{ "ng", Prefix, false, Unary, "operator-" },
	{ "nt", Prefix, false, Unary, "operator!" },
	{ "nw", New, /*Ary*/ false, Unary, "operator new" },
	{ "oR", Binary, false, Assign, "operator|=" },
	{ "oo", Binary, false, OrIf, "operator||" },
	{ "or", Binary, false, Ior, "operator|" },
	{ "pL", Binary, false, Assign, "operator+=" },
	{ "pl", Binary, false, Additive, "operator+" },
	{ "pm", Member, /*Named*/ true, PtrMem,
		"operator->*" },
	{ "pp", Postfix, false, PPostfix, "operator++" },
	{ "ps", Prefix, false, Unary, "operator+" },
	{ "pt", Member, /*Named*/ true, PPostfix,
		"operator->" },
	{ "qu", Conditional, false, PConditional,
		"operator?" },
	{ "rM", Binary, false, Assign, "operator%=" },
	{ "rS", Binary, false, Assign, "operator>>=" },
	{ "rc", NamedCast, false, PPostfix,
		"reinterpret_cast" },
	{ "rm", Binary, false, Multiplicative,
		"operator%" },
	{ "rs", Binary, false, Shift, "operator>>" },
	{ "sc", NamedCast, false, PPostfix, "static_cast" },
	{ "ss", Binary, false, Spaceship, "operator<=>" },
	{ "st", OfIdOp, /*Type*/ true, Unary, "sizeof " },
	{ "sz", OfIdOp, /*Type*/ false, Unary, "sizeof " },
	{ "te", OfIdOp, /*Type*/ false, PPostfix,
		"typeid " },
	{ "ti", OfIdOp, /*Type*/ true, PPostfix, "typeid " },
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

bool rule_operator_name(DemParser *p, const DemNode *parent, DemResult *r, NameState *ns) {
	RULE_HEAD(operator_name);
	const OperatorInfo *Op = parse_operator_info(p);
	if (Op) {
		if (Op->Kind == CCast) {
			bool old_not_parse = p->not_parse_template_args;
			p->not_parse_template_args = true;
			MUST_MATCH(CALL_RULE_N(node->conv_op_ty.ty, rule_type));
			p->not_parse_template_args = old_not_parse;
			if (ns) {
				ns->is_conversion_ctor_dtor = true;
			}
			node->tag = CP_DEM_TYPE_KIND_conv_op_ty;
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
		CTX_MUST_MATCH(rule, rule_source_name);
		TRACE_RETURN_SUCCESS;
	}

	RULE_FOOT(operator_name);
}

bool rule_expr_primary(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(expr_primary);
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

	// For simple builtin integer types, format as literal with suffix
	// Examples: Lj4E -> 4u, Li5E -> 5, Lm6E -> 6ul
	context_save(literal);
	char type_code = PEEK();
	const char *suffix = NULL;
	bool is_literal_int = false;

	switch (type_code) {
	case 'i': // int
		suffix = "";
		is_literal_int = true;
		break;
	case 'j': // unsigned int
		suffix = "u";
		is_literal_int = true;
		break;
	case 'l': // long
		suffix = "l";
		is_literal_int = true;
		break;
	case 'm': // unsigned long
		suffix = "ul";
		is_literal_int = true;
		break;
	case 'x': // long long
		suffix = "ll";
		is_literal_int = true;
		break;
	case 'y': // unsigned long long
		suffix = "ull";
		is_literal_int = true;
		break;
	case 's': // short
		suffix = "";
		is_literal_int = true;
		break;
	case 't': // unsigned short
		suffix = "u";
		is_literal_int = true;
		break;
	default:
		break;
	}

	if (is_literal_int) {
		ADV(); // skip type code
		bool is_negative = READ('n');
		ut64 num = 0;
		if (parse_non_neg_integer(p, &num) && READ('E')) {
			// Format the number with suffix
			char buf[64];
			int len = snprintf(buf, sizeof(buf), "%s%llu%s",
				is_negative ? "-" : "", (unsigned long long)num, suffix);
			if (len > 0 && len < (int)sizeof(buf)) {
				AST_APPEND_STRN(buf, len);
				TRACE_RETURN_SUCCESS;
			}
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

bool rule_braced_expression(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(braced_expression);
	if (PEEK() == 'd') {
		switch (PEEK_AT(1)) {
		case 'X':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_expression));
			MUST_MATCH(CALL_RULE(rule_expression));
			MUST_MATCH(CALL_RULE(rule_braced_expression));
			TRACE_RETURN_SUCCESS;
		case 'i':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_source_name));
			MUST_MATCH(CALL_RULE(rule_braced_expression));
			TRACE_RETURN_SUCCESS;
		case 'x':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_expression));
			MUST_MATCH(CALL_RULE(rule_braced_expression));
			TRACE_RETURN_SUCCESS;
		default:
			break;
		}
	}
	TRY_MATCH(CALL_RULE(rule_expression));
	RULE_FOOT(braced_expression);
}

static void swap(void **a, void **b) {
	void *temp = *a;
	*a = *b;
	*b = temp;
}

bool rule_fold_expression(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(fold_expression);
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
	CALL_RULE_N(Pack, rule_expression);
	if (!Pack) {
		TRACE_RETURN_FAILURE();
	}

	DemNode *init = NULL;
	if (HasInitializer) {
		CALL_RULE_N(init, rule_expression);
		if (!init) {
			TRACE_RETURN_FAILURE();
		}
	}
	if (init && IsLeftFold) {
		swap((void **)&Pack, (void **)&init);
	}

	TRACE_RETURN_SUCCESS;
}

bool rule_prefix_expression(DemParser *p, const DemNode *parent, DemResult *r, const OperatorInfo *op) {
	RULE_HEAD(expression);
	PDemNode expr = NULL;
	MUST_MATCH(CALL_RULE_N(expr, rule_expression));

	AST_APPEND_STR(opinfo_get_symbol(op));
	AST_APPEND_NODE(expr);
	TRACE_RETURN_SUCCESS;
}

bool rule_binary_expression(DemParser *p, const DemNode *parent, DemResult *r, const OperatorInfo *op) {
	RULE_HEAD(expression);
	AST_APPEND_STR("(");
	MUST_MATCH(CALL_RULE(rule_expression));
	AST_APPEND_STR(opinfo_get_symbol(op));
	MUST_MATCH(CALL_RULE(rule_expression));
	AST_APPEND_STR(")");
	TRACE_RETURN_SUCCESS;
}

bool rule_expression(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(expression);

	const OperatorInfo *Op = parse_operator_info(p);
	if (Op) {
		switch (Op->Kind) {
		case Prefix: return rule_prefix_expression(p, parent, r, Op);
		case Postfix:
			if (READ('_')) {
				return rule_prefix_expression(p, parent, r, Op);
			}
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(opinfo_get_symbol(Op));
			TRACE_RETURN_SUCCESS;
		case Binary: return rule_binary_expression(p, parent, r, Op);
		case Array: // ix: arr[idx]
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("[");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("]");
			TRACE_RETURN_SUCCESS;
		case Member: // dt/pt: expr.name / expr->name
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(opinfo_get_symbol(Op));
			MUST_MATCH(CALL_RULE(rule_expression));
			TRACE_RETURN_SUCCESS;
		case New: // nw/na
		case Del: // dl/da
			if (READ_STR("gs")) {
				AST_APPEND_STR("::");
			}
			AST_APPEND_STR(opinfo_get_symbol(Op));
			if (Op->Kind == New) {
				MUST_MATCH(CALL_MANY(rule_expression, " "));
				MUST_MATCH(READ('_') && AST_APPEND_STR(" "));
				MUST_MATCH(CALL_RULE(rule_type));
				if (PEEK() != 'E') {
					MUST_MATCH(CALL_RULE(rule_initializer));
				}
				MUST_MATCH(READ('E'));
			} else {
				AST_APPEND_STR(" ");
				MUST_MATCH(CALL_RULE(rule_expression));
			}
			TRACE_RETURN_SUCCESS;
		case Call: // cl: func(args)
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("(");
			MUST_MATCH(CALL_MANY(rule_expression, ", "));
			MUST_MATCH(READ('E'));
			AST_APPEND_STR(")");
			TRACE_RETURN_SUCCESS;
		case CCast: // cv: (type)expr or (type)(args)
			AST_APPEND_STR("(");
			MUST_MATCH(CALL_RULE(rule_type));
			AST_APPEND_STR(")");
			if (READ('_')) {
				AST_APPEND_STR("(");
				MUST_MATCH(CALL_MANY(rule_expression, ", "));
				MUST_MATCH(READ('E'));
				AST_APPEND_STR(")");
			} else {
				MUST_MATCH(CALL_RULE(rule_expression));
			}
			TRACE_RETURN_SUCCESS;
		case Conditional: // qu: cond ? then : else
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(" ? ");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(" : ");
			MUST_MATCH(CALL_RULE(rule_expression));
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
			TRACE_RETURN_SUCCESS;
		case Unnameable:
			TRACE_RETURN_FAILURE();
		}
		DEM_UNREACHABLE;
	}

	// Non-operator expressions
	TRY_MATCH(CALL_RULE(rule_expr_primary));
	TRY_MATCH(CALL_RULE(rule_template_param));
	TRY_MATCH(CALL_RULE(rule_function_param));
	TRY_MATCH(CALL_RULE(rule_fold_expression));
	TRY_MATCH(READ_STR("il") && CALL_MANY(rule_expression, "") && READ('E'));
	TRY_MATCH(READ_STR("tl") && CALL_RULE(rule_type) && CALL_MANY(rule_braced_expression, "") && READ('E'));
	TRY_MATCH(READ_STR("nx") && AST_APPEND_STR("noexcept(") && CALL_RULE(rule_expression) && AST_APPEND_STR(")"));
	TRY_MATCH(READ_STR("tw") && AST_APPEND_STR("throw ") && CALL_RULE(rule_expression));
	TRY_MATCH(READ_STR("tr") && AST_APPEND_STR("throw"));
	TRY_MATCH(READ_STR("sZ") && AST_APPEND_STR("sizeof...(") && (CALL_RULE(rule_template_param) || CALL_RULE(rule_function_param)) && AST_APPEND_STR(")"));
	TRY_MATCH(READ_STR("sP") && AST_APPEND_STR("sizeof...(") && CALL_MANY(rule_template_arg, "") && READ('E') && AST_APPEND_STR(")"));
	TRY_MATCH(READ_STR("sp") && CALL_RULE(rule_expression) && AST_APPEND_STR("..."));
	// NOTE: fl and fr are fold expressions, handled by rule_fold_expression above
	TRY_MATCH(CALL_RULE(rule_unresolved_name));

	RULE_FOOT(expression);
}

bool rule_simple_id(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(simple_id);
	TRY_MATCH((CALL_RULE(rule_source_name)) && (((CALL_RULE(rule_template_args))) || true));
	RULE_FOOT(simple_id);
}

bool rule_template_param(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_param);
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

	DemNode *t = template_param_get(p, level, index);
	if (!t) {
		// If substitution failed, create a forward reference
		// Use a placeholder that will be resolved later
		ForwardTemplateRef fwd_ref = {
			.wrapper = node,
			.level = level,
			.index = index
		};
		node->fwd_template_ref = malloc(sizeof(ForwardTemplateRef));
		if (!node->fwd_template_ref) {
			TRACE_RETURN_FAILURE();
		}
		*(node->fwd_template_ref) = fwd_ref;
		node->tag = CP_DEM_TYPE_KIND_fwd_template_ref;
		VecF(PForwardTemplateRef, append)(&p->forward_template_refs, &node->fwd_template_ref);
		if (p->trace) {
			fprintf(stderr, "[template_param] Created forward ref L%ld_%ld to %p\n",
				level, index, (void *)node);
		}
	} else {
		DemNode_copy(node, t);
	}

	TRACE_RETURN_SUCCESS;
}

bool rule_initializer(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(initializer);
	if (!READ_STR("pi")) {
		TRACE_RETURN_FAILURE();
	}
	AST_APPEND_STR(" (");
	MUST_MATCH(CALL_MANY(rule_expression, ", "));
	MUST_MATCH(READ('E'));
	AST_APPEND_STR(")");
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(initializer);
}

bool rule_call_offset(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(call_offset);
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
*/
bool rule_special_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(special_name);
	switch (PEEK()) {
	case 'T':
		ADV();
		switch (PEEK()) {
		case 'C':
			// TC <derived-type> <offset> _ <base-type>   # construction vtable
			ADV();
			DemNode *base_ty = NULL;
			DemNode *derived_ty = NULL;
			MUST_MATCH(CALL_RULE_N(base_ty, rule_type));
			ut64 offset = 0;
			MUST_MATCH(parse_non_neg_integer(p, &offset));
			MUST_MATCH(READ('_') || CALL_RULE_N(derived_ty, rule_type));
			AST_APPEND_STR("construction vtable for ");
			AST_APPEND_NODE(base_ty);
			if (derived_ty) {
				AST_APPEND_STR("-in-");
				AST_APPEND_NODE(derived_ty);
			}
			break;
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
			MUST_MATCH(AST_APPEND_STR("template parameter for ") && CALL_RULE(rule_template_arg));
			break;
		default:
			MUST_MATCH(CALL_RULE(rule_call_offset) && CALL_RULE(rule_encoding));
			break;
		}
		break;
	case 'G':
		ADV();
		switch (PEEK()) {
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

bool rule_function_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(function_type);
	// This rule only handles F...E (bare function type)
	// P prefix is handled in the type rule, which properly inserts * for function pointers
	parse_cv_qualifiers(p, &node->fn_ty.cv_qualifiers);
	CALL_RULE_N(node->fn_ty.exception_spec, rule_exception_spec);

	READ_STR("Dx");
	if (!READ('F')) {
		TRACE_RETURN_FAILURE();
	}
	READ('Y');
	CALL_RULE_N(node->fn_ty.ret, rule_type);
	if (!node->fn_ty.ret) {
		TRACE_RETURN_FAILURE();
	}

	DemResult param_result = { 0 };
	if (!READ('v')) {
		if (!match_many(p, node, &param_result, rule_type, ", ")) {
			TRACE_RETURN_FAILURE();
		}
	}

	parse_ref_qualifiers(p, &node->fn_ty.ref_qualifiers);
	MUST_MATCH(READ('E'));

	node->fn_ty.params = param_result.output;
	TRACE_RETURN_SUCCESS;
}

bool rule_function_param(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(function_param);
	CvQualifiers qualifiers = { 0 };
	TRY_MATCH(READ_STR("fL") && (CALL_RULE(rule_number)) && READ('p') &&
		parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") && (CALL_RULE(rule_number)) &&
		READ('_'));
	TRY_MATCH(READ_STR("fL") && (CALL_RULE(rule_number)) && READ('p') &&
		parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") && READ('_'));
	TRY_MATCH(READ_STR("fp") && parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") &&
		(CALL_RULE(rule_number)) && READ('_'));
	TRY_MATCH(READ_STR("fp") && parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") && READ('_'));
	TRY_MATCH(READ_STR("fPT"));
	RULE_FOOT(function_param);
}

bool rule_builtin_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(builtin_type);
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

bool rule_source_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(source_name);
	/* positive number providing length of name followed by it */
	ut64 name_len = 0;
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

bool rule_class_enum_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(class_enum_type);
	TRY_MATCH(((READ_STR("Ts") || READ_STR("Tu") || READ_STR("Te")) || true) && (CALL_RULE_VA(rule_name, NULL)));
	RULE_FOOT(class_enum_type);
}

bool rule_mangled_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(mangled_name);

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

bool rule_qualified_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(qualified_type);
	if (PEEK() == 'U') {
		ADV();
		MUST_MATCH(parse_base_source_name(p, &node->vendor_ext_qualified_ty.vendor_ext.buf, &node->vendor_ext_qualified_ty.vendor_ext.len));
		if (PEEK() == 'I') {
			MUST_MATCH(CALL_RULE_N(node->vendor_ext_qualified_ty.template_args, rule_template_args));
		}
		MUST_MATCH(CALL_RULE_N(node->vendor_ext_qualified_ty.inner_type, rule_qualified_type));
		node->tag = CP_DEM_TYPE_KIND_vendor_ext_qualified_type;
		TRACE_RETURN_SUCCESS;
	}

	parse_cv_qualifiers(p, &node->qualified_ty.qualifiers);
	MUST_MATCH(CALL_RULE_N(node->qualified_ty.inner_type, rule_type));
	TRACE_RETURN_SUCCESS;
}

bool rule_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(type);
	if (PASSTHRU_RULE(rule_builtin_type)) {
		TRACE_RETURN_SUCCESS;
	}
	if (PASSTHRU_RULE(rule_function_type)) {
		goto beach;
	}
	switch (PEEK()) {
	case 'r':
	case 'V':
	case 'K':
	case 'U': {
		MUST_MATCH(PASSTHRU_RULE(rule_qualified_type));
		break;
	}
	case 'M':
		MUST_MATCH(PASSTHRU_RULE(rule_pointer_to_member_type));
		break;
	case 'A':
		MUST_MATCH(PASSTHRU_RULE(rule_array_type));
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
		node->subtag = subtag;
		break;
	}
	case 'D':
		// Dp <type>       # pack expansion (C++0x)
		if (PEEK_AT(1) == 'p') {
			ADV_BY(2);
			PDemNode ty = NULL;
			MUST_MATCH(CALL_RULE_N(ty, rule_type));
			if (!ty) {
				TRACE_RETURN_FAILURE();
			}
			node->tag = CP_DEM_TYPE_KIND_parameter_pack_expansion;
			node->parameter_pack_expansion.ty = ty;
			break;
		}
		if (PEEK_AT(1) == 't' || PEEK_AT(1) == 'T') {
			MUST_MATCH(PASSTHRU_RULE(rule_decltype));
			break;
		}
		// fallthrough
	case 'T': {
		if (strchr("sue", PEEK_AT(1)) != NULL) {
			MUST_MATCH(PASSTHRU_RULE(rule_class_enum_type));
			break;
		}
		PDemNode template_param_node = NULL;
		PDemNode template_args_node = NULL;
		MUST_MATCH(CALL_RULE_N(template_param_node, rule_template_param));
		if (PEEK() == 'I' && !p->not_parse_template_args) {
			AST_APPEND_TYPE;
			CALL_RULE_N(template_args_node, rule_template_args);
			node->tag = CP_DEM_TYPE_KIND_name_with_template_args;
			node->name_with_template_args.name = template_param_node;
			node->name_with_template_args.template_args = template_args_node;
		} else {
			DemNode_move(node, template_param_node);
			free(template_param_node); // Free the container, content is now in node
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
				node->tag = CP_DEM_TYPE_KIND_name_with_template_args;
				node->name_with_template_args.name = result;
				node->name_with_template_args.template_args = ta;
			} else if (is_subst) {
				// Move result's content to node instead of replacing the pointer
				// This avoids use-after-free in PASSTHRU mode where node == r->output
				DemNode_move(node, result);
				free(result); // Free the result container, but its content is now in node
				TRACE_RETURN_SUCCESS;
			}
			break;
		}
		// fallthrough
	}
	default:
		MUST_MATCH(PASSTHRU_RULE(rule_class_enum_type));
		break;
	}

beach:
	if (CUR() > saved_pos_rule) {
		AST_APPEND_TYPE;
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(type);
}

bool rule_base_unresolved_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(base_unresolved_name);
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
	RULE_FOOT(base_unresolved_name);
}

bool rule_local_name(DemParser *p, const DemNode *parent, DemResult *r, NameState *ns) {
	RULE_HEAD(local_name);
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

bool rule_substitution(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(substitution);
	if (!READ('S')) {
		TRACE_RETURN_FAILURE();
	}

	switch (PEEK()) {
	case 't': {
		ADV();
		PRIMITIVE_TYPE("std");
		TRACE_RETURN_SUCCESS;
	}
	case 'a': {
		ADV();
		PRIMITIVE_TYPE("std::allocator");
		TRACE_RETURN_SUCCESS;
	}
	case 'b': {
		ADV();
		PRIMITIVE_TYPE("std::basic_string");
		TRACE_RETURN_SUCCESS;
	}
	case 's': {
		ADV();
		if (PEEK() == 'C' || PEEK() == 'D') {
			PRIMITIVE_TYPE("std::basic_string<char, std::char_traits<char>, std::allocator<char>>");
		} else {
			PRIMITIVE_TYPE("std::string");
		}
		TRACE_RETURN_SUCCESS;
	}
	case 'i': {
		ADV();
		PRIMITIVE_TYPE("std::istream");
		TRACE_RETURN_SUCCESS;
	}
	case 'o': {
		ADV();
		PRIMITIVE_TYPE("std::ostream");
		TRACE_RETURN_SUCCESS;
	}
	case 'd': {
		ADV();
		PRIMITIVE_TYPE("std::iostream");
		TRACE_RETURN_SUCCESS;
	}
	default: {
		DemNode *child_node = NULL;
		if (!parse_seq_id(p, &child_node)) {
			TRACE_RETURN_FAILURE();
		}
		DemNode_copy(node, child_node);
		TRACE_RETURN_SUCCESS;
		break;
	}
	}
	RULE_FOOT(substitution);
}

bool rule_float(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(float);
	while (IS_DIGIT(PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
		ADV();
	}
	RULE_FOOT(float);
}

bool rule_destructor_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(destructor_name);
	TRY_MATCH(CALL_RULE(rule_unresolved_type));
	TRY_MATCH(CALL_RULE(rule_simple_id));
	RULE_FOOT(destructor_name);
}

bool rule_name(DemParser *p, const DemNode *parent, DemResult *r, NameState *ns) {
	RULE_HEAD(name);
	if (PEEK() == 'N') {
		RETURN_SUCCESS_OR_FAIL(PASSTHRU_RULE_VA(rule_nested_name, ns));
	}
	if (PEEK() == 'Z') {
		RETURN_SUCCESS_OR_FAIL(PASSTHRU_RULE_VA(rule_local_name, ns));
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
		CALL_RULE_N(ta, rule_template_args);
		if (!ta) {
			DemNode_dtor(result);
			TRACE_RETURN_FAILURE();
		}
		if (ns) {
			ns->end_with_template_args = true;
		}
		node->tag = CP_DEM_TYPE_KIND_name_with_template_args;
		node->name_with_template_args.name = result;
		node->name_with_template_args.template_args = ta;
		TRACE_RETURN_SUCCESS;
	}
	if (is_subst) {
		DemNode_dtor(result);
		TRACE_RETURN_FAILURE();
	}
	DemNode_move(node, result);
	TRACE_RETURN_SUCCESS;
}

bool rule_nested_name(DemParser *p, const DemNode *parent, DemResult *r, NameState *ns) {
	RULE_HEAD(nested_name);
	if (!READ('N')) {
		TRACE_RETURN_FAILURE();
	}
	CvQualifiers cv_quals = { 0 };
	RefQualifiers ref_qual = { 0 };
	if (parse_cv_qualifiers(p, &cv_quals)) {
		p->cv_qualifiers = cv_quals;
	}
	if (parse_ref_qualifiers(p, &ref_qual)) {
		p->ref_qualifiers = ref_qual;
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
			if (ast_node->tag == CP_DEM_TYPE_KIND_name_with_template_args) {
				goto fail;
			}
			DemNode *ta = NULL;
			MUST_MATCH(CALL_RULE_N(ta, rule_template_args));
			if (ns) {
				ns->end_with_template_args = true;
			}
			ast_node = make_name_with_template_args(saved_pos_rule, CUR(), ast_node, ta);
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
				if (!subst || ast_node != NULL) {
					DemNode_dtor(subst);
					goto fail;
				}
				if (subst->tag == CP_DEM_TYPE_KIND_module_name) {
					module = subst;
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
	DemNode_move(node, ast_node);
	free(ast_node);
	TRACE_RETURN_SUCCESS;
fail:
	DemNode_dtor(ast_node);
	TRACE_RETURN_FAILURE();
}

bool is_template_param_decl(DemParser *p) {
	return PEEK() == 'T' && strchr("yptnk", PEEK_AT(1)) != NULL;
}

bool rule_template_arg(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_arg);
	switch (PEEK()) {
	case 'X': {
		ADV();
		MUST_MATCH(CALL_RULE(rule_expression) && READ('E'));
		TRACE_RETURN_SUCCESS;
	}
	case 'J': {
		ADV();
		MUST_MATCH(CALL_MANY(rule_template_arg, ", ") && READ('E'));
		node->tag = CP_DEM_TYPE_KIND_template_parameter_pack;
		TRACE_RETURN_SUCCESS;
	}
	case 'L': {
		if (PEEK_AT(1) == 'Z') {
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_encoding) && READ('E'));
			TRACE_RETURN_SUCCESS;
		}
		MUST_MATCH(CALL_RULE(rule_expr_primary));
		TRACE_RETURN_SUCCESS;
		break;
	}
	case 'T': {
		if (!is_template_param_decl(p)) {
			RETURN_SUCCESS_OR_FAIL(PASSTHRU_RULE(rule_type));
		}
		DEM_UNREACHABLE;
	}
	default:
		RETURN_SUCCESS_OR_FAIL(PASSTHRU_RULE(rule_type));
		break;
	}
	RULE_FOOT(template_arg);
}

static bool is_tag_templates(const DemNode *node) {
	if (!node) {
		return false;
	}

	// Check if this template belongs to a function's name
	// Case 1: Direct child of function_type
	if (node->parent && node->parent->tag == CP_DEM_TYPE_KIND_function_type) {
		return node->tag == CP_DEM_TYPE_KIND_name ||
			node->tag == CP_DEM_TYPE_KIND_nested_name ||
			node->tag == CP_DEM_TYPE_KIND_name_with_template_args;
	}

	// Case 2: Part of name_with_template_args which is part of function_type
	if (node->parent &&
		node->parent->tag == CP_DEM_TYPE_KIND_name_with_template_args &&
		node->parent->parent &&
		node->parent->parent->tag == CP_DEM_TYPE_KIND_function_type) {
		return true;
	}

	return false;
}

bool rule_template_args(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_args);
	if (!READ('I')) {
		TRACE_RETURN_FAILURE();
	}
	const bool tag_templates = is_tag_templates(parent);
	if (tag_templates) {
		VecPNodeList_clear(&p->template_params);
		VecPNodeList_append(&p->template_params, &p->outer_template_params);
		VecPDemNode_clear(p->outer_template_params);
	}
	PDemNode many_node = DemNode_ctor(CP_DEM_TYPE_KIND_many, saved_pos_rule, 1);
	if (!many_node) {
		TRACE_RETURN_FAILURE();
	}
	while (!READ('E')) {
		PDemNode child = NULL;
		if (!CALL_RULE_N(child, rule_template_arg)) {
			TRACE_RETURN_FAILURE();
		}
		if (tag_templates) {
			DemNode *node_arg_cloned = DemNode_clone(child);
			if (!node_arg_cloned) {
				TRACE_RETURN_FAILURE();
			}
			VecF(PDemNode, append)(p->outer_template_params, &node_arg_cloned);
		}
		Node_append(many_node, child);
		if (READ('Q')) {
			DEM_UNREACHABLE;
		}
	}
	many_node->many_ty.sep = ", ";
	many_node->val.len = CUR() - many_node->val.buf;
	AST_APPEND_NODE(many_node);
	TRACE_RETURN_SUCCESS;
}

bool rule_template_param_decl(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_param_decl);
	if (!READ('T')) {
		TRACE_RETURN_FAILURE();
	}
	// TODO: Handle different kinds of template parameters
	RULE_FOOT(template_param_decl);
}

bool rule_unnamed_type_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unnamed_type_name);
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
		while (is_template_param_decl(p)) {
			// TODO: Handle template_param_decl
			DEM_UNREACHABLE;
		}
		if (READ('Q')) {
			// TODO: Handle ConstraintExpr
			DEM_UNREACHABLE;
		}
		DemNode *params = NULL;
		if (!READ('v')) {
			CALL_MANY1_N(params, rule_type, ", ");
		}
		if (READ('Q')) {
			// TODO: Handle ConstraintExpr
			DEM_UNREACHABLE;
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
		node->tag = CP_DEM_TYPE_KIND_closure_ty_name;
		node->closure_ty_name.params = params;
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(unnamed_type_name);
}

bool rule_pointer_to_member_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(pointer_to_member_type);
	if (!READ('M')) {
		TRACE_RETURN_FAILURE();
	}
	context_save(0);
	// Grammar: M <class-type> <member-type>
	// For member function pointers: M <class> <function-type>
	// For member data pointers: M <class> <data-type>
	CTX_MUST_MATCH(0, CALL_RULE(rule_type));
	CTX_MUST_MATCH(0, CALL_RULE(rule_type));
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(pointer_to_member_type);
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

bool rule_encoding(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(encoding);
	// Handle special names (G=guard variable, T=typeinfo/vtable)
	// These have different structure than function signatures
	if (PEEK() == 'G' || PEEK() == 'T') {
		RETURN_SUCCESS_OR_FAIL(PASSTHRU_RULE(rule_special_name));
	}
	// Override tag to function_type since encoding produces function signatures
	node->tag = CP_DEM_TYPE_KIND_function_type;
	// Parse: name, [return_type], parameters
	NameState ns = { 0 };
	NameState_init(&ns, p);
	MUST_MATCH(CALL_RULE_N_VA(node->fn_ty.name, rule_name, &ns));
	if (!resolve_forward_template_refs(p, node->fn_ty.name)) {
		TRACE_RETURN_FAILURE();
	}

	if (is_end_of_encoding(p)) {
		DemNode temp_node = { 0 };
		DemNode_move(&temp_node, node->fn_ty.name);
		DemNode_move(node, &temp_node);
		TRACE_RETURN_SUCCESS;
	}

	if (ns.end_with_template_args && !ns.is_conversion_ctor_dtor) {
		// Template functions must have an explicit return type
		// Exception: conversion operators don't have explicit return types
		CALL_RULE_N(node->fn_ty.ret, rule_type);
	}

	// Parse function parameters using match_many to create a many node
	// 'v' means void (no parameters), otherwise parse parameter list
	if (!READ('v')) {
		if (!CALL_MANY1_N(node->fn_ty.params, rule_type, ", ")) {
			TRACE_RETURN_FAILURE();
		}
	}

	node->fn_ty.cv_qualifiers = p->cv_qualifiers;
	node->fn_ty.ref_qualifiers = p->ref_qualifiers;
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
	bool trace = (getenv("DEMANGLE_TRACE") != NULL);
#endif
	// Initialize DemParser
	DemParser parser = { 0 };
	DemParser *p = &parser;
	DemParser_init(p, mangled);
	parser.trace = trace;
	DemResult dem_result = { 0 };
	if (!rule(p, NULL, &dem_result)) {
		ctx->parser = parser;
		ctx->result = dem_result;
		return false;
	}
	if (parser.trace && VecPDemNode_len(&p->detected_types) > 0) {
		DemString buf = { 0 };
		vec_foreach_ptr_i(&p->detected_types, i, sub_ptr, {
			DemNode *sub = sub_ptr ? *sub_ptr : NULL;
			dem_string_appendf(&buf, "[%lu] = ", i);
			if (sub) {
				ast_pp(sub, &buf);
				dem_string_append(&buf, "\n");
			} else {
				dem_string_append(&buf, "(null)\n");
			}
		});
		char *buf_str = dem_string_drain_no_free(&buf);
		fprintf(stderr, "# substitutions:\n%s\n", buf_str ? buf_str : "(null)");
		free(buf_str);
	}
	DemNode *output_node = dem_result.output;
	ast_pp(output_node, &ctx->output);
	ctx->parser = parser;
	ctx->result = dem_result;

	// Generate DOT graph if tracing is enabled
	if (trace && dem_result.output) {
		DotGraph dot_graph = { 0 };
		dot_graph_init(&dot_graph, mangled);
		if (dot_graph.enabled) {
			dot_graph_generate(&dot_graph, dem_result.output);
			dot_graph_finish(&dot_graph);
		}
		dot_graph_cleanup(&dot_graph);
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
