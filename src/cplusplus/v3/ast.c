// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../vec.h"
#include "types.h"

DemNode *DemNode_new() {
	DemNode *ast_node = calloc(sizeof(DemNode), 1);
	if (!ast_node) {
		return NULL;
	}
	return ast_node;
}

DemNode *DemNode_ctor_inplace(DemNode *xs, CpDemTypeKind tag, const char *val_begin, size_t val_len) {
	if (!(xs && val_begin)) {
		return NULL;
	}
	xs->val = (DemStringView){ .buf = val_begin, .len = val_len };
	xs->tag = tag;
	xs->subtag = 0;
	xs->children = NULL;

	// Initialize union fields based on tag
	switch (tag) {
	case CP_DEM_TYPE_KIND_primitive_ty:
		dem_string_init(&xs->primitive_ty.name);
		break;
	case CP_DEM_TYPE_KIND_encoding:
	case CP_DEM_TYPE_KIND_function_type:
		xs->fn_ty.name = NULL;
		xs->fn_ty.params = NULL;
		xs->fn_ty.ret = NULL;
		xs->fn_ty.requires_node = NULL;
		xs->fn_ty.exception_spec = NULL;
		xs->fn_ty.cv_qualifiers = (CvQualifiers){ 0 };
		xs->fn_ty.ref_qualifiers = (RefQualifiers){ 0 };
		break;
	case CP_DEM_TYPE_KIND_module_name:
		xs->module_name_ty.IsPartition = false;
		xs->module_name_ty.name = NULL;
		xs->module_name_ty.pare = NULL;
		break;
	case CP_DEM_TYPE_KIND_name_with_template_args:
		xs->name_with_template_args.name = NULL;
		xs->name_with_template_args.template_args = NULL;
		break;
	case CP_DEM_TYPE_KIND_conv_op_ty:
		xs->conv_op_ty.ty = NULL;
		break;
	case CP_DEM_TYPE_KIND_parameter_pack_expansion:
		xs->parameter_pack_expansion.ty = NULL;
		break;
	case CP_DEM_TYPE_KIND_many:
		xs->many_ty.sep = NULL;
		// Fall through
	default:
		break;
	}

	return xs;
}

DemNode *DemNode_ctor(CpDemTypeKind tag, const char *val_begin, size_t val_len) {
	if (!(val_begin)) {
		return NULL;
	}
	DemNode *x = DemNode_new();
	if (!x) {
		return NULL;
	}
	DemNode_ctor_inplace(x, tag, val_begin, val_len);
	return x;
}

void DemNode_dtor(DemNode *xs) {
	DemNode_deinit(xs);
	free(xs);
}

bool DemNode_init(DemNode *xs) {
	if (!xs) {
		return false;
	}
	memset(xs, 0, sizeof(DemNode));
	return true;
}

void DemNode_deinit(DemNode *xs) {
	if (!xs) {
		return;
	}
	VecPDemNode_dtor(xs->children);
	// Handle different union variants based on tag
	switch (xs->tag) {
	case CP_DEM_TYPE_KIND_primitive_ty:
		// Free the primitive type's name string
		dem_string_deinit(&xs->primitive_ty.name);
		break;
	case CP_DEM_TYPE_KIND_encoding:
	case CP_DEM_TYPE_KIND_function_type:
		// Free function type fields (name, params, ret)
		if (xs->fn_ty.name) {
			DemNode_dtor(xs->fn_ty.name);
		}
		if (xs->fn_ty.params) {
			DemNode_dtor(xs->fn_ty.params);
		}
		if (xs->fn_ty.ret) {
			DemNode_dtor(xs->fn_ty.ret);
		}
		if (xs->fn_ty.requires_node) {
			DemNode_dtor(xs->fn_ty.requires_node);
		}
		if (xs->fn_ty.exception_spec) {
			DemNode_dtor(xs->fn_ty.exception_spec);
		}
		break;
	case CP_DEM_TYPE_KIND_qualified_type:
		// Free qualified type's inner type
		if (xs->qualified_ty.inner_type) {
			DemNode_dtor(xs->qualified_ty.inner_type);
		}
		break;
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type:
		// Free vendor ext qualified type's inner type and template args
		if (xs->vendor_ext_qualified_ty.inner_type) {
			DemNode_dtor(xs->vendor_ext_qualified_ty.inner_type);
		}
		if (xs->vendor_ext_qualified_ty.template_args) {
			DemNode_dtor(xs->vendor_ext_qualified_ty.template_args);
		}
		break;
	case CP_DEM_TYPE_KIND_module_name:
		if (xs->module_name_ty.name) {
			DemNode_dtor(xs->module_name_ty.name);
		}
		if (xs->module_name_ty.pare) {
			DemNode_dtor(xs->module_name_ty.pare);
		}
		break;
	case CP_DEM_TYPE_KIND_name_with_template_args:
		if (xs->name_with_template_args.name) {
			DemNode_dtor(xs->name_with_template_args.name);
		}
		if (xs->name_with_template_args.template_args) {
			DemNode_dtor(xs->name_with_template_args.template_args);
		}
		break;
	case CP_DEM_TYPE_KIND_closure_ty_name:
		if (xs->closure_ty_name.template_params) {
			DemNode_dtor(xs->closure_ty_name.template_params);
		}
		if (xs->closure_ty_name.params) {
			DemNode_dtor(xs->closure_ty_name.params);
		}
		// count is a DemStringView (not allocated), no need to free
		break;
	case CP_DEM_TYPE_KIND_nested_name:
		if (xs->nested_name.qual) {
			DemNode_dtor(xs->nested_name.qual);
		}
		if (xs->nested_name.name) {
			DemNode_dtor(xs->nested_name.name);
		}
		break;
	case CP_DEM_TYPE_KIND_local_name:
		if (xs->local_name.encoding) {
			DemNode_dtor(xs->local_name.encoding);
		}
		if (xs->local_name.entry) {
			DemNode_dtor(xs->local_name.entry);
		}
		break;
	case CP_DEM_TYPE_KIND_ctor_dtor_name:
		// NOTE: ctor_dtor_name.name is a non-owning pointer to the scope,
		// is_dtor is a bool, no need to free
		break;
	case CP_DEM_TYPE_KIND_conv_op_ty:
		if (xs->conv_op_ty.ty) {
			DemNode_dtor(xs->conv_op_ty.ty);
		}
		break;
	case CP_DEM_TYPE_KIND_parameter_pack_expansion:
		if (xs->parameter_pack_expansion.ty) {
			DemNode_dtor(xs->parameter_pack_expansion.ty);
		}
		break;
	case CP_DEM_TYPE_KIND_abi_tag_ty:
		if (xs->abi_tag_ty.ty) {
			DemNode_dtor(xs->abi_tag_ty.ty);
		}
		// tag is a DemStringView (not allocated), no need to free
		break;
	case CP_DEM_TYPE_KIND_vector_type:
	case CP_DEM_TYPE_KIND_array_type:
		if (xs->array_ty.inner_ty) {
			DemNode_dtor(xs->array_ty.inner_ty);
		}
		if (xs->array_ty.dimension) {
			DemNode_dtor(xs->array_ty.dimension);
		}
		break;
	case CP_DEM_TYPE_KIND_member_expression:
		if (xs->member_expr.lhs) {
			DemNode_dtor(xs->member_expr.lhs);
		}
		if (xs->member_expr.rhs) {
			DemNode_dtor(xs->member_expr.rhs);
		}
		// op is a DemStringView (not allocated), no need to free
		break;
	case CP_DEM_TYPE_KIND_fold_expression:
		if (xs->fold_expr.pack) {
			DemNode_dtor(xs->fold_expr.pack);
		}
		if (xs->fold_expr.init) {
			DemNode_dtor(xs->fold_expr.init);
		}
		// op is a DemStringView (not allocated), no need to free
		// is_left_fold is a bool, no need to free
		break;
	case CP_DEM_TYPE_KIND_braced_expression:
		if (xs->braced_expr.elem) {
			DemNode_dtor(xs->braced_expr.elem);
		}
		if (xs->braced_expr.init) {
			DemNode_dtor(xs->braced_expr.init);
		}
		// is_array is a bool, no need to free
		break;
	case CP_DEM_TYPE_KIND_braced_range_expression:
		if (xs->braced_range_expr.first) {
			DemNode_dtor(xs->braced_range_expr.first);
		}
		if (xs->braced_range_expr.last) {
			DemNode_dtor(xs->braced_range_expr.last);
		}
		if (xs->braced_range_expr.init) {
			DemNode_dtor(xs->braced_range_expr.init);
		}
		break;
	case CP_DEM_TYPE_KIND_init_list_expression:
		if (xs->init_list_expr.ty) {
			DemNode_dtor(xs->init_list_expr.ty);
		}
		if (xs->init_list_expr.inits) {
			DemNode_dtor(xs->init_list_expr.inits);
		}
		break;
	case CP_DEM_TYPE_KIND_binary_expression:
		if (xs->binary_expr.lhs) {
			DemNode_dtor(xs->binary_expr.lhs);
		}
		if (xs->binary_expr.rhs) {
			DemNode_dtor(xs->binary_expr.rhs);
		}
		// op is a DemStringView (not allocated), no need to free
		break;
	case CP_DEM_TYPE_KIND_prefix_expression:
		if (xs->prefix_expr.inner) {
			DemNode_dtor(xs->prefix_expr.inner);
		}
		// prefix is a DemStringView (not allocated), no need to free
		break;
	case CP_DEM_TYPE_KIND_new_expression:
		if (xs->new_expr.expr_list) {
			DemNode_dtor(xs->new_expr.expr_list);
		}
		if (xs->new_expr.ty) {
			DemNode_dtor(xs->new_expr.ty);
		}
		if (xs->new_expr.init_list) {
			DemNode_dtor(xs->new_expr.init_list);
		}
		// is_global is a bool, op is a DemStringView (not allocated), no need to free
		break;
	case CP_DEM_TYPE_KIND_many:
		// sep is a string literal, don't free it
		// Fall through to free children vector
	default:
		break;
	}
	memset(xs, 0, sizeof(DemNode));
}

bool DemNode_is_empty(DemNode *x) {
	if (!x) {
		return true;
	}
	return (x->val.len == 0);
}

void DemNode_copy(DemNode *dst, const DemNode *src) {
	if (!(dst && src)) {
		return;
	}
	// Free existing children vector if it exists to prevent memory leak
	if (dst->children) {
		VecF(PDemNode, dtor)(dst->children);
		dst->children = NULL;
	}
	dst->val = src->val;
	dst->tag = src->tag;
	dst->prec = src->prec;
	dst->subtag = src->subtag;
	if (src->children) {
		dst->children = VecF(PDemNode, ctor)();
		NodeList_copy(dst->children, src->children);
	} else {
		dst->children = NULL;
	}

	// Copy union fields based on tag
	switch (src->tag) {
	case CP_DEM_TYPE_KIND_primitive_ty:
		dem_string_init_clone(&dst->primitive_ty.name, &src->primitive_ty.name);
		break;
	case CP_DEM_TYPE_KIND_encoding:
	case CP_DEM_TYPE_KIND_function_type:
		// Deep copy function type fields
		dst->fn_ty.name = src->fn_ty.name ? DemNode_clone(src->fn_ty.name) : NULL;
		dst->fn_ty.ret = src->fn_ty.ret ? DemNode_clone(src->fn_ty.ret) : NULL;
		dst->fn_ty.requires_node = src->fn_ty.requires_node ? DemNode_clone(src->fn_ty.requires_node) : NULL;
		dst->fn_ty.exception_spec = src->fn_ty.exception_spec ? DemNode_clone(src->fn_ty.exception_spec) : NULL;
		dst->fn_ty.params = src->fn_ty.params ? DemNode_clone(src->fn_ty.params) : NULL;
		dst->fn_ty.cv_qualifiers = src->fn_ty.cv_qualifiers;
		dst->fn_ty.ref_qualifiers = src->fn_ty.ref_qualifiers;
		break;
	case CP_DEM_TYPE_KIND_qualified_type:
		// Deep copy qualified type fields
		dst->qualified_ty.inner_type = src->qualified_ty.inner_type ? DemNode_clone(src->qualified_ty.inner_type) : NULL;
		dst->qualified_ty.qualifiers = src->qualified_ty.qualifiers;
		break;
	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type:
		// Deep copy vendor qualified type fields
		dst->vendor_ext_qualified_ty.inner_type = src->vendor_ext_qualified_ty.inner_type ? DemNode_clone(src->vendor_ext_qualified_ty.inner_type) : NULL;
		dst->vendor_ext_qualified_ty.vendor_ext = src->vendor_ext_qualified_ty.vendor_ext;
		dst->vendor_ext_qualified_ty.template_args = src->vendor_ext_qualified_ty.template_args ? DemNode_clone(src->vendor_ext_qualified_ty.template_args) : NULL;
		break;
	case CP_DEM_TYPE_KIND_module_name:
		dst->module_name_ty.IsPartition = src->module_name_ty.IsPartition;
		dst->module_name_ty.name = src->module_name_ty.name ? DemNode_clone(src->module_name_ty.name) : NULL;
		dst->module_name_ty.pare = src->module_name_ty.pare ? DemNode_clone(src->module_name_ty.pare) : NULL;
		break;
	case CP_DEM_TYPE_KIND_name_with_template_args:
		dst->name_with_template_args.name = src->name_with_template_args.name ? DemNode_clone(src->name_with_template_args.name) : NULL;
		dst->name_with_template_args.template_args = src->name_with_template_args.template_args ? DemNode_clone(src->name_with_template_args.template_args) : NULL;
		break;
	case CP_DEM_TYPE_KIND_closure_ty_name:
		dst->closure_ty_name.template_params = src->closure_ty_name.template_params ? DemNode_clone(src->closure_ty_name.template_params) : NULL;
		dst->closure_ty_name.params = src->closure_ty_name.params ? DemNode_clone(src->closure_ty_name.params) : NULL;
		dst->closure_ty_name.count = src->closure_ty_name.count; // DemStringView, shallow copy
		break;
	case CP_DEM_TYPE_KIND_nested_name:
		dst->nested_name.qual = src->nested_name.qual ? DemNode_clone(src->nested_name.qual) : NULL;
		dst->nested_name.name = src->nested_name.name ? DemNode_clone(src->nested_name.name) : NULL;
		break;
	case CP_DEM_TYPE_KIND_local_name:
		dst->local_name.encoding = src->local_name.encoding ? DemNode_clone(src->local_name.encoding) : NULL;
		dst->local_name.entry = src->local_name.entry ? DemNode_clone(src->local_name.entry) : NULL;
		break;
	case CP_DEM_TYPE_KIND_ctor_dtor_name:
		// NOTE: ctor_dtor_name.name is a non-owning pointer.
		// For shallow copy, just copy the pointer (don't clone).
		dst->ctor_dtor_name.name = src->ctor_dtor_name.name;
		dst->ctor_dtor_name.is_dtor = src->ctor_dtor_name.is_dtor;
		break;
	case CP_DEM_TYPE_KIND_conv_op_ty:
		dst->conv_op_ty.ty = src->conv_op_ty.ty ? DemNode_clone(src->conv_op_ty.ty) : NULL;
		break;
	case CP_DEM_TYPE_KIND_parameter_pack_expansion:
		dst->parameter_pack_expansion.ty = src->parameter_pack_expansion.ty ? DemNode_clone(src->parameter_pack_expansion.ty) : NULL;
		break;
	case CP_DEM_TYPE_KIND_abi_tag_ty:
		dst->abi_tag_ty.ty = src->abi_tag_ty.ty ? DemNode_clone(src->abi_tag_ty.ty) : NULL;
		dst->abi_tag_ty.tag = src->abi_tag_ty.tag; // DemStringView, shallow copy
		break;
	case CP_DEM_TYPE_KIND_vector_type:
	case CP_DEM_TYPE_KIND_array_type:
		dst->array_ty.inner_ty = src->array_ty.inner_ty ? DemNode_clone(src->array_ty.inner_ty) : NULL;
		dst->array_ty.dimension = src->array_ty.dimension ? DemNode_clone(src->array_ty.dimension) : NULL;
		break;
	case CP_DEM_TYPE_KIND_member_expression:
		dst->member_expr.lhs = src->member_expr.lhs ? DemNode_clone(src->member_expr.lhs) : NULL;
		dst->member_expr.rhs = src->member_expr.rhs ? DemNode_clone(src->member_expr.rhs) : NULL;
		dst->member_expr.op = src->member_expr.op; // DemStringView, shallow copy
		break;
	case CP_DEM_TYPE_KIND_fold_expression:
		dst->fold_expr.pack = src->fold_expr.pack ? DemNode_clone(src->fold_expr.pack) : NULL;
		dst->fold_expr.init = src->fold_expr.init ? DemNode_clone(src->fold_expr.init) : NULL;
		dst->fold_expr.op = src->fold_expr.op; // DemStringView, shallow copy
		dst->fold_expr.is_left_fold = src->fold_expr.is_left_fold;
		break;
	case CP_DEM_TYPE_KIND_braced_expression:
		dst->braced_expr.elem = src->braced_expr.elem ? DemNode_clone(src->braced_expr.elem) : NULL;
		dst->braced_expr.init = src->braced_expr.init ? DemNode_clone(src->braced_expr.init) : NULL;
		dst->braced_expr.is_array = src->braced_expr.is_array;
		break;
	case CP_DEM_TYPE_KIND_braced_range_expression:
		dst->braced_range_expr.first = src->braced_range_expr.first ? DemNode_clone(src->braced_range_expr.first) : NULL;
		dst->braced_range_expr.last = src->braced_range_expr.last ? DemNode_clone(src->braced_range_expr.last) : NULL;
		dst->braced_range_expr.init = src->braced_range_expr.init ? DemNode_clone(src->braced_range_expr.init) : NULL;
		break;
	case CP_DEM_TYPE_KIND_init_list_expression:
		dst->init_list_expr.ty = src->init_list_expr.ty ? DemNode_clone(src->init_list_expr.ty) : NULL;
		dst->init_list_expr.inits = src->init_list_expr.inits ? DemNode_clone(src->init_list_expr.inits) : NULL;
		break;
	case CP_DEM_TYPE_KIND_binary_expression:
		dst->binary_expr.lhs = src->binary_expr.lhs ? DemNode_clone(src->binary_expr.lhs) : NULL;
		dst->binary_expr.rhs = src->binary_expr.rhs ? DemNode_clone(src->binary_expr.rhs) : NULL;
		dst->binary_expr.op = src->binary_expr.op; // DemStringView, shallow copy
		break;
	case CP_DEM_TYPE_KIND_prefix_expression:
		dst->prefix_expr.inner = src->prefix_expr.inner ? DemNode_clone(src->prefix_expr.inner) : NULL;
		dst->prefix_expr.prefix = src->prefix_expr.prefix; // DemStringView, shallow copy
		break;
	case CP_DEM_TYPE_KIND_new_expression:
		dst->new_expr.expr_list = src->new_expr.expr_list ? DemNode_clone(src->new_expr.expr_list) : NULL;
		dst->new_expr.ty = src->new_expr.ty ? DemNode_clone(src->new_expr.ty) : NULL;
		dst->new_expr.init_list = src->new_expr.init_list ? DemNode_clone(src->new_expr.init_list) : NULL;
		dst->new_expr.is_global = src->new_expr.is_global; // bool, shallow copy
		dst->new_expr.op = src->new_expr.op; // DemStringView, shallow copy
		break;
	case CP_DEM_TYPE_KIND_fwd_template_ref:
		dst->fwd_template_ref = src->fwd_template_ref;
		break;
	case CP_DEM_TYPE_KIND_many:
		// Deep copy many type fields
		dst->many_ty.sep = src->many_ty.sep; // Separator is a string literal
		// Fall through to copy children
	default:
		break;
	}
}

void DemNode_move(DemNode *dst, DemNode *src) {
	if (!(dst && src && dst != src)) {
		return;
	}
	DemNode_deinit(dst);
	memcpy(dst, src, sizeof(DemNode));
	memset(src, 0, sizeof(DemNode));
}

void DemNode_init_clone(DemNode *dst, const DemNode *src) {
	if (!(dst && src)) {
		return;
	}
	DemNode_init(dst);
	DemNode_copy(dst, src);
}

DemNode *DemNode_clone(const DemNode *src) {
	if (!src) {
		return NULL;
	}
	DemNode *dst = DemNode_new();
	if (!dst) {
		return NULL;
	}
	DemNode_copy(dst, src);
	return dst;
}

DemNode *make_primitive_type_inplace(DemNode *x, const char *begin, const char *end, const char *name, size_t name_len) {
	if (!x) {
		return NULL;
	}
	DemNode *node = DemNode_ctor_inplace(x, CP_DEM_TYPE_KIND_primitive_ty, begin, end - begin);
	if (!node) {
		return NULL;
	}
	dem_string_append_n(&node->primitive_ty.name, name, name_len);
	return node;
}

DemNode *make_primitive_type(const char *begin, const char *end, const char *name, size_t name_len) {
	DemNode *node = DemNode_ctor(CP_DEM_TYPE_KIND_primitive_ty, begin, end - begin);
	if (!node) {
		return NULL;
	}
	return make_primitive_type_inplace(node, begin, end, name, name_len);
}

DemNode *make_name_with_template_args(const char *begin, const char *end, DemNode *name_node, DemNode *template_args_node) {
	DemNode *node = DemNode_ctor(CP_DEM_TYPE_KIND_name_with_template_args, begin, end - begin);
	if (!node) {
		return NULL;
	}
	node->name_with_template_args.name = name_node;
	node->name_with_template_args.template_args = template_args_node;
	return node;
}
