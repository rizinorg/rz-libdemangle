// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "cplusplus/vec.h"
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
	dst->parent = src->parent;
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
		if (dst->module_name_ty.name) {
			dst->module_name_ty.name->parent = dst;
		}
		if (dst->module_name_ty.pare) {
			dst->module_name_ty.pare->parent = dst;
		}
		break;
	case CP_DEM_TYPE_KIND_name_with_template_args:
		dst->name_with_template_args.name = src->name_with_template_args.name ? DemNode_clone(src->name_with_template_args.name) : NULL;
		dst->name_with_template_args.template_args = src->name_with_template_args.template_args ? DemNode_clone(src->name_with_template_args.template_args) : NULL;
		if (dst->name_with_template_args.name) {
			dst->name_with_template_args.name->parent = dst;
		}
		if (dst->name_with_template_args.template_args) {
			dst->name_with_template_args.template_args->parent = dst;
		}
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
