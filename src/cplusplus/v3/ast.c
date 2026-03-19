// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../vec.h"
#include "types.h"

DemNode *DemNode_new(DemContext *ctx) {
	DemNode *ast_node = calloc(sizeof(DemNode), 1);
	if (!ast_node) {
		return NULL;
	}
	if (ctx) {
		PDemNode ptr = ast_node;
		if (!VecPDemNode_append(&ctx->node_pool, &ptr)) {
			free(ast_node);
			return NULL;
		}
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
	xs->children = (VecNodeRef){ 0 };

	// Initialize union fields based on tag
	switch (tag) {
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY:
		dem_string_init(&xs->primitive_ty.name);
		break;
	case CP_DEM_TYPE_KIND_ENCODING:
	case CP_DEM_TYPE_KIND_FUNCTION_TYPE:
		xs->fn_ty.name = NULL;
		xs->fn_ty.params = NULL;
		xs->fn_ty.ret = NULL;
		xs->fn_ty.requires_node = NULL;
		xs->fn_ty.exception_spec = NULL;
		xs->fn_ty.enable_if_attrs = NULL;
		xs->fn_ty.cv_qualifiers = (CvQualifiers){ 0 };
		xs->fn_ty.ref_qualifiers = (RefQualifiers){ 0 };
		break;
	case CP_DEM_TYPE_KIND_MODULE_NAME:
		xs->module_name_ty.IsPartition = false;
		xs->module_name_ty.name = NULL;
		xs->module_name_ty.pare = NULL;
		break;
	case CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS:
		xs->name_with_template_args.name = NULL;
		xs->name_with_template_args.template_args = NULL;
		break;
	case CP_DEM_TYPE_KIND_CONV_OP_TY:
		xs->conv_op_ty.ty = NULL;
		break;
	case CP_DEM_TYPE_KIND_PARAMETER_PACK_EXPANSION:
	case CP_DEM_TYPE_KIND_NOEXCEPT_SPEC:
	case CP_DEM_TYPE_KIND_DYNAMIC_EXCEPTION_SPEC:
	case CP_DEM_TYPE_KIND_CONSTRAINED_PLACEHOLDER:
		xs->child = NULL;
		break;
	case CP_DEM_TYPE_KIND_PARAMETER_PACK:
		break;
	case CP_DEM_TYPE_KIND_MANY:
		xs->many_ty.sep = NULL;
		// Fall through
	default:
		break;
	}

	return xs;
}

DemNode *DemNode_ctor(DemContext *ctx, CpDemTypeKind tag, const char *val_begin, size_t val_len) {
	if (!(val_begin)) {
		return NULL;
	}
	DemNode *x = DemNode_new(ctx);
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
	switch (xs->tag) {
	case CP_DEM_TYPE_KIND_PRIMITIVE_TY:
		dem_string_deinit(&xs->primitive_ty.name);
		break;
	default:
		break;
	}
	if (xs->children.data) {
		free(xs->children.data);
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
	if (dst == src) {
		return;
	}
	VecNodeRef saved_children = dst->children;
	memcpy(dst, src, sizeof(DemNode));
	dst->children = saved_children;
	if (src->children.data && src->children.length > 0) {
		if (!VecNodeRef_reserve(&dst->children, src->children.length)) {
			/* On allocation failure, avoid using a possibly NULL or undersized buffer. */
			dst->children.length = 0;
			return;
		}
		memcpy(dst->children.data, src->children.data, src->children.length * sizeof(NodeRef));
		dst->children.length = src->children.length;
	}
	if (src->tag == CP_DEM_TYPE_KIND_PRIMITIVE_TY && src->primitive_ty.name.buf) {
		dem_string_init(&dst->primitive_ty.name);
		dem_string_append_n(&dst->primitive_ty.name, src->primitive_ty.name.buf, src->primitive_ty.name.len);
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

DemNode *make_primitive_type_inplace(DemNode *x, const char *begin, const char *end, const char *name, size_t name_len) {
	if (!x) {
		return NULL;
	}
	DemNode *node = DemNode_ctor_inplace(x, CP_DEM_TYPE_KIND_PRIMITIVE_TY, begin, end - begin);
	if (!node) {
		return NULL;
	}
	dem_string_append_n(&node->primitive_ty.name, name, name_len);
	return node;
}

DemNode *make_primitive_type(DemContext *ctx, const char *begin, const char *end, const char *name, size_t name_len) {
	DemNode *node = DemNode_ctor(ctx, CP_DEM_TYPE_KIND_PRIMITIVE_TY, begin, end - begin);
	if (!node) {
		return NULL;
	}
	return make_primitive_type_inplace(node, begin, end, name, name_len);
}

DemNode *make_name_with_template_args(DemContext *ctx, const char *begin, const char *end, DemNode *name_node, DemNode *template_args_node) {
	DemNode *node = DemNode_ctor(ctx, CP_DEM_TYPE_KIND_NAME_WITH_TEMPLATE_ARGS, begin, end - begin);
	if (!node) {
		return NULL;
	}
	node->name_with_template_args.name = name_node;
	node->name_with_template_args.template_args = template_args_node;
	return node;
}


