// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "cplusplus/vec.h"
#include "types.h"

DemAstNode *DemAstNode_new() {
	DemAstNode *dan = (DemAstNode *)malloc(sizeof(DemAstNode));
	if (!dan) {
		return NULL;
	}
	if (!DemAstNode_init(dan)) {
		free(dan);
		return NULL;
	}
	return dan;
}

DemAstNode *DemAstNode_ctor_inplace(DemAstNode *dan, CpDemTypeKind tag, const char *dem, const char *val_begin, size_t val_len) {
	if (!(dan && dem && val_begin)) {
		return NULL;
	}
	dem_string_init(&dan->dem);
	dem_string_append(&dan->dem, dem);
	dan->val = (DemStringView){ .buf = val_begin, .len = val_len };
	dan->tag = tag;
	dan->children = NULL;
	return dan;
}

DemAstNode *DemAstNode_ctor(CpDemTypeKind tag, const char *dem, const char *val_begin, size_t val_len) {
	if (!(dem && val_begin)) {
		return NULL;
	}
	DemAstNode *dan = (DemAstNode *)malloc(sizeof(DemAstNode));
	if (!dan) {
		return NULL;
	}
	return DemAstNode_ctor_inplace(dan, tag, dem, val_begin, val_len);
}

void DemAstNode_dtor(DemAstNode *dan) {
	DemAstNode_deinit(dan);
	free(dan);
}

bool DemAstNode_init(DemAstNode *dan) {
	if (!dan) {
		return false;
	}
	memset(dan, 0, sizeof(DemAstNode));
	return true;
}

void DemAstNode_deinit(DemAstNode *dan) {
	if (!dan) {
		return;
	}
	if (getenv("DEMANGLE_TRACE")) {
		fprintf(stderr, "[DemAstNode_deinit] dan=%p, dem.buf=%p ('%s'), dem.len=%zu, children=%p\n",
			(void *)dan, (void *)dan->dem.buf, dan->dem.buf ? dan->dem.buf : "(null)",
			dan->dem.len, (void *)dan->children);
	}
	VecDemAstNode_dtor(dan->children);
	dem_string_deinit(&dan->dem);
	memset(dan, 0, sizeof(DemAstNode));
}

DemAstNode *DemAstNode_append(DemAstNode *xs, DemAstNode *x) {
	if (!xs) {
		return false;
	}
	if (!xs->children) {
		xs->children = VecF(DemAstNode, ctor)();
		if (!xs->children) {
			return false;
		}
	}
	DemAstNode *node = VecDemAstNode_append(xs->children, x);
	if (!x) {
		return node;
	}
	if (!node) {
		return NULL;
	}

	x->parent = xs;
	dem_string_concat(&xs->dem, &x->dem);
	xs->val.len += x->val.len;
	xs->val.buf = xs->val.buf == NULL ? x->val.buf : xs->val.buf;

	// Transfer ownership to the vector
	memset(x, 0, sizeof(DemAstNode));

	return node;
}

DemAstNode *DemAstNode_children_at(DemAstNode *xs, size_t idx) {
	if (!xs) {
		return NULL;
	}
	if (!xs->children) {
		xs->children = VecF(DemAstNode, ctor)();
		if (!xs->children) {
			return false;
		}
	}
	if (VecF(DemAstNode, len)(xs->children) <= idx) {
		VecF(DemAstNode, resize)(xs->children, idx + 1);
	}
	DemAstNode *x = VecF(DemAstNode, at)(xs->children, idx);
	x->parent = xs;
	return x;
}

bool DemAstNode_is_empty(DemAstNode *x) {
	if (!x) {
		return true;
	}
	return (x->dem.len == 0 && x->val.len == 0);
}

void DemAstNode_copy(DemAstNode *dst, const DemAstNode *src) {
	if (!(dst && src)) {
		return;
	}
	dem_string_init_clone(&dst->dem, &src->dem);
	dst->val = src->val;
	dst->tag = src->tag;
	dst->subtag = src->subtag;
	dst->parent = src->parent;
	if (!src->children) {
		return;
	}
	dst->children = VecF(DemAstNode, ctor)();
	NodeList_copy(dst->children, src->children);
}

void DemAstNode_init_clone(DemAstNode *dst, const DemAstNode *src) {
	if (!(dst && src)) {
		return;
	}
	DemAstNode_init(dst);
	DemAstNode_copy(dst, src);
}
