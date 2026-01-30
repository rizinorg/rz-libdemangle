// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <time.h>

#include "types.h"
#include "vec.h"
#include "v3_pp.h"

void NodeList_copy(NodeList *dst, const NodeList *src) {
	if (!(src && dst && src != dst)) {
		return;
	}

	VecF(PDemNode, deinit)(dst);
	VecF(PDemNode, init)(dst);

	vec_foreach_ptr(src, node_ptr, {
		if (!node_ptr || !*node_ptr) {
			return;
		}
		DemNode *cloned = DemNode_clone(*node_ptr);
		VecF(PDemNode, append)(dst, &cloned);
	});
}

NodeList *NodeList_make(NodeList *self, ut64 from, ut64 to) {
	if (to > VecF(PDemNode, len)(self) || from >= to) {
		return NULL;
	}
	ut64 sz = to - from;
	NodeList *new_list = VecF(PDemNode, ctor)();
	if (!new_list) {
		return NULL;
	}
	VecF(PDemNode, reserve)(new_list, sz);
	memcpy(new_list->data, VecF(PDemNode, at)(self, from), sizeof(PDemNode) * sz);
	new_list->length = sz;
	return new_list;
}

// ============================================================================
// DemParser functions
// ============================================================================

void DemParser_init(DemParser *p, const char *input) {
	if (!p) {
		return;
	}

	memset(p, 0, sizeof(DemParser));

	// Initialize string iterator fields
	p->beg = input;
	p->cur = input;
	p->end = input ? (input + strlen(input)) : NULL;

	// Initialize metadata fields
	p->outer_template_params = VecF(PDemNode, ctor)();
	vec_init(&p->detected_types);
	vec_init(&p->names);
	vec_init(&p->template_params);
	vec_init(&p->forward_template_refs);
}

void DemParser_deinit(DemParser *p) {
	if (!p) {
		return;
	}

	// Deinitialize metadata fields
	VecF(PDemNode, deinit)(&p->detected_types);
	VecF(PDemNode, deinit)(&p->names);
	VecF(PDemNode, dtor)(p->outer_template_params);
	VecF(PNodeList, deinit)(&p->template_params);
	VecF(PForwardTemplateRef, deinit)(&p->forward_template_refs);

	memset(p, 0, sizeof(DemParser));
}

void NameState_init(NameState *ns, const DemParser *p) {
	if (!ns || !p) {
		return;
	}
	memset(ns, 0, sizeof(NameState));
	ns->is_conversion_ctor_dtor = false;
	ns->end_with_template_args = false;
	ns->fwd_template_ref_begin = VecPForwardTemplateRef_len(&p->forward_template_refs);
}

void DemResult_deinit(DemResult *r) {
	if (!r) {
		return;
	}
	if (r->output) {
		DemNode_dtor(r->output);
		r->output = NULL;
	}
	r->error = DEM_ERR_OK;
}

/**
 * Append given type name to list of all detected types.
 * This vector is then used to refer back to a detected type in substitution
 * rules.
 */
bool append_type(DemParser *p, const DemNode *x) {
	if (!p || !x) {
		return false;
	}

	DemNode *new_node = DemNode_clone(x);
	PDemNode *slot = VecF(PDemNode, append)(&p->detected_types, &new_node);
	if (!slot) {
		DemNode_dtor(new_node);
		if (p->trace) {
			fprintf(stderr, "[append_type] FAILED to append type\n");
		}
		return false;
	}
	return true;
}

DemNode *substitute_get(DemParser *p, ut64 id) {
	if (p->detected_types.length <= id) {
		return NULL;
	}
	PDemNode *type_node_ptr = vec_ptr_at(&p->detected_types, id);
	return type_node_ptr ? *type_node_ptr : NULL;
}

DemNode *template_param_get(DemParser *p, ut64 level, ut64 index) {
	if (level >= p->template_params.length) {
		goto branch_fail;
	}
	NodeList **pptparams_at_level = vec_ptr_at(&p->template_params, level);
	if (!(pptparams_at_level && *pptparams_at_level && index < (*pptparams_at_level)->length)) {
		goto branch_fail;
	}
	NodeList *tparams_at_level = *pptparams_at_level;
	PDemNode *node_ptr = vec_ptr_at(tparams_at_level, index);
	return node_ptr ? *node_ptr : NULL;

branch_fail:
	if (p->trace) {
		fprintf(stderr, "[get_tparam] FAILED L%ld_%ld\n", level, index);
	}
	return NULL;
}

bool resolve_forward_template_refs(DemParser *p, DemNode *dan) {
	if (!p || p->forward_template_refs.length == 0 || !dan) {
		return true;
	}

	bool all_resolved = true;
	vec_foreach(&p->forward_template_refs, fwd_ref, {
		ut64 level = fwd_ref->level;
		ut64 index = fwd_ref->index;

		DemNode *ref_src = template_param_get(p, level, index);
		if (!ref_src) {
			all_resolved = false;
			continue;
		}

		fwd_ref->ref = ref_src;

		if (p->trace) {
			DemString buf = { 0 };
			ast_pp(ref_src, &buf);
			fprintf(stderr, "[resolve_fwd_ref] Resolved L%ld_%ld into node %s\n",
				level, index, dem_string_drain_no_free(&buf));
		}
	});

	if (p->forward_template_refs.length <= 0 || !all_resolved) {
		return all_resolved;
	}
	return true;
}
