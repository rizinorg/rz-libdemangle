// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <time.h>

#include "types.h"
#include "../vec.h"
#include "v3_pp.h"

// ============================================================================
// DemParser functions
// ============================================================================

void DemParser_init(DemParser *p, CpDemOptions options, const char *input) {
	if (!p) {
		return;
	}

	memset(p, 0, sizeof(DemParser));

	// Initialize string iterator fields
	p->beg = input;
	p->cur = input;
	p->end = input ? (input + strlen(input)) : NULL;
	p->options = options;

	// Initialize metadata fields
	p->outer_template_params = VecF(NodeRef, ctor)();
	VecNodeRef_init(&p->detected_types);
	VecNodeRef_init(&p->names);
	VecNodeRef_init(&p->orphan_nodes);
	VecVecNodeRef_init(&p->template_params);
	VecPForwardTemplateRef_init(&p->forward_template_refs);
	VecPForwardTemplateRef_init(&p->orphan_fwd_refs);

	p->parse_lambda_params_at_level = SIZE_MAX;
	p->permit_forward_template_refs = false;
}

void DemParser_deinit(DemParser *p) {
	if (!p) {
		return;
	}

	// Deinitialize metadata fields
	VecF(NodeRef, deinit)(&p->detected_types);
	VecF(NodeRef, deinit)(&p->names);
	VecF(NodeRef, deinit)(&p->orphan_nodes);
	VecF(NodeRef, dtor)(p->outer_template_params);
	VecF(VecNodeRef, deinit)(&p->template_params);
	VecF(PForwardTemplateRef, deinit)(&p->forward_template_refs);
	VecF(PForwardTemplateRef, deinit)(&p->orphan_fwd_refs);

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
	r->output = NULL;
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

	NodeRef *slot = VecF(NodeRef, append)(&p->detected_types, &x);
	if (!slot) {
		if (p->trace) {
			fprintf(stderr, "[append_type] FAILED to append type\n");
		}
		return false;
	}
	return true;
}

NodeRef substitute_get(DemParser *p, ut64 id) {
	if (p->detected_types.length <= id) {
		return NULL;
	}
	NodeRef *type_node_ptr = VecNodeRef_at(&p->detected_types, id);
	return type_node_ptr ? *type_node_ptr : NULL;
}

NodeRef template_param_get(DemParser *p, ut64 level, ut64 index) {
	if (level >= p->template_params.length) {
		goto branch_fail;
	}
	VecNodeRef *pptparams_at_level = VecVecNodeRef_at(&p->template_params, level);
	if (!(pptparams_at_level  && index < pptparams_at_level->length)) {
		goto branch_fail;
	}
	NodeRef *node_ptr = VecNodeRef_at(pptparams_at_level, index);
	return node_ptr ? *node_ptr : NULL;

branch_fail:
	if (p->trace) {
		fprintf(stderr, "[get_tparam] FAILED L%" PRIu64 "_%" PRIu64 "\n", level, index);
	}
	return NULL;
}

bool resolve_forward_template_refs(DemParser *p, NodeRef node) {
	if (!p || p->forward_template_refs.length == 0 || !node) {
		return true;
	}

	bool all_resolved = true;
	vec_foreach_ptr(PForwardTemplateRef, &p->forward_template_refs, pfwd_ref, {
		if (!pfwd_ref) {
			continue;
		}
		ForwardTemplateRef *fwd_ref = *pfwd_ref;
		ut64 level = fwd_ref->level;
		ut64 index = fwd_ref->index;

		NodeRef ref_src = template_param_get(p, level, index);
		if (!ref_src) {
			all_resolved = false;
			continue;
		}

		fwd_ref->ref = ref_src;

		if (p->trace) {
			DemString buf = { 0 };
			PPContext pp_ctx = { 0 };
			PPContext_init(&pp_ctx, p->options);
			ast_pp(ref_src, &buf, &pp_ctx);
			fprintf(stderr, "[resolve_fwd_ref] Resolved L%" PRIu64 "_%" PRIu64 " into node %s\n",
				level, index, buf.buf ? buf.buf : "");
			dem_string_deinit(&buf);
		}
	});

	if (p->forward_template_refs.length <= 0 || !all_resolved) {
		return all_resolved;
	}
	return true;
}
