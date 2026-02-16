// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "parser_combinator.h"

#include "macros.h"

bool match_many1(
	DemParser *p,
	DemResult *r,
	DemRule rule,
	const char *sep,
	const char stop) {
	const char *saved_pos = p->cur;
	if (!match_many(p, r, rule, sep, stop)) {
		p->cur = saved_pos;
		return false;
	}
	if (!r->output || VecF(PDemNode, len)(r->output->children) == 0) {
		p->cur = saved_pos;
		DemNode_dtor(r->output);
		r->output = NULL;
		return false;
	}
	return true;
}

bool match_many(
	DemParser *p,
	DemResult *r,
	DemRule rule,
	const char *sep,
	const char stop) {
	if (!rule || !r || !p) {
		r->error = DEM_ERR_INVALID_SYNTAX;
		return false;
	}

	// Allocate output node with tag=many
	DemNode *many_node = DemNode_new();
	if (!many_node) {
		r->error = DEM_ERR_OUT_OF_MEMORY;
		return false;
	}
	many_node->tag = CP_DEM_TYPE_KIND_MANY;
	many_node->val.buf = p->cur;

	// Allocate children vector
	many_node->children = VecPDemNode_ctor();
	if (!many_node->children) {
		free(many_node);
		r->error = DEM_ERR_OUT_OF_MEMORY;
		return false;
	}
	many_node->many_ty.sep = sep ? sep : ""; // Use provided separator or default to empty

	while (stop != '\0' ? !READ(stop) : true) {
		DemResult child_result = { 0 };
		const char *saved_pos = p->cur;
		if (rule(p, &child_result)) {
			// Check if the rule advanced the pointer
			if (p->cur == saved_pos) {
				// Rule succeeded but didn't advance - must clean up output
				if (child_result.output) {
					DemNode_dtor(child_result.output);
				}
				break;
			}
			if (child_result.output) {
				VecPDemNode_append(many_node->children, (PDemNode *)&child_result.output);
			}
		} else {
			// Restore position on failure
			p->cur = saved_pos;
			if (child_result.output) {
				DemNode_dtor(child_result.output);
			}
			break;
		}
	}

	many_node->val.len = p->cur - many_node->val.buf;

	/* we always match, even if nothing matches */
	r->output = many_node;
	r->error = DEM_ERR_OK;
	return true;
}
