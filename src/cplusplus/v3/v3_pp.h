// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_V3_PP_H
#define RZ_LIBDEMANGLE_V3_PP_H
#include "types.h"

// Pretty-print context to track formatting state
typedef struct {
	CpDemOptions opts;
	int paren_depth; // Current parenthesis nesting depth
	bool inside_template; // Whether we're inside template arguments

	ut32 current_pack_index;
	ut32 current_pack_max;

	int recursion_depth; // Guard against infinite recursion in AST printing

	const void *resolving_fwd_ref; // Currently resolving FWD_TEMPLATE_REF (cycle detection)
} PPContext;

static inline void PPContext_init(PPContext *ctx, CpDemOptions options) {
	if (!ctx) {
		return;
	}
	ctx->opts = options;
	ctx->paren_depth = 0;
	ctx->inside_template = false;
	ctx->current_pack_index = UT32_MAX;
	ctx->current_pack_max = UT32_MAX;
	ctx->recursion_depth = 0;
}

void ast_pp(DemNode *node, DemString *out, PPContext *ctx);
void pp_cv_qualifiers(CvQualifiers qualifiers, DemString *out, PPContext *ctx);
void pp_ref_qualifiers(RefQualifiers qualifiers, DemString *out, PPContext *ctx);

#endif // RZ_LIBDEMANGLE_V3_PP_H
