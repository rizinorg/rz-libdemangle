// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_PARSER_COMBINATOR_H
#define RZ_LIBDEMANGLE_PARSER_COMBINATOR_H

#include "../demangler_util.h"
#include "types.h"

bool match_one_or_more_rules(
	DemRuleFirst first,
	DemRule rule,
	const char *sep,
	DemAstNode *ast_node,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id);
bool match_zero_or_more_rules(
	DemRuleFirst first,
	DemRule rule,
	const char *sep,
	DemAstNode *ast_node,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id);

#endif // RZ_LIBDEMANGLE_PARSER_COMBINATOR_H
