// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "test_helper.h"
#include <demangler_util.h>
#include <cplusplus/types.h>
#include <cplusplus/v3.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations from meta.c
void meta_init(Meta *m);
void meta_deinit(Meta *m);

// Forward declaration from ast.c
void DemAstNode_dtor(DemAstNode *self);

CxxDemangleResult *cxx_demangle_with_subs(const char *mangled) {
	if (!mangled) {
		return NULL;
	}

	CxxDemangleResult *result = calloc(1, sizeof(CxxDemangleResult));
	if (!result) {
		return NULL;
	}

	// Initialize parsing state
	StrIter si = { .beg = mangled, .cur = mangled, .end = mangled + strlen(mangled) + 1 };
	StrIter *msi = &si;

	DemAstNode *dan = calloc(sizeof(DemAstNode), 1);
	if (!dan) {
		free(result);
		return NULL;
	}

	Meta meta = { 0 };
	meta_init(&meta);
	Meta *m = &meta;

	TraceGraph trace_graph = { 0 };
	TraceGraph *graph = &trace_graph;
	graph->enabled = false;

	// Try to demangle
	if (rule_mangled_name(dan, msi, m, graph, -1)) {
		result->success = 1;
		result->demangled = dan->dem.buf;
		dan->dem.buf = NULL;

		// Extract substitution table
		result->subs_count = VecDemAstNode_len(&m->detected_types);
		result->subs_table = calloc(result->subs_count, sizeof(char *));

		if (result->subs_table) {
			for (size_t i = 0; i < result->subs_count; i++) {
				DemAstNode *node = VecDemAstNode_at(&m->detected_types, i);
				if (node && node->dem.buf) {
					result->subs_table[i] = strdup(node->dem.buf);
				} else {
					result->subs_table[i] = strdup("(empty)");
				}
			}
		}
	} else {
		result->success = 0;
		result->demangled = NULL;
		result->subs_table = NULL;
		result->subs_count = 0;
	}

	// Cleanup
	dem_string_deinit(&dan->dem);
	meta_deinit(&meta);
	DemAstNode_dtor(dan);

	return result;
}

void cxx_demangle_result_free(CxxDemangleResult *result) {
	if (!result) {
		return;
	}

	free(result->demangled);

	if (result->subs_table) {
		for (size_t i = 0; i < result->subs_count; i++) {
			free(result->subs_table[i]);
		}
		free(result->subs_table);
	}

	free(result);
}
