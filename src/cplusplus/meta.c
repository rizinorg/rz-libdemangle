// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <time.h>

#include "types.h"
#include "vec.h"

void NodeList_copy(NodeList *dst, const NodeList *src) {
	if (!(src && dst && src != dst)) {
		return;
	}

	vec_deinit(dst);
	vec_init(dst);

	vec_foreach_ptr(src, n, {
		DemAstNode cloned = { 0 };
		DemAstNode_init_clone(&cloned, n);
		VecF(DemAstNode, append)(dst, &cloned);
	});
}

NodeList *NodeList_make(NodeList *self, ut64 from, ut64 to) {
	if (to < VecF(DemAstNode, len)(self) && from < to) {
		return NULL;
	}
	ut64 sz = to - from;
	NodeList *new_list = VecF(DemAstNode, ctor)();
	if (!new_list) {
		return NULL;
	}
	VecF(DemAstNode, reserve)(new_list, sz);
	memcpy(new_list, VecF(DemAstNode, at)(self, from), sizeof(DemAstNode) * sz);
	return new_list;
}

NodeList *NodeList_pop_trailing(NodeList *self, ut64 from) {
	if (from >= VecF(DemAstNode, len)(self)) {
		return NULL;
	}
	NodeList *new_list = NodeList_make(self, from, VecF(DemAstNode, len)(self));
	if (!new_list) {
		return NULL;
	}
	self->length = from;
	return new_list;
}

static void meta_copy_scalars(Meta *dst, Meta *src) {
	if (dst == src) {
		return;
	}
	dst->is_ctor = src->is_ctor;
	dst->is_dtor = src->is_dtor;
	dst->trace = src->trace;
}

void meta_deinit(Meta *m) {
	if (!m) {
		return;
	}

	VecF(DemAstNode, deinit)(&m->detected_types);
	VecF(DemAstNode, deinit)(&m->names);
	VecF(DemAstNode, deinit)(&m->outer_template_params);
	VecF(NodeList, deinit)(&m->template_params);
	memset(m, 0, sizeof(Meta));
}

bool meta_copy(Meta *dst, Meta *src) {
	if (!(src && dst && src != dst)) {
		return false;
	}

	meta_copy_scalars(dst, src);

	/* Reset destination dynamic members before cloning */
	VecF(DemAstNode, deinit)(&dst->detected_types);
	VecF(NodeList, deinit)(&dst->template_params);

	vec_init(&dst->detected_types);
	vec_init(&dst->names);
	vec_init(&dst->outer_template_params);
	vec_init(&dst->template_params);

	NodeList_copy(&dst->detected_types, &src->detected_types);
	NodeList_copy(&dst->names, &src->names);
	NodeList_copy(&dst->outer_template_params, &src->outer_template_params);

	vec_foreach_ptr(&src->template_params, n, {
		NodeList *dst_list = VecF(NodeList, append)(&dst->template_params, NULL);
		NodeList_copy(dst_list, n);
	});

	return true;
}

void meta_move(Meta *dst, Meta *src) {
	if (!(dst && src && dst != src)) {
		return;
	}
	meta_copy_scalars(dst, src);

	VecF(DemAstNode, deinit)(&dst->detected_types);
	VecF(DemAstNode, deinit)(&dst->names);
	VecF(DemAstNode, deinit)(&dst->outer_template_params);
	VecF(NodeList, deinit)(&dst->template_params);

	VecF(DemAstNode, move)(&dst->detected_types, &src->detected_types);
	VecF(DemAstNode, move)(&dst->names, &src->names);
	VecF(DemAstNode, move)(&dst->names, &src->outer_template_params);
	VecF(NodeList, move)(&dst->template_params, &src->template_params);

	memset(src, 0, sizeof(Meta));
}

static const char *builtin_type_stings[] = {
	"void",
	"wchar_t",
	"bool",
	"char",
	"signed char",
	"unsigned char",
	"short",
	"unsigned short",
	"int",
	"unsigned int",
	"long",
	"unsigned long",
	"long long",
	"__int64",
	"unsigned long long",
	"__int64",
	"__int128",
	"unsigned __int128",
	"float",
	"double",
	"long double",
	"__float80",
	"__float128",
	"...",
	"decimal64",
	"decimal128",
	"decimal32",
	"half",
	"char32_t",
	"char16_t",
	"char8_t",
	"auto",
	"decltype(auto)",
	"std::nullptr_t",
	"_Accum",
	"_Fract",
	NULL,
};
static const char *builtin_type_prefix_stings[] = {
	"_Float",
	"std::bfloat",
	"signed _BitInt(",
	"signed _BitInt(",
	"unsigned _BitInt(",
	"unsigned _BitInt(",
};

bool is_builtin_type(const char *t) {
	if (!(t && *t)) {
		return false;
	}
	for (size_t i = 0; i < sizeof(builtin_type_stings) / sizeof(builtin_type_stings[0]); i++) {
		if (!builtin_type_stings[i]) {
			break;
		}
		if (strcmp(builtin_type_stings[i], t) == 0) {
			return true;
		}
	}
	for (size_t i = 0;
		i < sizeof(builtin_type_prefix_stings) / sizeof(builtin_type_prefix_stings[0]);
		i++) {
		if (!builtin_type_prefix_stings[i]) {
			break;
		}
		if (strncmp(t, builtin_type_prefix_stings[i], strlen(builtin_type_prefix_stings[i])) ==
			0) {
			return true;
		}
	}
	return false;
}

/**
 * Append given type name to list of all detected types.
 * This vector is then used to refer back to a detected type in substitution
 * rules.
 */
bool append_type(Meta *m, const DemAstNode *x) {
	if (!m || !x || dem_string_empty(&x->dem)) {
		return false;
	}

	const DemString *t = &x->dem;

	// DEBUG
	if (getenv("DEMANGLE_TRACE")) {
		fprintf(stderr, "[append_type] trying to add: '%s'\n", t->buf);
	}

	DemAstNode *new_node = VecF(DemAstNode, append)(&m->detected_types, NULL);
	DemAstNode_copy(new_node, x);

	return true;
}

/**
 * Find the index of a type in the detected_types table.
 * Returns the index if found, or -1 if not found.
 */
st64 find_type_index(Meta *m, const char *type_str) {
	if (!m || !type_str) {
		return -1;
	}
	for (ut64 i = 0; i < m->detected_types.length; i++) {
		DemAstNode *dt = vec_ptr_at(&m->detected_types, i);
		if (dt && dt->dem.buf && !strcmp(dt->dem.buf, type_str)) {
			return (st64)i;
		}
	}
	return -1;
}

/**
 * Refer back to a previous type from detected types and then add that
 * type to the currently demangled string
 */
bool meta_substitute_type(Meta *m, ut64 id, DemAstNode *dan) {
	if (m->detected_types.length <= id) {
		return false;
	}
	DemAstNode *type_node = vec_ptr_at(&m->detected_types, id);
	if (DemAstNode_is_empty(type_node)) {
		return false;
	}

	DemAstNode x = { 0 };
	DemAstNode_init_clone(&x, type_node);
	DemAstNode_append(dan, &x);
	if (m->trace) {
		fprintf(stderr, "[substitute_type] %ld -> '%s'\n", id, type_node->dem.buf);
	}
	return true;
}

bool meta_substitute_tparam(Meta *m, DemAstNode *dan, ut64 level, ut64 index) {
	if (level >= m->template_params.length) {
		return false;
	}
	NodeList *tparams_at_level = vec_ptr_at(&m->template_params, level);
	if (!(tparams_at_level && index < tparams_at_level->length)) {
		return false;
	}
	DemAstNode *tparam_node = vec_ptr_at(tparams_at_level, index);
	if (!tparam_node || DemAstNode_is_empty(tparam_node)) {
		return false;
	}

	DemAstNode x = { 0 };
	DemAstNode_init_clone(&x, tparam_node);
	DemAstNode_append(dan, &x);
	if (m->trace) {
		fprintf(stderr, "[substitute_tparam] L%ld_%ld -> '%s'\n", level, index, tparam_node->dem.buf);
	}
	return true;
}

// counts the number of :: in a name and adds 1 to it
// but ignores :: inside template arguments (between < and >)
ut32 count_name_parts(const DemString *x) {
	// count number of parts
	const char *it = x->buf;
	const char *end = it + x->len;
	ut32 num_parts = 1;
	int template_depth = 0;

	while (it < end) {
		if (*it == '<') {
			template_depth++;
		} else if (*it == '>') {
			template_depth--;
		} else if (template_depth == 0 && it[0] == ':' && it[1] == ':') {
			// Only count :: when we're not inside template arguments
			if (it[2]) {
				num_parts++;
				it += 2; // advance past the "::" to avoid infinite loop
				continue;
			} else {
				// this case is possible and must be ignored with an error
				return 0;
			}
		}
		it++;
	}
	return num_parts;
}
