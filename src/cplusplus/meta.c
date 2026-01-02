// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <time.h>

#include "types.h"
#include "vec.h"

static inline void meta_copy_scalars(Meta *dst, Meta *src) {
	if (dst == src) {
		return;
	}
	dst->is_const = src->is_const;
	dst->is_ctor = src->is_ctor;
	dst->is_dtor = src->is_dtor;
	dst->trace = src->trace;
	dst->template_idx_start = src->template_idx_start;
	dst->last_reset_idx = src->last_reset_idx;
	dst->t_level = src->t_level;
	dst->template_reset = src->template_reset;
	dst->is_ctor_or_dtor_at_l0 = src->is_ctor_or_dtor_at_l0;
	dst->prefix_base_idx = src->prefix_base_idx;
	// Note: current_prefix is intentionally NOT copied as a scalar
	// It needs special handling - clone if needed
}

void meta_deinit(Meta *m) {
	if (!m) {
		return;
	}

	VecF(DemAstNode, deinit)(&m->detected_types);
	VecF(Name, deinit)(&m->template_params);
	DemAstNode_deinit(&m->current_prefix);
	memset(m, 0, sizeof(Meta));
}

bool meta_copy(Meta *dst, Meta *src) {
	if (!(src && dst && src != dst)) {
		return false;
	}

	meta_copy_scalars(dst, src);

	/* Reset destination dynamic members before cloning */
	VecF(DemAstNode, deinit)(&dst->detected_types);
	VecF(Name, deinit)(&dst->template_params);
	DemAstNode_deinit(&dst->current_prefix);

	vec_init(&dst->detected_types);
	vec_init(&dst->template_params);

	if (!DemAstNode_is_empty(&src->current_prefix)) {
		DemAstNode_init_clone(&dst->current_prefix, &src->current_prefix);
	} else {
		DemAstNode_init(&dst->current_prefix);
	}

	vec_foreach_ptr(&src->detected_types, n, {
		DemAstNode cloned = { 0 };
		DemAstNode_init_clone(&cloned, n);
		VecF(DemAstNode, append)(&dst->detected_types, &cloned);
	});

	vec_foreach_ptr(&src->template_params, n, {
		Name new_name = { 0 };
		dem_string_init_clone(&new_name.name, &n->name);
		new_name.num_parts = n->num_parts;
		VecF(Name, append)(&dst->template_params, &new_name);
	});

	return true;
}

void meta_move(Meta *dst, Meta *src) {
	if (!(dst && src && dst != src)) {
		return;
	}
	meta_copy_scalars(dst, src);

	DemAstNode_deinit(&dst->current_prefix);
	dst->current_prefix = src->current_prefix;
	src->current_prefix = (DemAstNode){ 0 };

	VecF(DemAstNode, deinit)(&dst->detected_types);
	VecF(Name, deinit)(&dst->template_params);
	VecF(DemAstNode, move)(&dst->detected_types, &src->detected_types);
	VecF(Name, move)(&dst->template_params, &src->template_params);

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
bool append_type(Meta *m, const DemAstNode *x, bool force_append) {
	if (!m || !x || dem_string_empty(&x->dem)) {
		return false;
	}

	const DemString *t = &x->dem;

	// Builtins are not substitutable per ABI, EXCEPT when force_append is true
	// (for template params that substitute to builtins)
	if (!force_append && is_builtin_type(t->buf)) {
		if (getenv("DEMANGLE_TRACE")) {
			fprintf(stderr, "[append_type] rejected (builtin): '%s'\n", t->buf);
		}
		return true;
	}

	// A hack to ingore constant values getting forcefully added from RULE(template_param)
	// because templates sometimes get values like "true", "false", "4u", etc...
	if (IS_DIGIT(t->buf[0]) || !strcmp(t->buf, "true") || !strcmp(t->buf, "false")) {
		return true;
	}

	// Note: We used to filter out "std" here, but that's incorrect.
	// While "std" alone is not a type, it CAN be a valid substitutable prefix
	// when followed by more components like "std::vector".
	// The ABI says special substitutions like St (std::) are not in the table,
	// but "std" as a namespace path IS substitutable when building types like std::vector.
	// Actually, per Itanium ABI, just "std" alone is NOT substitutable - only
	// qualified names like "std::vector" are. But since we build incrementally,
	// we may temporarily have "std" before adding "::vector". We should NOT add
	// "std" alone to the table, but we need to track it for building full paths.
	//
	// The real fix is to not call AST_APPEND_TYPE when the result would be just "std".
	// For now, keep filtering "std" - the fix should be in the calling code.
	if (!strcmp(t->buf, "std")) {
		return true;
	}

	// If we're not forcefully appending values, then check for uniqueness of times
	if (!force_append) {
		vec_foreach_ptr(&m->detected_types, dt, {
			if (!strcmp(dt->dem.buf, t->buf)) {
				return true;
			}
		});
	}

	DemAstNode *new_node = VecF(DemAstNode, append)(&m->detected_types, NULL);
	DemAstNode_copy(new_node, x);
	if (!count_name_parts(&new_node->dem)) {
		m->detected_types.length--;
		return false;
	}

	// DEBUG
	if (getenv("DEMANGLE_TRACE")) {
		fprintf(stderr, "[append_type] trying to add: '%s'\n", t->buf);
	}

	return true;
}

/**
 * Much like `append_type`, but for templates.
 */
bool append_tparam(Meta *m, DemString *t) {
	if (!m || !t || !t->len) {
		return false;
	}

	UNUSED(vec_reserve(&m->template_params, m->template_params.length + 1));
	m->template_params.length += 1;

	Name *new_name = vec_end(&m->template_params);
	dem_string_init_clone(&new_name->name, t);
	if (!count_name_parts(&new_name->name)) {
		m->template_params.length--;
		return false;
	}

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
	if (m->detected_types.length > id) {
		DemAstNode *type_node = vec_ptr_at(&m->detected_types, id);
		if (type_node && type_node->dem.buf) {
			DemAstNode x = { 0 };
			DemAstNode_init_clone(&x, type_node);
			DemAstNode_append(dan, &x);
			return true;
		}
	}
	return false;
}

bool meta_substitute_tparam(Meta *m, ut64 id, DemString *dem) {
	if (m->template_params.length > id) {
		Name *tparam_name = vec_ptr_at(&m->template_params, id);
		if (tparam_name && tparam_name->name.buf) {
			dem_string_append(dem, tparam_name->name.buf);
			return true;
		}
	}
	return false;
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

void name_deinit(Name *x) {
	if (!x) {
		return;
	}
	dem_string_deinit(&x->name);
}
