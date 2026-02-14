// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_PARAM_H
#define CPDEM_PARAM_H

#include "cplusplus/vec.h"
#include "demangler_util.h"

/**
 * Represents a template or function parameter.
 */
typedef struct {
	DemString name;
	DemString suffix;
	DemString prefix;
} Param;

/**
 * Initialize clone from p_src to p_dst.
 *
 * \param p_dst : Pointer to Param object to init clone into.
 * \param p_src : Pointer to Param object to init clone of.
 */
static inline void param_init_clone(
	Param *p_dst,
	const Param *p_src) {
	if (p_src) {
		dem_string_init_clone(&p_dst->name, &p_src->name);
		dem_string_init_clone(&p_dst->suffix, &p_src->suffix);
		dem_string_init_clone(&p_dst->prefix, &p_src->prefix);
	}
}

/**
 * Init object make it usable with other functions (macros).
 *
 * \param p : Pointer to function parameter.
 */
static inline void param_init(Param *p) {
	dem_string_init(&p->name);
	dem_string_init(&p->suffix);
	dem_string_init(&p->prefix);
}

/**
 * Deinit a given function param object.
 *
 * \param p : Pointer to function param object.
 */
static inline void param_deinit(Param *p) {
	dem_string_deinit(&p->name);
	dem_string_deinit(&p->suffix);
	dem_string_deinit(&p->prefix);
	memset(p, 0, sizeof(Param));
}

/**
 * Append a string to a function param field (name/suffix/prefix)
 *
 * \param p    : Pointer to function param.
 * \param field : Name of field to append to.
 * \param val   : Value to pe appended.
 */
#define param_append_to(p, field, val) \
	do { \
		dem_string_append(&((p)->field), val); \
	} while (0)

#define param_appendf_to(p, field, ...) \
	do { \
		const char *s = dem_str_newf(__VA_ARGS__); \
		if (s) { \
			param_append_to(p, field, s); \
			free((void *)s); \
		} \
	} while (0)

/**
 * Prepend a string to a function param field (name/suffix/prefix)
 *
 * \param p    : Pointer to function param.
 * \param field : Name of field to prepend to.
 * \param val   : Value to pe prepended.
 */
#define param_prepend_to(p, field, val) \
	do { \
		dem_string_append_prefix_n(&((p)->field), val, strlen(val)); \
	} while (0)

VecIMPL(Param, param_deinit);
typedef VecT(Param) ParamVec;

Param *param_append_to_dem_string(Param *p, DemString *ds);
ParamVec *param_vec_append_to_dem_string(ParamVec *pv, DemString *ds);

#endif // CPDEM_PARAM_H
