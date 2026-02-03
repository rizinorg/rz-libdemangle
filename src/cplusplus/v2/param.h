// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_param_H
#define CPDEM_param_H

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
 *
 * \return p_dst on success.
 * \return NULL otherwise.
 * */
#define param_init_clone(p_dst, p_src) \
	(((p_dst) && (p_src)) ? (dem_string_init_clone(&(p_dst)->name, &(p_src)->name), \
					dem_string_init_clone(&(p_dst)->suffix, &(p_src)->suffix), \
					dem_string_init_clone(&(p_dst)->prefix, &(p_src)->prefix), \
					(p_dst)) \
			      : NULL)

/**
 * Init object make it usable with other functions (macros).
 *
 * \param p : Pointer to function parameter.
 *
 * \return p on success.
 * \return NULL otherwise.
 * */
#define param_init(p) \
	((p) ? ((dem_string_init(&(p)->name) && dem_string_init(&(p)->suffix) && \
			dem_string_init(&(p)->prefix)) \
			       ? (p) \
			       : NULL) \
	     : NULL)

/**
 * Deinit a given function param object.
 *
 * \param p : Pointer to function param object.
 *
 * \return p on success.
 * \return NULL otherwise.
 */
#define param_deinit(p) \
	((p) ? (dem_string_deinit(&(p)->name), \
		       dem_string_deinit(&(p)->suffix), \
		       dem_string_deinit(&(p)->prefix), \
		       memset((p), 0, sizeof(Param)), \
		       (p)) \
	     : NULL)

/**
 * Append a string to a function param field (name/suffix/prefix)
 *
 * \param p    : Pointer to function param.
 * \param field : Name of field to append to.
 * \param val   : Value to pe appended.
 *
 * \return p on success.
 * \return NULL otherwise.
 */
#define param_append_to(p, field, val) \
	((p) ? (dem_string_append(&((p)->field), val) ? (p) : NULL) : NULL)

#define param_appendf_to(p, field, ...) \
	do { \
		if (p) { \
			const char *s = dem_str_newf(__VA_ARGS__); \
			if (s) { \
				param_append_to(p, field, s); \
				free((void *)s); \
			} \
		} \
	} while (0)

/**
 * Prepend a string to a function param field (name/suffix/prefix)
 *
 * \param p    : Pointer to function param.
 * \param field : Name of field to prepend to.
 * \param val   : Value to pe prepended.
 *
 * \return p on success.
 * \return NULL otherwise.
 */
#define param_prepend_to(p, field, val) \
	((p) ? (dem_string_append_prefix_n(&((p)->field), val, strlen(val)) ? (p) : NULL) : NULL)

typedef Vec(Param) ParamVec;

#define param_vec_init(pv) vec_init((pv))

#define param_vec_deinit(pv) \
	do { \
		vec_foreach_ptr_typed((pv), Param, param, { \
			void *_ = param_deinit(param); \
			((void)_); /* trick to silence unused variable warnings */ \
		}); \
		vec_deinit((pv)); \
	} while (0)

#define param_vec_append(pv, val) vec_append((pv), (val))

Param *param_append_to_dem_string(Param *p, DemString *ds);
ParamVec *param_vec_append_to_dem_string(ParamVec *pv, DemString *ds);

#endif // CPDEM_param_H
