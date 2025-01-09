// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_FPARAM_H
#define CPDEM_FPARAM_H

#include "demangler_util.h"
#include "vec.h"

/**
 * Represents a function parameter.
 */
typedef struct {
    DemString *name;
    DemString *suffix;
    DemString *prefix;
} FuncParam;

/**
 * Initialize clone from fp_src to fp_dst.
 *
 * \param fp_dst : Pointer to FuncParam object to init clone into.
 * \param fp_src : Pointer to FuncParam object to init clone of.
 *
 * \return fp_dst on success.
 * \return NULL otherwise.
 * */
#define fparam_init_clone(fp_dst, fp_src)                                                          \
    ((fparam_init (fp_dst) && (fp_src)) ? (dem_string_concat ((fp_dst)->name, (fp_src)->name),     \
                                           dem_string_concat ((fp_dst)->suffix, (fp_src)->suffix), \
                                           dem_string_concat ((fp_dst)->prefix, (fp_src)->prefix), \
                                           (fp_dst)) :                                             \
                                          NULL)

/**
 * Init object make it usable with other functions (macros).
 *
 * \param fp : Pointer to function parameter.
 *
 * \return fp on success.
 * \return NULL otherwise.
 * */
#define fparam_init(fp)                                                                            \
    ((fp) ? (((fp)->name = dem_string_new()),                                                      \
             ((fp)->suffix = dem_string_new()),                                                    \
             ((fp)->prefix = dem_string_new()),                                                    \
             (fp)) :                                                                               \
            NULL)

/**
 * Deinit a given function param object.
 *
 * \param fp : Pointer to function param object.
 *
 * \return fp on success.
 * \return NULL otherwise.
 */
#define fparam_deinit(fp)                                                                          \
    ((fp) ? (dem_string_free ((fp)->name),                                                         \
             dem_string_free ((fp)->suffix),                                                       \
             dem_string_free ((fp)->prefix),                                                       \
             memset ((fp), 0, sizeof (FuncParam)),                                                 \
             (fp)) :                                                                               \
            NULL)

/**
 * Append a string to a function param field (name/suffix/prefix)
 *
 * \param fp    : Pointer to function param.
 * \param field : Name of field to append to.
 * \param val   : Value to pe appended.
 *
 * \return fp on success.
 * \return NULL otherwise.
 */
#define fparam_append_to(fp, field, val)                                                           \
    ((fp) ? (dem_string_append ((fp)->field, val) ? (fp) : NULL) : NULL)

/**
 * Prepend a string to a function param field (name/suffix/prefix)
 *
 * \param fp    : Pointer to function param.
 * \param field : Name of field to prepend to.
 * \param val   : Value to pe prepended.
 *
 * \return fp on success.
 * \return NULL otherwise.
 */
#define fparam_prepend_to(fp, field, val)                                                          \
    ((fp) ? (dem_string_append_prefix_n ((fp)->field, val, strlen (val)) ? (fp) : NULL) : NULL)


typedef Vec (FuncParam) FuncParamVec;

#define fparam_vec_init(fpv) vec_init ((fpv))
#define fparam_vec_deinit(fpv)                                                                     \
    do {                                                                                           \
        vec_foreach_ptr (&dem->func_params, param, {                                               \
            void *_ = fparam_deinit (param);                                                       \
            ((void)_); /* trick to silence unused variable warnings */                             \
        });                                                                                        \
        vec_deinit (&dem->func_params);                                                            \
    } while (0)
#define fparam_vec_append(fpv, val) vec_append ((fpv), (val))

#endif // CPDEM_FPARAM_H
