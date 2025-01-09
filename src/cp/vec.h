// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_VEC_H
#define CPDEM_VEC_H

#define Vec(x)                                                                                     \
    struct {                                                                                       \
        x*   data;                                                                                 \
        ut64 length;                                                                               \
        ut64 capacity;                                                                             \
    }

#define VEC_DATA_TYPE(vec) __typeof__ ((vec)->data[0])

/**
 * This will just memset vector to 0, to make it usable with other function (macros).
 *
 * \param vec : Pointer to vector to be inited.
 *
 * \return vec on success.
 * \return NULL otherwise.
 */
#define vec_init(vec) ((vec) ? (memset ((vec), 0, sizeof (*(vec))), (vec)) : NULL)

/**
 * De initialize given vector. All memory held by items in this vector must be freed
 * prior to caling this. vec_tor will automatically free it's own memory assuming the previous
 * step is performed already.
 *
 * \param vec : Pointer to vector to be deinited.
 *
 * \return vec on success.
 * \return NULL otherwise.
 */
#define vec_deinit(vec)                                                                            \
    ((vec) ? (((vec)->data ? (free ((vec)->data), 1) : 1), vec_init (vec)) : NULL)

/**
 * Get data stored in vector at given idx.
 *
 * \param vec : Pointer to vector.
 * \param idx : Index to get data at.
 *
 * \return vec->data[idx] if vec is not NULL.
 * \return {0} otherwise.
 */
#define vec_at(vec, idx) ((vec) ? (vec)->data[idx] : ((VEC_DATA_TYPE (vec)) {0}))

/**
 * Get pointer to data stored in vector at given idx.
 *
 * \param vec : Pointer to vector.
 * \param idx : Index to get data at.
 *
 * \return vec->data[idx] if vec is not NULL.
 * \return {0} otherwise.
 */
#define vec_ptr_at(vec, idx) ((vec) ? ((vec)->data + (idx)) : NULL)

/**
 * Increase capacity of vector from current to new provided capacity. If new capacity
 * is less than or equal to current capacity, then this no changes are performed.
 *
 * \param vec     : Pointer to vector.
 * \param new_cap : New vector capacity.
 *
 * \return vec on success.
 * \return NULL otherwise.
 */
#define vec_reserve(vec, new_cap)                                                                  \
    ((vec) ? ((vec)->capacity < (new_cap) ?                                                        \
                  (vec->data = realloc ((vec)->data, sizeof (VEC_DATA_TYPE (vec)) * (new_cap)),    \
                   (vec)) :                                                                        \
                  NULL) :                                                                          \
             NULL)

/**
 * Append an item into vector.
 * Appended item is completely owned by vector after this call. Any memory
 * owned by the item must not be freed until unless vector is to be destroyed.
 *
 * \param vec      : Pointer to vector.
 * \param data_ptr : Pointer to data to be inserted.
 *
 * \return vec on success.
 * \return NULL otherwise.
 */
#define vec_append(vec, data_ptr)                                                                  \
    ((vec) ? vec_reserve ((vec), (vec)->length + 1) ?                                              \
             (memcpy ((vec)->data + (vec)->length++, (data_ptr), sizeof (VEC_DATA_TYPE (vec))),    \
              (vec)) :                                                                             \
             NULL :                                                                                \
             NULL)

/**
 * Iterate over each element in vector.
 * Provides a de-referenced access to each element one by one.
 *
 * \param v    : Pointer to vector.
 * \param var  : Variable where value will be stored.
 * \param body : For loop body. Yes, it's a parameter here! To handle local variable scope.
 */
#define vec_foreach(v, var, body)                                                                  \
    do {                                                                                           \
        size_t ___iter___     = 0;                                                                 \
        VEC_DATA_TYPE (v) var = {0};                                                               \
        if ((v) && (v)->length) {                                                                  \
            for ((___iter___) = 0; (___iter___) < (v)->length; ++(___iter___)) {                   \
                var = (v)->data[(___iter___)];                                                     \
                { body }                                                                           \
            }                                                                                      \
        }                                                                                          \
    } while (0)

/**
 * Iterate over each element in vector.
 * Provides a pointer to access to each element one by one.
 *
 * \param v    : Pointer to vector.
 * \param var  : Variable where pointer to variable will be stored.
 * \param body : For loop body. Yes, it's a parameter here! To handle local variable scope.
 */
#define vec_foreach_ptr(v, var, body)                                                              \
    do {                                                                                           \
        size_t ___iter___      = 0;                                                                \
        VEC_DATA_TYPE (v)* var = {0};                                                              \
        if ((v) && (v)->length) {                                                                  \
            for ((___iter___) = 0; (___iter___) < (v)->length; ++(___iter___)) {                   \
                var = &(v)->data[(___iter___)];                                                    \
                { body }                                                                           \
            }                                                                                      \
        }                                                                                          \
    } while (0)

#endif // CPDEM_VEC_H
