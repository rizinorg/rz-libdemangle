// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_VEC_H
#define CPDEM_VEC_H

#define UNUSED(xpr) ((void)(xpr))

#define nearest_power_of_two(v)                                                                    \
    (((v)--),                                                                                      \
     ((v) |= (v) >> 1),                                                                            \
     ((v) |= (v) >> 2),                                                                            \
     ((v) |= (v) >> 4),                                                                            \
     ((v) |= (v) >> 8),                                                                            \
     ((v) |= (v) >> 16),                                                                           \
     ((v) = v + 1))

#define Vec(x)                                                                                     \
    struct {                                                                                       \
        x*   data;                                                                                 \
        ut64 length;                                                                               \
        ut64 capacity;                                                                             \
    }

#define VEC_DATA_TYPE(vec) __typeof__ ((vec)->data[0])

#define vec_mem_size(vec) (sizeof (VEC_DATA_TYPE ((vec))) * (vec)->length)

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
#define vec_deinit(vec) ((vec) ? (((vec)->data ? free ((vec)->data) : 1), vec_init (vec)) : NULL)

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
#define vec_front(vec)   vec_at (vec, 0)
#define vec_back(vec)    vec_at (vec, (vec)->length - 1)

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
#define vec_begin(vec)       vec_ptr_at (vec, 0)
#define vec_end(vec)         vec_ptr_at (vec, (vec)->length - 1)

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
    ((vec) ?                                                                                       \
         ((vec)->capacity < (new_cap) ?                                                            \
              (/* make sure capacity can never be set to 0                                      */ \
               ((vec)->capacity = (new_cap) ? (new_cap) : 1),                                      \
               (/* make sure vector capacity is always in powers of two (not really necessary)*/   \
                nearest_power_of_two ((vec)->capacity)                                             \
               ),                                                                                  \
               (/* increase vector capacity                                                     */ \
                (vec)->data =                                                                      \
                    realloc ((vec)->data, sizeof (VEC_DATA_TYPE (vec)) * (vec)->capacity)          \
               ),                                                                                  \
               (/* memset new allocated region with 0 to make all pointers NULL                 */ \
                memset (                                                                           \
                    (vec)->data + (vec)->length,                                                   \
                    0,                                                                             \
                    sizeof (VEC_DATA_TYPE (vec)) * ((vec)->capacity - (vec)->length)               \
                )                                                                                  \
               ),                                                                                  \
               (vec)                                                                               \
              ) :                                                                                  \
              (vec)) :                                                                             \
         NULL)

#define vec_move(dst, src)                                                                         \
    ((dst && src && (src)->data) ? (vec_reserve (dst, (src)->length) &&                                           \
                     memcpy ((dst)->data, (src)->data, vec_mem_size (src)) &&                      \
                     ((dst)->length = (src)->length) &&                                            \
                     memset ((src)->data, 0, vec_mem_size (src)) && vec_deinit (src)) :            \
                    false)

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
#define vec_append(vec, data_ptr)                                                                   \
    ((vec) ?                                                                                        \
         ((/* make sure vector has sufficient space to insert one more item                       \
                * this has no effect if vector length is less than capacity                        */ \
           vec_reserve ((vec), (vec)->length + 1)                                                   \
          ) ?                                                                                       \
              (/* copy the data over from data_ptr to last element                               */ \
               memcpy ((vec)->data + (vec)->length, (data_ptr), sizeof (VEC_DATA_TYPE (vec))),      \
               (/* adjust the vector length after appending                                      */ \
                (vec)->length += 1                                                                  \
               ),                                                                                   \
               (vec)                                                                                \
              ) :                                                                                   \
              NULL) :                                                                               \
         NULL)

#define vec_pop(vec) (vec ? ((vec)->length > 0 ? --((vec)->length) : 0) : 0)

#define vec_append_const(vec, data_const)                                                           \
    ((vec) ?                                                                                        \
         ((/* make sure vector has sufficient space to insert one more item                       \
                 * this has no effect if vector length is less than capacity                        */ \
           vec_reserve ((vec), (vec)->length + 1)                                                   \
          ) ?                                                                                       \
              ( /* copy the data over from data to last element                               */    \
               (vec)->data[(vec)->length] = (data_const),                                           \
               (/* adjust the vector length after appending                                      */ \
                (vec)->length += 1                                                                  \
               ),                                                                                   \
               (vec)                                                                                \
              ) :                                                                                   \
              NULL) :                                                                               \
         NULL)

#define vec_concat(vec, other) vec_foreach_ptr ((other), o, { UNUSED (vec_append ((vec), o)); })

/**
 * Iterate over each element in vector.
 * Provides a de-referenced access to each element one by one.
 *
 * \param v    : Pointer to vector.
 * \param var  : Variable where value will be stored.
 * \param body : For loop body. Yes, it's a parameter here! To handle local variable scope.
 *
 * NOTE: to maintain this macro in future, consider replacing the large iterator name with a small one
 * and then replace it back to an uncommon name :-)
 */
#define vec_foreach(v, var, body)                                                                  \
    do {                                                                                           \
        size_t _i_needed_a_very_very_uncommon_name_for_this_iterator = 0;                          \
        VEC_DATA_TYPE (v) var                                        = {0};                        \
        if ((v) && (v)->length) {                                                                  \
            for ((_i_needed_a_very_very_uncommon_name_for_this_iterator) = 0;                      \
                 (_i_needed_a_very_very_uncommon_name_for_this_iterator) < (v)->length;            \
                 ++(_i_needed_a_very_very_uncommon_name_for_this_iterator)) {                      \
                var = (v)->data[(_i_needed_a_very_very_uncommon_name_for_this_iterator)];          \
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
 *
 * NOTE: to maintain this macro in future, consider replacing the large iterator name with a small one
 * and then replace it back to an uncommon name :-)
 */
#define vec_foreach_ptr(v, var, body)                                                              \
    do {                                                                                           \
        size_t _i_needed_a_very_very_uncommon_name_for_this_iterator = 0;                          \
        VEC_DATA_TYPE (v)* var                                       = {0};                        \
        if ((v) && (v)->length) {                                                                  \
            for ((_i_needed_a_very_very_uncommon_name_for_this_iterator) = 0;                      \
                 (_i_needed_a_very_very_uncommon_name_for_this_iterator) < (v)->length;            \
                 ++(_i_needed_a_very_very_uncommon_name_for_this_iterator)) {                      \
                var = &(v)->data[(_i_needed_a_very_very_uncommon_name_for_this_iterator)];         \
                { body }                                                                           \
            }                                                                                      \
        }                                                                                          \
    } while (0)

#endif // CPDEM_VEC_H
