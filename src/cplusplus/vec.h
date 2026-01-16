// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_VEC_H
#define CPDEM_VEC_H

#define UNUSED(xpr) ((void)(xpr))

#define nearest_power_of_two(v) \
	(((v)--), \
		((v) |= (v) >> 1), \
		((v) |= (v) >> 2), \
		((v) |= (v) >> 4), \
		((v) |= (v) >> 8), \
		((v) |= (v) >> 16), \
		((v) = v + 1))

#define Vec(x) \
	struct { \
		x *data; \
		ut64 length; \
		ut64 capacity; \
	}

#define VEC_DATA_TYPE(vec) __typeof__((vec)->data[0])

#define vec_mem_size(vec) (sizeof(VEC_DATA_TYPE((vec))) * (vec)->length)

/**
 * This will just memset vector to 0, to make it usable with other function (macros).
 *
 * \param vec : Pointer to vector to be inited.
 *
 * \return vec on success.
 * \return NULL otherwise.
 */
#define vec_init(vec) ((vec) ? (memset((vec), 0, sizeof(*(vec))), (vec)) : NULL)

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
#define vec_deinit(vec) ((vec) ? (((vec)->data ? free((vec)->data) : 1), vec_init(vec)) : NULL)

/**
 * Get data stored in vector at given idx.
 *
 * \param vec : Pointer to vector.
 * \param idx : Index to get data at.
 *
 * \return vec->data[idx] if vec is not NULL.
 * \return {0} otherwise.
 */
#define vec_at(vec, idx) ((vec) ? (vec)->data[idx] : ((VEC_DATA_TYPE(vec)){ 0 }))
#define vec_front(vec)   vec_at(vec, 0)
#define vec_back(vec)    vec_at(vec, (vec)->length - 1)

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
#define vec_begin(vec)       vec_ptr_at(vec, 0)
#define vec_end(vec)         vec_ptr_at(vec, (vec)->length - 1)

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
#define vec_reserve(vec, new_cap) \
	((vec) ? ((vec)->capacity < (new_cap) ? (/* make sure capacity can never be set to 0                                      */ \
							((vec)->capacity = (new_cap) ? (new_cap) : 1), \
							(/* make sure vector capacity is always in powers of two (not really necessary)*/ \
								nearest_power_of_two((vec)->capacity)), \
							(/* increase vector capacity                                                     */ \
								(vec)->data = \
									realloc((vec)->data, sizeof(VEC_DATA_TYPE(vec)) * (vec)->capacity)), \
							(/* memset new allocated region with 0 to make all pointers NULL                 */ \
								memset( \
									(vec)->data + (vec)->length, \
									0, \
									sizeof(VEC_DATA_TYPE(vec)) * ((vec)->capacity - (vec)->length))), \
							(vec)) \
					      : (vec)) \
	       : NULL)

#define vec_move(dst, src) \
	((dst && src && (src)->data) ? (vec_reserve(dst, (src)->length) && \
					       memcpy((dst)->data, (src)->data, vec_mem_size(src)) && \
					       ((dst)->length = (src)->length) && memset((src)->data, 0, vec_mem_size(src)) && \
					       vec_deinit(src)) \
				     : false)

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
#define vec_append(vec, data_ptr) \
	((vec) ? ((/* make sure vector has sufficient space to insert one more item \
		    * this has no effect if vector length is less than capacity                        */ \
			  vec_reserve((vec), (vec)->length + 1)) \
				 ? (/* copy the data over from data_ptr to last element                               */ \
					   memcpy((vec)->data + (vec)->length, (data_ptr), sizeof(VEC_DATA_TYPE(vec))), \
					   (/* adjust the vector length after appending                                      */ \
						   (vec)->length += 1), \
					   (vec)) \
				 : NULL) \
	       : NULL)

#define vec_pop(vec) (vec ? ((vec)->length > 0 ? --((vec)->length) : 0) : 0)

#define vec_append_const(vec, data_const) \
	((vec) ? ((/* make sure vector has sufficient space to insert one more item \
		    * this has no effect if vector length is less than capacity                        */ \
			  vec_reserve((vec), (vec)->length + 1)) \
				 ? (/* copy the data over from data to last element                               */ \
					   (vec)->data[(vec)->length] = (data_const), \
					   (/* adjust the vector length after appending                                      */ \
						   (vec)->length += 1), \
					   (vec)) \
				 : NULL) \
	       : NULL)

#define vec_concat(vec, other) vec_foreach_ptr((other), o, { UNUSED(vec_append((vec), o)); })

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
#define vec_foreach_ptr_i(v, I, var, body) \
	do { \
		size_t I = 0; \
		VEC_DATA_TYPE(v) *var = { 0 }; \
		if ((v) && (v)->length) { \
			for ((I) = 0; \
				(I) < (v)->length; \
				++(I)) { \
				var = &(v)->data[(I)]; \
				{ \
					body \
				} \
			} \
		} \
	} while (0)
#define vec_foreach_ptr(v, var, body) vec_foreach_ptr_i(v, _idx_##var, var, body)
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
#define vec_foreach(v, var, body) \
	do { \
		size_t _it_##var = 0; \
		VEC_DATA_TYPE(v) \
		var = { 0 }; \
		if ((v) && (v)->length) { \
			for ((_it_##var) = 0; \
				(_it_##var) < (v)->length; \
				++(_it_##var)) { \
				var = (v)->data[(_it_##var)]; \
				{ \
					body \
				} \
			} \
		} \
	} while (0)

#define Vec_t(T)   Vec##T##_t
#define VecT(T)    Vec##T
#define VecF(T, N) Vec##T##_##N
#define VecIMPL(T, F) \
	typedef struct Vec_t(T) { \
		T *data; \
		ut64 length; \
		ut64 capacity; \
	} Vec##T; \
	static inline T *VecF(T, data)(Vec##T * self) { \
		return self ? self->data : NULL; \
	} \
	static inline size_t VecF(T, len)(Vec##T * self) { \
		return self ? self->length : 0; \
	} \
	static inline size_t VecF(T, cap)(Vec##T * self) { \
		return self ? self->capacity : 0; \
	} \
	static inline bool VecF(T, empty)(Vec##T * self) { \
		return !self || !VecF(T, data)(self) || VecF(T, len)(self) == 0; \
	} \
	static inline size_t VecF(T, mem_size)(Vec##T * self) { \
		return VecF(T, len)(self) * sizeof(T); \
	} \
	static inline void VecF(T, init)(Vec##T * self) { \
		if (self) { \
			memset(self, 0, sizeof(VecT(T))); \
		} \
	} \
	static inline void VecF(T, deinit)(Vec##T * self) { \
		if (self && self->data) { \
			for (size_t i = 0; i < self->length; i++) { \
				F(&self->data[i]); \
			} \
			free(self->data); \
			self->data = NULL; \
			self->length = 0; \
			self->capacity = 0; \
		} \
	} \
	static inline VecT(T) * VecF(T, ctor)() { \
		return calloc(1, sizeof(VecT(T))); \
	} \
	static inline void VecF(T, dtor)(Vec##T * self) { \
		if (self) { \
			VecF(T, deinit)(self); \
			free(self); \
		} \
	} \
	static inline T *VecF(T, at)(Vec##T * self, size_t idx) { \
		if (self && self->data && idx < self->length) { \
			return &self->data[idx]; \
		} \
		return NULL; \
	} \
	static inline T *VecF(T, head)(Vec##T * self) { \
		return VecF(T, at)(self, 0); \
	} \
	static inline T *VecF(T, tail)(Vec##T * self) { \
		return VecF(T, at)(self, VecF(T, len)(self) - 1); \
	} \
	static inline bool VecF(T, reserve)(Vec##T * self, size_t new_cap) { \
		if (!self) { \
			return false; \
		} \
		if (self->capacity >= new_cap) { \
			return true; \
		} \
		T *new_data = realloc(self->data, sizeof(T) * new_cap); \
		if (!new_data) { \
			return false; \
		} \
		self->data = new_data; \
		self->capacity = new_cap; \
		return true; \
	} \
	static inline bool VecF(T, resize)(Vec##T * self, size_t new_size) { \
		if (!self) { \
			return false; \
		} \
		if (new_size > self->capacity) { \
			if (!VecF(T, reserve)(self, new_size)) { \
				return false; \
			} \
		} \
		if (new_size > self->length) { \
			memset( \
				self->data + self->length, \
				0, \
				(new_size - self->length) * sizeof(T)); \
		} \
		self->length = new_size; \
		return true; \
	} \
	static inline T *VecF(T, append)(Vec##T * self, const T *x) { \
		if (!self) { \
			return NULL; \
		} \
		if (self->length + 1 > self->capacity) { \
			size_t new_cap = self->capacity ? self->capacity * 2 : 4; \
			if (!VecF(T, reserve)(self, new_cap)) { \
				return NULL; \
			} \
		} \
		T *result = self->data + self->length; \
		if (x) { \
			memcpy(result, x, sizeof(T)); \
		} else { \
			memset(result, 0, sizeof(T)); \
		} \
		self->length++; \
		return result; \
	} \
	static inline T *VecF(T, pop)(Vec##T * self) { \
		if (VecF(T, empty)(self)) { \
			return NULL; \
		} \
		T *x = VecF(T, tail)(self); \
		self->length--; \
		return x; \
	} \
	static inline Vec##T *VecF(T, concat)(Vec##T * self, Vec##T * xs) { \
		if (!self || !xs) { \
			return NULL; \
		} \
		size_t new_len = self->length + xs->length; \
		if (new_len > self->capacity) { \
			if (!VecF(T, reserve)(self, new_len)) { \
				return NULL; \
			} \
		} \
		if (xs->length > 0) { \
			memcpy( \
				self->data + self->length, \
				xs->data, \
				xs->length * sizeof(T)); \
		} \
		self->length = new_len; \
		return self; \
	} \
	static inline Vec##T *VecF(T, copy)(Vec##T * self, Vec##T * xs) { \
		if (!self || !xs) { \
			return NULL; \
		} \
		if (self == xs) { \
			return self; \
		} \
		if (self->data == xs->data) { \
			self->length = xs->length; \
			return self; \
		} \
		VecF(T, resize)(self, xs->length); \
		if (xs->length > 0) { \
			memcpy( \
				self->data, \
				xs->data, \
				xs->length * sizeof(T)); \
		} \
		return self; \
	} \
	static inline Vec##T *VecF(T, move)(Vec##T * self, Vec##T * xs) { \
		if (!self || !xs || self == xs) { \
			return NULL; \
		} \
		VecF(T, deinit)(self); \
		*self = *xs; \
		memset(xs, 0, sizeof(VecT(T))); \
		return self; \
	} \
	static inline void VecF(T, clear)(Vec##T * self) { \
		if (!self) { \
			return; \
		} \
		VecF(T, deinit)(self); \
	}

#endif // CPDEM_VEC_H
