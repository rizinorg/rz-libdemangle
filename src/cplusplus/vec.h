// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_VEC_H
#define CPDEM_VEC_H

// MSVC compatibility: __attribute__ is not supported
#if defined(_MSC_VER)
#define __attribute__(x)
#endif

#define UNUSED(xpr) ((void)(xpr))

/**
 * Iterate over each element in vector.
 * Provides a pointer to access to each element one by one.
 */
#define vec_foreach_ptr_i(T, v, I, var, body) \
	do { \
		size_t I = 0; \
		T *var = NULL; \
		const void *_vec_p_##var = (v); \
		if (_vec_p_##var && (v)->length) { \
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

#define vec_foreach_ptr(T, v, var, body) vec_foreach_ptr_i(T, v, _idx_##var, var, body)

#define Vec_t(T)   Vec##T##_t
#define VecT(T)    Vec##T
#define VecF(T, N) Vec##T##_##N
#define VecIMPL(T, F) \
	typedef struct Vec_t(T) { \
		T *data; \
		ut64 length; \
		ut64 capacity; \
	} Vec##T; \
	__attribute__((unused)) static inline T *VecF(T, data)(Vec##T * self) { \
		return self ? self->data : NULL; \
	} \
	__attribute__((unused)) static inline size_t VecF(T, len)(const Vec##T *self) { \
		return self ? self->length : 0; \
	} \
	__attribute__((unused)) static inline size_t VecF(T, cap)(Vec##T * self) { \
		return self ? self->capacity : 0; \
	} \
	__attribute__((unused)) static inline bool VecF(T, empty)(Vec##T * self) { \
		return !self || !VecF(T, data)(self) || VecF(T, len)(self) == 0; \
	} \
	__attribute__((unused)) static inline size_t VecF(T, mem_size)(Vec##T * self) { \
		return VecF(T, len)(self) * sizeof(T); \
	} \
	__attribute__((unused)) static inline void VecF(T, init)(Vec##T * self) { \
		if (self) { \
			memset(self, 0, sizeof(VecT(T))); \
		} \
	} \
	__attribute__((unused)) static inline void VecF(T, deinit)(Vec##T * self) { \
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
	__attribute__((unused)) static inline VecT(T) * VecF(T, ctor)() { \
		return calloc(1, sizeof(VecT(T))); \
	} \
	__attribute__((unused)) static inline void VecF(T, dtor)(Vec##T * self) { \
		if (self) { \
			VecF(T, deinit)(self); \
			free(self); \
		} \
	} \
	__attribute__((unused)) static inline T *VecF(T, at)(Vec##T * self, size_t idx) { \
		if (self && self->data && idx < self->length) { \
			return &self->data[idx]; \
		} \
		return NULL; \
	} \
	__attribute__((unused)) static inline T *VecF(T, head)(Vec##T * self) { \
		return VecF(T, at)(self, 0); \
	} \
	__attribute__((unused)) static inline T *VecF(T, tail)(Vec##T * self) { \
		if (VecF(T, empty)(self)) { \
			return NULL; \
		} \
		return VecF(T, at)(self, VecF(T, len)(self) - 1); \
	} \
	__attribute__((unused)) static inline bool VecF(T, reserve)(Vec##T * self, size_t new_cap) { \
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
	__attribute__((unused)) static inline bool VecF(T, resize)(Vec##T * self, size_t new_size) { \
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
	__attribute__((unused)) static inline T *VecF(T, append)(Vec##T * self, const T *x) { \
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
	__attribute__((unused)) static inline T *VecF(T, pop)(Vec##T * self) { \
		if (VecF(T, empty)(self)) { \
			return NULL; \
		} \
		T *x = VecF(T, tail)(self); \
		self->length--; \
		return x; \
	} \
	__attribute__((unused)) static inline Vec##T *VecF(T, concat)(Vec##T * self, Vec##T * xs) { \
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
	__attribute__((unused)) static inline Vec##T *VecF(T, copy)(Vec##T * self, Vec##T * xs) { \
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
	__attribute__((unused)) static inline Vec##T *VecF(T, move)(Vec##T * self, Vec##T * xs) { \
		if (!self || !xs || self == xs) { \
			return NULL; \
		} \
		VecF(T, deinit)(self); \
		*self = *xs; \
		memset(xs, 0, sizeof(VecT(T))); \
		return self; \
	} \
	__attribute__((unused)) static inline void VecF(T, clear)(Vec##T * self) { \
		if (!self) { \
			return; \
		} \
		VecF(T, deinit)(self); \
	}

#endif // CPDEM_VEC_H
