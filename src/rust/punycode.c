// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2017 Rakholiya Jenish
// SPDX-License-Identifier: LGPL-3.0-only

#include "rust.h"

#define BASE         36
#define TMIN         1
#define TMAX         26
#define SKEW         38
#define DAMP         700
#define INITIAL_N    128
#define INITIAL_BIAS 72

static size_t utf32_len(ut32 *input) {
	size_t i = 0;
	while (*(input + i)) {
		i++;
	}
	return i;
}

static ut32 utf32_to_utf8(ut32 utf32, ut8 *utf8) {
	if (utf32 < 0x80) {
		*utf8 = utf32 & 0xff;
		return 1;
	} else if (utf32 < 0x800) {
		utf8[1] = 0x80 | (utf32 & 0x3f);
		utf8[0] = 0xc0 | ((utf32 >> 6) & 0x1f);
		return 2;
	} else if (utf32 < 0x10000) {
		utf8[2] = 0x80 | (utf32 & 0x3f);
		utf8[1] = 0x80 | ((utf32 >> 6) & 0x3f);
		utf8[0] = 0xe0 | ((utf32 >> 12) & 0xf);
		return 3;
	} else if (utf32 < 0x200000) {
		utf8[3] = 0x80 | (utf32 & 0x3f);
		utf8[2] = 0x80 | ((utf32 >> 6) & 0x3f);
		utf8[1] = 0x80 | ((utf32 >> 12) & 0x3f);
		utf8[0] = 0xf0 | ((utf32 >> 18) & 0x7);
		return 4;
	}
	return 0;
}

static ut8 *utf32_to_utf8_string(ut32 *input, size_t *length) {
	size_t len = utf32_len(input);
	ut8 *result = calloc(4, len + 1);
	if (!result) {
		return NULL;
	}

	size_t j = 0;
	for (size_t i = 0; i < len; i++) {
		ut32 used = utf32_to_utf8(input[i], result + j);
		if (used < 1) {
			free(result);
			return NULL;
		}
		j += used;
	}

	result[j] = 0;
	*length = j;
	return result;
}

static ut32 adapt_bias(ut32 delta, unsigned n_points, int is_first) {
	ut32 k = 0;
	delta /= is_first ? DAMP : 2;
	delta += delta / n_points;

	while (delta > ((BASE - TMIN) * TMAX) / 2) {
		delta /= (BASE - TMIN);
		k += BASE;
	}

	return k + (((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

static bool decode_digit(ut32 v, ut32 *digit) {
	if (IS_DIGIT(v)) {
		*digit = v - 22;
	} else if (IS_LOWER(v)) {
		*digit = v - 'a';
	} else if (IS_UPPER(v)) {
		*digit = v - 'A';
	} else {
		return false;
	}
	return true;
}

char *rust_punycode_to_utf8(const char *encoded, size_t length, size_t *decoded_len) {
	const char *p = NULL;
	ut32 di = 0;
	ut32 b = 0, n = 0, t = 0;
	ut32 digit = 0, org_i = 0, bias = 0;
	ut32 *utf32_string = NULL;
	ut8 *decoded = NULL;

	if (length < 1) {
		return NULL;
	}

	for (size_t si = 0; si < length; si++) {
		if (encoded[si] & 0x80) {
			return NULL;
		}
	}

	utf32_string = calloc((2 * length) + 10, 4);
	if (!utf32_string) {
		return NULL;
	}

	// Rust punycode deviates from standard
	// https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html#punycode-identifiers
	for (p = encoded + length - 1; p > encoded && *p != '_'; p--) {
		;
	}
	b = p - encoded;

	di = b;
	for (size_t i = 0; i < b; i++) {
		utf32_string[i] = encoded[i];
	}

	n = INITIAL_N;
	bias = INITIAL_BIAS;

	for (size_t i = 0, si = b + (b > 0); si < length; di++) {
		org_i = i;

		for (ut32 w = 1, k = BASE;; k += BASE) {
			if (!decode_digit(encoded[si++], &digit)) {
				free(utf32_string);
				return NULL;
			}

			if (digit > (UT32_MAX - i) / w) {
				free(utf32_string);
				return NULL;
			}

			i += digit * w;

			if (k <= bias) {
				t = TMIN;
			} else if (k >= bias + TMAX) {
				t = TMAX;
			} else {
				t = k - bias;
			}

			if (digit < t) {
				break;
			}

			if (w > UT32_MAX / (BASE - t)) {
				free(utf32_string);
				return NULL;
			}

			w *= BASE - t;
		}

		bias = adapt_bias(i - org_i, di + 1, org_i == 0);

		if (i / (di + 1) > UT32_MAX - n) {
			free(utf32_string);
			return NULL;
		}

		n += i / (di + 1);
		i %= (di + 1);

		memmove(utf32_string + i + 1, utf32_string + i, (di - i) * sizeof(ut32));
		utf32_string[i++] = n;
	}

	decoded = utf32_to_utf8_string(utf32_string, decoded_len);
	free(utf32_string);
	if (!decoded) {
		return NULL;
	}
	return (char *)decoded;
}
