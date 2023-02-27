// SPDX-FileCopyrightText: 2011-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include "demangler_util.h"
#include <rz_libdemangle.h>

uint32_t get_integer(const char **str) {
	/* Assuming the string in str is base 10 */

	uint32_t result = 0;
	const char *x = *str;

	while (IS_DIGIT(*x)) {
		result *= 10;
		result += *x & 0xf;
		x++;
	}

	/* Update the string pointer */
	*str = x;

	return result;
}

/**
 * @brief We return NULL instead of strdup-ing the string, because that way we can check for NULL
 * and invoke the CXX demangler \p sym again in case it a CXX symbol
 * We should not call the CXX demangler here because then this code will not be LGPL,
 * but GPL because CXX demangler is GPL
 */
char *libdemangle_handler_rust(const char *sym) {
	const char *post = sym;
	char *prefixes[] = { "_ZN", /* Windows */ "ZN", /* OSX */ "__ZN" };

	for (uint8_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		uint8_t len = strlen(prefixes[i]);
		if (!strncmp(sym, prefixes[i], len)) {
			post += len;
			break;
		}
	}

	if (sym == post) {
		/* Not a Rust symbol */
		return NULL;
	}

	const char *itr = post;
	while (*itr) {
		/* Check if only ASCII chars present */
		if (*itr & 0x80) {
			return NULL;
		}
		itr++;
	}

	DemString *result = dem_string_new();

	while (*post != 'E') {
		uint32_t len = get_integer(&post);

		/* Check if no digits found
		OR If end of string reached
		OR Element ends after (or when) the string ends */
		if (len == 0 || *post == '\0' || len >= strlen(post)) {
			/* All these cases are malformed */
			dem_string_free(result);
			return NULL;
		}

		dem_string_append_n(result, post, len);
		post += len;

		if (*post != 'E') {
			dem_string_append(result, "::");
		}
	}

	return dem_string_drain(result);
}
