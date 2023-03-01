// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangler_util.h"
#include <rz_libdemangle.h>

static uint32_t rebase_value(uint8_t char_code, uint8_t base) {
	if ((char_code >= 'a' && char_code <= 'z') || (char_code >= 'A' && char_code <= 'Z')) {
		/* lower/upper case letter */
		return (char_code | 0x20) - 'a' + 10;
	} else if (char_code >= '0' && char_code <= '9') {
		/* integer character */
		return char_code & 0xf;
	} else {
		/* invalid */
		return base;
	}
}

static uint32_t get_integer(const char **str, uint8_t base) {
	uint32_t result = 0;
	const char *x = *str;
	uint8_t digit;

	while ((digit = rebase_value(*x, base)) < base) {
		result *= base;
		result += digit;
		x++;
	}

	/* Update the string pointer */
	*str = x;

	return result;
}

static uint32_t utf_to_bytes(uint32_t utf) {
	/* returns in big endian */
	uint32_t result = 0;

	if (utf < 0x80) {
		result = utf << 24;
	} else if (utf < 0x800) {
		result = (utf & 0x3f) << 16;
		result |= ((utf >> 6) & 0x1f) << 24;
		result |= 0xc0800000;
	} else if (utf < 0x10000) {
		result = (utf & 0x3f) << 8;
		result |= ((utf >> 6) & 0x3f) << 16;
		result |= ((utf >> 12) & 0xf) << 24;
		result |= 0xe0808000;
	} else if (utf < 0x110000) {
		result = utf & 0x3f;
		result |= ((utf >> 6) & 0x3f) << 8;
		result |= ((utf >> 12) & 0x3f) << 16;
		result |= ((utf >> 18) & 0x7) << 24;
		result |= 0xf0808080;
	}

	return result;
}

static DemString *replace_utf(const char *utf_str) {
	DemString *demstr = dem_string_new();
	const char *utf_char = strchr(utf_str, '$');
	const char *last_ptr = utf_str;

	while (utf_char) {
		if (*(utf_char + 1) != 'u') {
			utf_char++;
			goto next_delim;
		}

		dem_string_append_n(demstr, last_ptr, utf_char - last_ptr);
		utf_char += 2;

		uint32_t utf_int = get_integer((const char **)&utf_char, 16);
		uint32_t utf_bytes = utf_to_bytes(utf_int);
		if (utf_bytes) {
			const char bytes_str[5] = { (utf_bytes >> 24) & 0xff, (utf_bytes >> 16) & 0xff,
				(utf_bytes >> 8) & 0xff, utf_bytes & 0xff,
				'\0' };
			dem_string_append(demstr, bytes_str);
			/* Consume closing $ */
			utf_char += 1;
		} else {
			/* Not a UTF character (unreachable, but just in case) */
			dem_string_append(demstr, "$u");
		}

		last_ptr = utf_char;

	next_delim:
		utf_char = strchr(utf_char, '$');
	}

	dem_string_append(demstr, last_ptr);
	return demstr;
}

static char *special_symbols[] = {
	"$SP$",
	"$BP$",
	"$RF$",
	"$LT$",
	"$GT$",
	"$LP$",
	"$RP$",
	"$C$",
	/* namespace */
	".."
};

static char *replacements[] = {
	"@",
	"*",
	"&",
	"<",
	">",
	"(",
	")",
	",",
	"::"
};

/**
 * \brief We return NULL instead of strdup-ing the string, because that way we can check for NULL
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
		uint32_t len = get_integer(&post, 10);

		/* Check if no digits found
		OR If end of string reached
		OR Element ends after (or when) the string ends */
		if (len == 0 || *post == '\0' || len >= strlen(post)) {
			/* All these cases are malformed */
			dem_string_free(result);
			return NULL;
		}

		if (!strncmp(post, "_$", strlen("_$"))) {
			/* special symbols can have an extra underscore before it, if first in token */
			post++;
			len--;
		}
		dem_string_append_n(result, post, len);
		post += len;

		if (*post != 'E') {
			dem_string_append(result, "::");
		}
	}

	char *demangled = dem_string_drain(result);
	for (uint8_t i = 0; i < sizeof(special_symbols) / sizeof(special_symbols[0]); i++) {
		dem_str_replace(demangled, special_symbols[i], replacements[i], 1);
	}

	DemString *utf_free = replace_utf(demangled);
	free(demangled);

	/* ThinLTO LLVM IR period delimited suffixes */
	const char *suff = post + 1;
	uint8_t llvm_len = strlen(".llvm.");
	const char *llvm_str = NULL;
	bool found_llvm = false, check_hex = false;

	while (*++post > 0x20) {
		if (check_hex && !(*post >= 'A' || *post <= 'Z' || *post >= '0' || *post <= '9')) {
			check_hex = false;
		}
		if (!found_llvm && !strncmp(post, ".llvm.", llvm_len)) {
			found_llvm = true;
			check_hex = true;
			llvm_str = post;
			post += llvm_len - 1;
			continue;
		}
	}
	if (*post != 0x00) {
		/* Invalid character found in suffix (post did not end yet) */
		dem_string_free(utf_free);
		return NULL;
	}

	if (llvm_str && check_hex) {
		/* Valid LLVM suffix found, then ignore it */
		post = llvm_str;
	}

	dem_string_append_n(utf_free, suff, post - suff);
	return dem_string_drain(utf_free);
}
