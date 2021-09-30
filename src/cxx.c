// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include "demangler_util.h"
#include "cxx/demangle.h"
#include <rz_libdemangle.h>

#if WITH_GPL
char *libdemangle_handler_cxx(const char *str) {
	// DMGL_TYPES | DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE | DMGL_RET_POSTFIX | DMGL_TYPES;
	uint32_t i;

	int flags = DMGL_NO_OPTS | DMGL_PARAMS;
	const char *prefixes[] = {
		"__symbol_stub1_",
		"reloc.",
		"sym.imp.",
		"imp.",
		NULL
	};
	char *tmpstr = strdup(str);
	char *p = tmpstr;

	if (p[0] == p[1] && *p == '_') {
		p++;
	}
	for (i = 0; prefixes[i]; i++) {
		uint32_t plen = strlen(prefixes[i]);
		if (!strncmp(p, prefixes[i], plen)) {
			p += plen;
			break;
		}
	}
	// remove CXXABI suffix
	char *cxxabi = strstr(p, "@@CXXABI");
	char *glibcxx = strstr(p, "@GLIBCXX");
	if (cxxabi) {
		*cxxabi = '\0';
	} else if (glibcxx) {
		if (p < glibcxx && glibcxx[-1] == '@') {
			glibcxx[-1] = '\0';
		} else {
			*glibcxx = '\0';
		}
	}

	uint32_t len = strlen(p);
	if (len > 4 && !strncmp(p + len - 4, "_ptr", 4)) {
		// remove _ptr from the end
		*(p + len - 4) = '\0';
	} else if (len > 1 && IS_DIGIT(*(p + len - 1))) {
		// removes version sequences like _5_2 or _18_4 etc... from the end
		bool expect_digit = true;
		bool expect_underscore = false;
		for (i = len - 1; i > 0; i--) {
			if (expect_digit && IS_DIGIT(p[i])) {
				if (i == 0) {
					break;
				} else if (p[i - 1] == '_') {
					expect_underscore = true;
					expect_digit = false;
				} else if (!IS_DIGIT(p[i - 1])) {
					break;
				}
			} else if (expect_underscore && p[i] == '_') {
				p[i] = '\0';
				if (i == 0) {
					break;
				} else if (!IS_DIGIT(p[i - 1])) {
					break;
				} else {
					expect_underscore = false;
					expect_digit = true;
				}
			}
		}
	}

	char *out = cplus_demangle_v3(p, flags);
	free(tmpstr);
	return out;
}
#endif
