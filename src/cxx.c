// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include "demangler_util.h"
#include "cxx/demangle.h"
#include <rz_libdemangle.h>

#if WITH_GPL
char *libdemangle_handler_cxx(const char *str) {
	// DMGL_TYPES | DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE | DMGL_RET_POSTFIX | DMGL_TYPES;
	int i;

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
		int plen = strlen(prefixes[i]);
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
	char *out = cplus_demangle_v3(p, flags);
	free(tmpstr);
	return out;
}
#endif
