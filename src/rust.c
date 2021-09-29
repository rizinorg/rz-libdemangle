// SPDX-FileCopyrightText: 2011-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include "demangler_util.h"
#include <rz_libdemangle.h>

#define RS(from, to) \
	if (replace_seq((const char **)&in, &out, (const char *)(from), to)) \
	continue

static bool replace_seq(const char **in, char **out, const char *seq, char value) {
	size_t len = strlen(seq);

	if (strncmp(*in, seq, len)) {
		return false;
	}

	**out = value;

	*in += len;
	*out += 1;

	return true;
}

char *libdemangle_handler_rust(const char *sym) {
	int len;
	char *str = NULL, *out, *in;

	str = libdemangle_handler_cxx(sym);

	if (!str) {
		return str;
	}

	out = in = str;
	len = strlen(str);

	if (*in == '_') {
		in++;
		len--;
	}

	while ((len = strlen(in)) > 0) {
		if (*in == '$') {
			RS("$SP$", '@');
			RS("$BP$", '*');
			RS("$RF$", '&');
			RS("$LT$", '<');
			RS("$GT$", '>');
			RS("$LP$", '(');
			RS("$RP$", ')');
			RS("$C$", ',');
			// maybe a good idea to replace all utf-sequences by regexp \$u[0-9a-f]{2}\$ or so
			RS("$u20$", ' ');
			RS("$u22$", '\"');
			RS("$u27$", '\'');
			RS("$u2b$", '+');
			RS("$u3b$", ';');
			RS("$u5b$", '[');
			RS("$u5d$", ']');
			RS("$u7e$", '~');
		}
		if (*in == '.') {
			if (len > 0 && in[1] == '.') {
				in += 2;
				*out++ = ':';
				*out++ = ':';
				len--;
			} else {
				in += 1;
				*out = '-';
			}
		} else {
			*out++ = *in++;
		}
	}
	*out = '\0';

	return str;
}
