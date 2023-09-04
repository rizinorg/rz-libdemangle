// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangler_util.h"
#include "rz_libdemangle.h"
#include "rz_libdemangle.h"

#if WITH_SWIFT_DEMANGLER
#define SWIFT "swift, "
#else
#define SWIFT ""
#endif

#define LANGUAGES "java, msvc, objc, " SWIFT "pascal, rust, c++ (incl. borland, gnu v3 & v2)"

typedef char *(*handler_t)(const char *symbol, RzDemangleOpts opts);

typedef struct {
	const char *name;
	handler_t demangle;
} language_t;

static language_t languages[] = {
	{ .name = "c++", .demangle = libdemangle_handler_cxx },
	{ .name = "rust", .demangle = libdemangle_handler_rust },
#if WITH_SWIFT_DEMANGLER
	{ .name = "swift", .demangle = libdemangle_handler_swift },
#endif
	{ .name = "java", .demangle = libdemangle_handler_java },
	{ .name = "msvc", .demangle = libdemangle_handler_msvc },
	{ .name = "objc", .demangle = libdemangle_handler_objc },
	{ .name = "pascal", .demangle = libdemangle_handler_pascal },
};

static void usage(const char *prog) {
	printf("usage: %s [option] <lang> <string to demangle>\n", prog);
	printf("The program will attempt to demangle the string for the given language.\n"
	       "Options:\n"
	       "  -s    demangles the entry and simplifies the result\n"
	       "\nSupported languages: " LANGUAGES "\n");
}

int main(int argc, char const *argv[]) {
	if (argc != 3 && argc != 4) {
		usage(argv[0]);
		return 1;
	}

	RzDemangleOpts opts = RZ_DEMANGLE_OPT_BASE;
	const char *lang = argv[1];
	const char *symbol = argv[2];

	if (argc == 4) {
		if (strcmp(argv[1], "-s")) {
			printf("error: invalid option: '%s'\n", argv[1]);
			usage(argv[0]);
			return 1;
		}
		opts |= RZ_DEMANGLE_OPT_SIMPLIFY;
		lang = argv[2];
		symbol = argv[3];
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(languages); ++i) {
		if (strcmp(languages[i].name, lang)) {
			continue;
		}
		char *result = languages[i].demangle(symbol, opts);
		if (result) {
			printf("%s\n", result);
			free(result);
			return 0;
		}
		return 1;
	}

	printf("unknown lang: %s\n", lang);
	usage(argv[0]);
	return 1;
}