// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file fuzz_demangle.c
 * \brief LLVM libFuzzer harness targeting the Itanium ABI v3 C++ demangler.
 *
 * This harness calls cp_demangle_v3() and cp_demangle_v3_type() directly,
 * bypassing the generic cp_demangle() dispatcher so that fuzzing is focused
 * on the v3 code paths (the site of the original double-free bug in
 * VecNodeRef_free_inner / DemContext_deinit).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cplusplus/demangle.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size > 4096) {
		return 0;
	}

	char *buf = malloc(size + 1);
	if (!buf) {
		return 0;
	}
	memcpy(buf, data, size);
	buf[size] = '\0';

	// Exercise the Itanium v3 demangler with multiple option combinations.
	// DEM_OPT_ALL enables all output features; DEM_OPT_SIMPLE enables
	// simplified/human-readable output (different code paths).
	char *result;

	result = cp_demangle_v3(buf, DEM_OPT_ALL);
	free(result);

	result = cp_demangle_v3(buf, DEM_OPT_SIMPLE);
	free(result);

	// Also fuzz bare-type demangling (e.g. type encodings without _Z prefix).
	result = cp_demangle_v3_type(buf, DEM_OPT_ALL);
	free(result);

	free(buf);
	return 0;
}
