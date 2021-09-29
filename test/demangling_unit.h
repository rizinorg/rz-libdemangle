// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MANGLING_UNIT_H
#define MANGLING_UNIT_H

#include "minunit.h"
#include "rz_libdemangle.h"

#define mu_demangle(name, input, expected) \
	do { \
		char *output = libdemangle_handler_##name(input); \
		if (expected) { \
			mu_assert_notnull(output, #name " " input); \
			mu_assert_streq_free(output, expected, #name " " input); \
		} else { \
			mu_assert_null(output, #name " " input); \
		} \
	} while (0)

#endif /* MANGLING_UNIT_H */
