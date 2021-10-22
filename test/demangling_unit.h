// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MANGLING_UNIT_H
#define MANGLING_UNIT_H

#include "minunit.h"

#define RZ_API
#include "rz_libdemangle.h"


#define mu_demangle_str(name, input, expected) \
	do { \
		char *output = libdemangle_handler_##name(input); \
		if (expected) { \
			mu_assert_notnull(output, #name " " input); \
			mu_assert_streq_free(output, expected, #name " " input); \
		} else { \
			mu_assert_null(output, #name " " input); \
		} \
	} while (0)

#define mu_demangle(fcnid, name, input, expected) \
	bool demangle_fcn_with_id_##fcnid(void) { \
		mu_demangle_str(name, input, expected); \
		mu_end; \
	}

#define mu_demangle_run(fcnid) mu_run_test(demangle_fcn_with_id_##fcnid)

#endif /* MANGLING_UNIT_H */
