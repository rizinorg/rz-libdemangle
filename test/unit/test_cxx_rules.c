// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz-minunit.h"
#include "../../src/cplusplus/v3.h"

int all_tests() {

	return tests_passed != tests_run;
}

mu_main(all_tests);
