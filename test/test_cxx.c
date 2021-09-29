// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

bool demangle(void) {
	mu_demangle(cxx, "_ZNSt2147483648ios_base4InitD1Ev", NULL);
	mu_end;
}

int all_tests() {
	mu_run_test(demangle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
