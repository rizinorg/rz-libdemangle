// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

bool demangle(void) {
	mu_demangle(objc, "_OBJC_CLASS_$_Employee", "class Employee");
	mu_demangle(objc, "_OBJC_Class_Employee", "class Employee");
	mu_demangle(objc, "_OBJC_IVAR_$_Employee._shortWord", "field int Employee::_shortWord");

	mu_demangle(objc, "_i_class1__method2_arg2_", "public int class1::method2(int, int)");
	mu_end;
}

int all_tests() {
	mu_run_test(demangle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
