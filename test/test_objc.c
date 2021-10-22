// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

mu_demangle(0, objc, "_OBJC_CLASS_$_Employee", "class Employee");
mu_demangle(1, objc, "_OBJC_Class_Employee", "class Employee");
mu_demangle(2, objc, "_OBJC_IVAR_$_Employee._shortWord", "field int Employee::_shortWord");
mu_demangle(3, objc, "_i_class1__method2_arg2_", "public int class1::method2(int, int)");
mu_demangle(4, objc, "-[class1 method2:arg2:]", "public int class1::method2(int, int)");
mu_demangle(5, objc, "+[Employee sayHello]", "static int Employee::sayHello()");

int all_tests() {
	mu_demangle_run(0);
	mu_demangle_run(1);
	mu_demangle_run(2);
	mu_demangle_run(3);
	mu_demangle_run(4);
	mu_demangle_run(5);
	return tests_passed != tests_run;
}

mu_main(all_tests)
