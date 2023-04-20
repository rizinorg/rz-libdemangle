// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"

mu_demangle_tests(objc,
	mu_demangle_test("_OBJC_CLASS_$_Employee", "class Employee"),
	mu_demangle_test("_OBJC_Class_Employee", "class Employee"),
	mu_demangle_test("_OBJC_IVAR_$_Employee._shortWord", "field int Employee::_shortWord"),
	mu_demangle_test("_i_class1__method2_arg2_", "public int class1::method2(int, int)"),
	mu_demangle_test("-[class1 method2:arg2:]", "public int class1::method2(int, int)"),
	mu_demangle_test("+[Employee sayHello]", "static int Employee::sayHello()"),
	// end
);

mu_main2(objc);