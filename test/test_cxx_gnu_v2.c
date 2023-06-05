// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"

mu_demangle_tests(gnu_v2,
	mu_demangle_test("_vt.foo", "foo virtual table"),
	mu_demangle_test("_vt$foo", "foo virtual table"),
	mu_demangle_test("_vt$foo$bar", "foo::bar virtual table"),
	mu_demangle_test("__vt_foo", "foo virtual table"),
	mu_demangle_test("_3foo$varname", "foo::varname"),
	mu_demangle_test("__thunk_4__$_7ostream", "virtual function thunk (delta:-4) for ostream::~ostream(void)"),
	mu_demangle_test("_$_3foo", "foo::~foo(void)"),
	mu_demangle_test("_._3foo", "foo::~foo(void)"),
	mu_demangle_test("_Q22rs2tu$vw", "rs::tu::vw"),
	mu_demangle_test("__t6vector1Zii", "vector<int>::vector(int)"),
	mu_demangle_test("foo__1Ai", "A::foo(int)"),
	mu_demangle_test("foo__1Afe", "A::foo(float,...)"),
	mu_demangle_test("_AddColor__10ZafDisplayUcUcUcUcUc", "ZafDisplay::_AddColor(unsigned char, unsigned char, unsigned char, unsigned char, unsigned char)"),
	// end
);

mu_main(gnu_v2, cxx);