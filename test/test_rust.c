// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

mu_demangle(0, rust, "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev", "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()");
mu_demangle(1, rust, "_ZN5alloc3oom3oom17h722648b727b8bcd0E", "alloc::oom::oom::h722648b727b8bcd0");
mu_demangle(2, rust, "_ZN4core3fmt5Write10write_char17hcc5144a9a84f2b15E", "core::fmt::Write::write_char::hcc5144a9a84f2b15");
mu_demangle(3, rust, "_ZN71_$LT$Test$u20$$u2b$$u20$$u27$static$u20$as$u20$foo..Bar$LT$Test$GT$$GT$3barE", "<Test + 'static as foo::Bar<Test>>::bar");
mu_demangle(4, rust, "_ZN96_$LT$core..fmt..Write..write_fmt..Adapter$LT$$u27$a$C$$u20$T$GT$$u20$as$u20$core..fmt..Write$GT$9write_str17he4f4768a2f446facE", "<core::fmt::Write::write_fmt::Adapter<'a, T> as core::fmt::Write>::write_str::he4f4768a2f446fac");

int all_tests() {
	mu_demangle_run(0);
	mu_demangle_run(1);
	mu_demangle_run(2);
	mu_demangle_run(3);
	mu_demangle_run(4);
	return tests_passed != tests_run;
}

mu_main(all_tests)
