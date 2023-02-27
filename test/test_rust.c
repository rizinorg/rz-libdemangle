// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

mu_demangle(0, rust, "_ZN5alloc3oom3oom17h722648b727b8bcd0E", "alloc::oom::oom::h722648b727b8bcd0");
mu_demangle(1, rust, "__ZN4core3fmt5Write10write_char17hcc5144a9a84f2b15E", "core::fmt::Write::write_char::hcc5144a9a84f2b15");
mu_demangle(2, rust, "ZN14rustc_demangle6legacy8demangleE", "rustc_demangle::legacy::demangle");
mu_demangle(3, rust, "_ZN4toolongE", NULL);
mu_demangle(4, rust, "___ZNwrong_formatE", NULL);
mu_demangle(5, rust, "_ZN10no_e_found", NULL);
mu_demangle(6, rust, "_ZN7onlyone", NULL);

int all_tests() {
	mu_demangle_run(0);
	mu_demangle_run(1);
	mu_demangle_run(2);
	mu_demangle_run(3);
	mu_demangle_run(4);
	mu_demangle_run(5);
	mu_demangle_run(6);
	return tests_passed != tests_run;
}

mu_main(all_tests)
