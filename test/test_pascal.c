// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

mu_demangle(0, pascal, "OUTPUT_$$_SQUARE$SMALLINT$$SMALLINT", "unit output square(smallint) smallint");
mu_demangle(1, pascal, "OUTPUT_$$_init", "unit output init()");
mu_demangle(2, pascal, "OUTPUT$_$MYOBJECT_$__$$_INIT$$QWORDBOOL", "unit output myobject.init() qwordbool");
mu_demangle(3, pascal, "OUTPUT$_$MYOBJECT_$__$$_MYMETHOD", "unit output myobject.mymethod()");
mu_demangle(4, pascal, "OUTPUT_$$_MYFUNC$$POINTER", "unit output myfunc() pointer");
mu_demangle(5, pascal, "OUTPUT_$$_MYPROCEDURE$SMALLINT$LONGINT$PCHAR", "unit output myprocedure(smallint, longint, pchar)");
mu_demangle(6, pascal, "OUTPUT_$$_MYFUNC2$SMALLINT$LONGINT$PCHAR$$POINTER", "unit output myfunc2(smallint, longint, pchar) pointer");
mu_demangle(7, pascal, "OUTPUT_$$_MYFUN3$SMALLINT", "unit output myfun3(smallint)");
mu_demangle(8, pascal, "OUTPUT_SQUARE$SMALLINT$$SMALLINT", "output_square(smallint) smallint");
mu_demangle(9, pascal, "OUTPUT_INIT$$SMALLINT", "output_init() smallint");
mu_demangle(10, pascal, "OUTPUT_INIT$SMALLINT", "output_init(smallint)");

int all_tests() {
	mu_demangle_run(0);
	mu_demangle_run(1);
	mu_demangle_run(2);
	mu_demangle_run(3);
	mu_demangle_run(4);
	mu_demangle_run(5);
	mu_demangle_run(6);
	mu_demangle_run(7);
	mu_demangle_run(8);
	mu_demangle_run(9);
	mu_demangle_run(10);
	return tests_passed != tests_run;
}

mu_main(all_tests)
