// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

bool demangle(void) {

	mu_demangle(java, "Ljava/lang/String;", "String");
	mu_demangle(java, "Lsome/random/Class;", "some.random.Class");
	mu_demangle(java, "B", "byte");
	mu_demangle(java, "C", "char");
	mu_demangle(java, "D", "double");
	mu_demangle(java, "F", "float");
	mu_demangle(java, "I", "int");
	mu_demangle(java, "J", "long");
	mu_demangle(java, "S", "short");
	mu_demangle(java, "V", "void");
	mu_demangle(java, "Z", "boolean");

	mu_demangle(java, "[Ljava/lang/String;", "String[]");
	mu_demangle(java, "[Lsome/random/Class;", "some.random.Class[]");
	mu_demangle(java, "[B", "byte[]");
	mu_demangle(java, "[C", "char[]");
	mu_demangle(java, "[D", "double[]");
	mu_demangle(java, "[F", "float[]");
	mu_demangle(java, "[I", "int[]");
	mu_demangle(java, "[J", "long[]");
	mu_demangle(java, "[S", "short[]");
	mu_demangle(java, "[V", "void[]");
	mu_demangle(java, "[Z", "boolean[]");

	// methods
	mu_demangle(java, "makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;", "String makeConcatWithConstants(String)");
	mu_demangle(java, "Lsome/random/Class;.makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;", "String some.random.Class.makeConcatWithConstants(String)");
	mu_demangle(java, "Fake([BCDFIJSZ)Ltest/class/name;", "test.class.name Fake(byte[], char, double, float, int, long, short, boolean)");
	mu_demangle(java, "Fake([BCDFIJSZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ltest/class/name;", "test.class.name Fake(byte[], char, double, float, int, long, short, boolean, String, String, String)");

	// fields
	mu_demangle(java, "makeConcatWithConstants.Ljava/lang/String;", "makeConcatWithConstants:String");
	mu_demangle(java, "Lsome/random/Class;.makeConcatWithConstants.Ljava/lang/String;", "some.random.Class.makeConcatWithConstants:String");
	mu_end;
}

int all_tests() {
	mu_run_test(demangle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
