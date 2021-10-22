// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

mu_demangle(0, java, "Ljava/lang/String;", "String");
mu_demangle(1, java, "Lsome/random/Class;", "some.random.Class");
mu_demangle(2, java, "B", "byte");
mu_demangle(3, java, "C", "char");
mu_demangle(4, java, "D", "double");
mu_demangle(5, java, "F", "float");
mu_demangle(6, java, "I", "int");
mu_demangle(7, java, "J", "long");
mu_demangle(8, java, "S", "short");
mu_demangle(9, java, "V", "void");
mu_demangle(10, java, "Z", "boolean");

mu_demangle(11, java, "[Ljava/lang/String;", "String[]");
mu_demangle(12, java, "[Lsome/random/Class;", "some.random.Class[]");
mu_demangle(13, java, "[B", "byte[]");
mu_demangle(14, java, "[C", "char[]");
mu_demangle(15, java, "[D", "double[]");
mu_demangle(16, java, "[F", "float[]");
mu_demangle(17, java, "[I", "int[]");
mu_demangle(18, java, "[J", "long[]");
mu_demangle(19, java, "[S", "short[]");
mu_demangle(20, java, "[V", "void[]");
mu_demangle(21, java, "[Z", "boolean[]");

// methods
mu_demangle(22, java, "makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;", "String makeConcatWithConstants(String)");
mu_demangle(23, java, "Lsome/random/Class;.makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;", "String some.random.Class.makeConcatWithConstants(String)");
mu_demangle(24, java, "Fake([BCDFIJSZ)Ltest/class/name;", "test.class.name Fake(byte[], char, double, float, int, long, short, boolean)");
mu_demangle(25, java, "Fake([BCDFIJSZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ltest/class/name;", "test.class.name Fake(byte[], char, double, float, int, long, short, boolean, String, String, String)");

// fields
mu_demangle(26, java, "makeConcatWithConstants.Ljava/lang/String;", "makeConcatWithConstants:String");
mu_demangle(27, java, "Lsome/random/Class;.makeConcatWithConstants.Ljava/lang/String;", "some.random.Class.makeConcatWithConstants:String");

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
	mu_demangle_run(11);
	mu_demangle_run(12);
	mu_demangle_run(13);
	mu_demangle_run(14);
	mu_demangle_run(15);
	mu_demangle_run(16);
	mu_demangle_run(17);
	mu_demangle_run(18);
	mu_demangle_run(19);
	mu_demangle_run(20);
	mu_demangle_run(21);
	mu_demangle_run(22);
	mu_demangle_run(23);
	mu_demangle_run(24);
	mu_demangle_run(25);
	mu_demangle_run(26);
	mu_demangle_run(27);
	return tests_passed != tests_run;
}

mu_main(all_tests)
