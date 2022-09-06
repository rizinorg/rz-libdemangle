// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

mu_demangle(0, pascal, "OUTPUT_$$_SQUARE$SMALLINT$$SMALLINT", "unit output square(smallint)smallint");
mu_demangle(1, pascal, "OUTPUT_$$_init", "unit output init()");
mu_demangle(2, pascal, "OUTPUT$_$MYOBJECT_$__$$_INIT$$QWORDBOOL", "unit output myobject.init()qwordbool");
mu_demangle(3, pascal, "OUTPUT$_$MYOBJECT_$__$$_MYMETHOD", "unit output myobject.mymethod()");
mu_demangle(4, pascal, "OUTPUT_$$_MYFUNC$$POINTER", "unit output myfunc()pointer");
mu_demangle(5, pascal, "OUTPUT_$$_MYPROCEDURE$SMALLINT$LONGINT$PCHAR", "unit output myprocedure(smallint,longint,pchar)");
mu_demangle(6, pascal, "OUTPUT_$$_MYFUNC2$SMALLINT$LONGINT$PCHAR$$POINTER", "unit output myfunc2(smallint,longint,pchar)pointer");
mu_demangle(7, pascal, "OUTPUT_$$_MYFUN3$SMALLINT", "unit output myfun3(smallint)");
mu_demangle(8, pascal, "OUTPUT_SQUARE$SMALLINT$$SMALLINT", "output_square(smallint)smallint");
mu_demangle(9, pascal, "OUTPUT_INIT$$SMALLINT", "output_init()smallint");
mu_demangle(10, pascal, "OUTPUT_INIT$SMALLINT", "output_init(smallint)");
mu_demangle(11, pascal, "CRT$_$ATTR2ANSI$LONGINT$LONGINT$$SHORTSTRING_$$_ADDSEP$CHAR", "unit crt attr2ansi(longint,longint)shortstring::addsep(char)");
mu_demangle(12, pascal, "SYSTEM$_$STR_REAL$crcEDBAA446_$$_U128_DIV_U64_TO_U64$QWORD$QWORD$QWORD$QWORD$QWORD$$BOOLEAN", "unit system str_real(crcedbaa446_)::u128_div_u64_to_u64(qword,qword,qword,qword,qword)boolean");
mu_demangle(13, pascal, "TC_$SYSTEM$_$FPOWER10$EXTENDED$LONGINT$$EXTENDED_$$_POW512", "unit tc.system fpower10(extended,longint)extended::pow512()");
mu_demangle(14, pascal, "RTTI_$BASEUNIX_$$_DIRENT", "unit rtti.baseunix dirent()");
mu_demangle(15, pascal, "VTBL_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN", "unit vtbl.system tcontainedobject_(_iunknown)");
mu_demangle(16, pascal, "VTBL_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN", "unit vtbl.system tinterfacedobject_(_iunknown)");
mu_demangle(17, pascal, "WRPR_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN_$_0_$_SYSTEM$_$TCONTAINEDOBJECT_$__$$_QUERYINTERFACE$TGUID$formal$$LONGINT", "unit wrpr.system.tcontainedobject.iunknown.0.system tcontainedobject.queryinterface(tguid,formal)longint");
mu_demangle(18, pascal, "WRPR_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN_$_1_$_SYSTEM$_$TAGGREGATEDOBJECT_$__$$__ADDREF$$LONGINT", "unit wrpr.system.tcontainedobject.iunknown.1.system taggregatedobject._addref()longint");
mu_demangle(19, pascal, "WRPR_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN_$_2_$_SYSTEM$_$TAGGREGATEDOBJECT_$__$$__RELEASE$$LONGINT", "unit wrpr.system.tcontainedobject.iunknown.2.system taggregatedobject._release()longint");
mu_demangle(20, pascal, "WRPR_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN_$_0_$_SYSTEM$_$TINTERFACEDOBJECT_$__$$_QUERYINTERFACE$TGUID$formal$$LONGINT", "unit wrpr.system.tinterfacedobject.iunknown.0.system tinterfacedobject.queryinterface(tguid,formal)longint");
mu_demangle(21, pascal, "WRPR_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN_$_1_$_SYSTEM$_$TINTERFACEDOBJECT_$__$$__ADDREF$$LONGINT", "unit wrpr.system.tinterfacedobject.iunknown.1.system tinterfacedobject._addref()longint");
mu_demangle(22, pascal, "WRPR_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN_$_2_$_SYSTEM$_$TINTERFACEDOBJECT_$__$$__RELEASE$$LONGINT", "unit wrpr.system.tinterfacedobject.iunknown.2.system tinterfacedobject._release()longint");

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
	return tests_passed != tests_run;
}

mu_main(all_tests)
