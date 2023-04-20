// SPDX-FileCopyrightText: 2022-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"

mu_demangle_tests(pascal,
	mu_demangle_test("OUTPUT_$$_SQUARE$SMALLINT$$SMALLINT", "unit output square(smallint)smallint"),
	mu_demangle_test("OUTPUT_$$_init", "unit output init()"),
	mu_demangle_test("OUTPUT$_$MYOBJECT_$__$$_INIT$$QWORDBOOL", "unit output myobject.init()qwordbool"),
	mu_demangle_test("OUTPUT$_$MYOBJECT_$__$$_MYMETHOD", "unit output myobject.mymethod()"),
	mu_demangle_test("OUTPUT_$$_MYFUNC$$POINTER", "unit output myfunc()pointer"),
	mu_demangle_test("OUTPUT_$$_MYPROCEDURE$SMALLINT$LONGINT$PCHAR", "unit output myprocedure(smallint,longint,pchar)"),
	mu_demangle_test("OUTPUT_$$_MYFUNC2$SMALLINT$LONGINT$PCHAR$$POINTER", "unit output myfunc2(smallint,longint,pchar)pointer"),
	mu_demangle_test("OUTPUT_$$_MYFUN3$SMALLINT", "unit output myfun3(smallint)"),
	mu_demangle_test("OUTPUT_SQUARE$SMALLINT$$SMALLINT", "output_square(smallint)smallint"),
	mu_demangle_test("OUTPUT_INIT$$SMALLINT", "output_init()smallint"),
	mu_demangle_test("OUTPUT_INIT$SMALLINT", "output_init(smallint)"),
	mu_demangle_test("CRT$_$ATTR2ANSI$LONGINT$LONGINT$$SHORTSTRING_$$_ADDSEP$CHAR", "unit crt attr2ansi(longint,longint)shortstring::addsep(char)"),
	mu_demangle_test("SYSTEM$_$STR_REAL$crcEDBAA446_$$_U128_DIV_U64_TO_U64$QWORD$QWORD$QWORD$QWORD$QWORD$$BOOLEAN", "unit system str_real(crcedbaa446_)::u128_div_u64_to_u64(qword,qword,qword,qword,qword)boolean"),
	mu_demangle_test("TC_$SYSTEM$_$FPOWER10$EXTENDED$LONGINT$$EXTENDED_$$_POW512", "unit tc.system fpower10(extended,longint)extended::pow512()"),
	mu_demangle_test("RTTI_$BASEUNIX_$$_DIRENT", "unit rtti.baseunix dirent()"),
	mu_demangle_test("VTBL_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN", "unit vtbl.system tcontainedobject_(_iunknown)"),
	mu_demangle_test("VTBL_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN", "unit vtbl.system tinterfacedobject_(_iunknown)"),
	mu_demangle_test("WRPR_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN_$_0_$_SYSTEM$_$TCONTAINEDOBJECT_$__$$_QUERYINTERFACE$TGUID$formal$$LONGINT", "unit wrpr.system.tcontainedobject.iunknown.0.system tcontainedobject.queryinterface(tguid,formal)longint"),
	mu_demangle_test("WRPR_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN_$_1_$_SYSTEM$_$TAGGREGATEDOBJECT_$__$$__ADDREF$$LONGINT", "unit wrpr.system.tcontainedobject.iunknown.1.system taggregatedobject._addref()longint"),
	mu_demangle_test("WRPR_$SYSTEM_$$_TCONTAINEDOBJECT_$_IUNKNOWN_$_2_$_SYSTEM$_$TAGGREGATEDOBJECT_$__$$__RELEASE$$LONGINT", "unit wrpr.system.tcontainedobject.iunknown.2.system taggregatedobject._release()longint"),
	mu_demangle_test("WRPR_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN_$_0_$_SYSTEM$_$TINTERFACEDOBJECT_$__$$_QUERYINTERFACE$TGUID$formal$$LONGINT", "unit wrpr.system.tinterfacedobject.iunknown.0.system tinterfacedobject.queryinterface(tguid,formal)longint"),
	mu_demangle_test("WRPR_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN_$_1_$_SYSTEM$_$TINTERFACEDOBJECT_$__$$__ADDREF$$LONGINT", "unit wrpr.system.tinterfacedobject.iunknown.1.system tinterfacedobject._addref()longint"),
	mu_demangle_test("WRPR_$SYSTEM_$$_TINTERFACEDOBJECT_$_IUNKNOWN_$_2_$_SYSTEM$_$TINTERFACEDOBJECT_$__$$__RELEASE$$LONGINT", "unit wrpr.system.tinterfacedobject.iunknown.2.system tinterfacedobject._release()longint"),
	// end
);

mu_main2(pascal);