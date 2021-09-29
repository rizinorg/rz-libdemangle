// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

bool demangle(void) {
	mu_demangle(swift, "__TFV4main7Balanceg5widthSd", "main.Balance.width.getter__Double");
	mu_demangle(swift, "__TFV4main7Balances5widthSd", "main.Balance.width.setter__Double");
	mu_demangle(swift, "__TFV4main7Balancem5widthSd", "main.Balance.width.method__Double");
	mu_demangle(swift, "__TFV4main7Balanceg6heightSd", "main.Balance.height.getter__Double");
	mu_demangle(swift, "__TFV4main7Balances6heightSd", "main.Balance.height.setter__Double");
	mu_demangle(swift, "__TFV4main7Balancem6heightSd", "main.Balance.height.method__Double");
	mu_demangle(swift, "__TFV4main7Balanceg3posSd", "main.Balance.pos.getter__Double");
	mu_demangle(swift, "__TFV4main7Balances3posSd", "main.Balance.pos.setter__Double");
	mu_demangle(swift, "__TFV4main7Balancem3posSd", "main.Balance.pos.method__Double");
	mu_demangle(swift, "__TFV4main7BalanceCfT5widthSd6heightSd3posSd_S0_", "main.Balance.allocator");
	mu_demangle(swift, "__TFV4main7BalanceCfT_S0_", "main.Balance.allocator");
	mu_demangle(swift, "__TFC4main8FooClasscfT_S0_", "main.FooClass.constructor");
	mu_demangle(swift, "__TFC4main8FooClassCfT_S0_", "main.FooClass.allocator");
	mu_demangle(swift, "__TFC4main8FooClass8sayHellofT_T_", "main.FooClass.sayHello");
	mu_demangle(swift, "__TFC4main8FooClassD", "main.FooClass.deallocator");
	mu_demangle(swift, "__TFC4main8FooClassd", "main.FooClass.destructor");
	mu_demangle(swift, "__TFC4main8FooClassg3fooSi", "main.FooClass.foo.getter__Swift.Int");
	mu_demangle(swift, "__TFC4main8FooClasss3fooSi", "main.FooClass.foo.setter__Swift.Int");
	mu_demangle(swift, "__TFC4main8FooClassm3fooSi", "main.FooClass.foo.method__Swift.Int");
	mu_demangle(swift, "__TFC4main8FooClassg3barSS", "main.FooClass.bar.getter__String");
	mu_demangle(swift, "__TFC4main8FooClasss3barSS", "main.FooClass.bar.setter__String");
	mu_demangle(swift, "__TFC4main8FooClassm3barSS", "main.FooClass.bar.method__String");
	mu_demangle(swift, "__TTWC4main8FooClassS_9FoodClassS_FS1_8sayHellofT_T_", "main.FooClass..FoodClass(String _)");
	mu_demangle(swift, "__TFe4mainRxCS_8FooClassxS_9FoodClassrS1_8sayHellofT_T_", "main..FooClass..FoodClass..sayHello..extension");
	mu_demangle(swift, "__TWaC4main8FooClassS_9FoodClassS_", "main.FooClass..FoodClass..protocol");
	mu_demangle(swift, "__TMfV4main7Balance", "main.Balance..metadata");
	mu_demangle(swift, "__TMfC4main8FooClass", "main.FooClass..metadata");
	mu_demangle(swift, "__TMfC4main8BarClass", "main.BarClass..metadata");
	mu_demangle(swift, "__TMfC4main4Tost", "main.Tost..metadata");
	mu_demangle(swift, "__TF4main4moinFT_Si", "main.moin () -> Swift.Int");
	mu_demangle(swift, "__TFC4main4TostCfT_S0_", "main.Tost.allocator");
	mu_demangle(swift, "__TFC4main4TostD", "main.Tost.deallocator");
	mu_demangle(swift, "__TFC4main4TostcfT_S0_", "main.Tost.constructor");
	mu_demangle(swift, "__TFC4main4Tostd", "main.Tost.destructor");
	mu_demangle(swift, "__TFC4main4Tostg3msgSS", "main.Tost.msg.getter__String");
	mu_demangle(swift, "__TFC4main4Tostm3msgSS", "main.Tost.msg.method__String");
	mu_demangle(swift, "__TFC4main4Tosts3msgSS", "main.Tost.msg.setter__String");
	mu_demangle(swift, "__TFC4main8BarClass8sayHellofT_T_", "main.BarClass.sayHello");
	mu_demangle(swift, "__TFC4main8BarClassCfT_S0_", "main.BarClass.allocator");
	mu_demangle(swift, "__TFC4main8BarClassD", "main.BarClass.deallocator");
	mu_demangle(swift, "__TFC4main8BarClasscfT_S0_", "main.BarClass.constructor");
	mu_demangle(swift, "__TFC4main8BarClassd", "main.BarClass.destructor");
	mu_demangle(swift, "__TMC4main4Tost", "main.Tost..metadata");
	mu_demangle(swift, "__TMC4main8BarClass", "main.BarClass..metadata");
	mu_demangle(swift, "__TMC4main8FooClass", "main.FooClass..metadata");
	mu_demangle(swift, "__TMLC4main4Tost", "main.Tost..lazy.metadata");
	mu_demangle(swift, "__TMLC4main8BarClass", "main.BarClass..lazy.metadata");
	mu_demangle(swift, "__TMLC4main8FooClass", "main.FooClass..lazy.metadata");
	mu_demangle(swift, "__TMV4main7Balance", "main.Balance..metadata");
	mu_demangle(swift, "__TMaC4main4Tost", "main.Tost..accessor.metadata");
	mu_demangle(swift, "__TMaC4main8BarClass", "main.BarClass..accessor.metadata");
	mu_demangle(swift, "__TMaC4main8FooClass", "main.FooClass..accessor.metadata");
	mu_demangle(swift, "__TMaV4main7Balance", "main.Balance..accessor.metadata");
	mu_demangle(swift, "__TMmC4main4Tost", "main.Tost..metaclass");
	mu_demangle(swift, "__TMmC4main8BarClass", "main.BarClass..metaclass");
	mu_demangle(swift, "__TMmC4main8FooClass", "main.FooClass..metaclass");
	mu_demangle(swift, "__TMnC4main4Tost", "main.Tost..metadata");
	mu_demangle(swift, "__TMnC4main8BarClass", "main.BarClass..metadata");
	mu_demangle(swift, "__TMnC4main8FooClass", "main.FooClass..metadata");
	mu_demangle(swift, "__TMnV4main7Balance", "main.Balance..metadata");
	mu_demangle(swift, "__TMp4main9FoodClass", "main.FoodClass..metadata");
	mu_demangle(swift, "__TWVV4main7Balance", "main.Balance");
	mu_demangle(swift, "__TWoFC4main4TostCfT_S0_", "Tost.allocator..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main4Tostg3msgSS", "Tost.msg.getter__String..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main4Tostm3msgSS", "Tost.msg.method__String..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main4Tosts3msgSS", "Tost.msg.setter__String..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8BarClass8sayHellofT_T_", "BarClass.sayHello..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8BarClassCfT_S0_", "BarClass.allocator..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClass8sayHellofT_T_", "FooClass.sayHello..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClassCfT_S0_", "FooClass.allocator..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClassg3barSS", "FooClass.bar.getter__String..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClassg3fooSi", "FooClass.foo.getter__Swift.Int..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClassm3barSS", "FooClass.bar.method__String..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClassm3fooSi", "FooClass.foo.method__Swift.Int..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClasss3barSS", "FooClass.bar.setter__String..init.witnesstable");
	mu_demangle(swift, "__TWoFC4main8FooClasss3fooSi", "FooClass.foo.setter__Swift.Int..init.witnesstable");
	mu_demangle(swift, "__TWvdvC4main4Tost3msgSS", "main.Tost.msg__String..field");
	mu_demangle(swift, "__TWvdvC4main8FooClass3barSS", "main.FooClass.bar__String..field");
	mu_demangle(swift, "__TWvdvC4main8FooClass3fooSi", "main.FooClass.foo..field");
	mu_demangle(swift, "__TMSS", "Swift.String.init (..metadata");
	mu_demangle(swift, "__TZvOs7Process11_unsafeArgvGSpGSpVs4Int8__", "Process._unsafeArgv");
	mu_demangle(swift, "__TZvOs7Process5_argcVs5Int32", "Process._argc");
	mu_end;
}

bool broken(void) {
	// these tests are broken because the demangler is demangling symbols in the wrong way
	mu_demangle(swift, "_TFSSCfT21_builtinStringLiteralBp8byteSizeBw7isASCIIBi1__SS", "Swift.String.init (_builtinStringLiteral(Builtin.RawPointer byteSize__Builtin.Word isASCII__Builtin.Int1 _) -> String");
	mu_ignore;
}

int all_tests() {
	mu_run_test(demangle);
	mu_run_test(broken);
	return tests_passed != tests_run;
}

mu_main(all_tests)
