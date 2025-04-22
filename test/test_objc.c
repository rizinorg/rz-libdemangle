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
	mu_demangle_test("-[LoaderDelegate setEnable:]_block_invoke", "public int LoaderDelegate::setEnable(int) block_invoke"),
	mu_demangle_test("-[LoaderDelegate setEnable:]_block_invoke_29", "public int LoaderDelegate::setEnable(int) block_invoke_29"),
	mu_demangle_test("___32+[XPCAgentServer sharedInstance]_block_invoke", "static int XPCAgentServer::sharedInstance() block_invoke"),
	mu_demangle_test("___53-[XPCAgentServer listener:shouldAcceptNewConnection:]_block_invoke", "public int XPCAgentServer::listener(int, int) block_invoke"),
	mu_demangle_test("___53-[XPCAgentServer listener:shouldAcceptNewConnection:]_block_invoke.46", "public int XPCAgentServer::listener(int, int) block_invoke.46"),
	mu_demangle_test("___55-[XPCAgentServer notifyUser:noticeId:notificationType:]_block_invoke", "public int XPCAgentServer::notifyUser(int, int, int) block_invoke"),
	mu_demangle_test("___59-[XPCAgentServer activateUniversalAccessAuthWarn:interval:]_block_invoke", "public int XPCAgentServer::activateUniversalAccessAuthWarn(int, int) block_invoke"),
	mu_demangle_test("_27-[XPCAgentServer launchApp]_block_invoke", "public int XPCAgentServer::launchApp() block_invoke"),
	mu_demangle_test("__27-[XPCAgentServer launchApp]_block_invoke.118", "public int XPCAgentServer::launchApp() block_invoke.118"),
	mu_demangle_test("___25-[XPCAgentServer restart]_block_invoke", "public int XPCAgentServer::restart() block_invoke"),
	mu_demangle_test("_", NULL),
	mu_demangle_test("_25", NULL),
	mu_demangle_test("__25-", NULL),
	mu_demangle_test("___25", NULL),
	mu_demangle_test("___25-", NULL),
	mu_demangle_test("___25-[", NULL),
/*#if WITH_GPL*/
/*	mu_demangle_test("_Z11GetFileNamePc", "GetFileName(char*)"),*/
/*#else*/
/*	mu_demangle_test("_Z11GetFileNamePc", NULL),*/
/*#endif*/
	// end
);

mu_main2(objc);
