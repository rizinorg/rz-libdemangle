// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"

mu_demangle_tests(rust,
	mu_demangle_test("_ZN5alloc3oom3oom17h722648b727b8bcd0E", "alloc::oom::oom::h722648b727b8bcd0"),
	mu_demangle_test("__ZN4core3fmt5Write10write_char17hcc5144a9a84f2b15E", "core::fmt::Write::write_char::hcc5144a9a84f2b15"),
	mu_demangle_test("ZN14rustc_demangle6legacy8demangleE", "rustc_demangle::legacy::demangle"),
	mu_demangle_test("_ZN4toolongE", NULL),
	mu_demangle_test("___ZNwrong_formatE", NULL),
	mu_demangle_test("_ZN10no_e_found", NULL),
	mu_demangle_test("_ZN7onlyone", NULL),
	mu_demangle_test("_ZN4$RP$E", ")"),
	mu_demangle_test("_ZN8$RF$testE", "&test"),
	mu_demangle_test("_ZN8$BP$test4foobE", "*test::foob"),
	mu_demangle_test("_ZN9$u20$test4foobE", " test::foob"),
	mu_demangle_test("_ZN35Bar$LT$$u5b$u32$u3b$$u20$4$u5d$$GT$E", "Bar<[u32; 4]>"),
	mu_demangle_test("_ZN13test$u20$test4foobE", "test test::foob"),
	mu_demangle_test("_ZN12test$BP$test4foobE", "test*test::foob"),
	mu_demangle_test("__ZN5alloc9allocator6Layout9for_value17h02a996811f781011E", "alloc::allocator::Layout::for_value::h02a996811f781011"),
	mu_demangle_test("__ZN38_$LT$core..option..Option$LT$T$GT$$GT$6unwrap18_MSG_FILE_LINE_COL17haf7cb8d5824ee659E", "<core::option::Option<T>>::unwrap::_MSG_FILE_LINE_COL::haf7cb8d5824ee659"),
	mu_demangle_test("__ZN4core5slice89_$LT$impl$u20$core..iter..traits..IntoIterator$u20$for$u20$$RF$$u27$a$u20$$u5b$T$u5d$$GT$9into_iter17h450e234d27262170E", "core::slice::<impl core::iter::traits::IntoIterator for &'a [T]>::into_iter::h450e234d27262170"),
	mu_demangle_test("ZN4testE", "test"),
	mu_demangle_test("ZN13test$u20$test4foobE", "test test::foob"),
	mu_demangle_test("ZN12test$RF$test4foobE", "test&test::foob"),
	mu_demangle_test("_ZN13_$LT$test$GT$E", "<test>"),
	mu_demangle_test("_ZN28_$u7b$$u7b$closure$u7d$$u7d$E", "{{closure}}"),
	mu_demangle_test("_ZN15__STATIC_FMTSTRE", "__STATIC_FMTSTR"),
	mu_demangle_test("_ZN71_$LT$Test$u20$$u2b$$u20$$u27$static$u20$as$u20$foo..Bar$LT$Test$GT$$GT$3barE", "<Test + 'static as foo::Bar<Test>>::bar"),
	mu_demangle_test("_ZN3foo17h05af221e174051e9E", "foo::h05af221e174051e9"),
	mu_demangle_test("_ZN3fooE", "foo"),
	mu_demangle_test("_ZN3foo3barE", "foo::bar"),
	mu_demangle_test("_ZN3foo20h05af221e174051e9abcE", "foo::h05af221e174051e9abc"),
	mu_demangle_test("_ZN3foo5h05afE", "foo::h05af"),
	mu_demangle_test("_ZN17h05af221e174051e93fooE", "h05af221e174051e9::foo"),
	mu_demangle_test("_ZN3foo16ffaf221e174051e9E", "foo::ffaf221e174051e9"),
	mu_demangle_test("_ZN3foo17hg5af221e174051e9E", "foo::hg5af221e174051e9"),
	mu_demangle_test("_ZN3fooE.llvm.9D1C9369", "foo"),
	mu_demangle_test("_ZN3fooE.llvm.9D1C9369@@16", "foo"),
	mu_demangle_test("_ZN9backtrace3foo17hbb467fcdaea5d79bE.llvm.A5310EB9", "backtrace::foo::hbb467fcdaea5d79b"),
	mu_demangle_test("_ZN4core5slice77_$LT$impl$u20$core..ops..index..IndexMut$LT$I$GT$$u20$for$u20$$u5b$T$u5d$$GT$9index_mut17haf9727c2edfbc47bE.exit.i.i", "core::slice::<impl core::ops::index::IndexMut<I> for [T]>::index_mut::haf9727c2edfbc47b.exit.i.i"),
	mu_demangle_test("_ZN3fooE.llvm moocow", NULL),
	mu_demangle_test("_ZN2222222222222222222222EE", NULL),
	mu_demangle_test("_ZN5*70527e27.ll34csaғE", NULL),
	mu_demangle_test("_ZN5*70527a54.ll34_$b.1E", NULL),
	mu_demangle_test("\
        _ZN5~saäb4e\n\
        2734cOsbE\n\
        5usage20h)3\0\0\0\0\0\0\07e2734cOsbE\
        ",
		NULL),
	mu_demangle_test("_ZNfooE", NULL),
	mu_demangle_test("_ZN151_$LT$alloc..boxed..Box$LT$alloc..boxed..FnBox$LT$A$C$$u20$Output$u3d$R$GT$$u20$$u2b$$u20$$u27$a$GT$$u20$as$u20$core..ops..function..FnOnce$LT$A$GT$$GT$9call_once17h69e8f44b3723e1caE", "<alloc::boxed::Box<alloc::boxed::FnBox<A, Output=R> + 'a> as core::ops::function::FnOnce<A>>::call_once::h69e8f44b3723e1ca"),
	mu_demangle_test("_ZN88_$LT$core..result..Result$LT$$u21$$C$$u20$E$GT$$u20$as$u20$std..process..Termination$GT$6report17hfc41d0da4a40b3e8E", "<core::result::Result<!, E> as std::process::Termination>::report::hfc41d0da4a40b3e8"),
	mu_demangle_test("_ZN11utf8_idents157_$u10e1$$u10d0$$u10ed$$u10db$$u10d4$$u10da$$u10d0$$u10d3$_$u10d2$$u10d4$$u10db$$u10e0$$u10d8$$u10d4$$u10da$$u10d8$_$u10e1$$u10d0$$u10d3$$u10d8$$u10da$$u10d8$17h21634fd5714000aaE", "utf8_idents::საჭმელად_გემრიელი_სადილი::h21634fd5714000aa"),
	mu_demangle_test("_ZN11issue_609253foo37Foo$LT$issue_60925..llv$u6d$..Foo$GT$3foo17h059a991a004536adE", "issue_60925::foo::Foo<issue_60925::llvm::Foo>::foo::h059a991a004536ad"),
	// end
);

mu_main2(rust);