// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"

mu_demangle_tests(gpl,

	mu_demangle_test("_Z1fB3fooB3barv", "f[abi:foo][abi:bar]()"),
	mu_demangle_test("_ZN1SB5outer1fB5innerEv", "S[abi:outer]::f[abi:inner]()"),
	mu_demangle_test("_ZN1SC2B8ctor_tagEv", "S::S[abi:ctor_tag]()"),
	mu_demangle_test("_ZplB4MERP1SS_", "operator+[abi:MERP](S, S)"),
	mu_demangle_test("_Z1fIJifcEEvDp5unaryIT_E", "void f<int, float, char>(unary<int>, unary<float>, unary<char>)"),
	mu_demangle_test("_Z1fIJicEEvDp7MuncherIAstT__S1_E", "void f<int, char>(Muncher<int [sizeof (int)]>, Muncher<char [sizeof (char)]>)"),
	mu_demangle_test("_ZN1SIJifcEE1fIJdjEEEiDp4MerpIJifcT_EE", "int S<int, float, char>::f<double, unsigned int>(Merp<int, float, char, double>, Merp<int, float, char, unsigned int>)"),
	// Some expression symbols found in clang's test/CodeGenCXX/mangle-exprs.cpp
	mu_demangle_test("_ZN5Casts1fILi6EEENS_1TIXT_EEEv", "Casts::T<6> Casts::f<6>()"),
	// Multiple qualifiers on the same type should all get the same entry in the substitution table.
	// String literals
	// FIXME: We need to encode the string contents in order to avoid symbol collisions.
	// Initializer list expressions
	// Designated init expressions
	// Inheriting constructors:
	// Exception specifiers:
	mu_demangle_test("_Z1bPDoFivE", "b(int (*)() noexcept)"),
	mu_demangle_test("_Z1fILb0EEvPDOT_EFivE", "void f<false>(int (*)() noexcept(false))"),
	mu_demangle_test("_Z1fILb1EEvPDOT_EFivE", "void f<true>(int (*)() noexcept(true))"),
	mu_demangle_test("_Z1gIJEEvPDwDpT_EFivE", "void g<>(int (*)() throw())"),
	mu_demangle_test("_Z1gIJfEEvPDwDpT_EFivE", "void g<float>(int (*)() throw(float))"),
	mu_demangle_test("_Z1hIJfEEPDwDpT_iEFivEPDwiS1_EFivE", "int (*h<float>(int (*)() throw(int, float)))() throw(float, int)"),
	mu_demangle_test("_Z1iIJEEPDwiDpT_EFivEPS2_", "int (*i<>(int (*)() throw(int)))() throw(int)"),
	mu_demangle_test("_Z1iIJEEPDwiDpT_EFivES3_", "int (*i<>(int (*)() throw(int)))() throw(int)"),
	mu_demangle_test("_Z1iIJfEEPDwiDpT_EFivEPS2_", "int (*i<float>(int (*)() throw(int, float)))() throw(int, float)"),
	mu_demangle_test("_Z1iIJfEEPDwiDpT_EFivES3_", "int (*i<float>(int (*)() throw(int, float)))() throw(int, float)"),
	mu_demangle_test("_Z1pM1SDoFivE", "p(int (S::*)() noexcept)"),
	mu_demangle_test("_ZNKR4llvm8OptionalINS_11MCFixupKindEEdeEv", "llvm::Optional<llvm::MCFixupKind>::operator*() const &"),
	mu_demangle_test("_ZZL23isValidCoroutineContextRN5clang4SemaENS_14SourceLocationEN4llvm9StringRefEENK3$_4clEZL23isValidCoroutineContextS1_S2_S4_E15InvalidFuncDiag", "isValidCoroutineContext(clang::Sema&, clang::SourceLocation, llvm::StringRef)::$_4::operator()(isValidCoroutineContext(clang::Sema&, clang::SourceLocation, llvm::StringRef)::InvalidFuncDiag) const"),
	// ABI tags can apply to built-in substitutions.
	mu_demangle_test("_Z1fSsB1XS_", "f(std::string[abi:X], std::string[abi:X])"),
	// Structured bindings:
	mu_demangle_test("_ZDC2a12a2E", "[a1, a2]"),
	mu_demangle_test("_ZN2NSDC1x1yEE", "NS::[x, y]"),
	// enable_if attributes:
	// Conversion operators:
	mu_demangle_test("_ZN5OuterI4MarpEcvT_I4MerpEEv", "Outer<Marp>::operator Merp<Merp>()"),
	// C++1z fold expressions:
	// reference collapsing:
	mu_demangle_test("_Z1fIR1SEiOT_", "int f<S&>(S&)"),
	mu_demangle_test("_Z1fIJR1SS0_EEiDpOT_", "int f<S&, S>(S&, S&&)"),
	// Darwin adds leading underscores to symbols, just demangle them anyways.
	mu_demangle_test("__Z1fv", "f()"),
	// Vendor extension types are substitution candidates.
	mu_demangle_test("_Z1fu3fooS_", "f(foo, foo)"),
	// alignof with type and expression, and __alignof__ with the same.
	// Legacy nonstandard mangling for __uuidof.
	// Current __uuidof mangling using vendor extended expression.
	// C++20 char8_t:
	mu_demangle_test("_ZTSPDu", "typeinfo name for char8_t*"),
	// C++20 lambda-expressions:
	// FIXME: Consider special-casing the call operator of a lambda and
	// producing something like
	//   "auto inline_func()::'lambda'<int, int>(int, int) const"
	// FIXME: This is wrong, should demangle to the same as the previous entry.
	// See https://github.com/itanium-cxx-abi/cxx-abi/issues/106.
	// See https://github.com/itanium-cxx-abi/cxx-abi/issues/165.
	// C++20 class type non-type template parameters:
	mu_demangle_test("_Z1fIXtl1BLPi0ELi1EEEEvv", "void f<B{(int*)0, 1}>()"),
	mu_demangle_test("_Z1fIXtl1BLPi32EEEEvv", "void f<B{(int*)32}>()"),
	mu_demangle_test("_Z1fIXtl1BrcPiLi0EEEEvv", "void f<B{reinterpret_cast<int*>(0)}>()"),
	mu_demangle_test("_Z1fIXtl1DLM7DerivedKi0ELi1EEEEvv", "void f<D{(int const Derived::*)0, 1}>()"),
	// FIXME: This is not valid pointer-to-member syntax.
	mu_demangle_test("_ZTAXtl1StlA32_cLc104ELc101ELc108ELc108ELc111ELc32ELc119ELc111ELc114ELc108ELc100EEEE", "template parameter object for S{char [32]{(char)104, (char)101, (char)108, (char)108, (char)111, (char)32, (char)119, (char)111, (char)114, (char)108, (char)100}}"),
	// FIXME: This is wrong; the S2_ backref should expand to OT_ and then to
	// "double&&". But we can't cope with a substitution that represents a
	// different type the node it is a substitute for.
	// See https://github.com/itanium-cxx-abi/cxx-abi/issues/106.
	mu_demangle_test("_Z1fIL4Enumn1EEvv", "void f<(Enum)-1>()"),
	// Optional template-args for vendor extended type qualifier.
	// See https://bugs.llvm.org/show_bug.cgi?id=48009.
	mu_demangle_test("_Z3fooILi79EEbU7_ExtIntIXT_EEi", "bool foo<79>(int _ExtInt<79>)"),
	// This should be invalid, but it is currently not recognized as such
	// See https://llvm.org/PR51407
	mu_demangle_test("_ZN2FnIXgs4BaseEX4BaseEEEvv", "void Fn<::Base, Base>()"),
	mu_demangle_test("_Z3TPLIiET_S0_", "int TPL<int>(int)"),
	mu_demangle_test("_ZN1XawEv", "X::operator co_await()"),
	// C++20 modules
	mu_demangle_test("_ZN5Outer5InnerW3FOO2FnERNS0_1XE", "Outer::Inner::Fn@FOO(Outer::Inner::X&)"),
	mu_demangle_test("_ZN5OuterW3FOO5Inner2FnERNS1_1XE", "Outer::Inner@FOO::Fn(Outer::Inner@FOO::X&)"),
	mu_demangle_test("_ZN4Quux4TotoW3FooW3Bar3BazEPNS0_S2_5PlughE", "Quux::Toto::Baz@Foo.Bar(Quux::Toto::Plugh@Foo.Bar*)"),
	mu_demangle_test("_ZW6Module1fNS_1a1bENS0_1cE", "f@Module(a@Module::b, a@Module::c)"),
	mu_demangle_test("_ZN3BobW3FOOW3BAR3BarEPS1_1APNS_S1_1BE", "Bob::Bar@FOO.BAR(A@FOO.BAR*, Bob::B@FOO.BAR*)"),
	mu_demangle_test("_ZW3FOOW3BAR3FooPS0_1APN3BobS0_1BE", "Foo@FOO.BAR(A@FOO.BAR*, Bob::B@FOO.BAR*)"),
	mu_demangle_test("_ZN3BobW3FOOW3BAZ3FooEPS0_W3BAR1APNS_S2_1BE", "Bob::Foo@FOO.BAZ(A@FOO.BAR*, Bob::B@FOO.BAR*)"),
	mu_demangle_test("_ZW3FOOW3BAZ3BarPS_W3BAR1APN3BobS1_1BE", "Bar@FOO.BAZ(A@FOO.BAR*, Bob::B@FOO.BAR*)"),
	mu_demangle_test("_ZNW3FOO3TPLIS_3OneE1MEPS1_", "TPL@FOO<One@FOO>::M(One@FOO*)"),
	mu_demangle_test("_ZNW3FOO3TPLIS_3OneE1NIS_3TwoEEvPS1_PT_", "void TPL@FOO<One@FOO>::N<Two@FOO>(One@FOO*, Two@FOO*)"),
	mu_demangle_test("_ZN3NMSW3FOO3TPLINS_S0_3OneEE1MEPS2_", "NMS::TPL@FOO<NMS::One@FOO>::M(NMS::One@FOO*)"),
	mu_demangle_test("_ZN3NMSW3FOO3TPLINS_S0_3OneEE1NINS_S0_3TwoEEEvPS2_PT_", "void NMS::TPL@FOO<NMS::One@FOO>::N<NMS::Two@FOO>(NMS::One@FOO*, NMS::Two@FOO*)"),
	mu_demangle_test("_ZNStW3STD9allocatorIiE1MEPi", "std::allocator@STD<int>::M(int*)"),
	mu_demangle_test("_ZNStW3STD9allocatorIiE1NIfEEPT_Pi", "float* std::allocator@STD<int>::N<float>(int*)"),
	mu_demangle_test("_ZNStW3STD9allocatorI4PoohE1MEPS1_", "std::allocator@STD<Pooh>::M(Pooh*)"),
	mu_demangle_test("_ZNStW3STD9allocatorI4PoohE1NI6PigletEEPT_PS1_", "Piglet* std::allocator@STD<Pooh>::N<Piglet>(Pooh*)"),
	mu_demangle_test("_ZW3FooDC1a1bE", "[a, b]@Foo"),
	mu_demangle_test("_ZN1NW3FooDC1a1bEE", "N::[a, b]@Foo"),
	mu_demangle_test("_ZN3NMSW3MOD3FooB3ABIEv", "NMS::Foo@MOD[abi:ABI]()"),
	mu_demangle_test("_ZGIW3Foo", "initializer for module Foo"),
	mu_demangle_test("_ZGIW3FooW3Bar", "initializer for module Foo.Bar"),
	mu_demangle_test("_ZGIW3FooWP3BarW3Baz", "initializer for module Foo:Bar.Baz"),
	mu_demangle_test("_ZW1ML4Oink", "Oink@M"),
	mu_demangle_test("_ZW1ML1fi", "f@M(int)"),
	// C++20 concepts, see https://github.com/itanium-cxx-abi/cxx-abi/issues/24.
	mu_demangle_test("_ZN5test51fINS_1XEEEvv", "void test5::f<test5::X>()"),
	mu_demangle_test("_ZN5test51gINS_1YEEEvv", "void test5::g<test5::Y>()"),
	mu_demangle_test("_ZN5test51hINS_1ZEEEvv", "void test5::h<test5::Z>()"),
	mu_demangle_test("_ZN5test51iIJNS_1ZENS_1XENS_1YEEEEvv", "void test5::i<test5::Z, test5::X, test5::Y>()"),
	mu_demangle_test("_ZN5test51pINS_1AEEEvv", "void test5::p<test5::A>()"),
	mu_demangle_test("_ZN5test51qINS_1BEEEvv", "void test5::q<test5::B>()"),
	// INCORRECT : 	mu_demangle_test("_ZN3FooIiE6methodITk4TrueIT_EiEEvS3_", "void Foo<int>::method<int>(T)"),
	// Special Substs a, b, d, i, o, s (not including std::)
	mu_demangle_test("_Z1fSaIiE", "f(std::allocator<int>)"),
	mu_demangle_test("_Z1fSbIiE", "f(std::basic_string<int>)"),
	mu_demangle_test("_Z1fSd", "f(std::iostream)"),
	mu_demangle_test("_Z1fSi", "f(std::istream)"),
	mu_demangle_test("_Z1fSo", "f(std::ostream)"),
	mu_demangle_test("_Z1fSs", "f(std::string)"),
	mu_demangle_test("_Z1fNSaIiE1gE", "f(std::allocator<int>::g)"),
	mu_demangle_test("_Z1fNSbIiE1gE", "f(std::basic_string<int>::g)"),
	mu_demangle_test("_Z1fNSd1gE", "f(std::iostream::g)"),
	mu_demangle_test("_Z1fNSi1gE", "f(std::istream::g)"),
	mu_demangle_test("_Z1fNSo1gE", "f(std::ostream::g)"),
	mu_demangle_test("_Z1fNSs1gE", "f(std::string::g)"),
	mu_demangle_test("_ZNSaIiED1Ev", "std::allocator<int>::~allocator()"),
	mu_demangle_test("_ZNSbIiED1Ev", "std::basic_string<int>::~basic_string()"),
	mu_demangle_test("_ZN1SB8ctor_tagC2Ev", "S[abi:ctor_tag]::S()"),
	mu_demangle_test("_ZN1SB8ctor_tagD2Ev", "S[abi:ctor_tag]::~S()"), );
mu_main(gpl, cxx, RZ_DEMANGLE_OPT_ENABLE_ALL);
