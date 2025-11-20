// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"

mu_demangle_tests(gpl,
	// <builtin-type> ::= v	# void
	//                ::= w	# wchar_t
	//                ::= b	# bool
	//                ::= c	# char
	//                ::= a	# signed char
	//                ::= h	# unsigned char
	//                ::= s	# short
	//                ::= t	# unsigned short
	//                ::= i	# int
	//                ::= j	# unsigned int
	//                ::= l	# long
	//                ::= m	# unsigned long
	//                ::= x	# long long, __int64
	//                ::= y	# unsigned long long, __int64
	//                ::= n	# __int128
	//                ::= o	# unsigned __int128
	//                ::= f	# float
	//                ::= d	# double
	//                ::= e	# long double, __float80
	//                ::= g	# __float128
	//                ::= z	# ellipsis
	//                ::= Dd # IEEE 754r decimal floating point (64 bits)
	//                ::= De # IEEE 754r decimal floating point (128 bits)
	//                ::= Df # IEEE 754r decimal floating point (32 bits)
	//                ::= Dh # IEEE 754r half-precision floating point (16 bits)
	//                ::= DF <number> _ # ISO/IEC TS 18661 binary floating point type _FloatN (N bits), C++23 std::floatN_t
	//                ::= DF <number> x # IEEE extended precision formats, C23 _FloatNx (N bits)
	//                ::= DF16b # C++23 std::bfloat16_t
	//                ::= DB <number> _        # C23 signed _BitInt(N)
	//                ::= DB <instantiation-dependent expression> _ # C23 signed _BitInt(N)
	//                ::= DU <number> _        # C23 unsigned _BitInt(N)
	//                ::= DU <instantiation-dependent expression> _ # C23 unsigned _BitInt(N)
	//                ::= Di # char32_t
	//                ::= Ds # char16_t
	//                ::= Du # char8_t
	//                ::= Da # auto
	//                ::= Dc # decltype(auto)
	//                ::= Dn # std::nullptr_t (i.e., decltype(nullptr))
	//                ::= [DS] DA  # N1169 fixed-point [_Sat] T _Accum
	//                ::= [DS] DR  # N1169 fixed-point [_Sat] T _Fract
	//                ::= u <source-name> [<template-args>] # vendor extended type

	mu_demangle_test("_ZTSv", "typeinfo name for void"),
	mu_demangle_test("_ZTSw", "typeinfo name for wchar_t"),
	mu_demangle_test("_ZTSb", "typeinfo name for bool"),
	mu_demangle_test("_ZTSc", "typeinfo name for char"),
	mu_demangle_test("_ZTSa", "typeinfo name for signed char"),
	mu_demangle_test("_ZTSh", "typeinfo name for unsigned char"),
	mu_demangle_test("_ZTSs", "typeinfo name for short"),
	mu_demangle_test("_ZTSt", "typeinfo name for unsigned short"),
	mu_demangle_test("_ZTSi", "typeinfo name for int"),
	mu_demangle_test("_ZTSj", "typeinfo name for unsigned int"),
	mu_demangle_test("_ZTSl", "typeinfo name for long"),
	mu_demangle_test("_ZTSm", "typeinfo name for unsigned long"),
	mu_demangle_test("_ZTSx", "typeinfo name for long long"),
	mu_demangle_test("_ZTSy", "typeinfo name for unsigned long long"),
	mu_demangle_test("_ZTSn", "typeinfo name for __int128"),
	mu_demangle_test("_ZTSo", "typeinfo name for unsigned __int128"),
	mu_demangle_test("_ZTSf", "typeinfo name for float"),
	mu_demangle_test("_ZTSd", "typeinfo name for double"),
	mu_demangle_test("_ZTSe", "typeinfo name for long double"),
	mu_demangle_test("_ZTSg", "typeinfo name for __float128"),
	// mu_demangle_test("_ZTSz", "typeinfo name for ellipsis"),
	mu_demangle_test("_ZTSDi", "typeinfo name for char32_t"),
	mu_demangle_test("_ZTSDs", "typeinfo name for char16_t"),
	mu_demangle_test("_ZTSDu", "typeinfo name for char8_t"),
	mu_demangle_test("_ZTSDa", "typeinfo name for auto"),
	mu_demangle_test("_ZTSDc", "typeinfo name for decltype(auto)"),
	mu_demangle_test("_ZTSDn", "typeinfo name for std::nullptr_t"),

	// <qualified-type>     ::= <qualifiers> <type>
	//
	// <qualifiers>         ::= <extended-qualifier>* <CV-qualifiers>
	// <extended-qualifier> ::= U <source-name> [<template-args>] # vendor extended type qualifier
	// <CV-qualifiers>      ::= [r] [V] [K] 	  # restrict (C99), volatile, const
	mu_demangle_test("_ZTSrv", "typeinfo name for void restrict"),
	mu_demangle_test("_ZTSVv", "typeinfo name for void volatile"),
	mu_demangle_test("_ZTSKv", "typeinfo name for void const"),
	mu_demangle_test("_ZTSrVKv", "typeinfo name for void const volatile restrict"),
	mu_demangle_test("_ZTSU4_farrVKPi", "typeinfo name for int* const volatile restrict _far"),

	//
);

mu_main(gpl, cxx, RZ_DEMANGLE_OPT_ENABLE_ALL);
