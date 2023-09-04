#!/bin/sh

# SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

CLI="$1"
if [ ! -f "$CLI" ]; then
    echo "$0 <path to demangle cli bin>"
    exit 1
fi

HAS_SWIFT=$("$CLI" | grep "swift")
HAS_GPL=$("$CLI" | grep "gnu v3")

# terminate on fail (!= 0)
set -e

"$CLI" 'java' 'makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;'
"$CLI" -s 'java' 'makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;'

## use borland which is always available even when gpl is disabled.
"$CLI" 'c++' '@Bar@foo9$wxqv'
"$CLI" -s 'c++' '@Bar@foo9$wxqv'

"$CLI" 'rust' 'ZN13test$u20$test4foobE'
"$CLI" -s 'rust' 'ZN13test$u20$test4foobE'

"$CLI" 'msvc' '.?AV?$GHI@$H0VPQR@MNO@JKL@@@DEF@ABC@@'
"$CLI" -s 'msvc' '.?AV?$GHI@$H0VPQR@MNO@JKL@@@DEF@ABC@@'

"$CLI" 'objc' '_i_class1__method2_arg2_'
"$CLI" -s 'objc' '_i_class1__method2_arg2_'

"$CLI" 'pascal' 'OUTPUT_$$_SQUARE$SMALLINT$$SMALLINT'
"$CLI" -s 'pascal' 'OUTPUT_$$_SQUARE$SMALLINT$$SMALLINT'

if [ ! -z "$HAS_SWIFT" ]; then
    "$CLI" 'swift' '__TFC4main8FooClasss3barSS'
    "$CLI" -s 'swift' '__TFC4main8FooClasss3barSS'
fi

if [ ! -z "$HAS_GPL" ]]; then
    "$CLI" 'c++' '_ZTTNSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEEE_ptr'
    "$CLI" -s 'c++' '_ZTTNSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEEE_ptr'
fi

