#!/bin/sh

CLI="$1"
if [ ! -f "$CLI" ]; then
    echo "$0 <path to demangle cli bin>"
    exit 1
fi

HAS_SWIFT=$("$CLI" | grep "swift")

# terminate on fail (!= 0)
set -e

"$CLI" 'java' 'makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;'
"$CLI" -s 'java' 'makeConcatWithConstants(Ljava/lang/String;)Ljava/lang/String;'

"$CLI" 'c++' '_ZTTNSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEEE_ptr'
"$CLI" -s 'c++' '_ZTTNSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEEE_ptr'

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

