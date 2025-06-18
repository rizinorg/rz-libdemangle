// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (ctor_name, {
    // NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
    MATCH (READ_STR ("C1") && SET_CTOR()); // gnu complete object ctor
    MATCH (READ_STR ("C2") && SET_CTOR()); // gnu base object ctor
    MATCH (READ_STR ("C3") && SET_CTOR()); // gnu complete object allocating ctor
    MATCH (READ_STR ("C4") && SET_CTOR()); // gnu unified ctor
    MATCH (READ_STR ("C5") && SET_CTOR()); // gnu object ctor group
    MATCH (READ_STR ("CI1") && SET_CTOR());
    MATCH (READ_STR ("CI2") && SET_CTOR());
});

DEFN_RULE (dtor_name, {
    // NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
    MATCH (READ_STR ("D0") && SET_DTOR()); // gnu deleting dtor
    MATCH (READ_STR ("D1") && SET_DTOR()); // gnu complete object dtor
    MATCH (READ_STR ("D2") && SET_DTOR()); // gnu base object dtor
    // 3 is not used
    MATCH (READ_STR ("D4") && SET_DTOR()); // gnu unified dtor
    MATCH (READ_STR ("D5") && SET_DTOR()); // gnu object dtor group
});

DEFN_RULE (ctor_dtor_name, {
    MATCH (RULE(ctor_name));
    MATCH (RULE(dtor_name));
});
