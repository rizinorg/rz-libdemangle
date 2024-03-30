// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RUST_H
#define RUST_H

#include "demangler_util.h"
#include <rz_libdemangle.h>

char *rust_demangle_legacy(const char *sym);
char *rust_demangle_v0(const char *sym, bool simplified);

#endif // RUST_H
