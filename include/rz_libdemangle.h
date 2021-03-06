// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_H
#define RZ_LIBDEMANGLE_H

#if WITH_GPL
RZ_API char *libdemangle_handler_cxx(const char *symbol);
RZ_API char *libdemangle_handler_rust(const char *symbol);
#endif

#if WITH_SWIFT_DEMANGLER
RZ_API char *libdemangle_handler_swift(const char *symbol);
#endif

RZ_API char *libdemangle_handler_java(const char *symbol);
RZ_API char *libdemangle_handler_msvc(const char *symbol);
RZ_API char *libdemangle_handler_objc(const char *symbol);

#endif