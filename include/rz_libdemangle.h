// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_H
#define RZ_LIBDEMANGLE_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && __GNUC__ >= 4
#define DEM_LIB_EXPORT __attribute__((visibility("default")))
#elif defined(_MSC_VER)
#define DEM_LIB_EXPORT __declspec(dllexport)
#else
#define DEM_LIB_EXPORT
#endif

typedef enum {
	RZ_DEMANGLE_OPT_BASE = 0,
	RZ_DEMANGLE_OPT_SIMPLIFY = (1 << 0),
	RZ_DEMANGLE_OPT_ENABLE_ALL = 0xFFFF,
} RzDemangleOpts;

DEM_LIB_EXPORT char *libdemangle_handler_cxx(const char *symbol, RzDemangleOpts opts);
DEM_LIB_EXPORT char *libdemangle_handler_rust(const char *symbol, RzDemangleOpts opts);

#if WITH_SWIFT_DEMANGLER
DEM_LIB_EXPORT char *libdemangle_handler_swift(const char *symbol, RzDemangleOpts opts);
#endif

DEM_LIB_EXPORT char *libdemangle_handler_java(const char *symbol, RzDemangleOpts opts);
DEM_LIB_EXPORT char *libdemangle_handler_msvc(const char *symbol, RzDemangleOpts opts);
DEM_LIB_EXPORT char *libdemangle_handler_objc(const char *symbol, RzDemangleOpts opts);
DEM_LIB_EXPORT char *libdemangle_handler_pascal(const char *symbol, RzDemangleOpts opts);

#ifdef __cplusplus
}
#endif

#endif /* RZ_LIBDEMANGLE_H */