// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CXX_H
#define CXX_H

#if WITH_GPL
char *demangle_gpl_cxx(const char *str);
#else
#define demangle_gpl_cxx(x) (NULL)
#endif

#endif /* CXX_H */