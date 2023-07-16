// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CXX_H
#define CXX_H

#if WITH_GPL
char *demangle_gpl_cxx(const char *str, bool simplify);
#else
#define demangle_gpl_cxx(x, y) (NULL)
#endif

char *find_block_invoke(char *p);

#endif /* CXX_H */