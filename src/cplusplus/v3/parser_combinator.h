// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_PARSER_COMB_H
#define V3_IMPL_PARSER_COMB_H

#include "types.h"

bool match_many1(DemParser *p, DemResult *r, DemRule rule, const char *sep, char stop);
bool match_many(DemParser *p, DemResult *r, DemRule rule, const char *sep, char stop);

#endif // V3_IMPL_PARSER_COMB_H
