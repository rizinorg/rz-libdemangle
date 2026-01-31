// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_V3_PP_H
#define RZ_LIBDEMANGLE_V3_PP_H
#include "types.h"

void ast_pp(DemNode *node, DemString *out);
void pp_cv_qualifiers(CvQualifiers qualifiers, DemString *out);
void pp_ref_qualifiers(RefQualifiers qualifiers, DemString *out);

#endif // RZ_LIBDEMANGLE_V3_PP_H
