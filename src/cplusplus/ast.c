// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DemAstNode* DemAstNode_ctor (DemString* dem, DemStringView* val, CpDemTypeKind tag) {
    if (!(dem && val)) {
        return NULL;
    }
    DemAstNode* dan = (DemAstNode*)malloc (sizeof (DemAstNode));
    if (!dan) {
        return NULL;
    }
    dan->dem = *dem;
    dan->val = *val;
    dan->tag = tag;
    vec_init (&dan->children);
    return dan;
}

void DemAstNode_dtor (DemAstNode* dan) {
    DemAstNode_deinit (dan);
    free (dan);
}

bool DemAstNode_init (DemAstNode* dan) {
    if (!(dan))
        return false;
    memset (dan, 0, sizeof (DemAstNode));
    return true;
}

void DemAstNode_deinit (DemAstNode* dan) {
    if (!dan)
        return;
    vec_foreach_ptr (&dan->children, x, { DemAstNode_deinit (x); });
    vec_deinit (&dan->children);
    dem_string_deinit (&dan->dem);
    memset (dan, 0, sizeof (DemAstNode));
}

bool DemAstNode_append (DemAstNode* xs, DemAstNode* x) {
    if (!(xs && x)) {
        return false;
    }
    vec_append (&xs->children, x);
    dem_string_concat (&xs->dem, &x->dem);
    xs->val.len += x->val.len;
    return true;
}
