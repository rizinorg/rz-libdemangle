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
    dan->dem      = *dem;
    dan->val      = *val;
    dan->tag      = tag;
    dan->children = NULL;
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
    VecDemAstNode_dtor (dan->children);
    dem_string_deinit (&dan->dem);
    memset (dan, 0, sizeof (DemAstNode));
}

DemAstNode* DemAstNode_append (DemAstNode* xs, DemAstNode* x) {
    if (!xs) {
        return false;
    }
    if (!xs->children) {
        xs->children = VecF (DemAstNode, ctor)();
        if (!xs->children) {
            return false;
        }
    }
    DemAstNode* node = VecDemAstNode_append (xs->children, x);
    if (!x) {
        return node;
    }
    if (!node) {
        return NULL;
    }

    dem_string_concat (&xs->dem, &x->dem);
    xs->val.len += x->val.len;
    xs->val.buf  = xs->val.buf == NULL ? x->val.buf : xs->val.buf;
    return node;
}

DemAstNode* DemAstNode_children_at (DemAstNode* xs, size_t idx) {
    if (!xs) {
        return NULL;
    }
    if (!xs->children) {
        xs->children = VecF (DemAstNode, ctor)();
        if (!xs->children) {
            return false;
        }
    }
    if (VecF (DemAstNode, len) (xs->children) <= idx) {
        VecF (DemAstNode, resize) (xs->children, idx + 1);
    }
    return VecF (DemAstNode, at) (xs->children, idx);
}
