#ifndef RZ_LIBDEMANGLE_PARSER_COMBINATOR_H
#define RZ_LIBDEMANGLE_PARSER_COMBINATOR_H

#include "demangler_util.h"
#include "types.h"

DemString* match_one_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
);
DemString* match_zero_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
);

#endif //RZ_LIBDEMANGLE_PARSER_COMBINATOR_H
