// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Documentation for used grammar can be found at either of
 * - https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling
 */

#include "v3.h"

#include "demangle.h"
#include "first.h"
#include "macros.h"
#include "parser_combinator.h"
#include "types.h"

DEFN_RULE (vendor_specific_suffix, { TRACE_RETURN_FAILURE(); });
DEFN_RULE (digit, {
    if (IS_DIGIT (PEEK())) {
        AST_APPEND_CHR (PEEK());
        ADV();
        TRACE_RETURN_SUCCESS;
    }

    TRACE_RETURN_FAILURE();
});
DEFN_RULE (number, { MATCH (OPTIONAL (READ ('n')) && RULE_ATLEAST_ONCE (digit)); });
DEFN_RULE (v_offset, {
    // ignore the number
    MATCH (RULE_DEFER (AST (0), number) && READ ('_') && RULE_DEFER (AST (1), number));
});


bool rule_unqualified_name (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (unqualified_name);

    MATCH (READ_STR ("DC") && RULE_ATLEAST_ONCE (source_name) && READ ('E'));
    MATCH (
        RULE_DEFER (AST (0), operator_name) && AST_MERGE (AST (0)) &&
        OPTIONAL (RULE_DEFER (AST (1), abi_tags) && AST_MERGE (AST (1)))
    );
    MATCH (READ_STR ("12_GLOBAL__N_1") && AST_APPEND_STR ("(anonymous namespace)"));
    MATCH1 (ctor_dtor_name);
    MATCH1 (source_name);
    MATCH1 (expr_primary);
    MATCH1 (unnamed_type_name);

    RULE_FOOT (unqualified_name);
}

DEFN_RULE (unresolved_name, {
    MATCH (
        READ_STR ("srN") && RULE (unresolved_type) &&
        RULE_ATLEAST_ONCE (unresolved_qualifier_level) && READ ('E') && RULE (base_unresolved_name)
    );
    MATCH (
        OPTIONAL (READ_STR ("gs") && AST_APPEND_STR ("::")) && READ_STR ("sr") &&
        RULE_ATLEAST_ONCE (unresolved_qualifier_level) && READ ('E') && RULE (base_unresolved_name)
    );
    MATCH (READ_STR ("sr") && RULE (unresolved_type) && RULE (base_unresolved_name));
    MATCH (OPTIONAL (READ_STR ("gs") && AST_APPEND_STR ("::")) && RULE (base_unresolved_name));
});

DEFN_RULE (unscoped_name, {
    MATCH (READ_STR ("St") && AST_APPEND_STR ("std::") && RULE (unqualified_name));
    MATCH (RULE (unqualified_name));
});
DEFN_RULE (unscoped_template_name, {
    MATCH (RULE (unscoped_name));
    MATCH (RULE (substitution));
});

DEFN_RULE (unresolved_type, {
    MATCH (RULE (template_param) && OPTIONAL (RULE (template_args)));
    MATCH (RULE (decltype));
    MATCH (RULE (substitution));
});
DEFN_RULE (unresolved_qualifier_level, { MATCH (RULE (simple_id)); });


DEFN_RULE (decltype, {
    MATCH (READ_STR ("Dt") && RULE (expression) && READ ('E'));
    MATCH (READ_STR ("DT") && RULE (expression) && READ ('E'));
});


DEFN_RULE (exception_spec, {
    MATCH (READ_STR ("DO") && RULE (expression) && READ ('E'));
    MATCH (READ_STR ("Dw") && RULE_ATLEAST_ONCE (type) && READ ('E'));
    MATCH (READ_STR ("Do"));
});


DEFN_RULE (array_type, {
    MATCH (READ ('A') && OPTIONAL (RULE (number)) && READ ('_') && RULE (type));
    MATCH (READ ('A') && RULE (expression) && READ ('_') && RULE (type));
});


DEFN_RULE (expression, {
    /* unary operators */
    MATCH (
        (READ_STR ("gsnw") || READ_STR ("nw")) && AST_APPEND_STR ("new (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && AST_APPEND_STR (") ") && READ ('_') &&
        RULE (type) && READ ('E')
    );
    MATCH (
        (READ_STR ("gsnw") || READ_STR ("nw")) && AST_APPEND_STR ("new (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && AST_APPEND_STR (") ") && READ ('_') &&
        RULE (type) && RULE (initializer)
    );
    MATCH (
        (READ_STR ("gsna") || READ_STR ("na")) && AST_APPEND_STR ("new[] (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && AST_APPEND_STR (") ") && READ ('_') &&
        RULE (type) && READ ('E')
    );
    MATCH (
        (READ_STR ("gsna") || READ_STR ("na")) && AST_APPEND_STR ("new[] (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && AST_APPEND_STR (") ") && READ ('_') &&
        RULE (type) && RULE (initializer)
    );
    MATCH (
        READ_STR ("cv") && RULE (type) && READ ('_') && AST_APPEND_STR ("(") &&
        RULE_MANY_WITH_SEP (expression, ", ") && AST_APPEND_STR (")") && READ ('E')
    );

    /* binary operators */
    MATCH (
        READ_STR ("qu") && RULE (expression) && AST_APPEND_STR ("?") && RULE (expression) &&
        AST_APPEND_STR (":") && RULE (expression)
    );
    MATCH (
        READ_STR ("cl") && RULE (expression) && AST_APPEND_STR ("(") &&
        RULE_MANY_WITH_SEP (expression, ", ") && AST_APPEND_STR (")") && READ ('E')
    );
    MATCH (
        READ_STR ("cp") && AST_APPEND_STR ("(") && RULE (base_unresolved_name) &&
        AST_APPEND_STR (")") && AST_APPEND_STR ("(") && RULE_MANY_WITH_SEP (expression, ", ") &&
        AST_APPEND_STR (")") && READ ('E')
    );
    MATCH (
        READ_STR ("tl") && RULE (type) && AST_APPEND_STR ("{") &&
        RULE_MANY_WITH_SEP (braced_expression, ", ") && AST_APPEND_STR ("}") && READ ('E')
    );
    MATCH (
        READ ('u') && RULE (source_name) && RULE_MANY_WITH_SEP (template_arg, ", ") && READ ('E')
    );
    MATCH (READ_STR ("pl") && RULE (expression) && AST_APPEND_STR ("+") && RULE (expression));
    MATCH (READ_STR ("mi") && RULE (expression) && AST_APPEND_STR ("-") && RULE (expression));
    MATCH (READ_STR ("ml") && RULE (expression) && AST_APPEND_STR ("*") && RULE (expression));
    MATCH (READ_STR ("dv") && RULE (expression) && AST_APPEND_STR ("/") && RULE (expression));
    MATCH (READ_STR ("rm") && RULE (expression) && AST_APPEND_STR ("%") && RULE (expression));
    MATCH (READ_STR ("an") && RULE (expression) && AST_APPEND_STR ("&") && RULE (expression));
    MATCH (READ_STR ("or") && RULE (expression) && AST_APPEND_STR ("|") && RULE (expression));
    MATCH (READ_STR ("eo") && RULE (expression) && AST_APPEND_STR ("^") && RULE (expression));
    MATCH (READ_STR ("aS") && RULE (expression) && AST_APPEND_STR ("=") && RULE (expression));
    MATCH (READ_STR ("pL") && RULE (expression) && AST_APPEND_STR ("+=") && RULE (expression));
    MATCH (READ_STR ("mI") && RULE (expression) && AST_APPEND_STR ("-=") && RULE (expression));
    MATCH (READ_STR ("mL") && RULE (expression) && AST_APPEND_STR ("*=") && RULE (expression));
    MATCH (READ_STR ("dV") && RULE (expression) && AST_APPEND_STR ("/=") && RULE (expression));
    MATCH (READ_STR ("rM") && RULE (expression) && AST_APPEND_STR ("%=") && RULE (expression));
    MATCH (READ_STR ("aN") && RULE (expression) && AST_APPEND_STR ("&=") && RULE (expression));
    MATCH (READ_STR ("oR") && RULE (expression) && AST_APPEND_STR ("|=") && RULE (expression));
    MATCH (READ_STR ("eO") && RULE (expression) && AST_APPEND_STR ("^=") && RULE (expression));
    MATCH (READ_STR ("ls") && RULE (expression) && AST_APPEND_STR ("<<") && RULE (expression));
    MATCH (READ_STR ("rs") && RULE (expression) && AST_APPEND_STR (">>") && RULE (expression));
    MATCH (READ_STR ("lS") && RULE (expression) && AST_APPEND_STR ("<<=") && RULE (expression));
    MATCH (READ_STR ("rS") && RULE (expression) && AST_APPEND_STR (">>=") && RULE (expression));
    MATCH (READ_STR ("eq") && RULE (expression) && AST_APPEND_STR ("==") && RULE (expression));
    MATCH (READ_STR ("ne") && RULE (expression) && AST_APPEND_STR ("!=") && RULE (expression));
    MATCH (READ_STR ("lt") && RULE (expression) && AST_APPEND_STR ("<") && RULE (expression));
    MATCH (READ_STR ("gt") && RULE (expression) && AST_APPEND_STR (">") && RULE (expression));
    MATCH (READ_STR ("le") && RULE (expression) && AST_APPEND_STR ("<=") && RULE (expression));
    /* ternary operator */
    MATCH (READ_STR ("ge") && RULE (expression) && AST_APPEND_STR (">=") && RULE (expression));

    /* type casting */
    /* will generate " (type)" */
    MATCH (READ_STR ("ss") && RULE (expression) && AST_APPEND_STR ("<=>") && RULE (expression));

    /* prefix operators */
    MATCH (READ_STR ("nt") && RULE (expression) && AST_APPEND_STR ("!") && RULE (expression));
    MATCH (READ_STR ("aa") && RULE (expression) && AST_APPEND_STR ("&&") && RULE (expression));

    /* expression (expr-list), call */
    MATCH (READ_STR ("oo") && RULE (expression) && AST_APPEND_STR ("||") && RULE (expression));

    /* (name) (expr-list), call that would use argument-dependent lookup but for the parentheses*/
    MATCH (
        READ_STR ("cv") && AST_APPEND_STR ("(") && RULE (type) && AST_APPEND_STR (")") &&
        RULE (expression)
    );

    /* type (expression), conversion with one argument */
    MATCH (
        READ_STR ("cv") && RULE (type) && AST_APPEND_STR ("(") && RULE (expression) &&
        AST_APPEND_STR (")")
    );

    /* type (expr-list), conversion with other than one argument */
    MATCH (
        READ_STR ("il") && AST_APPEND_STR ("{") && RULE_MANY_WITH_SEP (braced_expression, ", ") &&
        AST_APPEND_STR ("}") && READ ('E')
    );

    /* type {expr-list}, conversion with braced-init-list argument */
    MATCH (
        (READ_STR ("gsdl") || READ_STR ("dl")) && AST_APPEND_STR ("delete ") && RULE (expression)
    );

    /* {expr-list}, braced-init-list in any other context */
    MATCH (
        (READ_STR ("gsda") || READ_STR ("da")) && AST_APPEND_STR ("delete[] ") && RULE (expression)
    );

    /* new (expr-list) type */
    MATCH (
        READ_STR ("dc") && AST_APPEND_STR ("dynamic_cast<") && RULE (type) &&
        AST_APPEND_STR ("> (") && RULE (expression) && AST_APPEND_STR (")")
    );

    /* new (expr-list) type (init) */
    MATCH (
        READ_STR ("sc") && AST_APPEND_STR ("static_cast<") && RULE (type) &&
        AST_APPEND_STR ("> (") && RULE (expression) && AST_APPEND_STR (")")
    );

    /* new[] (expr-list) type */
    MATCH (
        READ_STR ("cc") && AST_APPEND_STR ("const_cast<") && RULE (type) &&
        AST_APPEND_STR ("> (") && RULE (expression) && AST_APPEND_STR (")")
    );

    /* new[] (expr-list) type (init) */
    MATCH (
        READ_STR ("rc") && AST_APPEND_STR ("reinterpret_cast<") && RULE (type) &&
        AST_APPEND_STR ("> (") && RULE (expression) && AST_APPEND_STR (")")
    );

    /* delete expression */
    MATCH (READ_STR ("dt") && RULE (expression) && AST_APPEND_CHR ('.') && RULE (unresolved_name));

    /* delete [] expression */
    MATCH (READ_STR ("pt") && RULE (expression) && AST_APPEND_STR ("->") && RULE (unresolved_name));

    // dc <type> <expression>                               # dynamic_cast<type> (expression)
    MATCH (READ_STR ("ds") && RULE (expression) && AST_APPEND_STR (".*") && RULE (expression));
    // sc <type> <expression>                               # static_cast<type> (expression)
    MATCH (
        READ_STR ("sP") && AST_APPEND_STR ("sizeof...(") && RULE_MANY (template_arg) &&
        AST_APPEND_CHR (')') && READ ('E')
    );
    // cc <type> <expression>                               # const_cast<type> (expression)
    MATCH (
        READ_STR ("fLpl") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" + ... + ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    // rc <type> <expression>                               # reinterpret_cast<type> (expression)
    MATCH (
        READ_STR ("fLmi") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" - ... - ") && RULE (expression) && AST_APPEND_CHR (')')
    );

    // ti <type>                                            # typeid (type)
    MATCH (
        READ_STR ("fLml") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" * ... * ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    // te <expression>                                      # typeid (expression)
    MATCH (
        READ_STR ("fLdv") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" / ... / ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    // st <type>                                            # sizeof (type)
    MATCH (
        READ_STR ("fLrm") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" % ... % ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    // sz <expression>                                      # sizeof (expression)
    MATCH (
        READ_STR ("fLan") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" & ... & ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    // at <type>                                            # alignof (type)
    MATCH (
        READ_STR ("fLor") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" | ... | ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    // az <expression>                                      # alignof (expression)
    MATCH (
        READ_STR ("fLeo") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" ^ ... ^ ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    // nx <expression>                                      # noexcept (expression)
    MATCH (
        READ_STR ("fLaS") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" = ... = ") && RULE (expression) && AST_APPEND_CHR (')')
    );

    MATCH (
        READ_STR ("fLpL") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" += ... += ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLmI") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" -= ... -= ") && RULE (expression) && AST_APPEND_CHR (')')
    );

    MATCH (
        READ_STR ("fLmL") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" *= ... *= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLdV") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" /= ... /= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLrM") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" %= ... %= ") && RULE (expression) && AST_APPEND_CHR (')')
    );

    MATCH (
        READ_STR ("fLaN") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" &= ... &= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLoR") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" |= ... |= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLeO") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" ^= ... ^= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLls") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" << ... << ") && RULE (expression) && AST_APPEND_CHR (')')
    );

    /* unary left fold */
    MATCH (
        READ_STR ("fLrs") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" >> ... >> ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLlS") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" <<= ... <<= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLrS") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" >>= ... >>= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLeq") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" == ... == ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLne") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" != ... != ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLlt") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" < ... < ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLgt") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" > ... > ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLle") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" <= ... <= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLge") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" >= ... >= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLss") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" <=> ... <=> ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLnt") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" ! ... ! ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLaa") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" && ... && ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLoo") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" || ... || ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRpl") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" + ... + ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRmi") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" - ... - ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRml") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" * ... * ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRdv") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" / ... / ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRrm") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" % ... % ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRan") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" & ... & ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRor") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" | ... | ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fReo") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" ^ ... ^ ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRaS") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" = ... = ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRpL") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" += ... += ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRmI") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" -= ... -= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRmL") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" *= ... *= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRdV") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" /= ... /= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRrM") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" %= ... %= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRaN") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" &= ... &= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRoR") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" |= ... |= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fReO") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" ^= ... ^= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRls") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" << ... << ") && RULE (expression) && AST_APPEND_CHR (')')
    );

    /* unary fold right */
    MATCH (
        READ_STR ("fRrs") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" >> ... >> ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRlS") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" <<= ... <<= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRrS") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" >>= ... >>= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fReq") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" == ... == ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRne") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" != ... != ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRlt") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" < ... < ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRgt") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" > ... > ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRle") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" <= ... <= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRge") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" >= ... >= ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRss") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" <=> ... <=> ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRnt") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" ! ... ! ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRaa") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" && ... && ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRoo") && AST_APPEND_CHR ('(') && RULE (expression) &&
        AST_APPEND_STR (" || ... || ") && RULE (expression) && AST_APPEND_CHR (')')
    );
    MATCH (READ_STR ("ps") && AST_APPEND_CHR ('+') && RULE (expression));
    MATCH (READ_STR ("ng") && AST_APPEND_CHR ('-') && RULE (expression));
    MATCH (READ_STR ("ad") && AST_APPEND_CHR ('&') && RULE (expression));
    MATCH (READ_STR ("de") && AST_APPEND_CHR ('*') && RULE (expression));
    MATCH (READ_STR ("co") && AST_APPEND_STR ("~") && RULE (expression));
    MATCH (READ_STR ("pp_") && AST_APPEND_STR ("++") && RULE (expression));
    MATCH (READ_STR ("mm_") && AST_APPEND_STR ("--") && RULE (expression));
    MATCH (READ_STR ("ti") && AST_APPEND_STR ("typeid(") && RULE (type) && AST_APPEND_STR (")"));
    MATCH (
        READ_STR ("te") && AST_APPEND_STR ("typeid(") && RULE (expression) && AST_APPEND_STR (")")
    );
    MATCH (READ_STR ("st") && AST_APPEND_STR ("sizeof(") && RULE (type) && AST_APPEND_STR (")"));
    MATCH (
        READ_STR ("sz") && AST_APPEND_STR ("sizeof(") && RULE (expression) && AST_APPEND_STR (")")
    );
    MATCH (READ_STR ("at") && AST_APPEND_STR ("alignof(") && RULE (type) && AST_APPEND_STR (")"));
    MATCH (
        READ_STR ("az") && AST_APPEND_STR ("alignof(") && RULE (expression) && AST_APPEND_STR (")")
    );
    MATCH (
        READ_STR ("nx") && AST_APPEND_STR ("noexcept(") && RULE (expression) && AST_APPEND_STR (")")
    );
    MATCH (
        READ_STR ("frss") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" <=>...")
    );
    MATCH (
        READ_STR ("sZ") && AST_APPEND_STR ("sizeof...(") && RULE (template_param) &&
        AST_APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("sZ") && AST_APPEND_STR ("sizeof...(") && RULE (function_param) &&
        AST_APPEND_CHR (')')
    );
    MATCH (READ_STR ("sp") && RULE (expression) && AST_APPEND_STR ("..."));

    /* binary left fold */
    // clang-format off
    MATCH (READ_STR ("flpl") && AST_APPEND_STR ("(... +") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flmi") && AST_APPEND_STR ("(... -") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flml") && AST_APPEND_STR ("(... *") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fldv") && AST_APPEND_STR ("(... /") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrm") && AST_APPEND_STR ("(... %") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flan") && AST_APPEND_STR ("(... &") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flor") && AST_APPEND_STR ("(... |") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fleo") && AST_APPEND_STR ("(... ^") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flaS") && AST_APPEND_STR ("(... =") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flpL") && AST_APPEND_STR ("(... +=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flmI") && AST_APPEND_STR ("(... -=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flmL") && AST_APPEND_STR ("(... *=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fldV") && AST_APPEND_STR ("(... /=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrM") && AST_APPEND_STR ("(... %=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flaN") && AST_APPEND_STR ("(... &=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("floR") && AST_APPEND_STR ("(... |=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fleO") && AST_APPEND_STR ("(... ^=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flls") && AST_APPEND_STR ("(... <<") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrs") && AST_APPEND_STR ("(... >>") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fllS") && AST_APPEND_STR ("(... <<=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrS") && AST_APPEND_STR ("(... >>=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fleq") && AST_APPEND_STR ("(... ==") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flne") && AST_APPEND_STR ("(... !=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fllt") && AST_APPEND_STR ("(... <") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flgt") && AST_APPEND_STR ("(... >") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flle") && AST_APPEND_STR ("(... <=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flge") && AST_APPEND_STR ("(... >=") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flss") && AST_APPEND_STR ("(... <=>") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flnt") && AST_APPEND_STR ("(... !") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flaa") && AST_APPEND_STR ("(... &&") && RULE (expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("floo") && AST_APPEND_STR ("(... ||") && RULE (expression) && AST_APPEND_CHR (')'));

    /* binary fold right */
    MATCH (READ_STR ("frpl") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" + ...)"));
    MATCH (READ_STR ("frmi") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" - ...)"));
    MATCH (READ_STR ("frml") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" * ...)"));
    MATCH (READ_STR ("frdv") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" / ...)"));
    MATCH (READ_STR ("frrm") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" % ...)"));
    MATCH (READ_STR ("fran") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" & ...)"));
    MATCH (READ_STR ("fror") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" | ...)"));
    MATCH (READ_STR ("freo") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" ^ ...)"));
    MATCH (READ_STR ("fraS") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" = ...)"));
    MATCH (READ_STR ("frpL") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" += ...)"));
    MATCH (READ_STR ("frmI") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" -= ...)"));
    MATCH (READ_STR ("frmL") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" *= ...)"));
    MATCH (READ_STR ("frdV") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" /= ...)"));
    MATCH (READ_STR ("frrM") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" %= ...)"));
    MATCH (READ_STR ("fraN") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" &= ...)"));
    MATCH (READ_STR ("froR") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" |= ...)"));
    MATCH (READ_STR ("freO") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" ^= ...)"));
    MATCH (READ_STR ("frls") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" << ...)"));
    MATCH (READ_STR ("frrs") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" >> ...)"));
    MATCH (READ_STR ("frlS") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" <<= ...)"));
    MATCH (READ_STR ("frrS") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" >>= ...)"));
    MATCH (READ_STR ("freq") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" == ...)"));
    MATCH (READ_STR ("frne") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" != ...)"));
    MATCH (READ_STR ("frlt") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" < ...)"));
    MATCH (READ_STR ("frgt") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" > ...)"));
    MATCH (READ_STR ("frle") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" <= ...)"));
    MATCH (READ_STR ("frge") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" >= ...)"));
    MATCH (READ_STR ("frnt") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" ! ...)"));
    MATCH (READ_STR ("fraa") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" && ...)"));
    MATCH (READ_STR ("froo") && AST_APPEND_CHR ('(') && RULE (expression) && AST_APPEND_STR (" || ...)"));
    MATCH (READ_STR ("tw") && AST_APPEND_STR ("throw ") && RULE (expression));
    // clang-format on

    // tw <expression>                                      # throw expression
    MATCH (RULE (template_param));
    // tr                                                   # throw with no operand (rethrow)
    MATCH (RULE (function_param));

    // u <source-name> <template-arg>* E                    # vendor extended expression
    MATCH (READ_STR ("tr") && AST_APPEND_STR ("throw"));

    MATCH (RULE (unresolved_name));
    MATCH (RULE (expr_primary));
});


DEFN_RULE (simple_id, { MATCH (RULE (source_name) && OPTIONAL (RULE (template_args))); });



DEFN_RULE (template_param, {
    SAVE_POS (0);
    if (READ ('T')) {
        if (IS_DIGIT (PEEK()) || IS_UPPER (PEEK())) {
            char* base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
            char* pos  = NULL;
            ut64  pow  = 1;
            ut64  sid  = 1;
            while ((pos = strchr (base, PEEK()))) {
                st64 based_val  = pos - base;
                sid            += based_val * pow;
                pow            *= 36;
                ADV();
            }
            if (!READ ('_')) {
                RESTORE_POS (0);
                TRACE_RETURN_FAILURE();
            }
            sid = sid + m->template_idx_start;
            if (m->template_params.length > sid &&
                vec_ptr_at (&m->template_params, sid)->name.buf) {}
            TRACE_RETURN_SUCCESS;
        } else if (READ ('_')) {
            size_t sid = m->template_idx_start;
            if (m->template_params.length > sid &&
                vec_ptr_at (&m->template_params, sid)->name.buf) {}
            TRACE_RETURN_SUCCESS;
        }
    }
    RESTORE_POS (0);
    TRACE_RETURN_FAILURE();
});


DEFN_RULE (discriminator, {
    if (READ ('_')) {
        // matched two "_"
        if (READ ('_')) {
            st64 numlt10 = -1;
            READ_NUMBER (numlt10);
            if (numlt10 >= 10) {
                // do something
                TRACE_RETURN_SUCCESS;
            }
        } else {
            // matched single "_"
            st64 numlt10 = -1;
            READ_NUMBER (numlt10);
            if (numlt10 >= 0 && numlt10 < 10) {
                // do something
                TRACE_RETURN_SUCCESS;
            }
        }
    }

    TRACE_RETURN_FAILURE();
});


DEFN_RULE (initializer, {
    MATCH (
        READ_STR ("pi") && AST_APPEND_STR (" (") && RULE_MANY_WITH_SEP (expression, ", ") &&
        AST_APPEND_CHR (')') && READ ('E')
    );
});


DEFN_RULE (abi_tag, {
    // will generate " \"<source_name>\","
    MATCH (READ ('B') && AST_APPEND_STR (" \"") && RULE (source_name) && AST_APPEND_STR ("\","));
});


DEFN_RULE (call_offset, {
    MATCH (
        READ ('h') && AST_APPEND_STR ("non-virtual thunk to ") && RULE (nv_offset) && READ ('_')
    );
    MATCH (READ ('v') && AST_APPEND_STR ("virtual thunk to ") && RULE (v_offset) && READ ('_'));
});


/*
 * NOTE: Taken from old c++v3 demangler code
 * Some of these are tested, others are not encountered yet.
 *
 * <special-name> ::= TV <type>
          ::= TT <type>
          ::= TI <type>
          ::= TS <type>
          ::= TA <template-arg>
          ::= GV <(object) name>
          ::= T <call-offset> <(base) encoding>
          ::= Tc <call-offset> <call-offset> <(base) encoding>
   Also g++ extensions:
          ::= TC <type> <(offset) number> _ <(base) type>
          ::= TF <type>
          ::= TJ <type>
          ::= GR <name>
          ::= GA <encoding>
          ::= Gr <resource name>
          ::= GTt <encoding>
          ::= GTn <encoding>
*/

DEFN_RULE (special_name, {
    MATCH (READ_STR ("Tc") && RULE (call_offset) && RULE (call_offset) && RULE (encoding));
    MATCH (
        READ_STR ("GR") && AST_APPEND_STR ("reference temporary for ") && RULE (name) &&
        RULE (seq_id) && READ ('_')
    );
    MATCH (READ ('T') && RULE (call_offset) && RULE (encoding));
    MATCH (
        READ_STR ("GR") && AST_APPEND_STR ("reference temporary for ") && RULE (name) && READ ('_')
    );
    MATCH (READ_STR ("TV") && AST_APPEND_STR ("vtable for ") && RULE (type));
    MATCH (READ_STR ("TT") && AST_APPEND_STR ("VTT structure for ") && RULE (type));
    MATCH (READ_STR ("TI") && AST_APPEND_STR ("typeinfo for ") && RULE (type));
    MATCH (READ_STR ("TS") && AST_APPEND_STR ("typeinfo name for ") && RULE (type));
    MATCH (READ_STR ("GV") && AST_APPEND_STR ("guard variable for ") && RULE (name));
    MATCH (READ_STR ("GTt") && RULE (encoding));
});


DEFN_RULE (function_type, {
    bool is_ptr = false;

    // if PF creates a (*)
    // simple F does not create any bracket
    // Example : PFvPvE -> void (*)(void*)
    // Example : FvPvE -> void (void*)

    MATCH (
        OPTIONAL (is_ptr = READ ('P')) &&

        OPTIONAL (RULE (cv_qualifiers)) && OPTIONAL (RULE (exception_spec)) &&
        OPTIONAL (READ_STR ("Dx")) && READ ('F') && OPTIONAL (READ ('Y')) &&

        // Return type. If return type is builtin type, then it's not substitutable
        // If return type is a type, then it's substitutable, so add using APPEND_TYPE
        ((RULE_DEFER (AST (0), builtin_type) || ((RULE_DEFER (AST (0), type)))) &&
         AST_MERGE (AST (0))) &&

        // if a pointer then we'll have a function pointer (*)
        (is_ptr ? AST_APPEND_STR (" (*)") : AST_APPEND_CHR (' ')) &&

        // arguments
        AST_APPEND_STR ("(") && RULE_ATLEAST_ONCE_WITH_SEP (type, ", ") && AST_APPEND_STR (")") &&

        OPTIONAL (RULE (ref_qualifier)) && READ ('E')
    );
});



DEFN_RULE (function_param, {
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && AST_APPEND_CHR (' ') && RULE (non_negative_number) &&
        READ ('_')
    );
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && AST_APPEND_CHR (' ') && READ ('_')
    );
    MATCH (
        READ_STR ("fp") && RULE (top_level_cv_qualifiers) && AST_APPEND_CHR (' ') &&
        RULE (non_negative_number) && READ ('_')
    );
    MATCH (READ_STR ("fp") && RULE (top_level_cv_qualifiers) && AST_APPEND_CHR (' ') && READ ('_'));
    MATCH (READ_STR ("fPT"));
});

bool rule_builtin_type (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (builtin_type);
    MATCH (
        READ_STR ("DF") && AST_APPEND_STR ("_Float") && RULE_DEFER (AST (0), number) &&
        READ ('_') && AST_MERGE (AST (0))
    );
    MATCH (
        READ_STR ("DF") && AST_APPEND_STR ("_Float") && RULE_DEFER (AST (0), number) &&
        READ ('x') && AST_MERGE (AST (0)) && AST_APPEND_STR ("x")
    );
    MATCH (
        READ_STR ("DF") && AST_APPEND_STR ("std::bfloat") && RULE_DEFER (AST (0), number) &&
        READ ('b') && AST_MERGE (AST (0)) && AST_APPEND_STR ("_t")
    );
    MATCH (
        READ_STR ("DB") && AST_APPEND_STR ("signed _BitInt(") && RULE_DEFER (AST (0), number) &&
        AST_MERGE (AST (0)) && AST_APPEND_STR (")") && READ ('_')
    );
    MATCH (
        READ_STR ("DB") && AST_APPEND_STR ("signed _BitInt(") && RULE_DEFER (AST (0), expression) &&
        AST_MERGE (AST (0)) && AST_APPEND_STR (")") && READ ('_')
    );
    MATCH (
        READ_STR ("DU") && AST_APPEND_STR ("unsigned _BitInt(") && RULE_DEFER (AST (0), number) &&
        AST_MERGE (AST (0)) && AST_APPEND_STR (")") && READ ('_')
    );
    MATCH (
        READ_STR ("DU") && AST_APPEND_STR ("unsigned _BitInt(") &&
        RULE_DEFER (AST (0), expression) && AST_MERGE (AST (0)) && AST_APPEND_STR (")") &&
        READ ('_')
    );
    MATCH (
        READ ('u') && RULE_DEFER (AST (0), source_name) && AST_MERGE (AST (0)) &&
        OPTIONAL (RULE_DEFER (AST (1), template_args) && AST_MERGE (AST (1)))
    );
    MATCH (READ_STR ("DS") && READ_STR ("DA") && AST_APPEND_STR ("_Sat _Accum"));
    MATCH (READ_STR ("DS") && READ_STR ("DR") && AST_APPEND_STR ("_Sat _Fract"));
    MATCH (READ ('v') && AST_APPEND_STR ("void"));
    MATCH (READ ('w') && AST_APPEND_STR ("wchar_t"));
    MATCH (READ ('b') && AST_APPEND_STR ("bool"));
    MATCH (READ ('c') && AST_APPEND_STR ("char"));
    MATCH (READ ('a') && AST_APPEND_STR ("signed char"));
    MATCH (READ ('h') && AST_APPEND_STR ("unsigned char"));
    MATCH (READ ('s') && AST_APPEND_STR ("short"));
    MATCH (READ ('t') && AST_APPEND_STR ("unsigned short"));
    MATCH (READ ('i') && AST_APPEND_STR ("int"));
    MATCH (READ ('j') && AST_APPEND_STR ("unsigned int"));
    MATCH (READ ('l') && AST_APPEND_STR ("long"));
    MATCH (READ ('m') && AST_APPEND_STR ("unsigned long"));
    MATCH (READ ('x') && AST_APPEND_STR ("long long"));
    MATCH (READ ('y') && AST_APPEND_STR ("unsigned long long"));
    MATCH (READ ('n') && AST_APPEND_STR ("__int128"));
    MATCH (READ ('o') && AST_APPEND_STR ("unsigned __int128"));
    MATCH (READ ('f') && AST_APPEND_STR ("float"));
    MATCH (READ ('d') && AST_APPEND_STR ("double"));
    MATCH (READ ('e') && AST_APPEND_STR ("long double"));
    MATCH (READ ('g') && AST_APPEND_STR ("__float128"));
    MATCH (READ ('z') && AST_APPEND_STR ("..."));
    MATCH (READ_STR ("Dd") && AST_APPEND_STR ("decimal64"));
    MATCH (READ_STR ("De") && AST_APPEND_STR ("decimal128"));
    MATCH (READ_STR ("Df") && AST_APPEND_STR ("decimal32"));
    MATCH (READ_STR ("Dh") && AST_APPEND_STR ("half"));
    MATCH (READ_STR ("Di") && AST_APPEND_STR ("char32_t"));
    MATCH (READ_STR ("Ds") && AST_APPEND_STR ("char16_t"));
    MATCH (READ_STR ("Du") && AST_APPEND_STR ("char8_t"));
    MATCH (READ_STR ("Da") && AST_APPEND_STR ("auto"));
    MATCH (READ_STR ("Dc") && AST_APPEND_STR ("decltype(auto)"));
    MATCH (READ_STR ("Dn") && AST_APPEND_STR ("std::nullptr_t"));
    MATCH (READ_STR ("DA") && AST_APPEND_STR ("_Accum"));
    MATCH (READ_STR ("DR") && AST_APPEND_STR ("_Fract"));

    RULE_FOOT (builtin_type);
}


DEFN_RULE (extended_qualifier, {
    MATCH (READ ('U') && RULE (source_name) && RULE (template_args));
    MATCH (READ ('U') && RULE (source_name));
});

bool rule_source_name (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (source_name);
    /* positive number providing length of name followed by it */
    st64 name_len = 0;
    READ_NUMBER (name_len);

    if (name_len == 0 || CUR() == dan->val.buf) {
        TRACE_RETURN_FAILURE();
    }
    if (CUR() + name_len >= END()) {
        TRACE_RETURN_FAILURE();
    }

    AST_APPEND_STR_N (CUR(), name_len);
    CUR() += name_len;
    TRACE_RETURN_SUCCESS;
}


DEFN_RULE (abi_tags, { MATCH (RULE_ATLEAST_ONCE (abi_tag)); });


/**
 * \b Parse sequence ID from mangled string iterator.
 *
 * Parses a sequence ID following the Itanium ABI specification:
 * - Empty (just '_'): returns 0
 * - Base-36 digits followed by '_': returns parsed value + 1
 *
 * \p msi   Mangled string iterator positioned at the sequence ID
 * \p m     Meta context (used for tracing if enabled)
 *
 * \return Parsed sequence ID (1 for empty, 2+ for base-36 values) on success
 * \return 0 on failure (invalid format)
 */
size_t parse_sequence_id (StrIter* msi, Meta* m) {
    if (!msi || !m) {
        return 0;
    }

    size_t sid           = 1; // Start at 1 for empty sequence
    bool   parsed_seq_id = false;

    if (IS_DIGIT (PEEK()) || IS_UPPER (PEEK())) {
        char*  base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
        char*  pos  = NULL;
        size_t pow  = 1;
        sid         = 2; // Start at 2 for base-36 sequences (1 + parsed value)
        while ((pos = strchr (base, PEEK()))) {
            size_t based_val  = (size_t)(pos - base);
            sid              += based_val * pow;
            pow              *= 36;
            ADV();
        }
        parsed_seq_id = true;
    } else if (PEEK() == '_') {
        sid           = 1; // Empty sequence maps to 1
        parsed_seq_id = true;
    }

    if (!parsed_seq_id || !READ ('_')) {
        return 0;
    }

    return sid;
}


DEFN_RULE (class_enum_type, {
    MATCH (
        OPTIONAL (READ_STR ("Ts") || READ_STR ("Tu") || READ_STR ("Te")) &&
        RULE_DEFER (AST (0), name) && AST_MERGE (AST (0))
    );
});


DEFN_RULE (bare_function_type, { MATCH (RULE_ATLEAST_ONCE_WITH_SEP (type, ", ")); });


DEFN_RULE (mangled_name, {
    MATCH (
        READ_STR ("_Z") && RULE (encoding) && OPTIONAL (READ ('.') && RULE (vendor_specific_suffix))
    );
});

bool rule_cv_qualifiers (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (cv_qualifiers);
    MATCH (READ ('K') && AST_APPEND_STR ("const") && SET_CONST());
    MATCH (READ ('V') && AST_APPEND_STR ("volatile"));
    MATCH (READ ('r') && AST_APPEND_STR ("restrict"));
    RULE_FOOT (cv_qualifiers);
}

bool rule_qualifiers (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (qualifiers);

    bool has_qualifiers = match_zero_or_more_rules (
                              first_of_rule_extended_qualifier,
                              rule_extended_qualifier,
                              " ",
                              AST (0),
                              msi,
                              m,
                              graph,
                              _my_node_id
                          ) &&
                          VecDemAstNode_len (AST (0)->children) > 0;

    MATCH (
        RULE_DEFER (AST (1), cv_qualifiers) && AST_MERGE (AST (1)) &&
        (!has_qualifiers || (AST_APPEND_CHR (' ') && AST_MERGE (AST (0))))
    );

    RULE_FOOT (qualifiers);
}

bool rule_qualified_type (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (qualified_type);

    if (rule_qualifiers (AST (0), msi, m, graph, _my_node_id) &&
        rule_type (AST (1), msi, m, graph, _my_node_id)) {
        // Output type first, then qualifiers (e.g., "QString const" not "constQString")
        AST_MERGE (AST (1));
        if (AST (0)->dem.len > 0) {
            AST_APPEND_STR (" ");
            AST_MERGE (AST (0));
        }
        TRACE_RETURN_SUCCESS;
    }
    TRACE_RETURN_FAILURE();

    RULE_FOOT (qualified_type);
}


bool rule_type (DemAstNode* dan, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (type);

    MATCH (RULE_DEFER (AST (0), function_type) && AST_MERGE (AST (0)));
    MATCH (RULE_CALL_DEFER (AST (0), qualified_type) && AST_MERGE (AST (0)) && AST_APPEND_TYPE);
    MATCH (
        READ ('C') && RULE_CALL_DEFER (AST (0), type) && AST_MERGE (AST (0))
    ); // complex pair (C99)
    MATCH (READ ('G') && RULE_CALL_DEFER (AST (0), type) && AST_MERGE (AST (0))); // imaginary (C99)
    MATCH (
        READ ('P') && RULE_CALL_DEFER (AST (0), type) && AST_MERGE (AST (0)) &&
        AST_APPEND_STR ("*") && AST_APPEND_TYPE
    );
    MATCH (
        READ ('R') && RULE_CALL_DEFER (AST (0), type) && AST_MERGE (AST (0)) &&
        AST_APPEND_STR ("&") && AST_APPEND_TYPE
    );
    MATCH (
        READ ('O') && RULE_CALL_DEFER (AST (0), type) && AST_MERGE (AST (0)) &&
        AST_APPEND_STR ("&&") && AST_APPEND_TYPE
    );
    // MATCH (RULE (template_template_param) && RULE (template_args));
    MATCH (
        RULE_DEFER (AST (0), template_param) && AST_MERGE (AST (0)) &&
        OPTIONAL (RULE_DEFER (AST (1), template_args) && AST_MERGE (AST (1)))
    );
    MATCH (
        RULE_DEFER (AST (0), substitution) && RULE_DEFER (AST (1), template_args) &&
        AST_MERGE (AST (0)) && AST_MERGE (AST (1))
    );
    MATCH (RULE_DEFER (AST (0), builtin_type) && AST_MERGE (AST (0)));
    MATCH (
        READ_STR ("Dp") && RULE_CALL_DEFER (AST (0), type) && AST_MERGE (AST (0))
    ); // pack expansion (C++11)

    // Extended qualifiers with CV qualifiers
    MATCH (RULE_DEFER (AST (0), class_enum_type) && AST_MERGE (AST (0)) && AST_APPEND_TYPE);
    MATCH (RULE_DEFER (AST (0), array_type) && AST_MERGE (AST (0)));
    MATCH (RULE_DEFER (AST (0), pointer_to_member_type) && AST_MERGE (AST (0)));
    MATCH (RULE_DEFER (AST (0), template_param) && AST_MERGE (AST (0)));
    MATCH (RULE_DEFER (AST (0), decltype) && AST_MERGE (AST (0)));
    MATCH (RULE_DEFER (AST (0), substitution) && AST_MERGE (AST (0)));

    RULE_FOOT (type);
}


DEFN_RULE (template_arg, {
    MATCH (READ ('X') && RULE_DEFER (AST (0), expression) && AST_MERGE (AST (0)) && READ ('E'));
    MATCH (READ ('J') && RULE_MANY (template_arg) && READ ('E'));
    MATCH (RULE_DEFER (AST (0), type) && AST_MERGE (AST (0)));
    MATCH (RULE_DEFER (AST (0), expr_primary) && AST_MERGE (AST (0)));
});


DEFN_RULE (base_unresolved_name, {
    MATCH (READ_STR ("on") && RULE (operator_name) && RULE (template_args));
    MATCH (READ_STR ("on") && RULE (operator_name));
    MATCH (READ_STR ("dn") && RULE (destructor_name));
    MATCH (RULE (simple_id));
});

static ut64 base36_to_int (const char* buf, ut64* px) {
    static const char* base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
    char*              pos  = NULL;
    ut64               pow  = 1;
    ut64               x    = 0;
    ut64               sz   = 0;
    while ((pos = strchr (base, buf[sz]))) {
        st64 based_val  = pos - base;
        x              += based_val * pow;
        pow            *= 36;
        sz++;
    }
    *px = x;
    return sz;
}


DEFN_RULE (seq_id, {
    if (IS_DIGIT (PEEK()) || IS_UPPER (PEEK())) {
        ut64 sid  = 0;
        msi->cur += base36_to_int (msi->cur, &sid);
        return meta_substitute_type (m, sid + 1, &dan->dem);
    }
    if (PEEK() == '_') {
        return meta_substitute_type (m, 0, &dan->dem);
    }
});



DEFN_RULE (local_name, {
    MATCH (
        READ ('Z') && RULE (encoding) && READ_STR ("Ed") && OPTIONAL (RULE (number)) &&
        READ ('_') && AST_APPEND_STR ("::") && RULE (name)
    );
    MATCH (
        READ ('Z') && RULE (encoding) && READ ('E') && AST_APPEND_STR ("::") && RULE (name) &&
        OPTIONAL (RULE (discriminator))
    );
    MATCH (READ ('Z') && RULE (encoding) && READ_STR ("Es") && OPTIONAL (RULE (discriminator)));
});



DEFN_RULE (substitution, {
    // HACK(brightprogrammer): This is not in original grammar, but this works!
    // Because having a "7__cxx11" just after a substitution "St" does not make sense to original grammar
    // Placing it here is also important, the order matters!
    MATCH (READ ('S') && RULE (seq_id) && READ ('_'));

    MATCH (READ_STR ("St7__cxx11") && AST_APPEND_STR ("std::__cxx11"));
    MATCH (READ_STR ("St") && AST_APPEND_STR ("std"));
    MATCH (READ_STR ("Sa") && AST_APPEND_STR ("std::allocator"));
    MATCH (READ_STR ("Sb") && AST_APPEND_STR ("std::basic_string"));
    MATCH (
        READ_STR ("Ss") &&
        // AST_APPEND_STR ("std::basic_string<char, std::char_traits<char>, std::allocator<char>>")
        AST_APPEND_STR ("std::string")
    );
    MATCH (
        READ_STR ("Si") && AST_APPEND_STR ("std::istream")
        // AST_APPEND_STR ("std::basic_istream<char, std::char_traits<char>>")
    );
    MATCH (
        READ_STR ("So") && AST_APPEND_STR ("std::ostream")
        // AST_APPEND_STR ("std::basic_ostream<char, std::char_traits<char>>")
    );

    MATCH (
        READ_STR ("Sd") && AST_APPEND_STR ("std::iostream")
        // AST_APPEND_STR ("std::basic_iostream<char, std::char_traits<char>>")
    );
});


DEFN_RULE (operator_name, {
    MATCH (READ ('v') && RULE (digit) && RULE (source_name));
    MATCH (READ_STR ("cv") && AST_APPEND_STR ("operator (") && RULE (type) && AST_APPEND_STR (")"));
    MATCH (READ_STR ("nw") && AST_APPEND_STR ("operator new"));
    MATCH (READ_STR ("na") && AST_APPEND_STR ("operator new[]"));
    MATCH (READ_STR ("dl") && AST_APPEND_STR ("operator delete"));
    MATCH (READ_STR ("da") && AST_APPEND_STR ("operator delete[]"));
    MATCH (READ_STR ("aw") && AST_APPEND_STR ("operator co_await"));
    MATCH (READ_STR ("ps") && AST_APPEND_STR ("operator+"));
    MATCH (READ_STR ("ng") && AST_APPEND_STR ("operator-"));
    MATCH (READ_STR ("ad") && AST_APPEND_STR ("operator&"));
    MATCH (READ_STR ("de") && AST_APPEND_STR ("operator*"));
    MATCH (READ_STR ("co") && AST_APPEND_STR ("operator~"));
    MATCH (READ_STR ("pl") && AST_APPEND_STR ("operator+"));
    MATCH (READ_STR ("mi") && AST_APPEND_STR ("operator-"));
    MATCH (READ_STR ("ml") && AST_APPEND_STR ("operator*"));
    MATCH (READ_STR ("dv") && AST_APPEND_STR ("operator/"));
    MATCH (READ_STR ("rm") && AST_APPEND_STR ("operator%"));
    MATCH (READ_STR ("an") && AST_APPEND_STR ("operator&"));
    MATCH (READ_STR ("or") && AST_APPEND_STR ("operator|"));
    MATCH (READ_STR ("eo") && AST_APPEND_STR ("operator^"));
    MATCH (READ_STR ("aS") && AST_APPEND_STR ("operator="));
    MATCH (READ_STR ("pL") && AST_APPEND_STR ("operator+="));
    MATCH (READ_STR ("mI") && AST_APPEND_STR ("operator-="));
    MATCH (READ_STR ("mL") && AST_APPEND_STR ("operator*="));
    MATCH (READ_STR ("dV") && AST_APPEND_STR ("operator/="));
    MATCH (READ_STR ("rM") && AST_APPEND_STR ("operator%="));
    MATCH (READ_STR ("aN") && AST_APPEND_STR ("operator&="));
    MATCH (READ_STR ("oR") && AST_APPEND_STR ("operator|="));
    MATCH (READ_STR ("eO") && AST_APPEND_STR ("operator^="));
    MATCH (READ_STR ("ls") && AST_APPEND_STR ("operator<<"));
    MATCH (READ_STR ("rs") && AST_APPEND_STR ("operator>>"));
    MATCH (READ_STR ("lS") && AST_APPEND_STR ("operator<<="));
    MATCH (READ_STR ("rS") && AST_APPEND_STR ("operator>>="));
    MATCH (READ_STR ("eq") && AST_APPEND_STR ("operator=="));
    MATCH (READ_STR ("ne") && AST_APPEND_STR ("operator!="));
    MATCH (READ_STR ("lt") && AST_APPEND_STR ("operator<"));
    MATCH (READ_STR ("gt") && AST_APPEND_STR ("operator>"));
    MATCH (READ_STR ("le") && AST_APPEND_STR ("operator<="));
    MATCH (READ_STR ("ge") && AST_APPEND_STR ("operator>="));
    MATCH (READ_STR ("ss") && AST_APPEND_STR ("operator<=>"));
    MATCH (READ_STR ("nt") && AST_APPEND_STR ("operator!"));
    MATCH (READ_STR ("aa") && AST_APPEND_STR ("operator&&"));
    MATCH (READ_STR ("oo") && AST_APPEND_STR ("operator||"));
    MATCH (READ_STR ("pp") && AST_APPEND_STR ("operator++"));
    MATCH (READ_STR ("mm") && AST_APPEND_STR ("operator--"));
    MATCH (READ_STR ("cm") && AST_APPEND_STR ("operator,"));
    MATCH (READ_STR ("pm") && AST_APPEND_STR ("operator->*"));
    MATCH (READ_STR ("pt") && AST_APPEND_STR ("operator->"));
    MATCH (READ_STR ("cl") && AST_APPEND_STR ("operator()"));

    /* will generate " (type)" */
    MATCH (READ_STR ("ix") && AST_APPEND_STR ("operator[]"));

    /* operator-name ::= li <source-name>          # operator ""*/
    MATCH (
        READ_STR ("li") && RULE (source_name)
    ); // TODO(brightprogrammer): How to generate for this operator?

    MATCH (READ_STR ("qu") && AST_APPEND_STR ("operator?"));
});


DEFN_RULE (float, {
    bool r = false;
    while (IS_DIGIT (PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
        r = true;
        ADV();
    }
    return r;
});


DEFN_RULE (destructor_name, {
    MATCH (RULE (unresolved_type));
    MATCH (RULE (simple_id));
});


bool rule_name (DemAstNode* dan, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (name);

    // For unscoped_name + template_args, we need to record:
    // 1. The template name (unscoped_name) BEFORE processing template_args
    // 2. The complete template instantiation AFTER merging both
    MATCH_AND_DO (RULE_DEFER (AST (0), unscoped_name) && AST_APPEND_TYPE1 (&AST (0)->dem) && RULE_DEFER (AST (1), template_args), {
        AST_MERGE (AST (0));
        AST_MERGE (AST (1));
        AST_APPEND_TYPE;
    });

    // For substitution + template_args, the substitution reference itself is already in the table
    MATCH_AND_DO (RULE_DEFER (AST (0), substitution) && RULE_DEFER (AST (1), template_args), {
        AST_MERGE (AST (0));
        AST_MERGE (AST (1));
        AST_APPEND_TYPE;
    });

    MATCH1 (nested_name);
    MATCH1 (unscoped_name);
    MATCH1 (local_name);

    RULE_FOOT (name);
}



bool rule_nested_name (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (nested_name);

    MATCH_AND_CONTINUE (READ ('N'));
    RULE_CALL_DEFER (AST (0), cv_qualifiers);
    RULE_CALL_DEFER (AST (1), ref_qualifier);

    // Case 1: template_prefix + template_args + E (try first because template_prefix is more specific)
    MATCH_AND_DO (
        RULE_CALL_DEFER (AST (2), template_prefix) && RULE_CALL_DEFER (AST (3), template_args) &&
            READ ('E'),
        {
            AST_MERGE (AST (2));
            AST_MERGE (AST (3));
        }
    );

    // Case 2: prefix + unqualified_name + E
    MATCH_AND_DO (
        RULE_CALL_DEFER (AST (2), prefix) && RULE_CALL_DEFER (AST (3), unqualified_name) &&
            READ ('E'),
        {
            AST_MERGE (AST (2));
            if (AST (2)->dem.len > 0) {
                AST_APPEND_STR ("::");
            }
            AST_MERGE (AST (3));
        }
    );

    RULE_FOOT (nested_name);
}

DEFN_RULE (template_template_param, {
    MATCH (RULE (template_param));
    MATCH (RULE (substitution));
});

// Helper to append the last detected class name for ctor/dtor
static bool append_last_class_name (DemAstNode* dan, Meta* m) {
    if (m->detected_types.length > 0) {
        Name* last_type = vec_ptr_at (&m->detected_types, m->detected_types.length - 1);
        if (last_type && last_type->name.buf) {
            // Find the last :: to get just the class name
            const char* name     = last_type->name.buf;
            const char* last_sep = name;
            const char* p        = name;
            while (*p) {
                if (p[0] == ':' && p[1] == ':') {
                    last_sep  = p + 2;
                    p        += 2;
                } else {
                    p++;
                }
            }
            // Also strip template arguments
            const char* tmpl = last_sep;
            while (*tmpl && *tmpl != '<') {
                tmpl++;
            }
            dem_string_append_n (&dan->dem, last_sep, tmpl - last_sep);
            return true;
        }
    }
    return false;
}

DEFN_RULE (ctor_name, {
    // NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
    MATCH (
        READ_STR ("C1") && SET_CTOR() && append_last_class_name (dan, m)
    ); // gnu complete object ctor
    MATCH (
        READ_STR ("C2") && SET_CTOR() && append_last_class_name (dan, m)
    ); // gnu base object ctor
    MATCH (
        READ_STR ("C3") && SET_CTOR() && append_last_class_name (dan, m)
    ); // gnu complete object allocating ctor
    MATCH (READ_STR ("C4") && SET_CTOR() && append_last_class_name (dan, m)); // gnu unified ctor
    MATCH (
        READ_STR ("C5") && SET_CTOR() && append_last_class_name (dan, m)
    ); // gnu object ctor group
    MATCH (READ_STR ("CI1") && SET_CTOR() && append_last_class_name (dan, m));
    MATCH (READ_STR ("CI2") && SET_CTOR() && append_last_class_name (dan, m));
});

DEFN_RULE (dtor_name, {
    // NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
    MATCH (
        READ_STR ("D0") && SET_DTOR() && AST_APPEND_STR ("~") && append_last_class_name (dan, m)
    ); // gnu deleting dtor
    MATCH (
        READ_STR ("D1") && SET_DTOR() && AST_APPEND_STR ("~") && append_last_class_name (dan, m)
    ); // gnu complete object dtor
    MATCH (
        READ_STR ("D2") && SET_DTOR() && AST_APPEND_STR ("~") && append_last_class_name (dan, m)
    ); // gnu base object dtor
    // 3 is not used
    MATCH (
        READ_STR ("D4") && SET_DTOR() && AST_APPEND_STR ("~") && append_last_class_name (dan, m)
    ); // gnu unified dtor
    MATCH (
        READ_STR ("D5") && SET_DTOR() && AST_APPEND_STR ("~") && append_last_class_name (dan, m)
    ); // gnu object dtor group
});

DEFN_RULE (ctor_dtor_name, {
    MATCH (RULE (ctor_name));
    MATCH (RULE (dtor_name));
});

DEFN_RULE (nv_offset, {
    MATCH_AND_DO (true, {
        SKIP_CH ('n');
        const char* offset_begin = CUR();
        while (IS_DIGIT (PEEK())) {
            ADV();
        }
        if (CUR() == offset_begin) {
            TRACE_RETURN_FAILURE();
        }
        AST_APPEND_STR_N (offset_begin, CUR() - offset_begin);
        TRACE_RETURN_SUCCESS;
    });
});


DEFN_RULE (template_args, {
    bool is_const;

    // we going down the rabbit hope
    m->t_level++;

    // in case we reset the template types (m->template_params)
    size_t template_idx_start = m->last_reset_idx;
    size_t last_reset_idx     = m->template_params.length;

    // if we're here more than once at the topmost level (t->level = 0)
    // then this means we have something like A<..>::B<...>
    // were we're just starting to read B, and have already parsed and generate template for A
    // now B won't be using A's template type substitutions, so we increase the offset
    // from which we use the template substitutions.
    if (m->template_reset) {
        m->template_idx_start = template_idx_start;
        m->last_reset_idx     = last_reset_idx;
        m->template_reset     = false;
    }

    MATCH_AND_DO (
        OPTIONAL ((is_const = IS_CONST()) && UNSET_CONST()) && READ ('I') && AST_APPEND_CHR ('<') &&
            RULE_ATLEAST_ONCE_WITH_SEP (template_arg, ", ") && AST_APPEND_CHR ('>') && READ ('E'),
        {
            // uppity up up
            m->t_level--;

            // number of <templates> at level 0
            if (!m->t_level) {
                m->template_reset = true;
            }

            if (is_const) {
                SET_CONST();
            }
        }
    );

    m->t_level--;
});


bool first_of_rule_non_neg_number (const char* i) {
    return (i[0] == '_') || strchr ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", *i);
}

DEFN_RULE (non_neg_number, {
    if (READ ('_')) {
        dem_string_append_char (&dan->dem, '1');
        TRACE_RETURN_SUCCESS;
    }

    char* e   = NULL;
    ut32  num = strtoul (CUR(), &e, 10) + 2;
    if (!e) {
        TRACE_RETURN_FAILURE();
    }
    dem_string_appendf (&dan->dem, "%u", num);
    msi->cur = e;

    TRACE_RETURN_SUCCESS;
});

DEFN_RULE (unnamed_type_name, {
    if (READ_STR ("Ut")) {
        st64 tidx = -1;
        READ_NUMBER (tidx);
        if (tidx >= 0) {
            // do something
        } else {
            TRACE_RETURN_FAILURE();
        }

        if (READ ('_')) {
            TRACE_RETURN_SUCCESS;
        }
    } else if (READ_STR ("Ul")) {
        MATCH (
            AST_APPEND_STR ("{lambda(") && RULE_ATLEAST_ONCE_WITH_SEP (type, ", ") && READ ('E') &&
            AST_APPEND_CHR (')') &&
            OPTIONAL (
                RULE_DEFER (AST (0), non_neg_number) && AST_APPEND_CHR ('#') && AST_MERGE (AST (0))
            ) &&
            AST_APPEND_CHR ('}') && AST_APPEND_TYPE
        );
    }

    TRACE_RETURN_FAILURE();
});



DEFN_RULE (pointer_to_member_type, { MATCH (READ ('M') && RULE (type) && RULE (type)); });


DEFN_RULE (ref_qualifier, {
    MATCH (READ ('R') && AST_APPEND_STR ("&"));
    MATCH (READ ('O') && AST_APPEND_STR ("&&"));
});


bool is_template (DemAstNode* n) {
    return n->tag == CP_DEM_TYPE_KIND_template_prefix;
}

bool rule_encoding (DemAstNode* dan, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (encoding);

    bool is_const_fn = false;

    MATCH (
        // determine if this function has const or const& at the end
        OPTIONAL (
            is_const_fn = (PEEK_AT (0) == 'N' && PEEK_AT (1) == 'K') || (PEEK_AT (0) == 'K')
        ) &&

        // get function name (can be template or non-template)
        RULE_DEFER (AST (0), name) && AST_MERGE (AST (0)) &&

        // determine whether this is a template function alongside normal demangling
        // template functions specify a return type
        // If this is a template function then get return type first
        OPTIONAL (
            is_template (AST (0)) && RULE_DEFER (AST (1), type) && AST_PREPEND_STR (" ") &&
            AST_PREPEND_DEMSTR (&AST (1)->dem)
        ) &&

        // get function params
        // set it as optional, because there's a rule which just matches for name,
        // so to supress the noise of backtracking, we just make it optional here
        OPTIONAL (
            RULE_DEFER (AST (2), bare_function_type) && AST_APPEND_CHR ('(') &&
            AST_MERGE (AST (2)) && AST_APPEND_CHR (')')
        ) &&

        // append const if it was detected to be a constant function
        OPTIONAL (is_const_fn && AST_APPEND_STR (" const"))
    );

    // MATCH (RULE (name));

    MATCH (RULE (special_name));

    RULE_FOOT (encoding);
}

DEFN_RULE (braced_expression, {
    MATCH (
        READ_STR ("dX") && AST_APPEND_STR (" [") && RULE (range_begin_expression) &&
        AST_APPEND_STR (" ... ") && RULE (range_end_expression) && AST_APPEND_STR ("] = ") &&
        RULE (braced_expression)
    );
    MATCH (
        READ_STR ("di") && AST_APPEND_STR (" .") && RULE (field_source_name) &&
        AST_APPEND_STR (" = ") && RULE (braced_expression)
    );
    MATCH (
        READ_STR ("dx") && AST_APPEND_STR (" [") && RULE (index_expression) &&
        AST_APPEND_STR ("] = ") && RULE (braced_expression)
    );
    MATCH (RULE (expression));
});


/* NOTE(brightprogrammer): The rule is modified. I've removed reading of 'E' from end.
 * The original grammar for some reason has no way to reach <expr-primary> rule and because
 * of that some matchings were failing.
 *
 * For this I manually added one alternative matching for this rule in the rule <unqualified-name>.
 * This branches from the original grammar here.
 */
DEFN_RULE (expr_primary, {
    // HACK: "(bool)0" is converted to "true"
    //       "(bool)1" is converted to "false"
    //       "(unsigned int)N" to "Nu"

    MATCH (
        READ ('L') && RULE (type) && RULE (real_part_float) && READ ('_') &&
        RULE (imag_part_float) && READ ('E')
    );
    MATCH (
        READ ('L') && AST_APPEND_STR ("(") && (PEEK() == 'P') && RULE (pointer_type) &&
        AST_APPEND_STR (")") && READ ('0') && AST_APPEND_CHR ('0') && READ ('E')
    );
    // TODO: fixme
    MATCH (
        READ ('L') && RULE_DEFER (AST (0), type) && RULE_DEFER (AST (1), value_number) && READ ('E')
    );

    MATCH (READ ('L') && RULE (type) && RULE (value_float) && READ ('E'));

    MATCH (READ ('L') && RULE (string_type) && READ ('E'));
    MATCH (READ_STR ("L_Z") && RULE (encoding) && READ ('E'));
    MATCH (READ_STR ("LDnE") && AST_APPEND_STR ("decltype(nullptr)0"));
    MATCH (READ_STR ("LDn0E") && AST_APPEND_STR ("(decltype(nullptr))0"));
});

/**
 * prefix
 * = prefix-start, [prefix-tail];
 *
 * prefix-start
 * = decltype
 * | unqualified-name, [prefix-suffix]
 * | template-param, [prefix-suffix]
 * | substitution, [prefix-suffix];
 *
 * prefix-tail
 * = unqualified-name, [prefix-suffix], [prefix-tail];
 *
 * prefix-suffix
 * = [template-args], ["M"];
 *
 */
bool rule_prefix_suffix (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (prefix_suffix);

    MATCH (
        RULE_DEFER (AST (0), template_args) && AST_MERGE (AST (0)) && READ ('M') &&
        (dan->tag = CP_DEM_TYPE_KIND_closure_prefix, true)
    );
    MATCH (RULE_DEFER (AST (0), template_args) && AST_MERGE (AST (0)));
    MATCH (READ ('M') && (dan->tag = CP_DEM_TYPE_KIND_closure_prefix, true));

    RULE_FOOT (prefix_suffix);
}

bool rule_prefix_start (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (prefix_start);

    MATCH1 (decltype);
    MATCH (
        (RULE_DEFER (AST (0), unqualified_name) || RULE_DEFER (AST (0), template_param) ||
         RULE_DEFER (AST (0), substitution)) &&
        (PEEK() == 'E' ?
             false :
             (AST_MERGE (AST (0)) &&
              // First record the unqualified_name (template name like QList)
              AST_APPEND_TYPE &&
              // Then optionally match and merge template_args
              OPTIONAL (RULE_CALL_DEFER (AST (1), prefix_suffix) && AST_MERGE (AST (1)) &&
                        // Record the complete template instantiation (QList<QOpenGLShader*>)
                        AST_APPEND_TYPE)))
    );

    RULE_FOOT (prefix_start);
}

bool rule_prefix_tail (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (prefix_tail);

    // Save position for potential backtrack
    const char* saved_pos = CUR();

    // Match unqualified_name and continue to next prefix_tail
    if (first_of_rule_unqualified_name (CUR()) &&
        rule_unqualified_name (AST (0), msi, m, graph, _my_node_id)) {
        // Check if followed by 'E' or 'I' - if so, this unqualified_name belongs to nested_name or template_prefix
        if (PEEK() == 'E' || PEEK() == 'I') {
            // Restore position and fail - let the caller consume this
            CUR() = saved_pos;
            RULE_FOOT (prefix_tail);
        }
        // Add :: before merging this component
        AST_APPEND_STR ("::");
        AST_MERGE (AST (0));
        // Record the qualified name as a substitution (e.g., "QMetaObject::Connection")
        AST_APPEND_TYPE;
        // Optional prefix_suffix
        if (rule_prefix_suffix (AST (1), msi, m, graph, _my_node_id)) {
            AST_MERGE (AST (1));
        }
        // Recursive prefix_tail
        if (first_of_rule_unqualified_name (CUR()) &&
            rule_prefix_tail (AST (2), msi, m, graph, _my_node_id)) {
            AST_MERGE (AST (2));
        }
        TRACE_RETURN_SUCCESS;
    }

    RULE_FOOT (prefix_tail);
}

bool rule_prefix (DemAstNode* dan, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (prefix);

    MATCH_AND_CONTINUE (RULE_CALL_DEFER (AST (0), prefix_start) && AST_MERGE (AST (0)));
    OPTIONAL (RULE_CALL_DEFER (AST (1), prefix_tail) && AST_MERGE (AST (1)));
    TRACE_RETURN_SUCCESS;

    RULE_FOOT (prefix);
}

bool rule_template_prefix (
    DemAstNode* dan,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (template_prefix);

    // Match unqualified_name only if followed by 'I' (template_args)
    MATCH (RULE_DEFER (AST (0), unqualified_name) && PEEK() == 'I' && AST_MERGE (AST (0)) && AST_APPEND_TYPE);
    // Match prefix + unqualified_name followed by 'I'
    MATCH (
        RULE_CALL_DEFER (AST (0), prefix) && RULE_DEFER (AST (1), unqualified_name) &&
        PEEK() == 'I' && AST_MERGE (AST (0)) && AST_APPEND_STR ("::") && AST_MERGE (AST (1)) && AST_APPEND_TYPE
    );

    MATCH1 (template_param);
    MATCH1 (substitution);

    RULE_FOOT (template_prefix);
}

char* demangle_rule (const char* mangled, DemRule rule, CpDemOptions opts) {
    if (!mangled) {
        return NULL;
    }

    StrIter  si  = {.beg = mangled, .cur = mangled, .end = mangled + strlen (mangled) + 1};
    StrIter* msi = &si;

    DemAstNode* dan = calloc (sizeof (DemAstNode), 1);

    Meta  meta = {0};
    Meta* m    = &meta;

    // Initialize trace graph
    TraceGraph  trace_graph = {0};
    TraceGraph* graph       = &trace_graph;

    // Enable tracing via environment variable or compile-time flag
#ifdef ENABLE_GRAPHVIZ_TRACE
    graph->enabled = true;
#else
    graph->enabled = (getenv ("DEMANGLE_TRACE") != NULL);
#endif

    if (graph->enabled) {
        trace_graph_init (graph);
    }
    char* result = NULL;

    if (rule (dan, msi, m, graph, -1)) {
        result       = dan->dem.buf;
        dan->dem.buf = NULL;
        dem_string_deinit (&dan->dem);
    }

    // Output graphviz trace if enabled
    if (graph->enabled) {
        // Mark the final successful path
        trace_graph_mark_final_path (graph);

        char graph_filename[256];
        snprintf (graph_filename, sizeof (graph_filename), "demangle_trace_%s.dot", mangled);
        // Replace problematic characters in filename
        for (char* p = graph_filename; *p; p++) {
            if (*p == ':' || *p == '<' || *p == '>' || *p == '|' || *p == '*' || *p == '?') {
                *p = '_';
            }
        }
        trace_graph_output_dot (graph, graph_filename, m);
    }

    trace_graph_cleanup (graph);
    VecName_deinit (&meta.detected_types);
    VecName_deinit (&meta.template_params);
    DemAstNode_dtor (dan);

    return result;
}

/**
 *
 * @param mangled
 * @param opts
 * @return
 */
char* cp_demangle_v3 (const char* mangled, CpDemOptions opts) {
    return demangle_rule (mangled, rule_mangled_name, opts);
}
