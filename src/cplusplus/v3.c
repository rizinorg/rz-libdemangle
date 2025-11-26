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
        APPEND_CHR (PEEK());
        ADV();
        TRACE_RETURN_SUCCESS (dem);
    }

    TRACE_RETURN_FAILURE();
});
DEFN_RULE (number, { MATCH (OPTIONAL (READ ('n')) && RULE_ATLEAST_ONCE (digit)); });
DEFN_RULE (v_offset, {
    // ignore the number
    DEFER_VAR (_);
    MATCH (
        RULE_DEFER (_, number) && READ ('_') && RULE_DEFER (_, number) && (dem_string_deinit (_), 1)
    );
});

// unqualified names come in sequence from prefix_nested_class_or_namespace in form of A::B::C
// we need to extract the last unqualified name from the dem string
const char* extract_last_unqualified_name (DemString* dem) {
    if (!dem) {
        return NULL;
    }
    const char* ptr = dem->buf + dem->len - 1;
    while (ptr >= dem->buf && *ptr != ':') {
        ptr--;
    }
    return ptr + 1;
}

DEFN_RULE (unqualified_name, {
    MATCH (READ_STR ("DC") && RULE_ATLEAST_ONCE (source_name) && READ ('E'));
    MATCH (RULE (operator_name) && OPTIONAL (RULE (abi_tags)));
    MATCH (READ_STR ("12_GLOBAL__N_1") && APPEND_STR ("(anonymous namespace)"));
    MATCH (RULE (ctor_dtor_name));
    MATCH (RULE (source_name));
    /* MATCH (RULE (expr_primary)); */
    MATCH (RULE (unnamed_type_name));
});

DEFN_RULE (unresolved_name, {
    MATCH (
        READ_STR ("srN") && RULE (unresolved_type) &&
        RULE_ATLEAST_ONCE (unresolved_qualifier_level) && READ ('E') && RULE (base_unresolved_name)
    );
    MATCH (
        OPTIONAL (READ_STR ("gs") && APPEND_STR ("::")) && READ_STR ("sr") &&
        RULE_ATLEAST_ONCE (unresolved_qualifier_level) && READ ('E') && RULE (base_unresolved_name)
    );
    MATCH (READ_STR ("sr") && RULE (unresolved_type) && RULE (base_unresolved_name));
    MATCH (OPTIONAL (READ_STR ("gs") && APPEND_STR ("::")) && RULE (base_unresolved_name));
});

DEFN_RULE (unscoped_name, {
    MATCH (READ_STR ("St") && APPEND_STR ("std::") && RULE (unqualified_name));
    MATCH (RULE (unqualified_name));
});
DEFN_RULE (unscoped_template_name, {
    MATCH (RULE (unscoped_name));
    MATCH (RULE (substitution));
});

DEFN_RULE (unresolved_type, {
    MATCH (
        RULE (template_param) && FORCE_APPEND_TYPE (dem) &&
        OPTIONAL (RULE (template_args) && APPEND_TYPE (dem))
    );
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
        (READ_STR ("gsnw") || READ_STR ("nw")) && APPEND_STR ("new (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        READ ('E')
    );
    MATCH (
        (READ_STR ("gsnw") || READ_STR ("nw")) && APPEND_STR ("new (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        RULE (initializer)
    );
    MATCH (
        (READ_STR ("gsna") || READ_STR ("na")) && APPEND_STR ("new[] (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        READ ('E')
    );
    MATCH (
        (READ_STR ("gsna") || READ_STR ("na")) && APPEND_STR ("new[] (") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (") ") && READ ('_') && RULE (type) &&
        RULE (initializer)
    );
    MATCH (
        READ_STR ("cv") && RULE (type) && READ ('_') && APPEND_STR ("(") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (")") && READ ('E')
    );

    /* binary operators */
    MATCH (
        READ_STR ("qu") && RULE (expression) && APPEND_STR ("?") && RULE (expression) &&
        APPEND_STR (":") && RULE (expression)
    );
    MATCH (
        READ_STR ("cl") && RULE (expression) && APPEND_STR ("(") &&
        RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (")") && READ ('E')
    );
    MATCH (
        READ_STR ("cp") && APPEND_STR ("(") && RULE (base_unresolved_name) && APPEND_STR (")") &&
        APPEND_STR ("(") && RULE_MANY_WITH_SEP (expression, ", ") && APPEND_STR (")") && READ ('E')
    );
    MATCH (
        READ_STR ("tl") && RULE (type) && APPEND_STR ("{") &&
        RULE_MANY_WITH_SEP (braced_expression, ", ") && APPEND_STR ("}") && READ ('E')
    );
    MATCH (
        READ ('u') && RULE (source_name) && RULE_MANY_WITH_SEP (template_arg, ", ") && READ ('E')
    );
    MATCH (READ_STR ("pl") && RULE (expression) && APPEND_STR ("+") && RULE (expression));
    MATCH (READ_STR ("mi") && RULE (expression) && APPEND_STR ("-") && RULE (expression));
    MATCH (READ_STR ("ml") && RULE (expression) && APPEND_STR ("*") && RULE (expression));
    MATCH (READ_STR ("dv") && RULE (expression) && APPEND_STR ("/") && RULE (expression));
    MATCH (READ_STR ("rm") && RULE (expression) && APPEND_STR ("%") && RULE (expression));
    MATCH (READ_STR ("an") && RULE (expression) && APPEND_STR ("&") && RULE (expression));
    MATCH (READ_STR ("or") && RULE (expression) && APPEND_STR ("|") && RULE (expression));
    MATCH (READ_STR ("eo") && RULE (expression) && APPEND_STR ("^") && RULE (expression));
    MATCH (READ_STR ("aS") && RULE (expression) && APPEND_STR ("=") && RULE (expression));
    MATCH (READ_STR ("pL") && RULE (expression) && APPEND_STR ("+=") && RULE (expression));
    MATCH (READ_STR ("mI") && RULE (expression) && APPEND_STR ("-=") && RULE (expression));
    MATCH (READ_STR ("mL") && RULE (expression) && APPEND_STR ("*=") && RULE (expression));
    MATCH (READ_STR ("dV") && RULE (expression) && APPEND_STR ("/=") && RULE (expression));
    MATCH (READ_STR ("rM") && RULE (expression) && APPEND_STR ("%=") && RULE (expression));
    MATCH (READ_STR ("aN") && RULE (expression) && APPEND_STR ("&=") && RULE (expression));
    MATCH (READ_STR ("oR") && RULE (expression) && APPEND_STR ("|=") && RULE (expression));
    MATCH (READ_STR ("eO") && RULE (expression) && APPEND_STR ("^=") && RULE (expression));
    MATCH (READ_STR ("ls") && RULE (expression) && APPEND_STR ("<<") && RULE (expression));
    MATCH (READ_STR ("rs") && RULE (expression) && APPEND_STR (">>") && RULE (expression));
    MATCH (READ_STR ("lS") && RULE (expression) && APPEND_STR ("<<=") && RULE (expression));
    MATCH (READ_STR ("rS") && RULE (expression) && APPEND_STR (">>=") && RULE (expression));
    MATCH (READ_STR ("eq") && RULE (expression) && APPEND_STR ("==") && RULE (expression));
    MATCH (READ_STR ("ne") && RULE (expression) && APPEND_STR ("!=") && RULE (expression));
    MATCH (READ_STR ("lt") && RULE (expression) && APPEND_STR ("<") && RULE (expression));
    MATCH (READ_STR ("gt") && RULE (expression) && APPEND_STR (">") && RULE (expression));
    MATCH (READ_STR ("le") && RULE (expression) && APPEND_STR ("<=") && RULE (expression));
    /* ternary operator */
    MATCH (READ_STR ("ge") && RULE (expression) && APPEND_STR (">=") && RULE (expression));

    /* type casting */
    /* will generate " (type)" */
    MATCH (READ_STR ("ss") && RULE (expression) && APPEND_STR ("<=>") && RULE (expression));

    /* prefix operators */
    MATCH (READ_STR ("nt") && RULE (expression) && APPEND_STR ("!") && RULE (expression));
    MATCH (READ_STR ("aa") && RULE (expression) && APPEND_STR ("&&") && RULE (expression));

    /* expression (expr-list), call */
    MATCH (READ_STR ("oo") && RULE (expression) && APPEND_STR ("||") && RULE (expression));

    /* (name) (expr-list), call that would use argument-dependent lookup but for the parentheses*/
    MATCH (
        READ_STR ("cv") && APPEND_STR ("(") && RULE (type) && APPEND_STR (")") && RULE (expression)
    );

    /* type (expression), conversion with one argument */
    MATCH (
        READ_STR ("cv") && RULE (type) && APPEND_STR ("(") && RULE (expression) && APPEND_STR (")")
    );

    /* type (expr-list), conversion with other than one argument */
    MATCH (
        READ_STR ("il") && APPEND_STR ("{") && RULE_MANY_WITH_SEP (braced_expression, ", ") &&
        APPEND_STR ("}") && READ ('E')
    );

    /* type {expr-list}, conversion with braced-init-list argument */
    MATCH ((READ_STR ("gsdl") || READ_STR ("dl")) && APPEND_STR ("delete ") && RULE (expression));

    /* {expr-list}, braced-init-list in any other context */
    MATCH ((READ_STR ("gsda") || READ_STR ("da")) && APPEND_STR ("delete[] ") && RULE (expression));

    /* new (expr-list) type */
    MATCH (
        READ_STR ("dc") && APPEND_STR ("dynamic_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );

    /* new (expr-list) type (init) */
    MATCH (
        READ_STR ("sc") && APPEND_STR ("static_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );

    /* new[] (expr-list) type */
    MATCH (
        READ_STR ("cc") && APPEND_STR ("const_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );

    /* new[] (expr-list) type (init) */
    MATCH (
        READ_STR ("rc") && APPEND_STR ("reinterpret_cast<") && RULE (type) && APPEND_STR ("> (") &&
        RULE (expression) && APPEND_STR (")")
    );

    /* delete expression */
    MATCH (READ_STR ("dt") && RULE (expression) && APPEND_CHR ('.') && RULE (unresolved_name));

    /* delete [] expression */
    MATCH (READ_STR ("pt") && RULE (expression) && APPEND_STR ("->") && RULE (unresolved_name));

    // dc <type> <expression>                               # dynamic_cast<type> (expression)
    MATCH (READ_STR ("ds") && RULE (expression) && APPEND_STR (".*") && RULE (expression));
    // sc <type> <expression>                               # static_cast<type> (expression)
    MATCH (
        READ_STR ("sP") && APPEND_STR ("sizeof...(") && RULE_MANY (template_arg) &&
        APPEND_CHR (')') && READ ('E')
    );
    // cc <type> <expression>                               # const_cast<type> (expression)
    MATCH (
        READ_STR ("fLpl") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" + ... + ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    // rc <type> <expression>                               # reinterpret_cast<type> (expression)
    MATCH (
        READ_STR ("fLmi") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" - ... - ") &&
        RULE (expression) && APPEND_CHR (')')
    );

    // ti <type>                                            # typeid (type)
    MATCH (
        READ_STR ("fLml") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" * ... * ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    // te <expression>                                      # typeid (expression)
    MATCH (
        READ_STR ("fLdv") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" / ... / ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    // st <type>                                            # sizeof (type)
    MATCH (
        READ_STR ("fLrm") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" % ... % ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    // sz <expression>                                      # sizeof (expression)
    MATCH (
        READ_STR ("fLan") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" & ... & ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    // at <type>                                            # alignof (type)
    MATCH (
        READ_STR ("fLor") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" | ... | ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    // az <expression>                                      # alignof (expression)
    MATCH (
        READ_STR ("fLeo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^ ... ^ ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    // nx <expression>                                      # noexcept (expression)
    MATCH (
        READ_STR ("fLaS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" = ... = ") &&
        RULE (expression) && APPEND_CHR (')')
    );

    MATCH (
        READ_STR ("fLpL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" += ... += ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLmI") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" -= ... -= ") &&
        RULE (expression) && APPEND_CHR (')')
    );

    MATCH (
        READ_STR ("fLmL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" *= ... *= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLdV") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" /= ... /= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLrM") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" %= ... %= ") &&
        RULE (expression) && APPEND_CHR (')')
    );

    MATCH (
        READ_STR ("fLaN") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" &= ... &= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLoR") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" |= ... |= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLeO") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^= ... ^= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLls") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" << ... << ") &&
        RULE (expression) && APPEND_CHR (')')
    );

    /* unary left fold */
    MATCH (
        READ_STR ("fLrs") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >> ... >> ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLlS") && APPEND_CHR ('(') && RULE (expression) &&
        APPEND_STR (" <<= ... <<= ") && RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLrS") && APPEND_CHR ('(') && RULE (expression) &&
        APPEND_STR (" >>= ... >>= ") && RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLeq") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" == ... == ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLne") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" != ... != ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLlt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" < ... < ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLgt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" > ... > ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLle") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <= ... <= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLge") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >= ... >= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLss") && APPEND_CHR ('(') && RULE (expression) &&
        APPEND_STR (" <=> ... <=> ") && RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLnt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ! ... ! ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLaa") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" && ... && ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fLoo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" || ... || ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRpl") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" + ... + ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRmi") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" - ... - ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRml") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" * ... * ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRdv") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" / ... / ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRrm") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" % ... % ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRan") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" & ... & ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRor") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" | ... | ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fReo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^ ... ^ ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRaS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" = ... = ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRpL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" += ... += ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRmI") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" -= ... -= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRmL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" *= ... *= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRdV") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" /= ... /= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRrM") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" %= ... %= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRaN") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" &= ... &= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRoR") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" |= ... |= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fReO") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^= ... ^= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRls") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" << ... << ") &&
        RULE (expression) && APPEND_CHR (')')
    );

    /* unary fold right */
    MATCH (
        READ_STR ("fRrs") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >> ... >> ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRlS") && APPEND_CHR ('(') && RULE (expression) &&
        APPEND_STR (" <<= ... <<= ") && RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRrS") && APPEND_CHR ('(') && RULE (expression) &&
        APPEND_STR (" >>= ... >>= ") && RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fReq") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" == ... == ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRne") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" != ... != ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRlt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" < ... < ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRgt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" > ... > ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRle") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <= ... <= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRge") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >= ... >= ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRss") && APPEND_CHR ('(') && RULE (expression) &&
        APPEND_STR (" <=> ... <=> ") && RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRnt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ! ... ! ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRaa") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" && ... && ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("fRoo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" || ... || ") &&
        RULE (expression) && APPEND_CHR (')')
    );
    MATCH (READ_STR ("ps") && APPEND_CHR ('+') && RULE (expression));
    MATCH (READ_STR ("ng") && APPEND_CHR ('-') && RULE (expression));
    MATCH (READ_STR ("ad") && APPEND_CHR ('&') && RULE (expression));
    MATCH (READ_STR ("de") && APPEND_CHR ('*') && RULE (expression));
    MATCH (READ_STR ("co") && APPEND_STR ("~") && RULE (expression));
    MATCH (READ_STR ("pp_") && APPEND_STR ("++") && RULE (expression));
    MATCH (READ_STR ("mm_") && APPEND_STR ("--") && RULE (expression));
    MATCH (READ_STR ("ti") && APPEND_STR ("typeid(") && RULE (type) && APPEND_STR (")"));
    MATCH (READ_STR ("te") && APPEND_STR ("typeid(") && RULE (expression) && APPEND_STR (")"));
    MATCH (READ_STR ("st") && APPEND_STR ("sizeof(") && RULE (type) && APPEND_STR (")"));
    MATCH (READ_STR ("sz") && APPEND_STR ("sizeof(") && RULE (expression) && APPEND_STR (")"));
    MATCH (READ_STR ("at") && APPEND_STR ("alignof(") && RULE (type) && APPEND_STR (")"));
    MATCH (READ_STR ("az") && APPEND_STR ("alignof(") && RULE (expression) && APPEND_STR (")"));
    MATCH (READ_STR ("nx") && APPEND_STR ("noexcept(") && RULE (expression) && APPEND_STR (")"));
    MATCH (READ_STR ("frss") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <=>..."));
    MATCH (
        READ_STR ("sZ") && APPEND_STR ("sizeof...(") && RULE (template_param) && APPEND_CHR (')')
    );
    MATCH (
        READ_STR ("sZ") && APPEND_STR ("sizeof...(") && RULE (function_param) && APPEND_CHR (')')
    );
    MATCH (READ_STR ("sp") && RULE (expression) && APPEND_STR ("..."));

    /* binary left fold */
    // clang-format off
    MATCH (READ_STR ("flpl") && APPEND_STR ("(... +") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flmi") && APPEND_STR ("(... -") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flml") && APPEND_STR ("(... *") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fldv") && APPEND_STR ("(... /") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrm") && APPEND_STR ("(... %") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flan") && APPEND_STR ("(... &") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flor") && APPEND_STR ("(... |") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fleo") && APPEND_STR ("(... ^") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flaS") && APPEND_STR ("(... =") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flpL") && APPEND_STR ("(... +=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flmI") && APPEND_STR ("(... -=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flmL") && APPEND_STR ("(... *=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fldV") && APPEND_STR ("(... /=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrM") && APPEND_STR ("(... %=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flaN") && APPEND_STR ("(... &=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("floR") && APPEND_STR ("(... |=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fleO") && APPEND_STR ("(... ^=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flls") && APPEND_STR ("(... <<") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrs") && APPEND_STR ("(... >>") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fllS") && APPEND_STR ("(... <<=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flrS") && APPEND_STR ("(... >>=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fleq") && APPEND_STR ("(... ==") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flne") && APPEND_STR ("(... !=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("fllt") && APPEND_STR ("(... <") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flgt") && APPEND_STR ("(... >") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flle") && APPEND_STR ("(... <=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flge") && APPEND_STR ("(... >=") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flss") && APPEND_STR ("(... <=>") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flnt") && APPEND_STR ("(... !") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("flaa") && APPEND_STR ("(... &&") && RULE (expression) && APPEND_CHR (')'));
    MATCH (READ_STR ("floo") && APPEND_STR ("(... ||") && RULE (expression) && APPEND_CHR (')'));

    /* binary fold right */
    MATCH (READ_STR ("frpl") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" + ...)"));
    MATCH (READ_STR ("frmi") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" - ...)"));
    MATCH (READ_STR ("frml") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" * ...)"));
    MATCH (READ_STR ("frdv") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" / ...)"));
    MATCH (READ_STR ("frrm") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" % ...)"));
    MATCH (READ_STR ("fran") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" & ...)"));
    MATCH (READ_STR ("fror") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" | ...)"));
    MATCH (READ_STR ("freo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^ ...)"));
    MATCH (READ_STR ("fraS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" = ...)"));
    MATCH (READ_STR ("frpL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" += ...)"));
    MATCH (READ_STR ("frmI") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" -= ...)"));
    MATCH (READ_STR ("frmL") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" *= ...)"));
    MATCH (READ_STR ("frdV") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" /= ...)"));
    MATCH (READ_STR ("frrM") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" %= ...)"));
    MATCH (READ_STR ("fraN") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" &= ...)"));
    MATCH (READ_STR ("froR") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" |= ...)"));
    MATCH (READ_STR ("freO") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ^= ...)"));
    MATCH (READ_STR ("frls") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" << ...)"));
    MATCH (READ_STR ("frrs") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >> ...)"));
    MATCH (READ_STR ("frlS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <<= ...)"));
    MATCH (READ_STR ("frrS") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >>= ...)"));
    MATCH (READ_STR ("freq") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" == ...)"));
    MATCH (READ_STR ("frne") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" != ...)"));
    MATCH (READ_STR ("frlt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" < ...)"));
    MATCH (READ_STR ("frgt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" > ...)"));
    MATCH (READ_STR ("frle") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" <= ...)"));
    MATCH (READ_STR ("frge") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" >= ...)"));
    MATCH (READ_STR ("frnt") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" ! ...)"));
    MATCH (READ_STR ("fraa") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" && ...)"));
    MATCH (READ_STR ("froo") && APPEND_CHR ('(') && RULE (expression) && APPEND_STR (" || ...)"));
    MATCH (READ_STR ("tw") && APPEND_STR ("throw ") && RULE (expression));
    // clang-format on

    // tw <expression>                                      # throw expression
    MATCH (RULE (template_param));
    // tr                                                   # throw with no operand (rethrow)
    MATCH (RULE (function_param));

    // u <source-name> <template-arg>* E                    # vendor extended expression
    MATCH (READ_STR ("tr") && APPEND_STR ("throw"));

    MATCH (RULE (unresolved_name));
    MATCH (RULE (expr_primary));
});


DEFN_RULE (simple_id, {
    MATCH (
        RULE (source_name) && APPEND_TYPE (dem) &&
        OPTIONAL (RULE (template_args) && APPEND_TYPE (dem))
    );
});



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
                vec_ptr_at (&m->template_params, sid)->name.buf) {
                FORCE_APPEND_TYPE (&vec_ptr_at (&m->template_params, sid)->name);
            }
            TRACE_RETURN_SUCCESS (meta_substitute_tparam (m, sid, dem));
        } else if (READ ('_')) {
            size_t sid = m->template_idx_start;
            if (m->template_params.length > sid &&
                vec_ptr_at (&m->template_params, sid)->name.buf) {
                FORCE_APPEND_TYPE (&vec_ptr_at (&m->template_params, sid)->name);
            }
            TRACE_RETURN_SUCCESS (meta_substitute_tparam (m, sid, dem));
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
                TRACE_RETURN_SUCCESS (dem);
            }
        } else {
            // matched single "_"
            st64 numlt10 = -1;
            READ_NUMBER (numlt10);
            if (numlt10 >= 0 && numlt10 < 10) {
                // do something
                TRACE_RETURN_SUCCESS (dem);
            }
        }
    }

    TRACE_RETURN_FAILURE();
});


DEFN_RULE (initializer, {
    MATCH (
        READ_STR ("pi") && APPEND_STR (" (") && RULE_MANY_WITH_SEP (expression, ", ") &&
        APPEND_CHR (')') && READ ('E')
    );
});


DEFN_RULE (abi_tag, {
    // will generate " \"<source_name>\","
    MATCH (READ ('B') && APPEND_STR (" \"") && RULE (source_name) && APPEND_STR ("\","));
});


DEFN_RULE (call_offset, {
    MATCH (READ ('h') && APPEND_STR ("non-virtual thunk to ") && RULE (nv_offset) && READ ('_'));
    MATCH (READ ('v') && APPEND_STR ("virtual thunk to ") && RULE (v_offset) && READ ('_'));
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
        READ_STR ("GR") && APPEND_STR ("reference temporary for ") && RULE (name) &&
        RULE (seq_id) && READ ('_')
    );
    MATCH (READ ('T') && RULE (call_offset) && RULE (encoding));
    MATCH (READ_STR ("GR") && APPEND_STR ("reference temporary for ") && RULE (name) && READ ('_'));
    MATCH (READ_STR ("TV") && APPEND_STR ("vtable for ") && RULE (type));
    MATCH (READ_STR ("TT") && APPEND_STR ("VTT structure for ") && RULE (type));
    MATCH (READ_STR ("TI") && APPEND_STR ("typeinfo for ") && RULE (type));
    MATCH (READ_STR ("TS") && APPEND_STR ("typeinfo name for ") && RULE (type));
    MATCH (READ_STR ("GV") && APPEND_STR ("guard variable for ") && RULE (name));
    MATCH (READ_STR ("GTt") && RULE (encoding));
});


DEFN_RULE (function_type, {
    DEFER_VAR (rtype);
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
        (RULE_DEFER (rtype, builtin_type) || ((RULE_DEFER (rtype, type)) && APPEND_TYPE (rtype))) &&
        APPEND_DEFER_VAR (rtype) &&

        // if a pointer then we'll have a function pointer (*)
        (is_ptr ? APPEND_STR (" (*)") : APPEND_CHR (' ')) &&

        // arguments
        APPEND_STR ("(") && RULE_ATLEAST_ONCE_WITH_SEP (type, ", ") && APPEND_STR (")") &&

        OPTIONAL (RULE (ref_qualifier)) && READ ('E')
    );
    dem_string_deinit (rtype);
});



DEFN_RULE (function_param, {
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && RULE (non_negative_number) &&
        READ ('_')
    );
    MATCH (
        READ_STR ("fL") && RULE (non_negative_number) && READ ('p') &&
        RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && READ ('_')
    );
    MATCH (
        READ_STR ("fp") && RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') &&
        RULE (non_negative_number) && READ ('_')
    );
    MATCH (READ_STR ("fp") && RULE (top_level_cv_qualifiers) && APPEND_CHR (' ') && READ ('_'));
    MATCH (READ_STR ("fPT"));
});


DEFN_RULE (builtin_type, {
    MATCH (READ_STR ("DF") && APPEND_STR ("_Float") && RULE (number) && READ ('_'));
    MATCH (
        READ_STR ("DF") && APPEND_STR ("_Float") && RULE (number) && READ ('x') && APPEND_STR ("x")
    );
    MATCH (
        READ_STR ("DF") && APPEND_STR ("std::bfloat") && RULE (number) && READ ('b') &&
        APPEND_STR ("_t")
    );
    MATCH (
        READ_STR ("DB") && APPEND_STR ("signed _BitInt(") && RULE (number) && APPEND_STR (")") &&
        READ ('_')
    );
    MATCH (
        READ_STR ("DB") && APPEND_STR ("signed _BitInt(") && RULE (expression) &&
        APPEND_STR (")") && READ ('_')
    );
    MATCH (
        READ_STR ("DU") && APPEND_STR ("unsigned _BitInt(") && RULE (number) && APPEND_STR (")") &&
        READ ('_')
    );
    MATCH (
        READ_STR ("DU") && APPEND_STR ("unsigned _BitInt(") && RULE (expression) &&
        APPEND_STR (")") && READ ('_')
    );
    MATCH (READ ('u') && RULE (source_name) && OPTIONAL (RULE (template_args)));
    MATCH (READ_STR ("DS") && READ_STR ("DA") && APPEND_STR ("_Sat _Accum"));
    MATCH (READ_STR ("DS") && READ_STR ("DR") && APPEND_STR ("_Sat _Fract"));
    MATCH (READ ('v') && APPEND_STR ("void"));
    MATCH (READ ('w') && APPEND_STR ("wchar_t"));
    MATCH (READ ('b') && APPEND_STR ("bool"));
    MATCH (READ ('c') && APPEND_STR ("char"));
    MATCH (READ ('a') && APPEND_STR ("signed char"));
    MATCH (READ ('h') && APPEND_STR ("unsigned char"));
    MATCH (READ ('s') && APPEND_STR ("short"));
    MATCH (READ ('t') && APPEND_STR ("unsigned short"));
    MATCH (READ ('i') && APPEND_STR ("int"));
    MATCH (READ ('j') && APPEND_STR ("unsigned int"));
    MATCH (READ ('l') && APPEND_STR ("long"));
    MATCH (READ ('m') && APPEND_STR ("unsigned long"));
    MATCH (READ ('x') && APPEND_STR ("long long"));
    MATCH (READ ('y') && APPEND_STR ("unsigned long long"));
    MATCH (READ ('n') && APPEND_STR ("__int128"));
    MATCH (READ ('o') && APPEND_STR ("unsigned __int128"));
    MATCH (READ ('f') && APPEND_STR ("float"));
    MATCH (READ ('d') && APPEND_STR ("double"));
    MATCH (READ ('e') && APPEND_STR ("long double"));
    MATCH (READ ('g') && APPEND_STR ("__float128"));
    MATCH (READ ('z') && APPEND_STR ("..."));
    MATCH (READ_STR ("Dd") && APPEND_STR ("decimal64"));
    MATCH (READ_STR ("De") && APPEND_STR ("decimal128"));
    MATCH (READ_STR ("Df") && APPEND_STR ("decimal32"));
    MATCH (READ_STR ("Dh") && APPEND_STR ("half"));
    MATCH (READ_STR ("Di") && APPEND_STR ("char32_t"));
    MATCH (READ_STR ("Ds") && APPEND_STR ("char16_t"));
    MATCH (READ_STR ("Du") && APPEND_STR ("char8_t"));
    MATCH (READ_STR ("Da") && APPEND_STR ("auto"));
    MATCH (READ_STR ("Dc") && APPEND_STR ("decltype(auto)"));
    MATCH (READ_STR ("Dn") && APPEND_STR ("std::nullptr_t"));
    MATCH (READ_STR ("DA") && APPEND_STR ("_Accum"));
    MATCH (READ_STR ("DR") && APPEND_STR ("_Fract"));
});


DEFN_RULE (extended_qualifier, {
    MATCH (READ ('U') && RULE (source_name) && RULE (template_args));
    MATCH (READ ('U') && RULE (source_name));
});

DemString* rule_source_name (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (source_name);
    /* positive number providing length of name followed by it */
    st64 name_len = 0;
    READ_NUMBER (name_len);

    if (name_len > 0) {
        /* identifiers don't start with digits or any other special characters */
        if (name_len-- && (IS_ALPHA (PEEK()) || PEEK() == '_')) {
            APPEND_CHR (PEEK());
            ADV();

            /* keep matching while length remains and a valid character is found*/
            while (name_len-- && (IS_ALPHA (PEEK()) || IS_DIGIT (PEEK()) || PEEK() == '_')) {
                APPEND_CHR (PEEK());
                ADV();
            }

            /* if length is non-zero after reading, then the name is invalid. */
            /* NOTE(brightprogrammer): for correct cases length actually goes "-1" here */
            if (name_len > 0) {
                TRACE_RETURN_FAILURE();
            }

            /* if atleast one character matches */
            TRACE_RETURN_SUCCESS (dem);
        }
    }

    RULE_FOOT (source_name);
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
    MATCH (OPTIONAL (READ_STR ("Ts") || READ_STR ("Tu") || READ_STR ("Te")) && RULE (name));
});


DEFN_RULE (bare_function_type, { MATCH (RULE_ATLEAST_ONCE_WITH_SEP (type, ", ")); });


DEFN_RULE (mangled_name, {
    MATCH (
        READ_STR ("_Z") && RULE (encoding) && OPTIONAL (READ ('.') && RULE (vendor_specific_suffix))
    );
});

DemString* rule_cv_qualifiers (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (cv_qualifiers);
    MATCH (READ ('K') && APPEND_STR (" const") && SET_CONST());
    MATCH (READ ('V') && APPEND_STR (" volatile"));
    MATCH (READ ('r') && APPEND_STR (" restrict"));
    RULE_FOOT (cv_qualifiers);
}

DemString*
    rule_qualifiers (DemString* dem, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (qualifiers);

    DEFER_VAR (dem_extended_qualifiers);
    (match_zero_or_more_rules (
        first_of_rule_extended_qualifier,
        rule_extended_qualifier,
        " ",
        dem_extended_qualifiers,
        msi,
        m,
        graph,
        _my_node_id
    ));
    MATCH_AND_DO (RULE (cv_qualifiers), {
        dem_extended_qualifiers->buf&& APPEND_CHR (' ') &&
            APPEND_STR (dem_extended_qualifiers->buf);
        dem_string_deinit (dem_extended_qualifiers);
    });

    RULE_FOOT (qualifiers);
}

DemString* rule_qualified_type (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (qualified_type);

    DemString dem_qualifiers = {0};
    DemString dem_type       = {0};
    if (rule_qualifiers (&dem_qualifiers, msi, m, graph, _my_node_id) &&
        rule_type_type (&dem_type, msi, m, graph, _my_node_id)) {
        dem_string_concat (dem, &dem_type) && dem_string_concat (dem, &dem_qualifiers);
        dem_string_deinit (&dem_qualifiers);
        dem_string_deinit (&dem_type);
        TRACE_RETURN_SUCCESS (dem);
    }
    TRACE_RETURN_FAILURE();

    RULE_FOOT (qualified_type);
}

DemString*
    rule_type_type (DemString* dem, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (type_type);

    MATCH (RULE (function_type));
    MATCH (RULE_CALL (qualified_type) && APPEND_TYPE (dem));
    MATCH (READ ('C') && RULE_CALL (type_type)); // complex pair (C99)
    MATCH (READ ('G') && RULE_CALL (type_type)); // imaginary (C99)
    MATCH (READ ('P') && RULE_CALL (type_type) && APPEND_STR ("*"));
    MATCH (READ ('R') && RULE_CALL (type_type) && APPEND_STR ("&"));
    MATCH (READ ('O') && RULE_CALL (type_type) && APPEND_STR ("&&"));
    // MATCH (RULE (template_template_param) && RULE (template_args));
    MATCH (RULE (template_param) && OPTIONAL (RULE (template_args)));
    MATCH (RULE (substitution) && RULE (template_args));
    MATCH (RULE (builtin_type));
    MATCH (READ_STR ("Dp") && RULE_CALL (type_type)); // pack expansion (C++11)

    // Extended qualifiers with CV qualifiers
    MATCH (RULE (class_enum_type) && APPEND_TYPE (dem));
    MATCH (RULE (array_type));
    MATCH (RULE (pointer_to_member_type));
    // MATCH (RULE (template_param));
    MATCH (RULE (decltype));
    MATCH (RULE (substitution));

    RULE_FOOT (type_type);
}

DemString*
    rule_type (DemString* dem, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (type);

    MATCH (rule_type_type (dem, msi, m, graph, _my_node_id) && APPEND_TYPE (dem));

    RULE_FOOT (type);
}



DEFN_RULE (template_arg, {
    MATCH (READ ('X') && RULE (expression) && READ ('E'));
    MATCH (READ ('J') && RULE_MANY (template_arg) && READ ('E'));
    MATCH (RULE (type));
    MATCH (RULE (expr_primary));
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
        return meta_substitute_type (m, sid + 1, dem);
    }
    if (PEEK() == '_') {
        return meta_substitute_type (m, 0, dem);
    }
});



DEFN_RULE (local_name, {
    MATCH (
        READ ('Z') && RULE (encoding) && READ_STR ("Ed") && OPTIONAL (RULE (number)) &&
        READ ('_') && APPEND_STR ("::") && RULE (name)
    );
    MATCH (
        READ ('Z') && RULE (encoding) && READ ('E') && APPEND_STR ("::") && RULE (name) &&
        OPTIONAL (RULE (discriminator))
    );
    MATCH (READ ('Z') && RULE (encoding) && READ_STR ("Es") && OPTIONAL (RULE (discriminator)));
});



DEFN_RULE (substitution, {
    // HACK(brightprogrammer): This is not in original grammar, but this works!
    // Because having a "7__cxx11" just after a substitution "St" does not make sense to original grammar
    // Placing it here is also important, the order matters!
    MATCH (READ ('S') && RULE (seq_id) && READ ('_'));

    MATCH (READ_STR ("St7__cxx11") && APPEND_STR ("std::__cxx11"));
    MATCH (READ_STR ("St") && APPEND_STR ("std"));
    MATCH (READ_STR ("Sa") && APPEND_STR ("std::allocator"));
    MATCH (READ_STR ("Sb") && APPEND_STR ("std::basic_string"));
    MATCH (
        READ_STR ("Ss") &&
        // APPEND_STR ("std::basic_string<char, std::char_traits<char>, std::allocator<char>>")
        APPEND_STR ("std::string")
    );
    MATCH (
        READ_STR ("Si") && APPEND_STR ("std::istream")
        // APPEND_STR ("std::basic_istream<char, std::char_traits<char>>")
    );
    MATCH (
        READ_STR ("So") && APPEND_STR ("std::ostream")
        // APPEND_STR ("std::basic_ostream<char, std::char_traits<char>>")
    );

    MATCH (
        READ_STR ("Sd") && APPEND_STR ("std::iostream")
        // APPEND_STR ("std::basic_iostream<char, std::char_traits<char>>")
    );
});




bool we_are_at_an_unqualified_name_starting (const char* p) {
    if (!p || !*p) {
        return false;
    }

    // Check for special global namespace replacement (starting with "12_GLOBAL__N_1")
    if (p[0] == '1' && p[1] == '2' && p[2] == '_' && strncmp (p, "12_GLOBAL__N_1", 14) == 0) {
        return true;
    }

    // Check for source_name (starting with digits)
    if (p[0] >= '0' && p[0] <= '9') {
        return true;
    }

    // Handle 'C' character patterns
    if (p[0] == 'C') {
        // Check for complete ctor names (C1, C2, C3, C4, C5, CI1, CI2)
        if (p[1] == '1' || p[1] == '2' || p[1] == '3' || p[1] == '4' || p[1] == '5') {
            return true;
        }
        if (p[1] == 'I' && p[2] && (p[2] == '1' || p[2] == '2')) {
            return true;
        }
        // Check for operator names starting with 'c'
        if (p[1] == 'o' || p[1] == 'l' || p[1] == 'm' || p[1] == 'p' || p[1] == 'v' ||
            p[1] == 'c') {
            return true;
        }
    }

    // Handle 'D' character patterns (more specific patterns first)
    if (p[0] == 'D') {
        // Check for structured binding declaration first (DC)
        if (p[1] == 'C') {
            return true;
        }
        // Check for dtor names (D0, D1, D2, D4, D5)
        if (p[1] == '0' || p[1] == '1' || p[1] == '2' || p[1] == '4' || p[1] == '5') {
            return true;
        }
        // Check for decltype (Dt, DT)
        if (p[1] == 't' || p[1] == 'T') {
            return true;
        }
        // Check for operator names starting with 'd'
        if (p[1] == 'l' || p[1] == 'a' || p[1] == 'e' || p[1] == 'v' || p[1] == 'V') {
            return true;
        }
    }

    // Check for operator names (match at least 2 characters when possible)
    if (p[0] == 'n') {
        if (p[1] == 'w' || p[1] == 'a' || p[1] == 'g' || p[1] == 't' || p[1] == 'x') {
            return true;
        }
    }
    if (p[0] == 'a') {
        if (p[1] == 'w' || p[1] == 'd' || p[1] == 'n' || p[1] == 'a' || p[1] == 'S' ||
            p[1] == 'N' || p[1] == 't' || p[1] == 'z') {
            return true;
        }
    }
    if (p[0] == 'p') {
        if (p[1] == 's' || p[1] == 'l' || p[1] == 'L' || p[1] == 'p' || p[1] == 'm' ||
            p[1] == 't') {
            return true;
        }
    }
    if (p[0] == 'm') {
        if (p[1] == 'i' || p[1] == 'l' || p[1] == 'I' || p[1] == 'L' || p[1] == 'm') {
            return true;
        }
    }
    if (p[0] == 'r') {
        if (p[1] == 'm' || p[1] == 's' || p[1] == 'M' || p[1] == 'S' || p[1] == 'c') {
            return true;
        }
    }
    if (p[0] == 'e') {
        if (p[1] == 'o' || p[1] == 'O' || p[1] == 'q') {
            return true;
        }
    }
    if (p[0] == 'l') {
        if (p[1] == 's' || p[1] == 'S' || p[1] == 't' || p[1] == 'e' || p[1] == 'i') {
            return true;
        }
    }
    if (p[0] == 'g') {
        if (p[1] == 't' || p[1] == 'e') {
            return true;
        }
    }
    if (p[0] == 's') {
        if (p[1] == 's' || p[1] == 'r' || p[1] == 'Z' || p[1] == 'P' || p[1] == 'p' ||
            p[1] == 't' || p[1] == 'z' || p[1] == 'c') {
            return true;
        }
    }
    if (p[0] == 'o') {
        if (p[1] == 'r' || p[1] == 'R' || p[1] == 'o' || p[1] == 'n') {
            return true;
        }
    }
    if (p[0] == 'q') {
        if (p[1] == 'u') {
            return true;
        }
    }
    if (p[0] == 'i') {
        if (p[1] == 'x' || p[1] == 'l') {
            return true;
        }
    }
    if (p[0] == 't') {
        if (p[1] == 'i' || p[1] == 'e' || p[1] == 'l' || p[1] == 'w' || p[1] == 'r') {
            return true;
        }
    }
    if (p[0] == 'f') {
        if (p[1] == 'l' || p[1] == 'r' || p[1] == 'L' || p[1] == 'R' || p[1] == 'p') {
            return true;
        }
    }
    if (p[0] == 'v') {
        // vendor extended operator: v {digit} {source-name}
        if (p[1] >= '0' && p[1] <= '9') {
            return true;
        }
    }

    // Check for unnamed_type_name (starting with 'U')
    if (p[0] == 'U') {
        if (p[1] == 't' || p[1] == 'l') { // Ut for unnamed type, Ul for closure/lambda
            return true;
        }
    }

    // Check for template parameters (T_ or T{number}_)
    if (p[0] == 'T') {
        if (p[1] == '_' || (p[1] >= '0' && p[1] <= '9')) {
            return true;
        }
    }

    // Check for substitutions (S_ or S{seq-id}_ or special ones like St, Sa, Sb, Ss, Si, So, Sd)
    if (p[0] == 'S') {
        if (p[1] == '_' || p[1] == 't' || p[1] == 'a' || p[1] == 'b' || p[1] == 's' ||
            p[1] == 'i' || p[1] == 'o' || p[1] == 'd' || (p[1] >= '0' && p[1] <= '9') ||
            (p[1] >= 'A' && p[1] <= 'Z')) {
            return true;
        }
    }

    // Check for vendor extended expressions/types starting with 'u'
    if (p[0] == 'u') {
        return true;
    }

    return false;
}

DEFN_RULE (operator_name, {
    MATCH (READ ('v') && RULE (digit) && RULE (source_name));
    MATCH (READ_STR ("cv") && APPEND_STR ("operator (") && RULE (type) && APPEND_STR (")"));
    MATCH (READ_STR ("nw") && APPEND_STR ("operator new"));
    MATCH (READ_STR ("na") && APPEND_STR ("operator new[]"));
    MATCH (READ_STR ("dl") && APPEND_STR ("operator delete"));
    MATCH (READ_STR ("da") && APPEND_STR ("operator delete[]"));
    MATCH (READ_STR ("aw") && APPEND_STR ("operator co_await"));
    MATCH (READ_STR ("ps") && APPEND_STR ("operator+"));
    MATCH (READ_STR ("ng") && APPEND_STR ("operator-"));
    MATCH (READ_STR ("ad") && APPEND_STR ("operator&"));
    MATCH (READ_STR ("de") && APPEND_STR ("operator*"));
    MATCH (READ_STR ("co") && APPEND_STR ("operator~"));
    MATCH (READ_STR ("pl") && APPEND_STR ("operator+"));
    MATCH (READ_STR ("mi") && APPEND_STR ("operator-"));
    MATCH (READ_STR ("ml") && APPEND_STR ("operator*"));
    MATCH (READ_STR ("dv") && APPEND_STR ("operator/"));
    MATCH (READ_STR ("rm") && APPEND_STR ("operator%"));
    MATCH (READ_STR ("an") && APPEND_STR ("operator&"));
    MATCH (READ_STR ("or") && APPEND_STR ("operator|"));
    MATCH (READ_STR ("eo") && APPEND_STR ("operator^"));
    MATCH (READ_STR ("aS") && APPEND_STR ("operator="));
    MATCH (READ_STR ("pL") && APPEND_STR ("operator+="));
    MATCH (READ_STR ("mI") && APPEND_STR ("operator-="));
    MATCH (READ_STR ("mL") && APPEND_STR ("operator*="));
    MATCH (READ_STR ("dV") && APPEND_STR ("operator/="));
    MATCH (READ_STR ("rM") && APPEND_STR ("operator%="));
    MATCH (READ_STR ("aN") && APPEND_STR ("operator&="));
    MATCH (READ_STR ("oR") && APPEND_STR ("operator|="));
    MATCH (READ_STR ("eO") && APPEND_STR ("operator^="));
    MATCH (READ_STR ("ls") && APPEND_STR ("operator<<"));
    MATCH (READ_STR ("rs") && APPEND_STR ("operator>>"));
    MATCH (READ_STR ("lS") && APPEND_STR ("operator<<="));
    MATCH (READ_STR ("rS") && APPEND_STR ("operator>>="));
    MATCH (READ_STR ("eq") && APPEND_STR ("operator=="));
    MATCH (READ_STR ("ne") && APPEND_STR ("operator!="));
    MATCH (READ_STR ("lt") && APPEND_STR ("operator<"));
    MATCH (READ_STR ("gt") && APPEND_STR ("operator>"));
    MATCH (READ_STR ("le") && APPEND_STR ("operator<="));
    MATCH (READ_STR ("ge") && APPEND_STR ("operator>="));
    MATCH (READ_STR ("ss") && APPEND_STR ("operator<=>"));
    MATCH (READ_STR ("nt") && APPEND_STR ("operator!"));
    MATCH (READ_STR ("aa") && APPEND_STR ("operator&&"));
    MATCH (READ_STR ("oo") && APPEND_STR ("operator||"));
    MATCH (READ_STR ("pp") && APPEND_STR ("operator++"));
    MATCH (READ_STR ("mm") && APPEND_STR ("operator--"));
    MATCH (READ_STR ("cm") && APPEND_STR ("operator,"));
    MATCH (READ_STR ("pm") && APPEND_STR ("operator->*"));
    MATCH (READ_STR ("pt") && APPEND_STR ("operator->"));
    MATCH (READ_STR ("cl") && APPEND_STR ("operator()"));

    /* will generate " (type)" */
    MATCH (READ_STR ("ix") && APPEND_STR ("operator[]"));

    /* operator-name ::= li <source-name>          # operator ""*/
    MATCH (
        READ_STR ("li") && RULE (source_name)
    ); // TODO(brightprogrammer): How to generate for this operator?

    MATCH (READ_STR ("qu") && APPEND_STR ("operator?"));
});


DEFN_RULE (float, {
    bool r = false;
    while (IS_DIGIT (PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
        r = true;
        ADV();
    }
    return r ? dem : NULL;
});


DEFN_RULE (destructor_name, {
    MATCH (RULE (unresolved_type));
    MATCH (RULE (simple_id));
});


DemString*
    rule_name (DemString* dem, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (name);
    DEFER_VAR (dem_template_args);

    MATCH_AND_CONTINUE (RULE (unscoped_name) && RULE_DEFER (dem_template_args, template_args));
    if (dem_template_args->buf) {
        APPEND_TYPE (dem);
        dem_string_concat (dem, dem_template_args);
        dem_string_deinit (dem_template_args);
        APPEND_TYPE (dem);
        TRACE_RETURN_SUCCESS (dem);
    }

    MATCH (RULE (substitution) && RULE (template_args) && APPEND_TYPE (dem));

    MATCH (RULE (nested_name)
    ); // NOTE: Nested name adds type selectively automatically, so no need to do it here!
    MATCH (RULE (unscoped_name));
    MATCH (RULE (local_name) && APPEND_TYPE (dem));

    RULE_FOOT (name);
}



// NOTE: Prefix parsing does not work well with multiple unqualified names
// We can create a new rule named second_last_unqualified_name and perform a trick
// to get the second last unqualified name always.
DECL_RULE (nested_name_with_substitution_only);
DemString* rule_nested_name (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (nested_name);
    DEFER_VAR (ref);
    DEFER_VAR (pfx);
    DEFER_VAR (uname);
    DEFER_VAR (dem_cv_qualifiers);

    bool is_ctor = false;
    bool is_dtor = false;

    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <ctor-name> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <dtor-name> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE_DEFER (dem_cv_qualifiers, cv_qualifiers)) &&
            OPTIONAL (RULE_DEFER (ref, ref_qualifier)) && RULE_DEFER (pfx, prefix) &&
            ((is_ctor = !!RULE (ctor_name)) || (is_dtor = !!RULE (dtor_name)) ||
             RULE_DEFER (uname, unqualified_name)) &&
            READ ('E'),
        {
            if (is_ctor || is_dtor) {
                dem_string_concat (dem, pfx);
            } else {
                dem_string_concat (dem, pfx);
                APPEND_TYPE (dem);
                dem_string_append_n (dem, "::", 2);
                dem_string_concat (dem, uname);
            }

            dem_string_deinit (pfx);
            dem_string_deinit (uname);
            dem_string_deinit (dem_cv_qualifiers);

            if (ref->len) {
                APPEND_STR (" ");
                (void)APPEND_DEFER_VAR (ref);
                APPEND_TYPE (dem);
            }
        }
    );

    dem_string_deinit (pfx);
    dem_string_deinit (ref);
    dem_string_deinit (dem_cv_qualifiers);
    dem_string_deinit (uname);
    is_ctor = is_dtor = false;

    DEFER_VAR (targs);

    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <ctor-name> <template-args> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <dtor-name> <template-args> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <unqualified-name> <template-args> E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE_DEFER (dem_cv_qualifiers, cv_qualifiers)) &&
            OPTIONAL (RULE_DEFER (ref, ref_qualifier)) && RULE_DEFER (pfx, template_prefix) &&
            ((is_ctor = !!RULE (ctor_name)) || (is_dtor = !!RULE (dtor_name)) ||
             RULE_DEFER (uname, unqualified_name)),
        {
            dem_string_concat (dem, pfx);
            if (!is_ctor && !is_dtor) {
                APPEND_TYPE (dem);
                dem_string_append_n (dem, "::", 2);
                dem_string_concat (dem, uname);
                APPEND_TYPE (dem);
            }

            dem_string_deinit (pfx);
            dem_string_deinit (uname);
            dem_string_deinit (dem_cv_qualifiers);

            if (RULE_DEFER (targs, template_args) && READ ('E')) {
                dem_string_concat (dem, targs);
                APPEND_TYPE (dem);
                dem_string_deinit (targs);
            } else {
                dem_string_deinit (targs);
                TRACE_RETURN_FAILURE();
            }

            if (ref->len) {
                APPEND_STR (" ");
                (void)APPEND_DEFER_VAR (ref);
                APPEND_TYPE (dem);
            }
        }
    );

    dem_string_deinit (pfx);
    dem_string_deinit (ref);
    dem_string_deinit (dem_cv_qualifiers);
    dem_string_deinit (targs);
    dem_string_deinit (uname);

    MATCH (RULE (nested_name_with_substitution_only));

    RULE_FOOT (nested_name);
}

DEFN_RULE (nested_name_with_substitution_only, {
    DEFER_VAR (ref);
    DEFER_VAR (targs);
    Name*  substituted_name = NULL;
    size_t sid              = 0;

    // N [<CV-qualifiers>] [<ref-qualifier>] S<seq-id>_ [I<template-args>E] E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) &&
            OPTIONAL (RULE_DEFER (ref, ref_qualifier)) && READ ('S') &&
            (sid = parse_sequence_id (msi, m)) && (m->detected_types.length > sid - 1) &&
            (substituted_name = vec_ptr_at (&m->detected_types, sid - 1)) &&
            (substituted_name->num_parts > 1) && OPTIONAL (RULE_DEFER (targs, template_args)) &&
            READ ('E'),
        {
            dem_string_concat (dem, &substituted_name->name);

            if (targs->len) {
                (void)APPEND_DEFER_VAR (targs);
                APPEND_TYPE (dem);
            }

            // Add ref-qualifier if present
            if (ref->len) {
                APPEND_STR (" ");
                (void)APPEND_DEFER_VAR (ref);
                APPEND_TYPE (dem);
            }
        }
    );

    dem_string_deinit (ref);
    dem_string_deinit (targs);
});



DEFN_RULE (template_template_param, {
    MATCH (RULE (template_param));
    MATCH (RULE (substitution));
});


DEFN_RULE (ctor_name, {
    // NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
    MATCH (READ_STR ("C1") && SET_CTOR()); // gnu complete object ctor
    MATCH (READ_STR ("C2") && SET_CTOR()); // gnu base object ctor
    MATCH (READ_STR ("C3") && SET_CTOR()); // gnu complete object allocating ctor
    MATCH (READ_STR ("C4") && SET_CTOR()); // gnu unified ctor
    MATCH (READ_STR ("C5") && SET_CTOR()); // gnu object ctor group
    MATCH (READ_STR ("CI1") && SET_CTOR());
    MATCH (READ_STR ("CI2") && SET_CTOR());
});

DEFN_RULE (dtor_name, {
    // NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
    MATCH (READ_STR ("D0") && SET_DTOR()); // gnu deleting dtor
    MATCH (READ_STR ("D1") && SET_DTOR()); // gnu complete object dtor
    MATCH (READ_STR ("D2") && SET_DTOR()); // gnu base object dtor
    // 3 is not used
    MATCH (READ_STR ("D4") && SET_DTOR()); // gnu unified dtor
    MATCH (READ_STR ("D5") && SET_DTOR()); // gnu object dtor group
});

DEFN_RULE (ctor_dtor_name, {
    MATCH (RULE (ctor_name));
    MATCH (RULE (dtor_name));
});

DEFN_RULE (nv_digit, {
    if (IS_DIGIT (PEEK())) {
        ADV();
        TRACE_RETURN_SUCCESS (dem);
    }

    TRACE_RETURN_FAILURE();
});

#define first_of_rule_nv_digit first_of_rule_digit

DEFN_RULE (nv_offset, { MATCH (OPTIONAL (READ ('n')) && RULE_ATLEAST_ONCE (nv_digit)); });


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
        OPTIONAL ((is_const = IS_CONST()) && UNSET_CONST()) && READ ('I') && APPEND_CHR ('<') &&
            RULE_ATLEAST_ONCE_WITH_SEP (template_arg, ", ") && APPEND_CHR ('>') && READ ('E'),
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
        dem_string_append_char (dem, '1');
        TRACE_RETURN_SUCCESS (dem);
    }

    char* e   = NULL;
    ut32  num = strtoul (CUR(), &e, 10) + 2;
    if (!e) {
        TRACE_RETURN_FAILURE();
    }
    dem_string_appendf (dem, "%u", num);
    msi->cur = e;

    TRACE_RETURN_SUCCESS (dem);
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
            TRACE_RETURN_SUCCESS (dem);
        }
    } else if (READ_STR ("Ul")) {
        DEFER_VAR (d);
        MATCH (
            APPEND_STR ("{lambda(") && RULE_ATLEAST_ONCE_WITH_SEP (type, ", ") && READ ('E') &&
            APPEND_CHR (')') &&
            OPTIONAL (RULE_DEFER (d, non_neg_number) && APPEND_CHR ('#') && APPEND_DEFER_VAR (d)) &&
            APPEND_CHR ('}') && APPEND_TYPE (dem)
        );
    }

    TRACE_RETURN_FAILURE();
});



DEFN_RULE (pointer_to_member_type, { MATCH (READ ('M') && RULE (type) && RULE (type)); });


DEFN_RULE (ref_qualifier, {
    MATCH (READ ('R') && APPEND_STR ("&"));
    MATCH (READ ('O') && APPEND_STR ("&&"));
});


bool is_template (DemString* n) {
    return n->buf[n->len - 1] == '>' && n->buf[n->len - 2] != '>';
}

DemString*
    rule_encoding (DemString* dem, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (encoding);

    bool is_const_fn = false;
    DEFER_VAR (n);
    DEFER_VAR (rt);
    DEFER_VAR (p);

    MATCH (
        // determine if this function has const or const& at the end
        OPTIONAL (
            is_const_fn = (PEEK_AT (0) == 'N' && PEEK_AT (1) == 'K') || (PEEK_AT (0) == 'K')
        ) &&

        // get function name (can be template or non-template)
        RULE_DEFER (n, name) && dem_string_concat (dem, n) &&

        // determine whether this is a template function alongside normal demangling
        // template functions specify a return type
        // If this is a template function then get return type first
        OPTIONAL (
            is_template (n) && RULE_DEFER (rt, type) && dem_string_append_prefix_n (dem, " ", 1) &&
            dem_string_append_prefix_n (dem, rt->buf, rt->len) && (dem_string_deinit (rt), 1)
        ) &&

        // get function params
        // set it as optional, because there's a rule which just matches for name,
        // so to supress the noise of backtracking, we just make it optional here
        OPTIONAL (
            RULE_DEFER (p, bare_function_type) && APPEND_CHR ('(') && APPEND_DEFER_VAR (p) &&
            APPEND_CHR (')')
        ) &&

        // append const if it was detected to be a constant function
        OPTIONAL (is_const_fn && APPEND_STR (" const")) &&

        // deinit name on a successful match for
        // - name
        // - name <params>
        // - <ret> name <params>
        (dem_string_deinit (n), 1)
    );

    dem_string_deinit (n);
    dem_string_deinit (rt);
    dem_string_deinit (p);

    // MATCH (RULE (name));

    MATCH (RULE (special_name));

    RULE_FOOT (encoding);
}

DEFN_RULE (braced_expression, {
    MATCH (
        READ_STR ("dX") && APPEND_STR (" [") && RULE (range_begin_expression) &&
        APPEND_STR (" ... ") && RULE (range_end_expression) && APPEND_STR ("] = ") &&
        RULE (braced_expression)
    );
    MATCH (
        READ_STR ("di") && APPEND_STR (" .") && RULE (field_source_name) && APPEND_STR (" = ") &&
        RULE (braced_expression)
    );
    MATCH (
        READ_STR ("dx") && APPEND_STR (" [") && RULE (index_expression) && APPEND_STR ("] = ") &&
        RULE (braced_expression)
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
    DEFER_VAR (t);
    DEFER_VAR (n);

    MATCH (
        READ ('L') && RULE (type) && RULE (real_part_float) && READ ('_') &&
        RULE (imag_part_float) && READ ('E')
    );
    MATCH (
        READ ('L') && APPEND_STR ("(") && (PEEK() == 'P') && RULE (pointer_type) &&
        APPEND_STR (")") && READ ('0') && APPEND_CHR ('0') && READ ('E')
    );
    MATCH (
        READ ('L') && RULE_DEFER (t, type) && RULE_DEFER (n, value_number) &&
        OPTIONAL (
            // change to bool
            !strcmp (t->buf, "bool") ?
                (!strcmp (n->buf, "0") ? (dem_string_deinit (t),
                                          dem_string_deinit (n),
                                          dem_string_append_n (dem, "false", 5)) :
                                         (dem_string_deinit (t),
                                          dem_string_deinit (n),
                                          dem_string_append_n (dem, "true", 4))) :
                // shorten unsigned int typecast
                !strcmp (t->buf, "unsigned int") ?
                (dem_string_deinit (t), APPEND_DEFER_VAR (n) && dem_string_append_char (dem, 'u')) :
                true
        ) &&
        READ ('E')
    );

    dem_string_deinit (t);
    dem_string_deinit (n);

    MATCH (READ ('L') && RULE (type) && RULE (value_float) && READ ('E'));

    MATCH (READ ('L') && RULE (string_type) && READ ('E'));
    MATCH (READ_STR ("L_Z") && RULE (encoding) && READ ('E'));
    MATCH (READ_STR ("LDnE") && APPEND_STR ("decltype(nullptr)0"));
    MATCH (READ_STR ("LDn0E") && APPEND_STR ("(decltype(nullptr))0"));
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

DemString* rule_prefix_suffix (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (prefix_suffix);
    MATCH (OPTIONAL (RULE (template_args)) && OPTIONAL (READ ('M')));
    RULE_FOOT (prefix_suffix);
}

DemString* rule_prefix_start (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (prefix_start);

    MATCH (RULE (decltype));
    MATCH (RULE (unqualified_name) && OPTIONAL (RULE_CALL (prefix_suffix)));
    MATCH (RULE (template_param) && OPTIONAL (RULE_CALL (prefix_suffix)));
    MATCH (RULE (substitution) && OPTIONAL (RULE_CALL (prefix_suffix)));

    RULE_FOOT (prefix_start);
}

DemString* rule_prefix_tail (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (prefix_tail);

    MATCH (
        RULE (unqualified_name) && OPTIONAL (RULE_CALL (prefix_suffix)) &&
        OPTIONAL (RULE_CALL (prefix_tail))
    );

    RULE_FOOT (prefix_tail);
}

DemString*
    rule_prefix (DemString* dem, StrIter* msi, Meta* m, TraceGraph* graph, int parent_node_id) {
    RULE_HEAD (prefix);

    MATCH (RULE_CALL (prefix_start) && OPTIONAL (RULE_CALL (prefix_tail)));

    RULE_FOOT (prefix);
}

/**
 * <template-prefix> ::= <template unqualified-name>           # global template
 *                   ::= <prefix> <template unqualified-name>  # nested template
 *                   ::= <template-param>                      # template template parameter
 *                   ::= <substitution>
*/
DemString* rule_template_prefix (
    DemString*  dem,
    StrIter*    msi,
    Meta*       m,
    TraceGraph* graph,
    int         parent_node_id
) {
    RULE_HEAD (template_prefix);

    MATCH (RULE (unqualified_name));
    MATCH (RULE_CALL (prefix) && RULE (unqualified_name));
    MATCH (RULE (template_param));
    MATCH (RULE (substitution));

    RULE_FOOT (template_prefix);
}

char* demangle_rule (const char* mangled, DemRule rule, CpDemOptions opts) {
    if (!mangled) {
        return NULL;
    }

    StrIter  si  = {.beg = mangled, .cur = mangled, .end = mangled + strlen (mangled) + 1};
    StrIter* msi = &si;

    DemString* dem = dem_string_new();

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

    if (rule (dem, msi, m, graph, -1)) {
        // Output graphviz trace if enabled
        if (graph->enabled) {
            // Mark the final successful path
            trace_graph_mark_final_path (graph);

            char graph_filename[256] = {0};
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
        names_deinit (&m->detected_types);

        return dem_string_drain (dem);
    } else {
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
        vec_deinit (&meta.detected_types);
        dem_string_free (dem);
        return NULL;
    }

    return NULL;
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
