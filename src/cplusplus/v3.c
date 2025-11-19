// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Documentation for used grammar can be found at either of
 * - https://files.brightprogrammer.in/cxx-abi/
 * - https://itanium-cxx-abi.github.io/cxx-abi/
 */

#include "demangle.h"
#include "first.h"
#include "macros.h"
#include "types.h"
#include "v3.h"

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
// NOTE(brightprogrammer):
// Manual replacements, this is not in original grammar
#if REPLACE_GLOBAL_N_WITH_ANON_NAMESPACE
    MATCH (READ_STR ("DC") && RULE_ATLEAST_ONCE (source_name) && READ ('E'));
#endif

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
    MATCH (READ_STR ("St") && APPEND_STR ("std::") && RULE (unqualified_name) && APPEND_TYPE (dem));
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


DEFN_RULE (closure_prefix, {
    // {closure-prefix-unit}
    MATCH (RULE (closure_prefix_unit) && RULE (closure_prefix_rr));

    // {closure-prefix-unit} {closure-prefix-rr}
    MATCH (RULE (closure_prefix_unit));
});


DEFN_RULE (simple_id, {
    MATCH (
        RULE (source_name) && APPEND_TYPE (dem) &&
        OPTIONAL (RULE (template_args) && APPEND_TYPE (dem))
    );
});


DEFN_RULE (prefix_start_unit, {
    DEFER_VAR (cname);
    MATCH (
        RULE_DEFER (cname, prefix_or_template_prefix_start) && dem_string_concat (dem, cname) &&
        APPEND_TYPE (dem) && OPTIONAL (RULE (template_args) && APPEND_TYPE (dem)) &&
        OPTIONAL (
            (first_of_rule_ctor_name (CUR()) && APPEND_STR ("::") && dem_string_concat (dem, cname)
            ) ||
            (first_of_rule_dtor_name (CUR()) && APPEND_STR ("::~") && dem_string_concat (dem, cname)
            )
        ) &&
        (dem_string_deinit (cname), 1)
    );
    dem_string_deinit (cname);

    MATCH (RULE (decltype) && APPEND_TYPE (dem));
    MATCH (RULE (closure_prefix));
});



DEFN_RULE (template_param, {
    SAVE_POS();
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
                RESTORE_POS();
                TRACE_RETURN_FAILURE();
            }
            sid = sid + m->template_idx_start;
            if (m->template_params.length > sid &&
                vec_ptr_at (&m->template_params, sid)->name.buf) {
                FORCE_APPEND_TYPE (&vec_ptr_at (&m->template_params, sid)->name);
            }
            TRACE_RETURN_SUCCESS (SUBSTITUTE_TPARAM (m, sid, dem));
        } else if (READ ('_')) {
            size_t sid = m->template_idx_start;
            if (m->template_params.length > sid &&
                vec_ptr_at (&m->template_params, sid)->name.buf) {
                FORCE_APPEND_TYPE (&vec_ptr_at (&m->template_params, sid)->name);
            }
            TRACE_RETURN_SUCCESS (SUBSTITUTE_TPARAM (m, sid, dem));
        }
    }
    RESTORE_POS();
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


DEFN_RULE (prefix_start_rr, {
    DEFER_VAR (pfx_rr);
    DEFER_VAR (cname);
    // {prefix-nested-class-or-namespace} {ctor-dtor-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (
        RULE (prefix_nested_class_or_namespace) && APPEND_TYPE (dem) &&
        OPTIONAL (
            (RULE (ctor_name) && APPEND_STR ("::")) || (RULE (dtor_name) && APPEND_STR ("::~"))
        ) &&
        dem_string_append (dem, extract_last_unqualified_name (dem)) && RULE (template_args) &&
        APPEND_TYPE (dem) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        )
    );

    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (
        RULE (prefix_nested_class_or_namespace) && APPEND_STR ("::") && RULE (unqualified_name) &&
        APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        )
    );
    dem_string_deinit (pfx_rr);

    // {unqualified-name} {template-args} [optional: {prefix-start-rr}]
    MATCH (
        RULE_DEFER (cname, unqualified_name) && dem_string_concat (dem, cname) &&
        APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        ) &&
        OPTIONAL (
            (first_of_rule_ctor_name (CUR()) && APPEND_STR ("::") && dem_string_concat (dem, cname)
            ) ||
            (first_of_rule_dtor_name (CUR()) && APPEND_STR ("::~") && dem_string_concat (dem, cname)
            )
        ) &&
        (dem_string_deinit (cname), 1)
    );
    dem_string_deinit (cname);
    dem_string_deinit (pfx_rr);
});



DemString* get_last_nested_name (DemString* full, DemString* last) {
    const char* b = strrchr (full->buf, ':');
    b             = b ? b + 1 : full->buf;

    dem_string_init (last);
    dem_string_appends (last, b);

    return last;
}

DEFN_RULE (prefix, {
    DEFER_VAR (pfx_nested);
    DEFER_VAR (last_name);
    // {prefix-start} {prefix-nested-class-or-namespace}
    // {prefix-start}
    MATCH (
        RULE (prefix_start) &&
        OPTIONAL (
            RULE_DEFER (pfx_nested, prefix_nested_class_or_namespace) && APPEND_STR ("::") &&
            dem_string_concat (dem, pfx_nested) && APPEND_TYPE (dem) &&
            OPTIONAL (
                first_of_rule_ctor_name (CUR()) ?
                    (APPEND_STR ("::") && get_last_nested_name (pfx_nested, last_name) &&
                     dem_string_concat (dem, last_name)) :
                first_of_rule_dtor_name (CUR()) ?
                    (APPEND_STR ("::~") && get_last_nested_name (pfx_nested, last_name) &&
                     dem_string_concat (dem, last_name)) :
                    (0)
            ) &&
            (dem_string_deinit (last_name), dem_string_deinit (pfx_nested), 1)
        )
    );
});



DEFN_RULE (cv_qualifiers, {
    MATCH (READ ('r') && APPEND_STR ("restrict"));
    MATCH (READ ('V') && APPEND_STR ("volatile"));
    MATCH (READ ('K') && SET_CONST());
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


DEFN_RULE (source_name, {
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

    TRACE_RETURN_FAILURE();
});


DEFN_RULE (abi_tags, { MATCH (RULE_ATLEAST_ONCE (abi_tag)); });


DEFN_RULE (prefix_start, {
    DEFER_VAR (pfx_rr);
    MATCH (
        RULE (prefix_start_unit) &&
        OPTIONAL (
            RULE_DEFER (pfx_rr, prefix_start_rr) && APPEND_STR ("::") && APPEND_DEFER_VAR (pfx_rr)
        )
    );
});



bool meta_tmp_init (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return false;
    }

    vec_concat (&tmp->detected_types, &og->detected_types);
    vec_concat (&tmp->template_params, &og->template_params);
    vec_concat (&tmp->parent_type_kinds, &og->parent_type_kinds);
    ;
    tmp->is_ctor  = og->is_ctor;
    tmp->is_dtor  = og->is_dtor;
    tmp->is_const = og->is_const;

    tmp->template_idx_start    = og->template_idx_start;
    tmp->last_reset_idx        = og->last_reset_idx;
    tmp->t_level               = og->t_level;
    tmp->template_reset        = og->template_reset;
    tmp->is_ctor_or_dtor_at_l0 = og->is_ctor_or_dtor_at_l0;

    return false;
}

void meta_tmp_apply (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return;
    }

    // transfer of ownership from tmp to og
    vec_move (&og->detected_types, &tmp->detected_types);
    vec_move (&og->template_params, &tmp->template_params);
    vec_move (&og->parent_type_kinds, &tmp->parent_type_kinds);

    og->is_ctor  = tmp->is_ctor;
    og->is_dtor  = tmp->is_dtor;
    og->is_const = tmp->is_const;

    og->template_idx_start    = tmp->template_idx_start;
    og->last_reset_idx        = tmp->last_reset_idx;
    og->t_level               = tmp->t_level;
    og->template_reset        = tmp->template_reset;
    og->is_ctor_or_dtor_at_l0 = tmp->is_ctor_or_dtor_at_l0;
}

void meta_tmp_fini (Meta* og, Meta* tmp) {
    if (!og || !tmp) {
        return;
    }

    // Only clean up newly added items in tmp (beyond og's original length)
    // Items 0..og->length-1 are shared and should not be cleaned up
    for (size_t i = og->detected_types.length; i < tmp->detected_types.length; i++) {
        Name* dt = vec_ptr_at (&tmp->detected_types, i);
        dem_string_deinit (&dt->name);
        dt->num_parts = 0;
    }
    UNUSED (vec_deinit (&tmp->detected_types));

    for (size_t i = og->template_params.length; i < tmp->template_params.length; i++) {
        Name* tp = vec_ptr_at (&tmp->template_params, i);
        dem_string_deinit (&tp->name);
        tp->num_parts = 0;
    }
    UNUSED (vec_deinit (&tmp->template_params));
    UNUSED (vec_deinit (&tmp->parent_type_kinds));

    memset (tmp, 0, sizeof (*tmp));
}

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

/**
 * \b Takes a rule and matches at least one occurence of it.
 * Meaning one or more rule matches. If not even a single match is available,
 * then returns NULL.
 *
 * \p rule  Rule to apply one or more times.
 * \p dem   Demangled string will be stored here.
 * \p msi   Mangled string iter.
 *
 * \return dem If at least one rule match exists for given rule.
 * \return NULL otherwise.
 */
DemString* match_one_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
) {
    if (!first || !rule || !dem || !msi || !m) {
        return NULL;
    }

    // NOTE(brightprogrammer): Just here to check the current iteration in debugger
    // No special use
    ut32 iter_for_dbg = 0;

    SAVE_POS();
    /* match atleast once, and then */
    if (first (CUR()) && rule (dem, msi, m, graph, parent_node_id) && ++iter_for_dbg) {
        /* match as many as possible */
        while (first (CUR())) {
            DemString tmp = {0};
            SAVE_POS();
            if (rule (&tmp, msi, m, graph, parent_node_id) && ++iter_for_dbg) {
                /* add separator before appending demangled string */
                if (sep) {
                    dem_string_append_prefix_n (&tmp, sep, strlen (sep));
                }

                /* append the demangled string and deinit tmp */
                dem_string_concat (dem, &tmp);
                dem_string_deinit (&tmp);
            } else {
                RESTORE_POS();
                dem_string_deinit (&tmp);
                break;
            }
        }

        return dem;
    }

    RESTORE_POS();
    return NULL;
}

/**
 * \b Takes a rule and matches at any number of occurences of it.
 * Meaning one or more rule matches. If not even a single match is available,
 * then returns NULL.
 *
 * \p rule  Rule to apply any number of times.
 * \p sep   If provided, is appended after each rule match success.
 * \p dem   Demangled string will be stored here.
 * \p msi   Mangled string iter.
 *
 * \return dem If given arguments are non-null.
 * \return NULL otherwise.
 */
DemString* match_zero_or_more_rules (
    DemRuleFirst first,
    DemRule      rule,
    const char*  sep,
    DemString*   dem,
    StrIter*     msi,
    Meta*        m,
    TraceGraph*  graph,
    int          parent_node_id
) {
    if (!rule || !dem || !msi || !m) {
        return NULL;
    }

    ut32 match_count = 0;
    while (true) {
        DemString tmp = {0};
        SAVE_POS();
        if (first (CUR()) && rule (&tmp, msi, m, graph, parent_node_id)) {
            match_count++;
            if (sep) {
                dem_string_append (&tmp, sep);
            }
            dem_string_concat (dem, &tmp);
            dem_string_deinit (&tmp);
        } else {
            RESTORE_POS();
            dem_string_deinit (&tmp);
            break;
        }
    }

    /* remove last sep */
    // if (sep) {
    //     for (int l = 0; l < strlen (sep); l++) {
    //         dem->buf[--dem->len] = 0;
    //     }
    // }

    /* we always match, even if nothing matches */
    return dem;
}

// counts the number of :: in a name and adds 1 to it
// but ignores :: inside template arguments (between < and >)
static ut32 count_name_parts (Name* n) {
    // count number of parts
    const char* it     = n->name.buf;
    const char* end    = it + n->name.len;
    n->num_parts       = 1;
    int template_depth = 0;

    while (it < end) {
        if (*it == '<') {
            template_depth++;
        } else if (*it == '>') {
            template_depth--;
        } else if (template_depth == 0 && it[0] == ':' && it[1] == ':') {
            // Only count :: when we're not inside template arguments
            if (it[2]) {
                n->num_parts++;
                it += 2; // advance past the "::" to avoid infinite loop
                continue;
            } else {
                // this case is possible and must be ignored with an error
                dem_string_deinit (&n->name);
                n->num_parts = 0;
                return 0;
            }
        }
        it++;
    }
    return n->num_parts;
}

/**
 * Append given type name to list of all detected types.
 * This vector is then used to refer back to a detected type in substitution
 * rules.
 */
bool append_type (Meta* m, DemString* t, bool force_append) {
    if (!m || !t || !t->len) {
        return false;
    }

    // A hack to ingore constant values getting forcefully added from RULE(template_param)
    // because templates sometimes get values like "true", "false", "4u", etc...
    if (IS_DIGIT (t->buf[0]) || !strcmp (t->buf, "true") || !strcmp (t->buf, "false")) {
        return true;
    }

    // sometimes by mistake "std" is appended as type, but name manglers don't generate it to be a type
    if (!strcmp (t->buf, "std")) {
        return true;
    }

    // If we're not forcefully appending values, then check for uniqueness of times
    if (!force_append) {
        vec_foreach_ptr (&m->detected_types, dt, {
            if (!strcmp (dt->name.buf, t->buf)) {
                return true;
            }
        });
    }

    UNUSED (vec_reserve (&m->detected_types, m->detected_types.length + 1));
    m->detected_types.length += 1;

    Name* new_name = vec_end (&m->detected_types);
    dem_string_init_clone (&new_name->name, t);
    if (!count_name_parts (new_name)) {
        m->detected_types.length--;
        return false;
    }

    return true;
}

/**
 * Much like `append_type`, but for templates.
 */
bool append_tparam (Meta* m, DemString* t) {
    if (!m || !t || !t->len) {
        return false;
    }

    UNUSED (vec_reserve (&m->template_params, m->template_params.length + 1));
    m->template_params.length += 1;

    Name* new_name = vec_end (&m->template_params);
    dem_string_init_clone (&new_name->name, t);
    if (!count_name_parts (new_name)) {
        m->template_params.length--;
        return false;
    }

    return true;
}

// Graphviz trace helper functions implementation
void trace_graph_init (TraceGraph* graph) {
    if (!graph) {
        return;
    }

    vec_init (&graph->nodes);
    graph->next_node_id    = 0;
    graph->current_node_id = -1;
    // Don't reset enabled flag - it should be set by caller
}

// Helper function to check if any ancestor node is failed
static bool has_failed_ancestor (TraceGraph* graph, int parent_id) {
    if (parent_id < 0) {
        return false; // No parent, so no failed ancestor
    }

    // Find the parent node
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* parent = vec_ptr_at (&graph->nodes, i);
        if (parent->id == parent_id) {
            if (parent->status == 2) { // parent is failed
                return true;
            }
            // Recursively check parent's ancestors
            return has_failed_ancestor (graph, parent->parent_id);
        }
    }

    return false; // Parent not found (shouldn't happen)
}

int trace_graph_add_node (
    TraceGraph* graph,
    const char* rule_name,
    size_t      pos,
    const char* input,
    int         parent_id
) {
    if (!graph || !graph->enabled || !rule_name) {
        return -1;
    }

    // Ensure vector has space
    if (vec_reserve (&graph->nodes, graph->nodes.length + 1)) {
        TraceNode* node = vec_ptr_at (&graph->nodes, graph->nodes.length);

        node->id        = graph->next_node_id++;
        node->parent_id = parent_id;
        node->rule_name = strdup (rule_name);
        node->start_pos = pos;
        node->end_pos   = pos; // Will be updated on completion

        // Create input snippet
        if (input) {
            size_t snippet_len  = strlen (input);
            node->input_snippet = malloc (snippet_len + 4);
            strncpy (node->input_snippet, input, snippet_len);
            node->input_snippet[snippet_len] = '\0';
        } else {
            node->input_snippet = strdup ("");
        }

        node->result        = NULL;
        node->attempt_order = 0;     // Will be set by caller if needed
        node->final_path    = false; // Initialize as not part of final path

        // Check if any ancestor is failed - if so, this node should be failed too
        if (has_failed_ancestor (graph, parent_id)) {
            node->status = 2; // failed
        } else {
            node->status = 0; // running
        }

        graph->nodes.length++;
        return node->id;
    }

    return -1;
}

// Helper function to recursively propagate failure to all descendants
static void propagate_failure_to_descendants (TraceGraph* graph, int parent_id) {
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* child = vec_ptr_at (&graph->nodes, i);
        if (child->parent_id == parent_id) {
            // Mark child as failed if it's not already failed
            if (child->status != 2) {
                child->status     = 2;     // failed
                child->final_path = false; // Can't be part of final path if failed

                // Recursively propagate to this child's descendants
                propagate_failure_to_descendants (graph, child->id);
            }
        }
    }
}

void trace_graph_set_result_impl (
    TraceGraph* graph,
    int         node_id,
    size_t      pos,
    const char* result,
    int         status
) {
    if (!graph || !graph->enabled || node_id < 0) {
        return;
    }

    // Find the node
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->id == node_id) {
            // Detect backtracking: if node was previously successful (status 1) and is now being marked as failed (status 2)
            if (node->status == 1 && status == 2) {
                status = 3; // Mark as backtracked instead of failed
            }

            node->status = status;
            if (result && strlen (result) > 0) {
                // Limit result length for readability
                size_t result_len = strlen (result);
                node->result      = malloc (result_len + 4);
                strncpy (node->result, result, result_len);
                node->result[result_len] = '\0';
            }

            if (pos - node->start_pos > 0) {
                node->end_pos = pos;
            }

            // If this node is being marked as failed, propagate failure to all descendants
            if (status == 2) {            // failed
                node->final_path = false; // Can't be part of final path if failed
                propagate_failure_to_descendants (graph, node_id);
            } else if (status == 3) {     // backtracked
                node->final_path = false; // Can't be part of final path if backtracked
                // Don't propagate failure for backtracked nodes - their children might still be valid
            }

            break;
        }
    }
}

void trace_graph_output_dot (TraceGraph* graph, const char* filename, Meta* meta) {
    if (!graph || !filename) {
        return;
    }

    char  buf[256] = {0};
    FILE* f        = fopen (filename, "w");
    if (!f) {
        return;
    }

    fprintf (f, "digraph DemangleTrace {\n");
    fprintf (f, "  rankdir=TB;\n");
    fprintf (f, "  node [shape=box, fontname=\"Courier\", fontsize=10];\n");
    fprintf (f, "  edge [fontname=\"Arial\", fontsize=8];\n\n");


    // Output nodes
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode*  node = vec_ptr_at (&graph->nodes, i);
        const char* color;
        const char* style;
        const char* penwidth = "1";

        if (node->final_path) {
            // Final path nodes get special highlighting
            switch (node->status) {
                case 1 : // success
                    color    = "gold";
                    style    = "filled,bold";
                    penwidth = "3";
                    break;
                default :
                    color    = "lightyellow";
                    style    = "filled,bold";
                    penwidth = "2";
                    break;
            }
        } else {
            // Regular nodes
            switch (node->status) {
                case 1 : // success
                    color = "lightgreen";
                    style = "filled";
                    break;
                case 2 : // failed
                    color = "lightcoral";
                    style = "filled";
                    break;
                case 3 : // backtracked
                    color = "orange";
                    style = "filled,dashed";
                    break;
                default : // running
                    color = "lightblue";
                    style = "filled";
                    break;
            }
        }

        buf[0]    = '\0';
        size_t sz = node->end_pos - node->start_pos > sizeof (buf) - 1 ?
                        sizeof (buf) - 1 :
                        node->end_pos - node->start_pos;
        memcpy (buf, node->input_snippet, sz);
        buf[sz] = '\0';


        fprintf (
            f,
            "  n%d [label=\"%s@pos:%zu\\n'%s'",
            node->id,
            node->rule_name,
            node->start_pos,
            buf
        );

        if (node->result && strlen (node->result) > 0) {
            fprintf (f, "\\n→ '%s'", node->result);
        }

        fprintf (f, "\", fillcolor=%s, style=\"%s\", penwidth=%s];\n", color, style, penwidth);
    }

    fprintf (f, "\n");

    // Output edges
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->parent_id >= 0) {
            const char* edge_color = "black";
            const char* edge_style = "solid";
            const char* penwidth   = "1";

            // Check if both parent and child are in final path
            bool parent_in_final_path = false;
            for (size_t j = 0; j < graph->nodes.length; j++) {
                TraceNode* parent = vec_ptr_at (&graph->nodes, j);
                if (parent->id == node->parent_id) {
                    parent_in_final_path = parent->final_path;
                    break;
                }
            }

            if (node->final_path && parent_in_final_path) {
                // Final path edges
                edge_color = "gold";
                edge_style = "solid";
                penwidth   = "3";
            } else {
                // Regular edges
                if (node->status == 2) {        // failed
                    edge_color = "red";
                } else if (node->status == 3) { // backtracked
                    edge_color = "orange";
                    edge_style = "dashed";
                } else if (node->status == 1) { // success
                    edge_color = "green";
                }
            }

            fprintf (
                f,
                "  n%d -> n%d [color=%s, style=%s, penwidth=%s];\n",
                node->parent_id,
                node->id,
                edge_color,
                edge_style,
                penwidth
            );
        }
    }

    fprintf (f, "\n  // Legend\n");
    fprintf (f, "  subgraph cluster_legend {\n");
    fprintf (f, "    label=\"Legend\";\n");
    fprintf (f, "    style=filled;\n");
    fprintf (f, "    fillcolor=white;\n");
    fprintf (
        f,
        "    legend_final_path [label=\"Final Path\", fillcolor=gold, style=\"filled,bold\", "
        "penwidth=3];\n"
    );
    fprintf (f, "    legend_success [label=\"Success\", fillcolor=lightgreen, style=filled];\n");
    fprintf (f, "    legend_failed [label=\"Failed\", fillcolor=lightcoral, style=filled];\n");
    fprintf (
        f,
        "    legend_backtrack [label=\"Backtracked\", fillcolor=orange, style=\"filled,dashed\"];\n"
    );
    fprintf (f, "    legend_running [label=\"Running\", fillcolor=lightblue, style=filled];\n");
    fprintf (f, "  }\n");

    // Add substitution table if meta is provided and has detected types
    if (meta && meta->detected_types.length > 0) {
        fprintf (f, "\n  // Substitution Table\n");
        fprintf (f, "  subgraph cluster_substitutions {\n");
        fprintf (f, "    label=\"Detected Substitutable Types\";\n");
        fprintf (f, "    style=filled;\n");
        fprintf (f, "    fillcolor=lightyellow;\n");
        fprintf (f, "    pencolor=black;\n");
        fprintf (f, "    fontname=\"Arial\";\n");
        fprintf (f, "    fontsize=12;\n");

        // Create table header
        fprintf (f, "    substitution_table [shape=plaintext, label=<\n");
        fprintf (
            f,
            "      <TABLE BORDER=\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\" BGCOLOR=\"white\">\n"
        );
        fprintf (f, "        <TR>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Index</B></TD>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Substitution</B></TD>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Type</B></TD>\n");
        fprintf (f, "          <TD BGCOLOR=\"lightgray\"><B>Parts</B></TD>\n");
        fprintf (f, "        </TR>\n");

        // Add each detected type
        for (size_t i = 0; i < meta->detected_types.length; i++) {
            Name*       type = vec_ptr_at (&meta->detected_types, i);
            const char* sub_notation;

            if (i == 0) {
                sub_notation = "S_";
            } else {
                sub_notation = dem_str_newf ("S%zu_", i - 1);
            }

            fprintf (f, "        <TR>\n");
            fprintf (f, "          <TD>%zu</TD>\n", i);
            fprintf (f, "          <TD><FONT FACE=\"Courier\">%s</FONT></TD>\n", sub_notation);

            // Escape HTML characters in the type name
            char* escaped_name = NULL;
            if (type->name.buf && type->name.len > 0) {
                size_t escaped_len = type->name.len * 6 + 1; // worst case: all chars become &xxxx;
                escaped_name       = calloc (escaped_len, sizeof (char));
                if (escaped_name) {
                    const char* src = type->name.buf;
                    char*       dst = escaped_name;
                    for (size_t j = 0; j < type->name.len && src[j]; j++) {
                        switch (src[j]) {
                            case '<' :
                                strcpy (dst, "&lt;");
                                dst += 4;
                                break;
                            case '>' :
                                strcpy (dst, "&gt;");
                                dst += 4;
                                break;
                            case '&' :
                                strcpy (dst, "&amp;");
                                dst += 5;
                                break;
                            case '"' :
                                strcpy (dst, "&quot;");
                                dst += 6;
                                break;
                            case '\'' :
                                strcpy (dst, "&#39;");
                                dst += 5;
                                break;
                            default :
                                *dst++ = src[j];
                                break;
                        }
                    }
                    *dst = '\0';
                }
            }

            fprintf (
                f,
                "          <TD><FONT FACE=\"Courier\">%s</FONT></TD>\n",
                escaped_name ? escaped_name : "(empty)"
            );
            fprintf (f, "          <TD>%u</TD>\n", type->num_parts);
            fprintf (f, "        </TR>\n");

            if (escaped_name) {
                free (escaped_name);
            }
            if (i > 0) {
                free ((void*)sub_notation);
            }
        }

        fprintf (f, "      </TABLE>\n");
        fprintf (f, "    >];\n");
        fprintf (f, "  }\n");
    }

    fprintf (f, "}\n");
    fclose (f);
}

void trace_graph_cleanup (TraceGraph* graph) {
    if (!graph) {
        return;
    }

    // Free all allocated strings
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->rule_name) {
            free (node->rule_name);
        }
        if (node->input_snippet) {
            free (node->input_snippet);
        }
        if (node->result) {
            free (node->result);
        }
    }

    vec_deinit (&graph->nodes);
    graph->next_node_id    = 0;
    graph->current_node_id = -1;
    graph->enabled         = false;
}

// Helper function for marking final path recursively
static void mark_path_recursive (TraceGraph* graph, int node_id) {
    // Mark current node
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);
        if (node->id == node_id) {
            node->final_path = true;
            break;
        }
    }

    // Find ALL successful children and mark them too
    // In a recursive descent parser, all successful children contribute to the final result
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* child = vec_ptr_at (&graph->nodes, i);
        if (child->parent_id == node_id && child->status == 1) {
            mark_path_recursive (graph, child->id);
        }
    }
}

void trace_graph_mark_final_path (TraceGraph* graph) {
    if (!graph || !graph->enabled) {
        return;
    }

    // Better approach: A node is part of the final path if:
    // 1. It's successful (status == 1)
    // 2. It doesn't have any later siblings that also succeeded (indicating backtracking)
    // 3. All its ancestors are also part of the final path

    // For each successful node, check if it's the latest successful sibling
    for (size_t i = 0; i < graph->nodes.length; i++) {
        TraceNode* node = vec_ptr_at (&graph->nodes, i);

        if (node->status != 1) {
            continue; // Only consider successful nodes
        }

        // Check if this node is the latest successful sibling
        bool is_final_choice              = true;
        int  latest_successful_sibling_id = node->id;

        for (size_t j = 0; j < graph->nodes.length; j++) {
            TraceNode* sibling = vec_ptr_at (&graph->nodes, j);
            if (sibling->parent_id == node->parent_id && sibling->status == 1 &&
                sibling->id > latest_successful_sibling_id) {
                latest_successful_sibling_id = sibling->id;
                is_final_choice              = false;
            }
        }

        // If this is the latest successful sibling, it's part of the final path
        if (is_final_choice) {
            node->final_path = true;
        }
    }

    // Now propagate the final_path marking up the tree
    // A node should only be marked final if it has at least one final child
    // (except for leaf nodes which we already marked above)
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < graph->nodes.length; i++) {
            TraceNode* node = vec_ptr_at (&graph->nodes, i);

            if (node->status != 1 || node->final_path) {
                continue; // Skip non-successful or already marked nodes
            }

            // Check if this node has any final_path children
            bool has_final_child = false;
            for (size_t j = 0; j < graph->nodes.length; j++) {
                TraceNode* child = vec_ptr_at (&graph->nodes, j);
                if (child->parent_id == node->id && child->final_path) {
                    has_final_child = true;
                    break;
                }
            }

            if (has_final_child) {
                node->final_path = true;
                changed          = true;
            }
        }
    }
}



DEFN_RULE (class_enum_type, {
    MATCH (OPTIONAL (READ_STR ("Ts") || READ_STR ("Tu") || READ_STR ("Te")) && RULE (name));
});


DEFN_RULE (bare_function_type, { MATCH (RULE_ATLEAST_ONCE_WITH_SEP (type, ", ")); });



DEFN_RULE (template_prefix, {
    // {prefix-start} {prefix-nested-class-or-namespace} {unqualified-name}
    // {prefix-start} {unqualified-name}
    DEFER_VAR (nname);
    MATCH (
        RULE (prefix_start) &&
        OPTIONAL (
            RULE_DEFER (nname, prefix_nested_class_or_namespace) && APPEND_STR ("::") &&
            APPEND_DEFER_VAR (nname)
        ) &&
        APPEND_STR ("::") && RULE (unqualified_name)
    );

    // {prefix-or-template-prefix-start}
    MATCH (RULE (prefix_or_template_prefix_start));
});



DEFN_RULE (mangled_name, {
    MATCH (
        READ_STR ("_Z") && RULE (encoding) && OPTIONAL (READ ('.') && RULE (vendor_specific_suffix))
    );
});


DEFN_RULE (type, {
    MATCH (RULE (function_type) && APPEND_TYPE (dem));

    MATCH_AND_DO (
        first_of_rule_extended_qualifier (CUR()) && RULE_ATLEAST_ONCE (extended_qualifier),
        {
            MATCH (READ_STR ("rVK") && RULE (type) && APPEND_STR (" restrict const volatile"));
            MATCH (READ_STR ("rV") && RULE (type) && APPEND_STR (" restrict volatile"));
            MATCH (READ_STR ("rK") && RULE (type) && APPEND_STR (" restrict const"));
            MATCH (READ_STR ("VK") && RULE (type) && APPEND_STR (" const volatile"));
            MATCH (READ ('P') && RULE (type) && APPEND_STR ("*") && APPEND_TYPE (dem));
            MATCH (READ ('R') && RULE (type) && APPEND_STR ("&") && APPEND_TYPE (dem));
            MATCH (READ ('K') && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem));
            MATCH (READ ('O') && RULE (type) && APPEND_STR ("&&") && APPEND_TYPE (dem));
            MATCH_FAILED();
        }
    );

    MATCH (READ ('C') && RULE (type)); // complex pair (C99)
    MATCH (READ ('G') && RULE (type)); // imaginary (C99)

    MATCH (READ ('P') && RULE (type) && APPEND_STR ("*") && APPEND_TYPE (dem));
    MATCH (READ ('R') && RULE (type) && APPEND_STR ("&") && APPEND_TYPE (dem));
    MATCH (READ ('O') && RULE (type) && APPEND_STR ("&&") && APPEND_TYPE (dem));

    MATCH (READ_STR ("rVK") && RULE (type) && APPEND_STR (" restrict const volatile"));
    MATCH (READ_STR ("rV") && RULE (type) && APPEND_STR (" restrict volatile"));
    MATCH (READ_STR ("rK") && RULE (type) && APPEND_STR (" restrict const"));
    MATCH (READ_STR ("VK") && RULE (type) && APPEND_STR (" const volatile"));
    MATCH (READ ('r') && RULE (type) && APPEND_STR (" restrict"));
    MATCH (READ ('V') && RULE (type) && APPEND_STR (" volatile"));
    MATCH (READ ('K') && RULE (type) && APPEND_STR (" const") && APPEND_TYPE (dem));

    // MATCH (RULE (template_template_param) && APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem));
    MATCH (
        RULE (template_param) && APPEND_TYPE (dem) &&
        OPTIONAL (RULE (template_args) && APPEND_TYPE (dem))
    );
    MATCH (RULE (substitution) && RULE (template_args) && APPEND_TYPE (dem));


    MATCH (RULE (builtin_type));
    MATCH (READ_STR ("Dp") && RULE (type)); // pack expansion (C++11)

    // Extended qualifiers with CV qualifiers
    MATCH (RULE (class_enum_type) && APPEND_TYPE (dem));
    MATCH (RULE (array_type) && APPEND_TYPE (dem));
    MATCH (RULE (pointer_to_member_type) && APPEND_TYPE (dem));
    // MATCH (RULE (template_param) && APPEND_TYPE (dem));
    MATCH (RULE (decltype) && APPEND_TYPE (dem));
    MATCH (RULE (substitution));
});



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


DEFN_RULE (seq_id, {
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
        return SUBSTITUTE_TYPE (m, sid, dem);
    } else if (PEEK() == '_') {
        return SUBSTITUTE_TYPE (m, 0, dem);
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

DEFN_RULE (prefix_nested_class_or_namespace, {
    // {unqualified-name} {prefix-nested-class-or-namespace}
    MATCH (
        RULE (unqualified_name) && APPEND_STR ("::") && RULE (prefix_nested_class_or_namespace) &&
        APPEND_TYPE (dem)
    );

    // {unqualified-name}
    MATCH (RULE (unqualified_name) && we_are_at_an_unqualified_name_starting (msi->cur));
});



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


DEFN_RULE (name, {
    MATCH (RULE (unscoped_name) && APPEND_TYPE (dem) && RULE (template_args) && APPEND_TYPE (dem));
    MATCH (RULE (substitution) && RULE (template_args) && APPEND_TYPE (dem));

    MATCH (RULE (nested_name)
    ); // NOTE: Nested name adds type selectively automatically, so no need to do it here!
    MATCH (RULE (unscoped_name));
    MATCH (RULE (local_name) && APPEND_TYPE (dem));
});



// TODO: merge common patterns, to keep trace as small as possible!

DEFN_RULE (closure_prefix_rr, {
    // {unqualified-name} M
    MATCH (
        RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) &&
        RULE (unqualified_name) && APPEND_TYPE (dem) && RULE (template_args) && READ ('M') &&
        APPEND_TYPE (dem) && RULE (closure_prefix_rr)
    );

    // {prefix-start-rr} {unqualified-name} M
    MATCH (
        RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) &&
        RULE (unqualified_name) && APPEND_TYPE (dem) && RULE (template_args) && READ ('M') &&
        APPEND_TYPE (dem)
    );

    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (
        RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) &&
        RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem) && RULE (closure_prefix_rr)
    );

    // {unqualified-name} {template-args} M
    MATCH (
        RULE (prefix_start_rr) && RULE (unqualified_name) && APPEND_TYPE (dem) &&
        RULE (template_args) && READ ('M') && APPEND_TYPE (dem) && RULE (closure_prefix_rr)
    );

    // {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (
        RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && APPEND_TYPE (dem) &&
        RULE (template_args) && READ ('M') && APPEND_TYPE (dem) && RULE (closure_prefix_rr)
    );

    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M
    MATCH (
        RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) &&
        RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M
    MATCH (
        RULE (prefix_start_rr) && RULE (unqualified_name) && APPEND_TYPE (dem) &&
        RULE (template_args) && READ ('M') && APPEND_TYPE (dem)
    );

    // {unqualified-name} M {closure-prefix-rr}
    MATCH (
        RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && APPEND_TYPE (dem) &&
        RULE (template_args) && READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-start-rr} {unqualified-name} M {closure-prefix-rr}
    MATCH (
        RULE (prefix_start_rr) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem) &&
        RULE (closure_prefix_rr)
    );

    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M {closure-prefix-rr}
    MATCH (
        RULE (unqualified_name) && APPEND_TYPE (dem) && RULE (template_args) && READ ('M') &&
        APPEND_TYPE (dem) && RULE (closure_prefix_rr)
    );

    // {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (RULE (prefix_start_rr) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem));

    // {prefix-start-rr} {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (
        RULE (unqualified_name) && APPEND_TYPE (dem) && RULE (template_args) && READ ('M') &&
        APPEND_TYPE (dem)
    );

    // {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem) && RULE (closure_prefix_rr));

    // {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} {template-args} M {closure-prefix-rr}
    MATCH (RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem));
});



DECL_RULE (nested_name_with_substitution_only);

// NOTE: Prefix parsing does not work well with multiple unqualified names
// We can create a new rule named second_last_unqualified_name and perform a trick
// to get the second last unqualified name always.

DEFN_RULE (nested_name, {
    DEFER_VAR (ref);
    DEFER_VAR (pfx);
    DEFER_VAR (uname);

    bool is_ctor = false;
    bool is_dtor = false;

    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <ctor-name> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <dtor-name> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) &&
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

            if (ref->len) {
                APPEND_STR (" ");
                (void)APPEND_DEFER_VAR (ref);
                APPEND_TYPE (dem);
            }
        }
    );

    dem_string_deinit (pfx);
    dem_string_deinit (ref);
    dem_string_deinit (uname);
    is_ctor = is_dtor = false;

    DEFER_VAR (targs);

    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <ctor-name> <template-args> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <dtor-name> <template-args> E
    // N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <unqualified-name> <template-args> E
    MATCH_AND_DO (
        READ ('N') && OPTIONAL (RULE (cv_qualifiers)) &&
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
    dem_string_deinit (targs);
    dem_string_deinit (uname);

    MATCH (RULE (nested_name_with_substitution_only));
});

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


DEFN_RULE (qualified_type, { MATCH (RULE (qualifiers) && RULE (type)); });


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



DEFN_RULE (qualifiers, { MATCH (RULE_MANY (extended_qualifier) && RULE (cv_qualifiers)); });


DEFN_RULE (nv_digit, {
    if (IS_DIGIT (PEEK())) {
        ADV();
        TRACE_RETURN_SUCCESS (dem);
    }

    TRACE_RETURN_FAILURE();
});

#define first_of_rule_nv_digit first_of_rule_digit

DEFN_RULE (nv_offset, { MATCH (OPTIONAL (READ ('n')) && RULE_ATLEAST_ONCE (nv_digit)); });



// TODO: merge common patterns, to keep trace as small as possible!


DEFN_RULE (closure_prefix_unit, {
    // {prefix-or-template-prefix-start} {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) &&
        RULE (prefix_start_rr) && RULE (prefix_nested_class_or_namespace) &&
        RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem)
    );

    // {decltype} {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) &&
        RULE (prefix_start_rr) && RULE (unqualified_name) && RULE (template_args) && READ ('M') &&
        APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {template-args} {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) &&
        RULE (prefix_start_rr) && RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {prefix-start-rr} {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (prefix_start_rr) &&
        RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && READ ('M') &&
        APPEND_TYPE (dem)
    );

    // {decltype} {prefix-start-rr} {unqualified-name} M
    MATCH (
        RULE (decltype) && APPEND_TYPE (dem) && RULE (prefix_start_rr) &&
        RULE (prefix_nested_class_or_namespace) && RULE (unqualified_name) && READ ('M') &&
        APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {template-args} {prefix-start-rr} {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) &&
        RULE (unqualified_name) && RULE (template_args) && READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (prefix_start_rr) &&
        RULE (unqualified_name) && RULE (template_args) && READ ('M') && APPEND_TYPE (dem)
    );

    // {decltype} {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (
        RULE (decltype) && APPEND_TYPE (dem) && RULE (prefix_start_rr) && RULE (unqualified_name) &&
        RULE (template_args) && READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {template-args} {prefix-start-rr} {prefix-nested-class-or-namespace} {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) &&
        RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem)
    );

    // {unqualified-name} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (prefix_start_rr) &&
        RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {unqualified-name} {template-args} M
    MATCH (
        RULE (decltype) && APPEND_TYPE (dem) && RULE (prefix_start_rr) && RULE (unqualified_name) &&
        READ ('M') && APPEND_TYPE (dem)
    );

    // {decltype} {unqualified-name} {template-args} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (unqualified_name) && RULE (template_args) &&
        READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {template-args} {unqualified-name} {template-args} M
    MATCH (
        RULE (decltype) && APPEND_TYPE (dem) && RULE (unqualified_name) && RULE (template_args) &&
        READ ('M') && APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (unqualified_name) && READ ('M') &&
        APPEND_TYPE (dem)
    );

    // {decltype} {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (
        RULE (decltype) && APPEND_TYPE (dem) && RULE (unqualified_name) && READ ('M') &&
        APPEND_TYPE (dem)
    );

    // {prefix-or-template-prefix-start} {template-args} {prefix-start-rr} {unqualified-name} {template-args} M
    MATCH (
        RULE (prefix_or_template_prefix_start) && RULE (template_args) && APPEND_TYPE (dem) &&
        READ ('M')
    );

    // {prefix-or-template-prefix-start} {template-args} M
    MATCH (RULE (unqualified_name) && READ ('M') && APPEND_TYPE (dem));
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

DEFN_RULE (encoding, {
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
});



DEFN_RULE (prefix_or_template_prefix_start, {
    MATCH (RULE (unqualified_name));
    MATCH (RULE (template_param));
    MATCH (RULE (substitution));
});



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

const char* cp_demangle_v3 (const char* mangled, CpDemOptions opts) {
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

    if (first_of_rule_mangled_name (msi->cur) && rule_mangled_name (dem, msi, m, graph, -1)) {
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
        vec_deinit (&meta.detected_types);

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
