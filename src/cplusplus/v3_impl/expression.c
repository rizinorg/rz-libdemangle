// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

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