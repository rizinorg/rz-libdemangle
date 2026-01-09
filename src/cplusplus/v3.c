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
#include "demangler_util.h"
#include "first.h"
#include "macros.h"
#include "parser_combinator.h"
#include "types.h"
#include "vec.h"
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

bool rule_vendor_specific_suffix(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(vendor_specific_suffix);
	TRACE_RETURN_FAILURE();
	RULE_FOOT(vendor_specific_suffix);
}

bool rule_digit(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(digit);
	if (IS_DIGIT(PEEK())) {
		AST_APPEND_CHR(PEEK());
		ADV();
		TRACE_RETURN_SUCCESS;
	}

	TRACE_RETURN_FAILURE();
	RULE_FOOT(digit);
}

bool rule_number(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(number);
	MATCH(OPTIONAL(READ('n')) && RULE_ATLEAST_ONCE(digit));
	RULE_FOOT(number);
}

bool rule_v_offset(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(v_offset);
	// ignore the number
	MATCH(RULE_DEFER(AST(0), number) && READ('_') && RULE_DEFER(AST(1), number));
	RULE_FOOT(v_offset);
}

bool rule_unqualified_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(unqualified_name);

	MATCH(READ_STR("DC") && RULE_ATLEAST_ONCE(source_name) && READ('E'));
	MATCH(RULE_X(0, operator_name) && OPTIONAL(RULE_X(1, abi_tags)));
	MATCH(READ_STR("12_GLOBAL__N_1") && AST_APPEND_STR("(anonymous namespace)"));
	MATCH1(ctor_dtor_name);
	MATCH1(source_name);
	MATCH1(expr_primary);
	MATCH1(unnamed_type_name);

	RULE_FOOT(unqualified_name);
}

bool rule_unresolved_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(unresolved_name);
	MATCH(READ_STR("srN") && RULE_X(0, unresolved_type) &&
		RULE_DEFER_ATLEAST_ONCE(AST(1), unresolved_qualifier_level) && AST_MERGE(AST(1)) && READ('E') && RULE_X(2, base_unresolved_name));
	MATCH(OPTIONAL(READ_STR("gs") && AST_APPEND_STR("::")) && READ_STR("sr") &&
		RULE_DEFER_ATLEAST_ONCE(AST(0), unresolved_qualifier_level) && AST_MERGE(AST(0)) && READ('E') && RULE_X(1, base_unresolved_name));
	MATCH(READ_STR("sr") && RULE_X(0, unresolved_type) && RULE_X(1, base_unresolved_name));
	MATCH(OPTIONAL(READ_STR("gs") && AST_APPEND_STR("::")) && RULE_X(0, base_unresolved_name));
	RULE_FOOT(unresolved_name);
}

bool rule_unscoped_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(unscoped_name);
	MATCH(READ_STR("St") && AST_APPEND_STR("std::") && RULE_X(0, unqualified_name));
	MATCH1(unqualified_name);
	RULE_FOOT(unscoped_name);
}

bool rule_unscoped_template_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(unscoped_template_name);
	MATCH1(unscoped_name);
	MATCH1(substitution);
	RULE_FOOT(unscoped_template_name);
}

bool rule_unresolved_type(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(unresolved_type);
	MATCH(RULE_X(0, template_param) && OPTIONAL(RULE_X(1, template_args)) && AST_APPEND_TYPE);
	MATCH(RULE_X(0, decltype) && AST_APPEND_TYPE);
	MATCH1(substitution);
	RULE_FOOT(unresolved_type);
}

bool rule_unresolved_qualifier_level(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(unresolved_qualifier_level);
	MATCH1(simple_id);
	RULE_FOOT(unresolved_qualifier_level);
}

bool rule_decltype(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(decltype);
	MATCH(READ_STR("Dt") && RULE_X(0, expression) && READ('E'));
	MATCH(READ_STR("DT") && RULE_X(0, expression) && READ('E'));
	RULE_FOOT(decltype);
}

bool rule_exception_spec(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(exception_spec);
	MATCH(READ_STR("DO") && RULE_X(0, expression) && READ('E'));
	MATCH(READ_STR("Dw") && RULE_X(0, type) && READ('E'));
	MATCH(READ_STR("Do"));
	RULE_FOOT(exception_spec);
}

bool rule_array_type(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(array_type);
	MATCH(READ('A') && OPTIONAL(RULE_X(0, number)) && READ('_') && RULE_X(1, type));
	MATCH(READ('A') && RULE_X(0, expression) && READ('_') && RULE_X(1, type));
	RULE_FOOT(array_type);
}

bool rule_expression(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(expression);
	/* unary operators */
	MATCH(
		(READ_STR("gsnw") || READ_STR("nw")) && AST_APPEND_STR("new (") &&
		RULE_DEFER_ATLEAST_ONCE_WITH_SEP(AST(0), expression, ", ") &&
		AST_MERGE(AST(0)) && AST_APPEND_STR(") ") && READ('_') &&
		RULE_X(1, type) && READ('E'));
	MATCH(
		(READ_STR("gsnw") || READ_STR("nw")) && AST_APPEND_STR("new (") &&
		RULE_DEFER_ATLEAST_ONCE_WITH_SEP(AST(0), expression, ", ") &&
		AST_MERGE(AST(0)) && AST_APPEND_STR(") ") && READ('_') &&
		RULE_X(1, type) && RULE_X(2, initializer));
	MATCH(
		(READ_STR("gsna") || READ_STR("na")) && AST_APPEND_STR("new[] (") &&
		RULE_DEFER_ATLEAST_ONCE_WITH_SEP(AST(0), expression, ", ") &&
		AST_MERGE(AST(0)) && AST_APPEND_STR(") ") && READ('_') &&
		RULE_X(1, type) && READ('E'));
	MATCH(
		(READ_STR("gsna") || READ_STR("na")) && AST_APPEND_STR("new[] (") &&
		RULE_DEFER_ATLEAST_ONCE_WITH_SEP(AST(0), expression, ", ") &&
		AST_MERGE(AST(0)) && AST_APPEND_STR(") ") && READ('_') &&
		RULE_X(1, type) && RULE_X(2, initializer));
	MATCH(
		READ_STR("cv") && RULE_X(0, type) && READ('_') && AST_APPEND_STR("(") &&
		RULE_DEFER_ATLEAST_ONCE_WITH_SEP(AST(1), expression, ", ") &&
		AST_MERGE(AST(1)) && AST_APPEND_STR(")") && READ('E'));
	/* binary operators */
	MATCH(
		READ_STR("qu") && RULE_X(0, expression) && AST_APPEND_STR("?") && RULE_X(1, expression) &&
		AST_APPEND_STR(":") && RULE_X(2, expression));
	MATCH(
		READ_STR("cl") && RULE_X(0, expression) && AST_APPEND_STR("(") &&
		RULE_DEFER_MANY_WITH_SEP(AST(1), expression, ", ") &&
		AST_MERGE(AST(1)) && AST_APPEND_STR(")") && READ('E'));
	MATCH(
		READ_STR("cp") && AST_APPEND_STR("(") && RULE_X(0, base_unresolved_name) &&
		AST_APPEND_STR(")") && AST_APPEND_STR("(") && RULE_DEFER_MANY_WITH_SEP(AST(1), expression, ", ") &&
		AST_MERGE(AST(1)) &&
		AST_APPEND_STR(")") && READ('E'));
	MATCH(
		READ_STR("tl") && RULE_X(0, type) && AST_APPEND_STR("{") &&
		RULE_DEFER_MANY_WITH_SEP(AST(1), braced_expression, ", ") &&
		AST_MERGE(AST(1)) && AST_APPEND_STR("}") && READ('E'));
	MATCH(
		READ('u') && RULE_X(0, source_name) && RULE_DEFER_MANY_WITH_SEP(AST(1), template_arg, ", ") &&
		AST_MERGE(AST(1)) && READ('E'));
#define EXPRESSION_BINARY_OP(OP_STR, OP_CODE) \
	MATCH_AND_DO( \
		READ_STR(OP_CODE) && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression), \
		{ \
			AST_MERGE(AST(0)); \
			AST_APPEND_STR(OP_STR); \
			AST_MERGE(AST(1)); \
		});

	EXPRESSION_BINARY_OP("+", "pl")
	EXPRESSION_BINARY_OP("-", "mi")
	EXPRESSION_BINARY_OP("*", "ml")
	EXPRESSION_BINARY_OP("/", "dv")
	EXPRESSION_BINARY_OP("%", "rm")
	EXPRESSION_BINARY_OP("&", "an")
	EXPRESSION_BINARY_OP("|", "or")
	EXPRESSION_BINARY_OP("^", "eo")
	EXPRESSION_BINARY_OP("=", "aS")
	EXPRESSION_BINARY_OP("+=", "pL")
	EXPRESSION_BINARY_OP("-=", "mI")
	EXPRESSION_BINARY_OP("*=", "mL")
	EXPRESSION_BINARY_OP("/=", "dV")
	EXPRESSION_BINARY_OP("%=", "rM")
	EXPRESSION_BINARY_OP("&=", "aN")
	EXPRESSION_BINARY_OP("|=", "oR")
	EXPRESSION_BINARY_OP("^=", "eO")
	EXPRESSION_BINARY_OP("<<", "ls")
	EXPRESSION_BINARY_OP(">>", "rs")
	EXPRESSION_BINARY_OP("<<=", "lS")
	EXPRESSION_BINARY_OP(">>=", "rS")
	EXPRESSION_BINARY_OP("==", "eq")
	EXPRESSION_BINARY_OP("!=", "ne")
	EXPRESSION_BINARY_OP("<", "lt")
	EXPRESSION_BINARY_OP(">", "gt")
	EXPRESSION_BINARY_OP("<=", "le")
	/* ternary operator */
	EXPRESSION_BINARY_OP(">=", "ge")

	/* type casting */
	/* will generate " (type)" */
	EXPRESSION_BINARY_OP("<=>", "ss")

	/* prefix operators */
	EXPRESSION_BINARY_OP("!", "nt");
	EXPRESSION_BINARY_OP("&&", "aa");

	/* expression (expr-list), call */
	EXPRESSION_BINARY_OP("||", "oo");

	/* (name) (expr-list), call that would use argument-dependent lookup but for the parentheses*/
	MATCH_AND_DO(
		READ_STR("cv") && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_STR("(");
			AST_MERGE(AST(0));
			AST_APPEND_STR(")");
			AST_MERGE(AST(1));
		});

	/* type (expression), conversion with one argument */
	MATCH_AND_DO(
		READ_STR("cv") && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), expression), {
			AST_MERGE(AST(0));
			AST_APPEND_STR("(");
			AST_MERGE(AST(1));
			AST_APPEND_STR(")");
		});
	/* type (expr-list), conversion with other than one argument */
	MATCH_AND_DO(
		READ_STR("il") && RULE_DEFER_MANY_WITH_SEP(AST(0), braced_expression, ", ") && READ('E'),
		{
			AST_APPEND_STR("{");
			AST_MERGE(AST(0));
			AST_APPEND_STR("}");
		});

	/* type {expr-list}, conversion with braced-init-list argument */
	MATCH((READ_STR("gsdl") || READ_STR("dl")) && AST_APPEND_STR("delete ") && RULE_X(0, expression));

	/* {expr-list}, braced-init-list in any other context */
	MATCH((READ_STR("gsda") || READ_STR("da")) && AST_APPEND_STR("delete[] ") && RULE_X(0, expression));

	/* new (expr-list) type */
	MATCH_AND_DO(
		READ_STR("dc") && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_STR("dynamic_cast<");
			AST_MERGE(AST(0));
			AST_APPEND_STR("> (");
			AST_MERGE(AST(1));
			AST_APPEND_STR(")");
		});

	/* new (expr-list) type (init) */
	MATCH_AND_DO(
		READ_STR("sc") && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_STR("static_cast<");
			AST_MERGE(AST(0));
			AST_APPEND_STR("> (");
			AST_MERGE(AST(1));
			AST_APPEND_STR(")");
		});

	/* new[] (expr-list) type */
	MATCH_AND_DO(
		READ_STR("cc") && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_STR("const_cast<");
			AST_MERGE(AST(0));
			AST_APPEND_STR("> (");
			AST_MERGE(AST(1));
			AST_APPEND_STR(")");
		});

	/* new[] (expr-list) type (init) */
	MATCH_AND_DO(
		READ_STR("rc") && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_STR("reinterpret_cast<");
			AST_MERGE(AST(0));
			AST_APPEND_STR("> (");
			AST_MERGE(AST(1));
			AST_APPEND_STR(")");
		});

	/* delete expression */
	MATCH_AND_DO(
		READ_STR("dt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), unresolved_name),
		{
			AST_MERGE(AST(0));
			AST_APPEND_CHR('.');
			AST_MERGE(AST(1));
		});

	/* delete [] expression */
	MATCH_AND_DO(
		READ_STR("pt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), unresolved_name),
		{
			AST_MERGE(AST(0));
			AST_APPEND_STR("->");
			AST_MERGE(AST(1));
		});

	// dc <type> <expression>                               # dynamic_cast<type> (expression)
	MATCH_AND_DO(
		READ_STR("ds") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_MERGE(AST(0));
			AST_APPEND_STR(".*");
			AST_MERGE(AST(1));
		});
	// sc <type> <expression>                               # static_cast<type> (expression)
	MATCH(
		READ_STR("sP") && AST_APPEND_STR("sizeof...(") && RULE_MANY(template_arg) &&
		AST_APPEND_CHR(')') && READ('E'));
	// cc <type> <expression>                               # const_cast<type> (expression)
	MATCH_AND_DO(
		READ_STR("fLpl") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" + ... + ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	// rc <type> <expression>                               # reinterpret_cast<type> (expression)
	MATCH_AND_DO(
		READ_STR("fLmi") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" - ... - ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});

	// ti <type>                                            # typeid (type)
	MATCH_AND_DO(
		READ_STR("fLml") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" * ... * ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	// te <expression>                                      # typeid (expression)
	MATCH_AND_DO(
		READ_STR("fLdv") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" / ... / ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	// st <type>                                            # sizeof (type)
	MATCH_AND_DO(
		READ_STR("fLrm") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" % ... % ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	// sz <expression>                                      # sizeof (expression)
	MATCH_AND_DO(
		READ_STR("fLan") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" & ... & ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	// at <type>                                            # alignof (type)
	MATCH_AND_DO(
		READ_STR("fLor") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" | ... | ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	// az <expression>                                      # alignof (expression)
	MATCH_AND_DO(
		READ_STR("fLeo") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" ^ ... ^ ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	// nx <expression>                                      # noexcept (expression)
	MATCH_AND_DO(
		READ_STR("fLaS") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" = ... = ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});

	MATCH_AND_DO(
		READ_STR("fLpL") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" += ... += ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLmI") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" -= ... -= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});

	MATCH_AND_DO(
		READ_STR("fLmL") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" *= ... *= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLdV") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" /= ... /= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLrM") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" %= ... %= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});

	MATCH_AND_DO(
		READ_STR("fLaN") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" &= ... &= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLoR") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" |= ... |= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLeO") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" ^= ... ^= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLls") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" << ... << ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});

	/* unary left fold */
	MATCH_AND_DO(
		READ_STR("fLrs") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" >> ... >> ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLlS") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" <<= ... <<= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLrS") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" >>= ... >>= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLeq") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" == ... == ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLne") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" != ... != ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLlt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" < ... < ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLgt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" > ... > ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLle") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" <= ... <= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLge") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" >= ... >= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLss") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" <=> ... <=> ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLnt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" ! ... ! ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLaa") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" && ... && ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fLoo") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" || ... || ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRpl") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" + ... + ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRmi") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" - ... - ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRml") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" * ... * ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRdv") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" / ... / ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRrm") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" % ... % ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRan") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" & ... & ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRor") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" | ... | ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fReo") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" ^ ... ^ ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRaS") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" = ... = ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRpL") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" += ... += ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRmI") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" -= ... -= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRmL") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" *= ... *= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRdV") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" /= ... /= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRrM") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" %= ... %= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRaN") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" &= ... &= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRoR") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" |= ... |= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fReO") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" ^= ... ^= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRls") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" << ... << ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});

	/* unary fold right */
	MATCH_AND_DO(
		READ_STR("fRrs") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" >> ... >> ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRlS") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" <<= ... <<= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRrS") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" >>= ... >>= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fReq") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" == ... == ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRne") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" != ... != ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRlt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" < ... < ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRgt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" > ... > ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRle") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" <= ... <= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRge") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" >= ... >= ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRss") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" <=> ... <=> ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRnt") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" ! ... ! ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRaa") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" && ... && ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH_AND_DO(
		READ_STR("fRoo") && RULE_DEFER(AST(0), expression) && RULE_DEFER(AST(1), expression),
		{
			AST_APPEND_CHR('(');
			AST_MERGE(AST(0));
			AST_APPEND_STR(" || ... || ");
			AST_MERGE(AST(1));
			AST_APPEND_CHR(')');
		});
	MATCH(READ_STR("ps") && AST_APPEND_CHR('+') && RULE_X(0, expression));
	MATCH(READ_STR("ng") && AST_APPEND_CHR('-') && RULE_X(0, expression));
	MATCH(READ_STR("ad") && AST_APPEND_CHR('&') && RULE_X(0, expression));
	MATCH(READ_STR("de") && AST_APPEND_CHR('*') && RULE_X(0, expression));
	MATCH(READ_STR("co") && AST_APPEND_STR("~") && RULE_X(0, expression));
	MATCH(READ_STR("pp_") && AST_APPEND_STR("++") && RULE_X(0, expression));
	MATCH(READ_STR("mm_") && AST_APPEND_STR("--") && RULE_X(0, expression));
	MATCH(READ_STR("ti") && AST_APPEND_STR("typeid(") && RULE_X(0, type) && AST_APPEND_STR(")"));
	MATCH(READ_STR("te") && AST_APPEND_STR("typeid(") && RULE_X(0, expression) && AST_APPEND_STR(")"));
	MATCH(READ_STR("st") && AST_APPEND_STR("sizeof(") && RULE_X(0, type) && AST_APPEND_STR(")"));
	MATCH(READ_STR("sz") && AST_APPEND_STR("sizeof(") && RULE_X(0, expression) && AST_APPEND_STR(")"));
	MATCH(READ_STR("at") && AST_APPEND_STR("alignof(") && RULE_X(0, type) && AST_APPEND_STR(")"));
	MATCH(READ_STR("az") && AST_APPEND_STR("alignof(") && RULE_X(0, expression) && AST_APPEND_STR(")"));
	MATCH(READ_STR("nx") && AST_APPEND_STR("noexcept(") && RULE_X(0, expression) && AST_APPEND_STR(")"));
	MATCH(READ_STR("frss") && AST_APPEND_CHR('(') && RULE_X(0, expression) && AST_APPEND_STR(" <=>..."));
	MATCH(READ_STR("sZ") && AST_APPEND_STR("sizeof...(") && RULE_X(0, template_param) && AST_APPEND_CHR(')'));
	MATCH(READ_STR("sZ") && AST_APPEND_STR("sizeof...(") && RULE_X(0, function_param) && AST_APPEND_CHR(')'));
	MATCH(READ_STR("sp") && RULE_X(0, expression) && AST_APPEND_STR("..."));

	/* binary left fold */
	// clang-format off
    MATCH (READ_STR ("flpl") && AST_APPEND_STR ("(... +") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flmi") && AST_APPEND_STR ("(... -") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flml") && AST_APPEND_STR ("(... *") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fldv") && AST_APPEND_STR ("(... /") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrm") && AST_APPEND_STR ("(... %") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flan") && AST_APPEND_STR ("(... &") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flor") && AST_APPEND_STR ("(... |") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fleo") && AST_APPEND_STR ("(... ^") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flaS") && AST_APPEND_STR ("(... =") && RULE_X (0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flpL") && AST_APPEND_STR ("(... +=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flmI") && AST_APPEND_STR ("(... -=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flmL") && AST_APPEND_STR ("(... *=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fldV") && AST_APPEND_STR ("(... /=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrM") && AST_APPEND_STR ("(... %=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flaN") && AST_APPEND_STR ("(... &=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("floR") && AST_APPEND_STR ("(... |=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fleO") && AST_APPEND_STR ("(... ^=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flls") && AST_APPEND_STR ("(... <<") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrs") && AST_APPEND_STR ("(... >>") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fllS") && AST_APPEND_STR ("(... <<=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flrS") && AST_APPEND_STR ("(... >>=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fleq") && AST_APPEND_STR ("(... ==") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flne") && AST_APPEND_STR ("(... !=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("fllt") && AST_APPEND_STR ("(... <") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flgt") && AST_APPEND_STR ("(... >") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flle") && AST_APPEND_STR ("(... <=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flge") && AST_APPEND_STR ("(... >=") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flss") && AST_APPEND_STR ("(... <=>") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flnt") && AST_APPEND_STR ("(... !") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("flaa") && AST_APPEND_STR ("(... &&") && RULE_X(0,expression) && AST_APPEND_CHR (')'));
    MATCH (READ_STR ("floo") && AST_APPEND_STR ("(... ||") && RULE_X(0,expression) && AST_APPEND_CHR (')'));

    /* binary fold right */
    MATCH (READ_STR ("frpl") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" + ...)"));
    MATCH (READ_STR ("frmi") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" - ...)"));
    MATCH (READ_STR ("frml") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" * ...)"));
    MATCH (READ_STR ("frdv") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" / ...)"));
    MATCH (READ_STR ("frrm") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" % ...)"));
    MATCH (READ_STR ("fran") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" & ...)"));
    MATCH (READ_STR ("fror") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" | ...)"));
    MATCH (READ_STR ("freo") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" ^ ...)"));
    MATCH (READ_STR ("fraS") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" = ...)"));
    MATCH (READ_STR ("frpL") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" += ...)"));
    MATCH (READ_STR ("frmI") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" -= ...)"));
    MATCH (READ_STR ("frmL") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" *= ...)"));
    MATCH (READ_STR ("frdV") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" /= ...)"));
    MATCH (READ_STR ("frrM") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" %= ...)"));
    MATCH (READ_STR ("fraN") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" &= ...)"));
    MATCH (READ_STR ("froR") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" |= ...)"));
    MATCH (READ_STR ("freO") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" ^= ...)"));
    MATCH (READ_STR ("frls") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" << ...)"));
    MATCH (READ_STR ("frrs") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" >> ...)"));
    MATCH (READ_STR ("frlS") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" <<= ...)"));
    MATCH (READ_STR ("frrS") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" >>= ...)"));
    MATCH (READ_STR ("freq") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" == ...)"));
    MATCH (READ_STR ("frne") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" != ...)"));
    MATCH (READ_STR ("frlt") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" < ...)"));
    MATCH (READ_STR ("frgt") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" > ...)"));
    MATCH (READ_STR ("frle") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" <= ...)"));
    MATCH (READ_STR ("frge") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" >= ...)"));
    MATCH (READ_STR ("frnt") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" ! ...)"));
    MATCH (READ_STR ("fraa") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" && ...)"));
    MATCH (READ_STR ("froo") && AST_APPEND_CHR ('(') && RULE_X (0,expression) && AST_APPEND_STR (" || ...)"));
    MATCH (READ_STR ("tw") && AST_APPEND_STR ("throw ") && RULE_X(0,expression));
	// clang-format on

	// tw <expression>                                      # throw expression
	MATCH1(template_param);
	// tr                                                   # throw with no operand (rethrow)
	MATCH1(function_param);

	// u <source-name> <template-arg>* E                    # vendor extended expression
	MATCH(READ_STR("tr") && AST_APPEND_STR("throw"));

	MATCH1(unresolved_name);
	MATCH1(expr_primary);
	RULE_FOOT(expression);
}

bool rule_simple_id(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(simple_id);
	MATCH(RULE_X(0, source_name) && OPTIONAL(RULE_X(1, template_args)));
	RULE_FOOT(simple_id);
}

bool parse_non_neg_number(
	StrIter *msi, ut64 *out) {
	*out = 0;
	if (PEEK() < '0' || PEEK() > '9') {
		return false;
	}
	while (PEEK() >= '0' && PEEK() <= '9') {
		*out *= 10;
		*out += (ut64)(*CONSUME() - '0');
	}
	return true;
}

bool rule_template_param(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(template_param);
	if (!(READ('T'))) {
		TRACE_RETURN_FAILURE();
	}

	ut64 level = 0;
	if (READ('L')) {
		if (!(parse_non_neg_number(msi, &level) && READ('_'))) {
			TRACE_RETURN_FAILURE();
		}
		level++;
	}

	ut64 index = 0;
	if (!READ('_')) {
		if (!(parse_non_neg_number(msi, &index) && READ('_'))) {
			TRACE_RETURN_FAILURE();
		}
		index++;
	}

	if (!meta_substitute_tparam(m, dan, level, index)) {
		TRACE_RETURN_FAILURE();
	}
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(template_param);
}

bool rule_discriminator(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(discriminator);
	if (READ('_')) {
		// matched two "_"
		if (READ('_')) {
			st64 numlt10 = -1;
			READ_NUMBER(numlt10);
			if (numlt10 >= 10) {
				// do something
				TRACE_RETURN_SUCCESS;
			}
		} else {
			// matched single "_"
			st64 numlt10 = -1;
			READ_NUMBER(numlt10);
			if (numlt10 >= 0 && numlt10 < 10) {
				// do something
				TRACE_RETURN_SUCCESS;
			}
		}
	}

	TRACE_RETURN_FAILURE();
	RULE_FOOT(discriminator);
}

bool rule_initializer(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(initializer);
	MATCH(
		READ_STR("pi") && AST_APPEND_STR(" (") && RULE_MANY_WITH_SEP(expression, ", ") &&
		AST_APPEND_CHR(')') && READ('E'));
	RULE_FOOT(initializer);
}

bool rule_abi_tag(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(abi_tag);
	// will generate " \"<source_name>\","
	MATCH(READ('B') && AST_APPEND_STR(" \"") && RULE_X(0, source_name) && AST_APPEND_STR("\","));
	RULE_FOOT(abi_tag);
}

bool rule_call_offset(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(call_offset);
	MATCH(READ('h') && AST_APPEND_STR("non-virtual thunk to ") && RULE_X(0, nv_offset) && READ('_'));
	MATCH(READ('v') && AST_APPEND_STR("virtual thunk to ") && RULE_X(0, v_offset) && READ('_'));
	RULE_FOOT(call_offset);
}

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

bool rule_special_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(special_name);
	MATCH(READ_STR("Tc") && RULE_X(0, call_offset) && RULE_X(1, call_offset) && RULE_X(2, encoding));
	MATCH_AND_DO(
		READ_STR("GR") && RULE_DEFER(AST(0), name) && RULE_DEFER(AST(1), seq_id) && READ('_'),
		{
			AST_APPEND_STR("reference temporary for ");
			AST_MERGE(AST(0));
			AST_MERGE(AST(1));
		});
	MATCH(READ('T') && RULE_X(0, call_offset) && RULE_X(1, encoding));
	MATCH(READ_STR("GR") && AST_APPEND_STR("reference temporary for ") && RULE_X(0, name) && READ('_'));
	MATCH(READ_STR("TV") && AST_APPEND_STR("vtable for ") && RULE_X(0, type));
	MATCH(READ_STR("TT") && AST_APPEND_STR("VTT structure for ") && RULE_X(0, type));
	MATCH(READ_STR("TI") && AST_APPEND_STR("typeinfo for ") && RULE_X(0, type));
	MATCH(READ_STR("TS") && AST_APPEND_STR("typeinfo name for ") && RULE_X(0, type));
	MATCH(READ_STR("GV") && AST_APPEND_STR("guard variable for ") && RULE_X(0, name));
	MATCH(READ_STR("GTt") && RULE_X(0, encoding));
	// TODO: GI <module-name> v
	RULE_FOOT(special_name);
}

bool rule_function_type(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(function_type);
	// This rule only handles F...E (bare function type)
	// P prefix is handled in the type rule, which properly inserts * for function pointers

	MATCH_AND_DO(
		OPTIONAL(RULE_DEFER(AST(0), cv_qualifiers)) && OPTIONAL(RULE_DEFER(AST(1), exception_spec)) &&
			OPTIONAL(READ_STR("Dx")) && READ('F') && OPTIONAL(READ('Y')) &&

			// Return type. If return type is builtin type, then it's not substitutable
			// If return type is a type, then it's substitutable, so add using APPEND_TYPE
			RULE_DEFER(AST(2), type) &&
			RULE_DEFER(AST(3), bare_function_type) &&
			OPTIONAL(RULE_DEFER(AST(4), ref_qualifier)) && READ('E'),
		{
			AST_MERGE(AST(2)); // return type
			AST_APPEND_STR(" (");
			AST_MERGE(AST(3)); // bare-function-type
			AST_APPEND_STR(")");
			AST_MERGE_OPT(AST(4)); // ref-qualifier
			AST_MERGE_OPT(AST(0)); // cv-qualifiers
			AST_MERGE_OPT(AST(1)); // exception spec
			AST_APPEND_TYPE;
		});
	RULE_FOOT(function_type);
}

static void handle_pointer_to_func(DemAstNode *dan) {
	if (VecF(DemAstNode, len)(dan->children) == 2 && AST(1)->tag == CP_DEM_TYPE_KIND_function_type) {
		DemAstNode *func_node = AST(1);
		AST_APPEND_DEMSTR(&AST_(func_node, 2)->dem); // return type
		AST_APPEND_STR(" (");
		AST_APPEND_DEMSTR(&AST(0)->dem);
		AST_APPEND_STR("::*)");

		AST_APPEND_STR("(");
		AST_APPEND_DEMSTR_OPT(&AST_(func_node, 3)->dem); // bare-function-type
		AST_APPEND_STR(")");

		AST_APPEND_DEMSTR_OPT(&AST_(func_node, 4)->dem); // ref-qualifier
		AST_APPEND_DEMSTR_OPT(&AST_(func_node, 0)->dem); // cv-qualifiers
		AST_APPEND_DEMSTR_OPT(&AST_(func_node, 1)->dem); // exception spec
	} else {
		DEM_UNREACHABLE;
	}
}

static DemAstNode *extract_from_subs(DemAstNode *dan) {
	if (dan->tag == CP_DEM_TYPE_KIND_substitution && AST(0)->tag == CP_DEM_TYPE_KIND_seq_id) {
		return AST_(AST(0), 0);
	}
	return NULL;
}

static DemAstNode *extract_func_type_node(DemAstNode *dan, DemString *func_name) {
	DemAstNode *func_node = NULL;
	if (dan->tag == CP_DEM_TYPE_KIND_function_type) {
		return dan;
	}

	if (func_name && dem_string_non_empty(func_name)) {
		char *p = NULL;
		if ((p = strstr(dan->dem.buf, "(*"))) {
			size_t name_len = strchr(p, ')') - (p + 1);
			dem_string_append_n(func_name, p + 1, name_len);
		}
	}

	if (AST(0)->tag == CP_DEM_TYPE_KIND_function_type) {
		func_node = AST(0);
	} else if (dan->tag == CP_DEM_TYPE_KIND_type) {
		DemAstNode *node = dan;
		if (VecF(DemAstNode, len)(node->children) == 1 && AST_(node, 0)->tag == CP_DEM_TYPE_KIND_function_type) {
			return AST_(node, 0);
		}

		if (VecF(DemAstNode, len)(node->children) == 2) {
			if (AST_(node, 1)->tag == CP_DEM_TYPE_KIND_type) {
				node = AST_(node, 1);
			} else if (AST_(node, 1)->tag == CP_DEM_TYPE_KIND_substitution) {
				node = extract_from_subs(AST_(node, 1));
				if (!node || node->tag != CP_DEM_TYPE_KIND_type) {
					return NULL;
				}
			}
		}

		while (node->tag == CP_DEM_TYPE_KIND_type) {
			if (!(node->subtag == POINTER_TYPE || node->subtag == REFERENCE_TYPE || node->subtag == RVALUE_REFERENCE_TYPE || node->subtag == QUALIFIED_TYPE)) {
				return NULL;
			}
			if (node->tag == QUALIFIED_TYPE) {
				node = AST_(node, 1);
			} else {
				node = AST_(node, 0);
			}
			if (node->tag == CP_DEM_TYPE_KIND_function_type) {
				return node;
			}
		}
	} else if ((func_node = extract_from_subs(dan))) {
		if (!(func_node->tag == CP_DEM_TYPE_KIND_type && VecF(DemAstNode, len)(func_node->children) == 1 && AST_(func_node, 0)->tag == CP_DEM_TYPE_KIND_function_type)) {
			return NULL;
		}
	} else if (VecF(DemAstNode, len)(dan->children) == 2) {
		// Case for qualified_type where AST(1) is the pointer/func type
		if (AST(1)->tag == CP_DEM_TYPE_KIND_type &&
			VecF(DemAstNode, len)(AST(1)->children) == 1 &&
			AST_(AST(1), 0)->tag == CP_DEM_TYPE_KIND_function_type) {
			func_node = AST_(AST(1), 0);
		}
	}

	return func_node;
}

static void handle_func_pointer(DemAstNode *dan, DemAstNode *func_node, DemString *func_name, const char *postfix) {
	if (!func_node) {
		DEM_UNREACHABLE;
	}

	if (func_node->tag == CP_DEM_TYPE_KIND_type && AST_(func_node, 0)->tag == CP_DEM_TYPE_KIND_function_type) {
		func_node = AST_(func_node, 0);
	}

	AST_APPEND_DEMSTR(&AST_(func_node, 2)->dem); // return type
	AST_APPEND_STR(" (");
	if (dem_string_non_empty(func_name)) {
		AST_APPEND_DEMSTR(func_name);
	}
	if (*postfix != '*' && *postfix != '&') {
		AST_APPEND_CHR(' ');
	}
	AST_APPEND_STR(postfix);
	AST_APPEND_STR(")");

	AST_APPEND_STR("(");
	AST_APPEND_DEMSTR_OPT(&AST_(func_node, 3)->dem); // bare-function-type
	AST_APPEND_STR(")");

	AST_APPEND_DEMSTR_OPT(&AST_(func_node, 4)->dem); // ref-qualifier
	AST_APPEND_DEMSTR_OPT(&AST_(func_node, 0)->dem); // cv-qualifiers
	AST_APPEND_DEMSTR_OPT(&AST_(func_node, 1)->dem); // exception spec
}

bool rule_function_param(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(function_param);
	MATCH(READ_STR("fL") && RULE_X(0, non_negative_number) && READ('p') &&
		RULE_X(1, top_level_cv_qualifiers) && AST_APPEND_CHR(' ') && RULE_X(2, non_negative_number) &&
		READ('_'));
	MATCH(READ_STR("fL") && RULE_X(0, non_negative_number) && READ('p') &&
		RULE_X(1, top_level_cv_qualifiers) && AST_APPEND_CHR(' ') && READ('_'));
	MATCH(READ_STR("fp") && RULE_X(0, top_level_cv_qualifiers) && AST_APPEND_CHR(' ') &&
		RULE_X(1, non_negative_number) && READ('_'));
	MATCH(READ_STR("fp") && RULE_X(0, top_level_cv_qualifiers) && AST_APPEND_CHR(' ') && READ('_'));
	MATCH(READ_STR("fPT"));
	RULE_FOOT(function_param);
}

bool rule_builtin_type(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(builtin_type);
	MATCH(READ_STR("DF") && AST_APPEND_STR("_Float") && RULE_X(0, number) && READ('_'));
	MATCH(READ_STR("DF") && AST_APPEND_STR("_Float") && RULE_X(0, number) && READ('x') && AST_APPEND_STR("x"));
	MATCH(READ_STR("DF") && AST_APPEND_STR("std::bfloat") && RULE_X(0, number) && READ('b') && AST_APPEND_STR("_t"));
	MATCH(READ_STR("DB") && AST_APPEND_STR("signed _BitInt(") && RULE_X(0, number) && AST_APPEND_STR(")") && READ('_'));
	MATCH(READ_STR("DB") && AST_APPEND_STR("signed _BitInt(") && RULE_X(0, expression) && AST_APPEND_STR(")") && READ('_'));
	MATCH(READ_STR("DU") && AST_APPEND_STR("unsigned _BitInt(") && RULE_X(0, number) && AST_APPEND_STR(")") && READ('_'));
	MATCH(READ_STR("DU") && AST_APPEND_STR("unsigned _BitInt(") && RULE_X(0, expression) && AST_APPEND_STR(")") && READ('_'));
	MATCH(READ('u') && RULE_X(0, source_name) && OPTIONAL(RULE_X(1, template_args)));
	MATCH(READ_STR("DS") && READ_STR("DA") && AST_APPEND_STR("_Sat _Accum"));
	MATCH(READ_STR("DS") && READ_STR("DR") && AST_APPEND_STR("_Sat _Fract"));
	MATCH(READ('v') && AST_APPEND_STR("void"));
	MATCH(READ('w') && AST_APPEND_STR("wchar_t"));
	MATCH(READ('b') && AST_APPEND_STR("bool"));
	MATCH(READ('c') && AST_APPEND_STR("char"));
	MATCH(READ('a') && AST_APPEND_STR("signed char"));
	MATCH(READ('h') && AST_APPEND_STR("unsigned char"));
	MATCH(READ('s') && AST_APPEND_STR("short"));
	MATCH(READ('t') && AST_APPEND_STR("unsigned short"));
	MATCH(READ('i') && AST_APPEND_STR("int"));
	MATCH(READ('j') && AST_APPEND_STR("unsigned int"));
	MATCH(READ('l') && AST_APPEND_STR("long"));
	MATCH(READ('m') && AST_APPEND_STR("unsigned long"));
	MATCH(READ('x') && AST_APPEND_STR("long long"));
	MATCH(READ('y') && AST_APPEND_STR("unsigned long long"));
	MATCH(READ('n') && AST_APPEND_STR("__int128"));
	MATCH(READ('o') && AST_APPEND_STR("unsigned __int128"));
	MATCH(READ('f') && AST_APPEND_STR("float"));
	MATCH(READ('d') && AST_APPEND_STR("double"));
	MATCH(READ('e') && AST_APPEND_STR("long double"));
	MATCH(READ('g') && AST_APPEND_STR("__float128"));
	MATCH(READ('z') && AST_APPEND_STR("..."));
	MATCH(READ_STR("Dd") && AST_APPEND_STR("decimal64"));
	MATCH(READ_STR("De") && AST_APPEND_STR("decimal128"));
	MATCH(READ_STR("Df") && AST_APPEND_STR("decimal32"));
	MATCH(READ_STR("Dh") && AST_APPEND_STR("half"));
	MATCH(READ_STR("Di") && AST_APPEND_STR("char32_t"));
	MATCH(READ_STR("Ds") && AST_APPEND_STR("char16_t"));
	MATCH(READ_STR("Du") && AST_APPEND_STR("char8_t"));
	MATCH(READ_STR("Da") && AST_APPEND_STR("auto"));
	MATCH(READ_STR("Dc") && AST_APPEND_STR("decltype(auto)"));
	MATCH(READ_STR("Dn") && AST_APPEND_STR("std::nullptr_t"));
	MATCH(READ_STR("DA") && AST_APPEND_STR("_Accum"));
	MATCH(READ_STR("DR") && AST_APPEND_STR("_Fract"));

	RULE_FOOT(builtin_type);
}

bool rule_extended_qualifier(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(extended_qualifier);
	MATCH(READ('U') && RULE_X(0, source_name) && RULE_X(1, template_args));
	MATCH(READ('U') && RULE_X(0, source_name));
	RULE_FOOT(extended_qualifier);
}

bool rule_source_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(source_name);
	/* positive number providing length of name followed by it */
	st64 name_len = 0;
	READ_NUMBER(name_len);

	if (name_len == 0 || CUR() == dan->val.buf) {
		TRACE_RETURN_FAILURE();
	}
	// Avoid pointer overflow and ensure we have enough data
	st64 remaining = END() - CUR();
	if (name_len < 0 || name_len > remaining) {
		TRACE_RETURN_FAILURE();
	}

	AST_APPEND_STR_N(CUR(), name_len);
	CUR() += name_len;
	TRACE_RETURN_SUCCESS;
}

bool rule_abi_tags(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(abi_tags);
	MATCH(RULE_ATLEAST_ONCE(abi_tag));
	RULE_FOOT(abi_tags);
}

bool rule_class_enum_type(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(class_enum_type);
	MATCH(OPTIONAL(READ_STR("Ts") || READ_STR("Tu") || READ_STR("Te")) && RULE_X(0, name));
	RULE_FOOT(class_enum_type);
}

bool rule_bare_function_type(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(bare_function_type);
	// If only parameter is void, output nothing (empty params)
	// This is per Itanium ABI: "void" as the only parameter means no parameters
	MATCH(READ('v') && true); // consume 'v' but output nothing);
	MATCH(RULE_ATLEAST_ONCE_WITH_SEP(type, ", "));
	RULE_FOOT(bare_function_type);
}

bool rule_mangled_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(mangled_name);
	MATCH(READ_STR("_Z") && RULE_X(0, encoding) && OPTIONAL(READ('.') && RULE_X(1, vendor_specific_suffix)));
	RULE_FOOT(mangled_name);
}

bool rule_cv_qualifiers(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(cv_qualifiers);
	MATCH(READ('K') && AST_APPEND_STR("const"));
	MATCH(READ('V') && AST_APPEND_STR("volatile"));
	MATCH(READ('r') && AST_APPEND_STR("restrict"));
	RULE_FOOT(cv_qualifiers);
}

bool rule_qualifiers(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(qualifiers);

	bool has_qualifiers = match_zero_or_more_rules(
				      first_of_rule_extended_qualifier,
				      rule_extended_qualifier,
				      " ",
				      AST(0),
				      msi,
				      m,
				      graph,
				      _my_node_id) &&
		VecDemAstNode_len(AST(0)->children) > 0;

	MATCH(RULE_X(1, cv_qualifiers) && (!has_qualifiers || (AST_APPEND_CHR(' ') && AST_MERGE(AST(0)))));

	RULE_FOOT(qualifiers);
}

bool rule_type(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(type);

	MATCH_AND_DO(RULE_CALL_DEFER(AST(0), qualifiers) && RULE_CALL_DEFER(AST(1), type), {
		dan->subtag = QUALIFIED_TYPE;
		DemAstNode *func_node = NULL;
		DemString func_name = { 0 };
		if ((func_node = extract_func_type_node(AST(1), &func_name))) {
			handle_func_pointer(dan, func_node, &func_name, AST(0)->dem.buf);
			dem_string_deinit(&func_name);
		} else {
			AST_MERGE(AST(1));
			if (AST(0)->dem.len > 0) {
				AST_APPEND_STR(" ");
				AST_MERGE(AST(0));
			}
		}
		AST_APPEND_TYPE;
	});
	MATCH(READ('C') && RULE_X(0, type)); // complex pair (C99)
	MATCH(READ('G') && RULE_X(0, type)); // imaginary (C99)

	// Handle pointer types - special handling for function types
	// For PF...E, we need to produce "ret (*)(args)" and add both S_entries
	MATCH_AND_DO(READ('P') && RULE_CALL_DEFER(AST(0), type), {
		// Check if this is a function type by checking child AST tag
		dan->subtag = POINTER_TYPE;
		DemAstNode *func_node = NULL;
		DemString func_name = { 0 };
		if ((func_node = extract_func_type_node(AST(0), &func_name))) {
			handle_func_pointer(dan, func_node, &func_name, "*");
			dem_string_deinit(&func_name);
		} else {
			// Regular pointer: just append "*"
			dem_string_concat(&dan->dem, &AST(0)->dem);
			dem_string_append(&dan->dem, "*");
		}
		AST_APPEND_TYPE;
	});

	MATCH_AND_DO(READ('R') && RULE_CALL_DEFER(AST(0), type), {
		// Check if this is a function pointer type
		dan->subtag = REFERENCE_TYPE;
		DemAstNode *func_node = NULL;
		DemString func_name = { 0 };
		if ((func_node = extract_func_type_node(AST(0), &func_name))) {
			// Function pointer: insert & inside the (*...) before the closing )
			// "void (* const)(int)" -> "void (* const&)(int)"
			handle_func_pointer(dan, func_node, &func_name, "&");
			dem_string_deinit(&func_name);
		} else {
			AST_MERGE(AST(0));
			dem_string_append(&dan->dem, "&");
		}
		// Reference types ARE substitutable per Itanium ABI section 5.1.5
		AST_APPEND_TYPE;
	});
	MATCH_AND_DO(READ('O') && RULE_CALL_DEFER(AST(0), type), {
		// Check if this is a function pointer type
		dan->subtag = RVALUE_REFERENCE_TYPE;
		DemAstNode *func_node = NULL;
		DemString func_name = { 0 };
		if ((func_node = extract_func_type_node(AST(0), &func_name))) {
			// Function pointer: insert && inside the (*...) before the closing )
			// "void (* const)(int)" -> "void (* const&&)(int)"
			handle_func_pointer(dan, func_node, &func_name, "&&");
			dem_string_deinit(&func_name);
		} else {
			AST_MERGE(AST(0));
			dem_string_append(&dan->dem, "&&");
		}
		// Rvalue reference types ARE substitutable per Itanium ABI section 5.1.5
		AST_APPEND_TYPE;
	});
	MATCH(READ_STR("Dp") && RULE_X(0, type)); // pack expansion (C++11)

	MATCH1(builtin_type);
	MATCH1(array_type);
	MATCH1(pointer_to_member_type);
	MATCH1(decltype);
	MATCH1(function_type);

	switch (PEEK()) {
	case 'T': {
		if (strchr("sue", PEEK_AT(1)) != NULL) {
			if (!RULE_CALL_DEFER(AST(0), class_enum_type)) {
				TRACE_RETURN_FAILURE();
			}
			AST_MERGE(AST(0));
			break;
		}
		if (!RULE_CALL_DEFER(AST(0), template_param)) {
			TRACE_RETURN_FAILURE();
		}
		AST_MERGE(AST(0));
		if (PEEK() == 'I') {
			AST_APPEND_TYPE;
			DemAstNode node_template_args = { 0 };
			if (!rule_template_args(RULE_ARGS(&node_template_args))) {
				TRACE_RETURN_FAILURE();
			}
			AST_APPEND_NODE(&node_template_args);
		}
		break;
	}
	case 'S': {
		// Save position to check what substitution we parsed
		const char *before_subst = CUR();
		if (!rule_substitution(RULE_ARGS(AST(0)))) {
			TRACE_RETURN_FAILURE();
		}
		const char *after_subst = CUR();

		AST_MERGE(AST(0));

		// Special case: St followed by digit means std::<identifier>
		// Check if we consumed exactly "St" and next char is a digit
		bool is_std_identifier = false;
		if (after_subst - before_subst == 2 && before_subst[0] == 'S' && before_subst[1] == 't' && isdigit(PEEK())) {
			is_std_identifier = true;
			dem_string_append(&dan->dem, "::");
			if (!RULE_CALL_DEFER(AST(1), source_name)) {
				TRACE_RETURN_FAILURE();
			}
			AST_MERGE(AST(1));
			// Add the qualified name (e.g., "std::function") to substitution table
			// BEFORE parsing template args, so back-references work correctly
			if (PEEK() == 'I') {
				AST_APPEND_TYPE;
			}
		}

		if (!(RULE_X(2, template_args))) {
			// Only add to substitution table if we parsed St<identifier>
			// Builtin substitutions (St, So, Sa, etc.) and back-references (S_, S0_, etc.) should NOT be added
			if (is_std_identifier) {
				AST_APPEND_TYPE;
			}
			TRACE_RETURN_SUCCESS;
		}
		break;
	}
	default:
		if (!RULE_CALL(class_enum_type)) {
			TRACE_RETURN_FAILURE();
		}
		break;
	}

	if (DemAstNode_non_empty(dan)) {
		AST_APPEND_TYPE;
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(type);
}

bool rule_base_unresolved_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(base_unresolved_name);
	MATCH(READ_STR("on") && RULE_X(0, operator_name) && RULE_X(1, template_args));
	MATCH(READ_STR("on") && RULE_X(0, operator_name));
	MATCH(READ_STR("dn") && RULE_X(0, destructor_name));
	MATCH(RULE_X(0, simple_id));
	RULE_FOOT(base_unresolved_name);
}

bool rule_local_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(local_name);
	MATCH_AND_DO(
		READ('Z') && RULE_DEFER(AST(0), encoding) && READ_STR("Ed") && OPTIONAL(RULE_DEFER(AST(1), number)) &&
			READ('_') && RULE_DEFER(AST(2), name),
		{
			AST_MERGE(AST(0));
			AST_MERGE(AST(1));
			AST_APPEND_STR("::");
			AST_MERGE(AST(2));
		});
	MATCH_AND_DO(
		READ('Z') && RULE_DEFER(AST(0), encoding) && READ('E') && RULE_DEFER(AST(1), name) &&
			OPTIONAL(RULE_DEFER(AST(2), discriminator)),
		{
			AST_MERGE(AST(0));
			AST_APPEND_STR("::");
			AST_MERGE(AST(1));
			AST_MERGE(AST(2));
		});
	MATCH(READ('Z') && RULE_X(0, encoding) && READ_STR("Es") && OPTIONAL(RULE_X(1, discriminator)));
	RULE_FOOT(local_name);
}

static ut64 base36_to_int(const char *buf, ut64 *px) {
	static const char *base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
	char *pos = NULL;
	ut64 pow = 1;
	ut64 x = 0;
	ut64 sz = 0;
	while ((pos = strchr(base, buf[sz]))) {
		st64 based_val = pos - base;
		x += based_val * pow;
		pow *= 36;
		sz++;
	}
	*px = x;
	return sz;
}

bool rule_seq_id(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(seq_id);
	if (IS_DIGIT(PEEK()) || IS_UPPER(PEEK())) {
		ut64 sid = 0;
		msi->cur += base36_to_int(msi->cur, &sid);
		return meta_substitute_type(m, sid + 1, dan);
	}
	if (PEEK() == '_') {
		return meta_substitute_type(m, 0, dan);
	}
	RULE_FOOT(seq_id);
}

bool rule_substitution(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(substitution);
	if (PEEK() != 'S') {
		TRACE_RETURN_FAILURE();
	}
	MATCH(READ('S') && RULE_X(0, seq_id) && READ('_'));

	MATCH(READ_STR("St") && AST_APPEND_STR("std"));
	MATCH(READ_STR("Sa") && AST_APPEND_STR("std::allocator"));
	MATCH(READ_STR("Sb") && AST_APPEND_STR("std::basic_string"));
	// For std::string (Ss), expand to full form when followed by ctor/dtor (C or D)
	// This handles cases like _ZNSsC2ERKSs (std::basic_string constructor)
	MATCH(READ_STR("Ss") && ((PEEK() == 'C' || PEEK() == 'D') ? AST_APPEND_STR("std::basic_string<char, std::char_traits<char>, std::allocator<char>>") : AST_APPEND_STR("std::string")));
	MATCH(READ_STR("Si") && AST_APPEND_STR("std::istream")
		// AST_APPEND_STR ("std::basic_istream<char, std::char_traits<char>>")
	);
	MATCH(READ_STR("So") && AST_APPEND_STR("std::ostream")
		// AST_APPEND_STR ("std::basic_ostream<char, std::char_traits<char>>")
	);

	MATCH(READ_STR("Sd") && AST_APPEND_STR("std::iostream")
		// AST_APPEND_STR ("std::basic_iostream<char, std::char_traits<char>>")
	);
	RULE_FOOT(substitution);
}

bool rule_operator_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(operator_name);
	MATCH(READ('v') && RULE_X(0, digit) && RULE_X(1, source_name));
	MATCH(READ_STR("cv") && AST_APPEND_STR("operator (") && RULE_X(0, type) && AST_APPEND_STR(")"));
	MATCH(READ_STR("nw") && AST_APPEND_STR("operator new"));
	MATCH(READ_STR("na") && AST_APPEND_STR("operator new[]"));
	MATCH(READ_STR("dl") && AST_APPEND_STR("operator delete"));
	MATCH(READ_STR("da") && AST_APPEND_STR("operator delete[]"));
	MATCH(READ_STR("aw") && AST_APPEND_STR("operator co_await"));
	MATCH(READ_STR("ps") && AST_APPEND_STR("operator+"));
	MATCH(READ_STR("ng") && AST_APPEND_STR("operator-"));
	MATCH(READ_STR("ad") && AST_APPEND_STR("operator&"));
	MATCH(READ_STR("de") && AST_APPEND_STR("operator*"));
	MATCH(READ_STR("co") && AST_APPEND_STR("operator~"));
	MATCH(READ_STR("pl") && AST_APPEND_STR("operator+"));
	MATCH(READ_STR("mi") && AST_APPEND_STR("operator-"));
	MATCH(READ_STR("ml") && AST_APPEND_STR("operator*"));
	MATCH(READ_STR("dv") && AST_APPEND_STR("operator/"));
	MATCH(READ_STR("rm") && AST_APPEND_STR("operator%"));
	MATCH(READ_STR("an") && AST_APPEND_STR("operator&"));
	MATCH(READ_STR("or") && AST_APPEND_STR("operator|"));
	MATCH(READ_STR("eo") && AST_APPEND_STR("operator^"));
	MATCH(READ_STR("aS") && AST_APPEND_STR("operator="));
	MATCH(READ_STR("pL") && AST_APPEND_STR("operator+="));
	MATCH(READ_STR("mI") && AST_APPEND_STR("operator-="));
	MATCH(READ_STR("mL") && AST_APPEND_STR("operator*="));
	MATCH(READ_STR("dV") && AST_APPEND_STR("operator/="));
	MATCH(READ_STR("rM") && AST_APPEND_STR("operator%="));
	MATCH(READ_STR("aN") && AST_APPEND_STR("operator&="));
	MATCH(READ_STR("oR") && AST_APPEND_STR("operator|="));
	MATCH(READ_STR("eO") && AST_APPEND_STR("operator^="));
	MATCH(READ_STR("ls") && AST_APPEND_STR("operator<<"));
	MATCH(READ_STR("rs") && AST_APPEND_STR("operator>>"));
	MATCH(READ_STR("lS") && AST_APPEND_STR("operator<<="));
	MATCH(READ_STR("rS") && AST_APPEND_STR("operator>>="));
	MATCH(READ_STR("eq") && AST_APPEND_STR("operator=="));
	MATCH(READ_STR("ne") && AST_APPEND_STR("operator!="));
	MATCH(READ_STR("lt") && AST_APPEND_STR("operator<"));
	MATCH(READ_STR("gt") && AST_APPEND_STR("operator>"));
	MATCH(READ_STR("le") && AST_APPEND_STR("operator<="));
	MATCH(READ_STR("ge") && AST_APPEND_STR("operator>="));
	MATCH(READ_STR("ss") && AST_APPEND_STR("operator<=>"));
	MATCH(READ_STR("nt") && AST_APPEND_STR("operator!"));
	MATCH(READ_STR("aa") && AST_APPEND_STR("operator&&"));
	MATCH(READ_STR("oo") && AST_APPEND_STR("operator||"));
	MATCH(READ_STR("pp") && AST_APPEND_STR("operator++"));
	MATCH(READ_STR("mm") && AST_APPEND_STR("operator--"));
	MATCH(READ_STR("cm") && AST_APPEND_STR("operator,"));
	MATCH(READ_STR("pm") && AST_APPEND_STR("operator->*"));
	MATCH(READ_STR("pt") && AST_APPEND_STR("operator->"));
	MATCH(READ_STR("cl") && AST_APPEND_STR("operator()"));

	/* will generate " (type)" */
	MATCH(READ_STR("ix") && AST_APPEND_STR("operator[]"));

	/* operator-name ::= li <source-name>          # operator ""*/
	MATCH(READ_STR("li") && RULE_X(0, source_name)); // TODO(brightprogrammer): How to generate for this operator?

	MATCH(READ_STR("qu") && AST_APPEND_STR("operator?"));
	RULE_FOOT(operator_name);
}

bool rule_float(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(float);
	bool r = false;
	while (IS_DIGIT(PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
		r = true;
		ADV();
	}
	return r;
	RULE_FOOT(float);
}

bool rule_destructor_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(destructor_name);
	MATCH1(unresolved_type);
	MATCH1(simple_id);
	RULE_FOOT(destructor_name);
}

bool rule_name(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(name);

	// For unscoped_name + template_args, we need to record:
	// 1. The template name (unscoped_name) BEFORE processing template_args
	// 2. NOTE: The complete template instantiation is NOT added here because
	//    function/variable template instantiations are not substitutable per ABI 5.1.4
	//    Only type template instantiations are substitutable (handled in rule_type)
	MATCH(RULE_X(0, unscoped_name) &&
		// If followed by template args, add the template name to substitution table NOW
		// This ensures correct ordering (template name comes before template args)
		(PEEK() == 'I' ? AST_APPEND_TYPE1(AST(0)) : true) &&
		RULE_X(1, template_args));

	// For substitution + template_args, the substitution reference itself is already in the table
	MATCH(RULE_X(0, substitution) && RULE_X(1, template_args));

	// nested_name - propagate tag if it's a template function
	MATCH1(nested_name);
	MATCH1(unscoped_name);
	MATCH1(local_name);

	RULE_FOOT(name);
}

bool rule_nested_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(nested_name);
	if (!READ('N')) {
		TRACE_RETURN_FAILURE();
	}

	RULE_CALL_DEFER(AST(0), cv_qualifiers);
	RULE_CALL_DEFER(AST(1), ref_qualifier);

	DemAstNode *ast_node = NULL;
	while (!READ('E')) {
		if (PEEK() == 'T') {
			if (ast_node != NULL) {
				TRACE_RETURN_FAILURE();
			}
			DemAstNode node_template_param = { 0 };
			if (rule_template_param(RULE_ARGS(&node_template_param))) {
				ast_node = VecF(DemAstNode, append)(dan->children, &node_template_param);
				AST_MERGE(ast_node);
			}
		} else if (PEEK() == 'I') {
			if (ast_node == NULL) {
				TRACE_RETURN_FAILURE();
			}
			DemAstNode node_template_args = { 0 };
			if (rule_template_args(RULE_ARGS(&node_template_args))) {
				if (ast_node && VecDemAstNode_len(ast_node->children) > 0 && VecDemAstNode_tail(ast_node->children)->tag == CP_DEM_TYPE_KIND_template_args) {
					TRACE_RETURN_FAILURE();
				}
				DemAstNode_append(dan, &node_template_args);
			} else {
				TRACE_RETURN_FAILURE();
			}
			ast_node = dan;
		} else if (PEEK() == 'D' && (PEEK_AT(1) == 't' || PEEK_AT(1) == 'T')) {
			if (ast_node != NULL) {
				TRACE_RETURN_FAILURE();
			}
			DemAstNode node_decltype = { 0 };
			if (rule_decltype(RULE_ARGS(&node_decltype))) {
				ast_node = DemAstNode_append(dan, &node_decltype);
			}
		} else {
			if (PEEK() == 'S') {
				DemAstNode *subst = NULL;
				if (PEEK_AT(1) == 't') {
					subst = VecF(DemAstNode, append)(dan->children, NULL);
					DemAstNode_ctor_inplace(subst, CP_DEM_TYPE_KIND_name, "std", CUR(), 2);
					ADV_BY(2);
					AST_MERGE(subst);
				} else {
					DemAstNode node_substitution = { 0 };
					if (rule_substitution(RULE_ARGS(&node_substitution))) {
						subst = DemAstNode_append(dan, &node_substitution);
					}
				}
				if (!subst) {
					TRACE_RETURN_FAILURE();
				}
				if (ast_node != NULL) {
					TRACE_RETURN_FAILURE();
				} else {
					ast_node = subst;
					continue;
				}
			}

			DemAstNode node_unqualified_name = { 0 };
			if (rule_unqualified_name(RULE_ARGS(&node_unqualified_name))) {
				// Only add "::" if we've already added name components
				// Note: indices 0,1 are pre-allocated for cv_qualifiers/ref_qualifier
				// so actual name components start at index 2
				if (dan->children && VecDemAstNode_len(dan->children) > 2) {
					AST_APPEND_STR("::");
				}
				ast_node = VecF(DemAstNode, append)(dan->children, &node_unqualified_name);
				AST_MERGE(ast_node);
			} else if (PEEK() != 'E' && PEEK() != 'M') {
				// If unqualified_name fails and we're not at a valid terminator, fail
				TRACE_RETURN_FAILURE();
			}
		}

		if (ast_node == NULL) {
			TRACE_RETURN_FAILURE();
		}
		AST_APPEND_TYPE;

		READ('M');
	}

	if (ast_node == NULL || VecF(DemAstNode, empty)(&m->detected_types)) {
		TRACE_RETURN_FAILURE();
	}
	VecF(DemAstNode, pop)(&m->detected_types);
	TRACE_RETURN_SUCCESS;

	RULE_FOOT(nested_name);
}

bool rule_template_template_param(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(template_template_param);
	MATCH1(template_param);
	MATCH1(substitution);
	RULE_FOOT(template_template_param);
}

// Helper to append the last detected class name for ctor/dtor
static bool append_last_class_name(DemAstNode *dan, Meta *m) {
	if (m->detected_types.length > 0) {
		DemAstNode *last_type = vec_ptr_at(&m->detected_types, m->detected_types.length - 1);
		if (last_type && last_type->dem.buf) {
			// Find the last :: that is NOT inside template arguments <...>
			const char *name = last_type->dem.buf;
			const char *last_sep = name;
			const char *p = name;
			int depth = 0; // Track template argument nesting depth
			while (*p) {
				if (*p == '<') {
					depth++;
				} else if (*p == '>') {
					depth--;
				} else if (p[0] == ':' && p[1] == ':' && depth == 0) {
					last_sep = p + 2;
					p += 2;
					continue;
				}
				p++;
			}
			// Also strip template arguments (find first < at depth 0)
			const char *tmpl = last_sep;
			while (*tmpl && *tmpl != '<') {
				tmpl++;
			}
			// For std::basic_string<...> constructor/destructor, output "basic_string" not "string"
			size_t name_len = tmpl - last_sep;
			if (name_len == 6 && memcmp(last_sep, "string", 6) == 0) {
				// Check if this is std::basic_string<...> by looking at the full name
				const char *basic_str =
					"std::basic_string<char, std::char_traits<char>, std::allocator<char>>";
				if (strncmp(name, basic_str, strlen(basic_str)) == 0) {
					dem_string_append(&dan->dem, "basic_string");
					return true;
				}
			}
			dem_string_append_n(&dan->dem, last_sep, name_len);
			return true;
		}
	}
	return false;
}

bool rule_ctor_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(ctor_name);
	// NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
	MATCH(
		READ_STR("C1") && SET_CTOR() && append_last_class_name(dan, m)); // gnu complete object ctor
	MATCH(
		READ_STR("C2") && SET_CTOR() && append_last_class_name(dan, m)); // gnu base object ctor
	MATCH(
		READ_STR("C3") && SET_CTOR() && append_last_class_name(dan, m)); // gnu complete object allocating ctor
	MATCH(READ_STR("C4") && SET_CTOR() && append_last_class_name(dan, m)); // gnu unified ctor
	MATCH(
		READ_STR("C5") && SET_CTOR() && append_last_class_name(dan, m)); // gnu object ctor group
	MATCH(READ_STR("CI1") && SET_CTOR() && append_last_class_name(dan, m));
	MATCH(READ_STR("CI2") && SET_CTOR() && append_last_class_name(dan, m));
	RULE_FOOT(ctor_name);
}

bool rule_dtor_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(dtor_name);
	// NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
	MATCH(
		READ_STR("D0") && SET_DTOR() && AST_APPEND_STR("~") && append_last_class_name(dan, m)); // gnu deleting dtor
	MATCH(
		READ_STR("D1") && SET_DTOR() && AST_APPEND_STR("~") && append_last_class_name(dan, m)); // gnu complete object dtor
	MATCH(
		READ_STR("D2") && SET_DTOR() && AST_APPEND_STR("~") && append_last_class_name(dan, m)); // gnu base object dtor
	// 3 is not used
	MATCH(
		READ_STR("D4") && SET_DTOR() && AST_APPEND_STR("~") && append_last_class_name(dan, m)); // gnu unified dtor
	MATCH(
		READ_STR("D5") && SET_DTOR() && AST_APPEND_STR("~") && append_last_class_name(dan, m)); // gnu object dtor group
	RULE_FOOT(dtor_name);
}

bool rule_ctor_dtor_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(ctor_dtor_name);
	MATCH1(ctor_name);
	MATCH1(dtor_name);
	RULE_FOOT(ctor_dtor_name);
}

bool rule_nv_offset(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(nv_offset);
	MATCH_AND_DO(true, {
		SKIP_CH('n');
		const char *offset_begin = CUR();
		while (IS_DIGIT(PEEK())) {
			ADV();
		}
		if (CUR() == offset_begin) {
			TRACE_RETURN_FAILURE();
		}
		AST_APPEND_STR_N(offset_begin, CUR() - offset_begin);
		TRACE_RETURN_SUCCESS;
	});
	RULE_FOOT(nv_offset);
}

bool is_template_param_decl(StrIter *msi) {
	return PEEK() == 'T' && strchr("yptnk", PEEK_AT(1)) != NULL;
}

bool rule_template_arg(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(template_arg);

	switch (PEEK()) {
	case 'X': {
		ADV();
		DemAstNode arg = { 0 };
		if (rule_expression(RULE_ARGS(&arg)) && READ('E')) {
			AST_APPEND_NODE(&arg);
			TRACE_RETURN_SUCCESS;
		}
		TRACE_RETURN_FAILURE();
	}
	case 'J': {
		const char *start_pos = CUR();
		ADV();
		ut64 args_begin = VecF(DemAstNode, len)(&m->names);
		while (!READ('E')) {
			DemAstNode node_arg = { 0 };
			if (rule_template_arg(RULE_ARGS(&node_arg))) {
				VecF(DemAstNode, append)(&m->names, &node_arg);
			} else {
				TRACE_RETURN_FAILURE();
			}
		}
		NodeList *args_list = NodeList_pop_trailing(&m->names, args_begin);
		DemAstNode node_args = { 0 };
		DemAstNode_ctor_inplace(&node_args, CP_DEM_TYPE_KIND_template_args, "<", start_pos, 1);
		for (ut64 i = 0; i < args_list->length; i++) {
			DemAstNode_append(&node_args, vec_ptr_at(args_list, i));
		}
		dem_string_append(&node_args.dem, ">");
		AST_APPEND_NODE(&node_args);
	}
	case 'L': {
		if (!rule_expr_primary(RULE_ARGS(AST(0)))) {
			TRACE_RETURN_FAILURE();
		}
		AST_MERGE(AST(0));
		TRACE_RETURN_SUCCESS;
		break;
	}
	case 'T': {
		if (!is_template_param_decl(msi)) {
			if (!rule_type(RULE_ARGS(AST(0)))) {
				TRACE_RETURN_FAILURE();
			}
			AST_MERGE(AST(0));
			TRACE_RETURN_SUCCESS;
		}
		DEM_UNREACHABLE;
	}
	default:
		if (!rule_type(RULE_ARGS(AST(0)))) {
			TRACE_RETURN_FAILURE();
		}
		AST_MERGE(AST(0));
		TRACE_RETURN_SUCCESS;
		break;
	}

	RULE_FOOT(template_arg);
}

bool is_tag_templates(DemAstNode *dan) {
	if (!(dan && dan->parent && dan->parent->parent)) {
		return false;
	}
	return dan->parent->tag == CP_DEM_TYPE_KIND_name && dan->parent->parent->tag == CP_DEM_TYPE_KIND_encoding;
}

bool rule_template_args(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(template_args);
	if (!READ('I')) {
		TRACE_RETURN_FAILURE();
	}

	const bool tag_templates = is_tag_templates(dan) || (dan->parent && dan->parent->tag == CP_DEM_TYPE_KIND_nested_name && is_tag_templates(dan->parent));

	if (tag_templates) {
		VecPNodeList_clear(&m->template_params);
		VecPNodeList_append(&m->template_params, &m->outer_template_params);
		VecDemAstNode_clear(m->outer_template_params);
	}

	if (PEEK() != 'E') {
		AST_APPEND_STR("<");
	}

	while (!READ('E')) {
		DemAstNode node_arg = { 0 };
		if (!rule_template_arg(RULE_ARGS(&node_arg))) {
			TRACE_RETURN_FAILURE();
		}
		if (tag_templates) {
			DemAstNode node_arg_cloned = { 0 };
			DemAstNode_copy(&node_arg_cloned, &node_arg);
			VecF(DemAstNode, append)(m->outer_template_params, &node_arg_cloned);
		}
		if (VecF(DemAstNode, len)(dan->children) > 0) {
			AST_APPEND_STR(", ");
		}
		AST_APPEND_NODE(&node_arg);
		if (READ('Q')) {
			DEM_UNREACHABLE;
		}
	}
	AST_APPEND_STR(">");
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(template_args);
}

bool rule_unnamed_type_name(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(unnamed_type_name);
	if (READ_STR("Ut")) {
		st64 tidx = -1;
		READ_NUMBER(tidx);
		if (tidx >= 0) {
			// do something
		} else {
			TRACE_RETURN_FAILURE();
		}

		if (READ('_')) {
			TRACE_RETURN_SUCCESS;
		}
	} else if (READ_STR("Ul")) {
		ut64 number = 0;
		MATCH_AND_DO(
			RULE_DEFER_MANY_WITH_SEP(AST(0), type, ", ") && READ('E') && OPTIONAL(parse_non_neg_number(msi, &number)) && READ('_'),
			{
				AST_APPEND_STR("'lambda'(");
				if (DemAstNode_non_empty(AST(0)) && strcmp(AST(0)->dem.buf, "void") != 0) {
					AST_MERGE(AST(0));
				}
				AST_APPEND_CHR(')');
				if (number > 0) {
					dem_string_appendf(&dan->dem, "#%llu", number);
				}
			});
	}

	RULE_FOOT(unnamed_type_name);
}

bool rule_pointer_to_member_type(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(pointer_to_member_type);
	MATCH_AND_DO(
		READ('M') && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), type),
		{
			if (AST(1) && (AST(1)->tag == CP_DEM_TYPE_KIND_function_type)) {
				handle_pointer_to_func(dan);
			} else {
				AST_MERGE(AST(0));
				AST_MERGE(AST(1));
			}
		});
	RULE_FOOT(pointer_to_member_type);
}

bool rule_ref_qualifier(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(ref_qualifier);
	MATCH(READ('R') && AST_APPEND_STR("&"));
	MATCH(READ('O') && AST_APPEND_STR("&&"));
	RULE_FOOT(ref_qualifier);
}

bool is_template(DemAstNode *dan) {
	if (!dan) {
		return false;
	}
	return dan->tag == CP_DEM_TYPE_KIND_template_prefix || (VecF(DemAstNode, len)(dan->children) > 0 && VecF(DemAstNode, tail)(dan->children)->tag == CP_DEM_TYPE_KIND_template_args);
}

bool rule_encoding(DemAstNode *dan, StrIter *msi, Meta *m, TraceGraph *graph, int parent_node_id) {
	RULE_HEAD(encoding);

	bool is_const_fn = false;

	MATCH_AND_DO(
		// determine if this function has const or const& at the end
		OPTIONAL(
			is_const_fn = (PEEK_AT(0) == 'N' && PEEK_AT(1) == 'K') || (PEEK_AT(0) == 'K')) &&
			// get function name (can be template or non-template)
			RULE_DEFER(AST(0), name) &&

			// determine whether this is a template function alongside normal demangling
			// template functions specify a return type
			// If this is a template function then get return type first
			OPTIONAL(
				is_template(AST(0)) && RULE_DEFER(AST(1), type)) &&

			// get function params
			// set it as optional, because there's a rule which just matches for name,
			// so to supress the noise of backtracking, we just make it optional here
			OPTIONAL(
				RULE_DEFER(AST(2), bare_function_type)),
		{
			if (DemAstNode_non_empty(AST(1))) {
				AST_MERGE(AST(1));
				AST_APPEND_STR(" ");
			}
			AST_MERGE(AST(0));
			if (DemAstNode_non_empty(AST(2))) {
				AST_APPEND_STR("(");
				if (!dem_str_equals(AST(2)->dem.buf, "void")) {
					AST_MERGE(AST(2));
				}
				AST_APPEND_STR(")");
			}
			// append const if it was detected to be a constant function
			if (is_const_fn) {
				AST_APPEND_STR(" const");
			}
		});

	// MATCH (RULE (name));

	MATCH1(special_name);

	RULE_FOOT(encoding);
}

bool rule_braced_expression(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(braced_expression);
	MATCH(READ_STR("dX") && AST_APPEND_STR(" [") && RULE_X(0, range_begin_expression) &&
		AST_APPEND_STR(" ... ") && RULE_X(1, range_end_expression) && AST_APPEND_STR("] = ") &&
		RULE_X(2, braced_expression));
	MATCH(READ_STR("di") && AST_APPEND_STR(" .") && RULE_X(0, field_source_name) &&
		AST_APPEND_STR(" = ") && RULE_X(1, braced_expression));
	MATCH(READ_STR("dx") && AST_APPEND_STR(" [") && RULE_X(0, index_expression) &&
		AST_APPEND_STR("] = ") && RULE_X(1, braced_expression));
	MATCH1(expression);
	RULE_FOOT(braced_expression);
}

/* NOTE(brightprogrammer): The rule is modified. I've removed reading of 'E' from end.
 * The original grammar for some reason has no way to reach <expr-primary> rule and because
 * of that some matchings were failing.
 *
 * For this I manually added one alternative matching for this rule in the rule <unqualified-name>.
 * This branches from the original grammar here.
 */
bool rule_expr_primary(
	DemAstNode *dan,
	StrIter *msi,
	Meta *m,
	TraceGraph *graph,
	int parent_node_id) {
	RULE_HEAD(expr_primary);
	// HACK: "(bool)0" is converted to "true"
	//       "(bool)1" is converted to "false"
	//       "(unsigned int)N" to "Nu"

	MATCH(READ('L') && RULE_X(0, type) && RULE_X(1, real_part_float) && READ('_') && RULE_X(2, imag_part_float) && READ('E'));
	MATCH(READ('L') && AST_APPEND_STR("(") && (PEEK() == 'P') && RULE_X(0, pointer_type) &&
		AST_APPEND_STR(")") && READ('0') && AST_APPEND_CHR('0') && READ('E'));
	// Non-type template parameter: L<type><value>E
	// For bool: Lb0E -> false, Lb1E -> true
	// For other types: L<type><number>E -> (<type>)<number> or just <number>
	MATCH_AND_DO(
		READ('L') && RULE_DEFER(AST(0), type) && RULE_DEFER(AST(1), value_number) &&
			READ('E'),
		{
			const char *type_str = AST(0)->dem.buf;
			const char *value_str = AST(1)->dem.buf;
			if (type_str && value_str) {
				// Convert bool to true/false
				if (strcmp(type_str, "bool") == 0) {
					if (strcmp(value_str, "0") == 0) {
						AST_APPEND_STR("false");
					} else {
						AST_APPEND_STR("true");
					}
				} else {
					// For other types, just output the value
					// Optionally with suffix for unsigned types
					AST_MERGE(AST(1));
					if (strstr(type_str, "unsigned") != NULL ||
						strcmp(type_str, "unsigned int") == 0) {
						AST_APPEND_STR("u");
					}
				}
			}
		});

	MATCH(READ('L') && RULE_X(0, type) && RULE_X(1, value_float) && READ('E'));
	MATCH(READ('L') && RULE_X(0, string_type) && READ('E'));
	MATCH(READ_STR("L_Z") && RULE_X(0, encoding) && READ('E'));
	MATCH(READ_STR("LDnE") && AST_APPEND_STR("decltype(nullptr)0"));
	MATCH(READ_STR("LDn0E") && AST_APPEND_STR("(decltype(nullptr))0"));
	RULE_FOOT(expr_primary);
}

char *demangle_rule(const char *mangled, DemRule rule, CpDemOptions opts) {
	if (!mangled) {
		return NULL;
	}

	StrIter si = { .beg = mangled, .cur = mangled, .end = mangled + strlen(mangled) + 1 };
	StrIter *msi = &si;

	DemAstNode *dan = calloc(sizeof(DemAstNode), 1);

	Meta meta = { 0 };
	meta_init(&meta);
	Meta *m = &meta;

	// Initialize trace graph
	TraceGraph trace_graph = { 0 };
	TraceGraph *graph = &trace_graph;

	// Enable tracing via environment variable or compile-time flag
#ifdef ENABLE_GRAPHVIZ_TRACE
	graph->enabled = true;
	m->trace = true;
#else
	m->trace = (getenv("DEMANGLE_TRACE") != NULL);
	graph->enabled = m->trace;
#endif

	if (graph->enabled) {
		trace_graph_init(graph);
	}
	char *result = NULL;

	if (rule(dan, msi, m, graph, -1)) {
		result = dan->dem.buf;
		dan->dem.buf = NULL;
		dem_string_deinit(&dan->dem);
	}

	// Output graphviz trace if enabled
	if (graph->enabled) {
		// Mark the final successful path
		trace_graph_mark_final_path(graph);

		char graph_filename[256];
		snprintf(graph_filename, sizeof(graph_filename), "demangle_trace_%s.dot", mangled);
		// Replace problematic characters in filename
		for (char *p = graph_filename; *p; p++) {
			if (*p == ':' || *p == '<' || *p == '>' || *p == '|' || *p == '*' || *p == '?') {
				*p = '_';
			}
		}
		trace_graph_output_dot(graph, graph_filename, m);
	}

	trace_graph_cleanup(graph);
	meta_deinit(&meta);
	DemAstNode_dtor(dan);

	return result;
}

/**
 *
 * @param mangled
 * @param opts
 * @return
 */
char *cp_demangle_v3(const char *mangled, CpDemOptions opts) {
	return demangle_rule(mangled, rule_mangled_name, opts);
}
