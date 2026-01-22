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
#include "dot_graph.h"
#include "macros.h"
#include "parser_combinator.h"
#include "types.h"
#include "vec.h"
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void pp_cv_qualifiers(CvQualifiers qualifiers, DemString *out) {
	if (qualifiers.is_const) {
		dem_string_append(out, " const");
	}
	if (qualifiers.is_volatile) {
		dem_string_append(out, " volatile");
	}
	if (qualifiers.is_restrict) {
		dem_string_append(out, " restrict");
	}
}

static void pp_ref_qualifiers(RefQualifiers qualifiers, DemString *out) {
	if (qualifiers.is_l_value) {
		dem_string_append(out, " &");
	}
	if (qualifiers.is_r_value) {
		dem_string_append(out, " &&");
	}
}

bool pp_pack_expansion(DemNode *node, DemString *out) {
	return true;
}

void ast_pp(DemNode *node, DemString *out) {
	if (!node || !out) {
		return;
	}

	switch (node->tag) {
	case CP_DEM_TYPE_KIND_primitive_ty:
		// Primitive type nodes contain literal strings
		if (node->primitive_ty.name.buf) {
			dem_string_append(out, node->primitive_ty.name.buf);
		}
		break;

	case CP_DEM_TYPE_KIND_function_type:
		if (node->fn_ty.ret) {
			ast_pp(node->fn_ty.ret, out);
			dem_string_append(out, " ");
		}
		ast_pp(node->fn_ty.name, out);
		dem_string_append(out, "(");
		ast_pp(node->fn_ty.params, out);
		dem_string_append(out, ")");
		if (node->fn_ty.exception_spec) {
			ast_pp(node->fn_ty.exception_spec, out);
		}
		pp_cv_qualifiers(node->fn_ty.cv_qualifiers, out);
		pp_ref_qualifiers(node->fn_ty.ref_qualifiers, out);
		break;
	case CP_DEM_TYPE_KIND_module_name:
		if (node->module_name_ty.pare) {
			ast_pp(node->module_name_ty.pare, out);
			dem_string_append(out, ".");
		}
		if (node->module_name_ty.name) {
			ast_pp(node->module_name_ty.name, out);
			if (node->module_name_ty.IsPartition) {
				dem_string_append(out, ":");
			} else if (node->parent && node->parent->tag == CP_DEM_TYPE_KIND_module_name) {
				dem_string_append(out, ".");
			}
		}
		break;
	case CP_DEM_TYPE_KIND_name_with_template_args:
		if (node->name_with_template_args.name) {
			ast_pp(node->name_with_template_args.name, out);
		}
		if (node->name_with_template_args.template_args) {
			ast_pp(node->name_with_template_args.template_args, out);
		}
		break;

	case CP_DEM_TYPE_KIND_qualified_type:
		if (node->qualified_ty.inner_type) {
			ast_pp(node->qualified_ty.inner_type, out);
			pp_cv_qualifiers(node->qualified_ty.qualifiers, out);
		}
		break;

	case CP_DEM_TYPE_KIND_vendor_ext_qualified_type:
		if (node->vendor_ext_qualified_ty.inner_type) {
			ast_pp(node->vendor_ext_qualified_ty.inner_type, out);
			if (node->vendor_ext_qualified_ty.vendor_ext.buf) {
				dem_string_append(out, " ");
				dem_string_append(out, node->vendor_ext_qualified_ty.vendor_ext.buf);
			}
			if (node->vendor_ext_qualified_ty.template_args) {
				ast_pp(node->vendor_ext_qualified_ty.template_args, out);
			}
		}
		break;

	case CP_DEM_TYPE_KIND_many:
		// Print children with separator
		if (node->children) {
			bool first = true;
			vec_foreach_ptr(node->children, child_ptr, {
				DemNode *child = child_ptr ? *child_ptr : NULL;
				if (child) {
					if (!first && node->many_ty.sep) {
						dem_string_append(out, node->many_ty.sep);
					}
					ast_pp(child, out);
					first = false;
				}
			});
		}
		break;

	case CP_DEM_TYPE_KIND_nested_name:
		// Nested names are separated by "::"
		if (node->nested_name.qual) {
			ast_pp(node->nested_name.qual, out);
			dem_string_append(out, "::");
		}
		if (node->nested_name.name) {
			ast_pp(node->nested_name.name, out);
		}
		break;

	case CP_DEM_TYPE_KIND_template_args:
		dem_string_append(out, "<");
		{
			bool first = true;
			vec_foreach_ptr(node->children, child_ptr, {
				if (!first) {
					dem_string_append(out, ", ");
				}
				ast_pp(*child_ptr, out);
				first = false;
			});
		}
		dem_string_append(out, ">");
		break;

	case CP_DEM_TYPE_KIND_type:
		vec_foreach_ptr(node->children, child_ptr, {
			ast_pp(*child_ptr, out);
		});
		if (node->subtag == POINTER_TYPE) {
			dem_string_append(out, "*");
		} else if (node->subtag == REFERENCE_TYPE) {
			dem_string_append(out, "&");
		} else if (node->subtag == RVALUE_REFERENCE_TYPE) {
			dem_string_append(out, "&&");
		}
		break;

	case CP_DEM_TYPE_KIND_fwd_template_ref:
		if (node->fwd_template_ref) {
			ast_pp(node->fwd_template_ref->node, out);
		}
		break;
	default:
		// For all other nodes with children, recursively print all children
		if (node->children) {
			vec_foreach_ptr(node->children, child_ptr, {
				DemNode *child = child_ptr ? *child_ptr : NULL;
				if (child) {
					ast_pp(child, out);
				}
			});
		}
		break;
	}
}

static bool parse_base36(DemParser *p, ut64 *px) {
	static const char *base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* base 36 */
	char *pos = NULL;
	ut64 x = 0;
	ut64 sz = 0;
	while ((pos = strchr(base, p->cur[sz]))) {
		st64 based_val = pos - base;
		if (x > 0) {
			x *= 36;
		}
		x += based_val;
		sz++;
	}
	*px = x;
	p->cur += sz;
	return true;
}

bool parse_number(
	DemParser *p, DemStringView *out, bool allow_negative) {
	const char *start = p->cur;
	if (allow_negative) {
		READ('n');
	}
	if (!IN_RANGE(CUR()) || !isdigit(PEEK())) {
		if (out) {
			out->buf = NULL;
			out->len = 0;
		}
		return true;
	}
	while (IN_RANGE(CUR()) && isdigit(PEEK())) {
		ADV();
	}
	if (out) {
		out->buf = start;
		out->len = p->cur - start;
	}
	return true;
}

bool parse_non_neg_integer(
	DemParser *p, ut64 *out) {
	*out = 0;
	if (PEEK() < '0' || PEEK() > '9') {
		return false;
	}
	while (PEEK() >= '0' && PEEK() <= '9' && IN_RANGE(CUR())) {
		*out *= 10;
		*out += (ut64)(PEEK() - '0');
		ADV();
	}
	return true;
}

bool parse_cv_qualifiers(DemParser *p, CvQualifiers *quals) {
	const char *start = p->cur;
	if (READ('r')) {
		quals->is_restrict = true;
	}
	if (READ('V')) {
		quals->is_volatile = true;
	}
	if (READ('K')) {
		quals->is_const = true;
	}
	return p->cur != start;
}

bool parse_ref_qualifiers(DemParser *p, RefQualifiers *quals) {
	const char *start = p->cur;
	if (READ('R')) {
		quals->is_l_value = true;
	}
	if (READ('O')) {
		quals->is_r_value = true;
	}
	return p->cur != start;
}

bool parse_base_source_name(DemParser *p, const char **pout, ut64 *plen) {
	ut64 num = 0;
	if (!parse_non_neg_integer(p, &num)) {
		return false;
	}
	// Check if the length is valid and within bounds
	// Prevent overflow and ensure we stay within the input buffer
	if (num > (ut64)(END() - CUR())) {
		return false;
	}
	if (pout) {
		*pout = CUR();
	}
	if (plen) {
		*plen = num;
	}
	CUR() += num;
	return true;
}

bool parse_seq_id(DemParser *p, DemNode **pp_out_node) {
	ut64 sid = 0;
	if (IS_DIGIT(PEEK()) || IS_UPPER(PEEK())) {
		if (!parse_base36(p, &sid)) {
			return false;
		}
		sid += 1;
	}
	if (!READ('_')) {
		return false;
	}
	DemNode *ref = substitute_get(p, sid);
	if (!ref) {
		return false;
	}
	// Return the reference directly without cloning.
	if (pp_out_node) {
		*pp_out_node = ref;
	}
	return true;
}

bool rule_vendor_specific_suffix(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(vendor_specific_suffix);
	// Handle Apple/Objective-C block_invoke patterns
	// These appear as suffixes after the main symbol
	// Look for _block_invoke followed by optional number
	if (READ_STR("block_invoke")) {
		AST_APPEND_STR(" block_invoke");
		if (READ('_')) {
			AST_APPEND_STR("_");
			CALL_RULE(rule_number);
		}
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(vendor_specific_suffix);
}

bool rule_number(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(number);
	if (!(isdigit(PEEK()) || (PEEK() == 'n' && isdigit(PEEK_AT(1))))) {
		TRACE_RETURN_FAILURE();
	}
	READ('n');
	ut64 num = 0;
	if (!parse_non_neg_integer(p, &num)) {
		TRACE_RETURN_FAILURE();
	}
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(number);
}

bool rule_ctor_dtor_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(ctor_dtor_name);

	// NOTE: reference taken from https://github.com/rizinorg/rz-libdemangle/blob/c2847137398cf8d378d46a7510510aaefcffc8c6/src/cxx/cp-demangle.c#L2143
	if (READ('C')) {
		bool IsInherited = READ('I');
		if (PEEK() < '1' && PEEK() > '5') {
			TRACE_RETURN_FAILURE();
		}
		ADV();
		if (IsInherited) {
			MUST_MATCH(CALL_RULE(rule_name));
		}
		TRACE_RETURN_SUCCESS;
	}

	if (READ('D')) {
		if (PEEK() < '0' && PEEK() > '5') {
			TRACE_RETURN_FAILURE();
		}
		ADV();
		AST_APPEND_STR("~");
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(ctor_dtor_name);
}

bool rule_module_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(module_name);
	DemNode *Module = NULL;
	while (READ('W')) {
		bool IsPartition = READ('P');
		DemNode *Sub = NULL;
		CALL_RULE_N(Sub, rule_source_name);
		if (!Sub) {
			return true;
		}
		DemNode *sub_module = DemNode_ctor(CP_DEM_TYPE_KIND_module_name, save_pos_rule, CUR() - save_pos_rule);
		if (!sub_module) {
			TRACE_RETURN_FAILURE();
		}
		sub_module->module_name_ty.pare = Module;
		sub_module->module_name_ty.IsPartition = IsPartition;
		sub_module->module_name_ty.name = Sub;
		Module = sub_module;
		AST_APPEND_TYPE1(Module);
		Module->parent = node;
	}

	TRACE_RETURN_SUCCESS;
}

bool rule_unqualified_name(DemParser *p, const DemNode *parent, DemResult *r,
	DemNode *scope, DemNode *module) {
	RULE_HEAD(unqualified_name);

	bool is_member_like_friend = scope && READ('F');
	READ('L');

	DemNode *result = NULL;
	if (READ_STR("DC")) {
		CALL_MANY1_N(result, rule_source_name, ", ");
		if (!READ('E')) {
			TRACE_RETURN_FAILURE();
		}
	} else if (PEEK() == 'U') {
		CALL_RULE_N(result, rule_unnamed_type_name);
	} else if (PEEK() == 'D' || PEEK() == 'C') {
		if (scope == NULL || module != NULL) {
			TRACE_RETURN_FAILURE();
		}
		CALL_RULE_N(result, rule_ctor_dtor_name);
	} else if (isdigit(PEEK())) {
		CALL_RULE_N(result, rule_source_name);
	} else {
		CALL_RULE_N(result, rule_operator_name);
	}

	if (result && module) {
		// TODO: handle module scoping
		DEM_UNREACHABLE;
	}
	if (result) {
		DemNode *abi_tags = NULL;
		CALL_MANY1_N(abi_tags, rule_abi_tag, " ");
	}
	if (result && is_member_like_friend) {
		// TODO: MemberLikeFriendName
		DEM_UNREACHABLE;
	} else if (result && scope) {
		node->tag = CP_DEM_TYPE_KIND_nested_name;
		node->nested_name.qual = scope;
		node->nested_name.name = result;
		TRACE_RETURN_SUCCESS;
	}

	if (!result) {
		TRACE_RETURN_FAILURE();
	}
	DemNode_move(node, result);
	TRACE_RETURN_SUCCESS;
}

bool rule_unresolved_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unresolved_name);
	(void)READ_STR("gs");
	if (READ_STR("srN")) {
		MATCH_AND_DO((CALL_RULE(rule_unresolved_type)) &&
				(PEEK() == 'I' ? CALL_RULE(rule_template_args) : true) &&
				CALL_MANY1(rule_unresolved_qualifier_level, "") && READ('E') &&
				CALL_RULE(rule_base_unresolved_name),
			{});
	}
	if (!(READ_STR("sr"))) {
		MUST_MATCH(CALL_RULE(rule_base_unresolved_name));

		TRACE_RETURN_SUCCESS
	}
	if (isdigit(PEEK())) {
		MUST_MATCH(CALL_MANY1(rule_unresolved_qualifier_level, "") && READ('E'));
	} else {
		MUST_MATCH(CALL_RULE(rule_unresolved_type));
		if (PEEK() == 'I') {
			MUST_MATCH(CALL_RULE(rule_template_args) && READ('E'));
		}
	}
	MUST_MATCH(CALL_RULE(rule_base_unresolved_name));
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(unresolved_name);
}

bool rule_unscoped_name(DemParser *p, const DemNode *parent, DemResult *r, bool *is_subst) {
	RULE_HEAD(unscoped_name);

	DemNode *std_node = NULL;
	if (READ_STR("St")) {
		std_node = make_primitive_type(CUR(), CUR(), "std::", 5);
		if (!std_node) {
			TRACE_RETURN_FAILURE();
		}
	}

	DemNode *result = NULL;
	DemNode *module = NULL;
	DemNode *subst = NULL;
	if (PEEK() == 'S') {
		MUST_MATCH(CALL_RULE_N(subst, rule_substitution));
		if (subst->tag == CP_DEM_TYPE_KIND_module_name) {
			module = subst;
		} else if (is_subst && !std_node) {
			*is_subst = true;
			result = subst;
		} else {
			DemNode_dtor(std_node);
			DemNode_dtor(result);
			DemNode_dtor(module);
			DemNode_dtor(subst);
			TRACE_RETURN_FAILURE();
		}
	}

	if (!result || std_node) {
		PASSTHRU_RULE_VA(rule_unqualified_name, std_node, module);
		TRACE_RETURN_FAILURE();
	}
	if (result) {
		DemNode_move(node, result);
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(unscoped_name);
}

bool rule_unresolved_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unresolved_type);
	TRY_MATCH((CALL_RULE(rule_template_param)) && (((CALL_RULE(rule_template_args))) || true) && AST_APPEND_TYPE);
	TRY_MATCH((CALL_RULE(rule_decltype)) && AST_APPEND_TYPE);
	TRY_MATCH(CALL_RULE(rule_substitution));
	RULE_FOOT(unresolved_type);
}

bool rule_unresolved_qualifier_level(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unresolved_qualifier_level);
	TRY_MATCH(CALL_RULE(rule_simple_id));
	RULE_FOOT(unresolved_qualifier_level);
}

bool rule_decltype(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(decltype);
	TRY_MATCH(READ_STR("Dt") && (CALL_RULE(rule_expression)) && READ('E'));
	TRY_MATCH(READ_STR("DT") && (CALL_RULE(rule_expression)) && READ('E'));
	RULE_FOOT(decltype);
}

bool rule_exception_spec(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(exception_spec);
	TRY_MATCH(READ_STR("DO") && (CALL_RULE(rule_expression)) && READ('E'));
	TRY_MATCH(READ_STR("Dw") && (CALL_RULE(rule_type)) && READ('E'));
	TRY_MATCH(READ_STR("Do"));
	RULE_FOOT(exception_spec);
}

void pp_array_type(DemNode *node, DemString *out) {
	if (!node || node->tag != CP_DEM_TYPE_KIND_array_type) {
		return;
	}
	DemNode *type_node = node;
	DemNode *size_node = node;
	while (type_node->tag == CP_DEM_TYPE_KIND_array_type) {
		DemNode *parent_node = type_node;
		type_node = AST_(parent_node, 1);
		size_node = AST_(parent_node, 0);
		dem_string_appends(out, "[");
		ast_pp(size_node, out);
		dem_string_appends(out, "]");
	}
	dem_string_appends_prefix(out, " ");
	ast_pp(type_node, out);
}

bool rule_array_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(array_type);
	MUST_MATCH(READ('A'));
	node->subtag = ARRAY_TYPE;
	if (PEEK() == '_') {
		// Empty dimension: A_<type> - just consume the '_' without creating a size node
		MUST_MATCH(READ('_'));
	} else if (isdigit(PEEK())) {
		MUST_MATCH(CALL_RULE(rule_number) && READ('_'));
	} else {
		MUST_MATCH(CALL_RULE(rule_expression) && READ('_'));
	}
	MUST_MATCH(CALL_RULE(rule_type));
	AST_APPEND_TYPE;
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(array_type);
}

typedef enum {
	Prefix, // Prefix unary: @ expr
	Postfix, // Postfix unary: expr @
	Binary, // Binary: lhs @ rhs
	Array, // Array index:  lhs [ rhs ]
	Member, // Member access: lhs @ rhs
	New, // New
	Del, // Delete
	Call, // Function call: expr (expr*)
	CCast, // C cast: (type)expr
	Conditional, // Conditional: expr ? expr : expr
	NameOnly, // Overload only, not allowed in expression.
	// Below do not have operator names
	NamedCast, // Named cast, @<type>(expr)
	OfIdOp, // alignof, sizeof, typeid
	Unnameable,
} OIKind;

typedef enum {
	Primary,
	PPostfix,
	Unary,
	Cast,
	PtrMem,
	Multiplicative,
	Additive,
	Shift,
	Spaceship,
	Relational,
	Equality,
	And,
	Xor,
	Ior,
	AndIf,
	OrIf,
	PConditional,
	Assign,
	Comma,
	Default,
} Prec;

typedef struct {
	char Enc[2]; // Encoding
	OIKind Kind; // Kind of operator
	bool Flag; // Entry-specific flag
	Prec Prec; // Precedence
	const char *Name; // Spelling
} OperatorInfo;

static const OperatorInfo Ops[] = {
	// Keep ordered by encoding
	{ "aN", Binary, false, Assign, "operator&=" },
	{ "aS", Binary, false, Assign, "operator=" },
	{ "aa", Binary, false, AndIf, "operator&&" },
	{ "ad", Prefix, false, Unary, "operator&" },
	{ "an", Binary, false, And, "operator&" },
	{ "at", OfIdOp, /*Type*/ true, Unary, "alignof " },
	{ "aw", NameOnly, false, Primary,
		"operator co_await" },
	{ "az", OfIdOp, /*Type*/ false, Unary, "alignof " },
	{ "cc", NamedCast, false, PPostfix, "const_cast" },
	{ "cl", Call, /*Paren*/ false, PPostfix,
		"operator()" },
	{ "cm", Binary, false, Comma, "operator," },
	{ "co", Prefix, false, Unary, "operator~" },
	{ "cp", Call, /*Paren*/ true, PPostfix,
		"operator()" },
	{ "cv", CCast, false, Cast, "operator" }, // C Cast
	{ "dV", Binary, false, Assign, "operator/=" },
	{ "da", Del, /*Ary*/ true, Unary,
		"operator delete[]" },
	{ "dc", NamedCast, false, PPostfix, "dynamic_cast" },
	{ "de", Prefix, false, Unary, "operator*" },
	{ "dl", Del, /*Ary*/ false, Unary,
		"operator delete" },
	{ "ds", Member, /*Named*/ false, PtrMem,
		"operator.*" },
	{ "dt", Member, /*Named*/ false, PPostfix,
		"operator." },
	{ "dv", Binary, false, Assign, "operator/" },
	{ "eO", Binary, false, Assign, "operator^=" },
	{ "eo", Binary, false, Xor, "operator^" },
	{ "eq", Binary, false, Equality, "operator==" },
	{ "ge", Binary, false, Relational, "operator>=" },
	{ "gt", Binary, false, Relational, "operator>" },
	{ "ix", Array, false, PPostfix, "operator[]" },
	{ "lS", Binary, false, Assign, "operator<<=" },
	{ "le", Binary, false, Relational, "operator<=" },
	{ "ls", Binary, false, Shift, "operator<<" },
	{ "lt", Binary, false, Relational, "operator<" },
	{ "mI", Binary, false, Assign, "operator-=" },
	{ "mL", Binary, false, Assign, "operator*=" },
	{ "mi", Binary, false, Additive, "operator-" },
	{ "ml", Binary, false, Multiplicative,
		"operator*" },
	{ "mm", Postfix, false, PPostfix, "operator--" },
	{ "na", New, /*Ary*/ true, Unary,
		"operator new[]" },
	{ "ne", Binary, false, Equality, "operator!=" },
	{ "ng", Prefix, false, Unary, "operator-" },
	{ "nt", Prefix, false, Unary, "operator!" },
	{ "nw", New, /*Ary*/ false, Unary, "operator new" },
	{ "oR", Binary, false, Assign, "operator|=" },
	{ "oo", Binary, false, OrIf, "operator||" },
	{ "or", Binary, false, Ior, "operator|" },
	{ "pL", Binary, false, Assign, "operator+=" },
	{ "pl", Binary, false, Additive, "operator+" },
	{ "pm", Member, /*Named*/ true, PtrMem,
		"operator->*" },
	{ "pp", Postfix, false, PPostfix, "operator++" },
	{ "ps", Prefix, false, Unary, "operator+" },
	{ "pt", Member, /*Named*/ true, PPostfix,
		"operator->" },
	{ "qu", Conditional, false, PConditional,
		"operator?" },
	{ "rM", Binary, false, Assign, "operator%=" },
	{ "rS", Binary, false, Assign, "operator>>=" },
	{ "rc", NamedCast, false, PPostfix,
		"reinterpret_cast" },
	{ "rm", Binary, false, Multiplicative,
		"operator%" },
	{ "rs", Binary, false, Shift, "operator>>" },
	{ "sc", NamedCast, false, PPostfix, "static_cast" },
	{ "ss", Binary, false, Spaceship, "operator<=>" },
	{ "st", OfIdOp, /*Type*/ true, Unary, "sizeof " },
	{ "sz", OfIdOp, /*Type*/ false, Unary, "sizeof " },
	{ "te", OfIdOp, /*Type*/ false, PPostfix,
		"typeid " },
	{ "ti", OfIdOp, /*Type*/ true, PPostfix, "typeid " },
};
static const size_t NumOps = sizeof(Ops) / sizeof(Ops[0]);

const OperatorInfo *parse_operator_info(DemParser *p) {
	if (P_SIZE() < 2) {
		return NULL;
	}

	size_t lower = 0u, upper = NumOps - 1;
	while (upper != lower) {
		size_t middle = (upper + lower) / 2;
		if (Ops[middle].Enc[0] < PEEK() || (Ops[middle].Enc[0] == PEEK() && Ops[middle].Enc[1] < PEEK_AT(1))) {
			lower = middle + 1;
		} else {
			upper = middle;
		}
	}
	if (!(Ops[lower].Enc[0] == PEEK() && Ops[lower].Enc[1] == PEEK_AT(1))) {
		return NULL;
	}

	ADV_BY(2);
	return &Ops[lower];
}

bool rule_operator_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(operator_name);
	const OperatorInfo *Op = parse_operator_info(p);
	if (Op) {
		if (Op->Kind == CCast) {
			p->is_conversion_operator = true;
			bool old_not_parse = p->not_parse_template_args;
			p->not_parse_template_args = true;
			CTX_MUST_MATCH(rule, rule_type);
			p->not_parse_template_args = old_not_parse;
			TRACE_RETURN_SUCCESS;
		}
		if (Op->Kind >= Unnameable) {
			TRACE_RETURN_FAILURE();
		}
		if (Op->Kind == Member && !Op->Flag) {
			TRACE_RETURN_FAILURE();
		}

		AST_APPEND_STR(Op->Name);
		TRACE_RETURN_SUCCESS;
	}

	if (READ_STR("li")) {
		// ::= li <source-name>  # operator ""
		CTX_MUST_MATCH(rule, rule_source_name);
		TRACE_RETURN_SUCCESS;
	}

	if (READ_STR("v")) {
		// ::= v <digit> <source-name>        # vendor extended operator
		ut64 num = 0;
		if (!parse_non_neg_integer(p, &num)) {
			TRACE_RETURN_FAILURE();
		}
		CTX_MUST_MATCH(rule, rule_source_name);
		TRACE_RETURN_SUCCESS;
	}

	RULE_FOOT(operator_name);
}

bool rule_expr_primary(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(expr_primary);
	if (!READ('L')) {
		TRACE_RETURN_FAILURE();
	}
	TRY_MATCH(PEEK() == 'P' && AST_APPEND_STR("(") && (CALL_RULE(rule_type)) &&
		AST_APPEND_STR(")") && READ('0') && AST_APPEND_STR("0") && READ('E'));
	TRY_MATCH(READ_STR("_Z") && (CALL_RULE(rule_encoding)) && READ('E'));
	TRY_MATCH(READ_STR("DnE") && AST_APPEND_STR("decltype(nullptr)0"));
	TRY_MATCH(READ_STR("Dn0E") && AST_APPEND_STR("(decltype(nullptr))0"));

	// Non-type template parameter: L<type><value>E
	// For bool: Lb0E -> false, Lb1E -> true
	// For other types: L<type><number>E -> (<type>)<number> or just <number>
	MUST_MATCH(CALL_RULE(rule_type));
	TRY_MATCH(CALL_RULE(rule_number) && READ('E'));
	TRY_MATCH((CALL_RULE(rule_float)) && READ('_') && (CALL_RULE(rule_float)) && READ('E'));
	TRY_MATCH((CALL_RULE(rule_float)) && READ('E'));
	RULE_FOOT(expr_primary);
}

bool rule_braced_expression(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(braced_expression);
	if (PEEK() == 'd') {
		switch (PEEK_AT(1)) {
		case 'X':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_expression));
			MUST_MATCH(CALL_RULE(rule_expression));
			MUST_MATCH(CALL_RULE(rule_braced_expression));
			TRACE_RETURN_SUCCESS;
		case 'i':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_source_name));
			MUST_MATCH(CALL_RULE(rule_braced_expression));
			TRACE_RETURN_SUCCESS;
		case 'x':
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_expression));
			MUST_MATCH(CALL_RULE(rule_braced_expression));
			TRACE_RETURN_SUCCESS;
		default:
			break;
		}
	}
	TRY_MATCH(CALL_RULE(rule_expression));
	RULE_FOOT(braced_expression);
}

static void swap(void **a, void **b) {
	void *temp = *a;
	*a = *b;
	*b = temp;
}

bool rule_fold_expression(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(fold_expression);
	if (!READ('f')) {
		TRACE_RETURN_FAILURE();
	}
	bool IsLeftFold = false, HasInitializer = false;
	switch (PEEK()) {
	default:
		TRACE_RETURN_FAILURE();
	case 'L':
		IsLeftFold = true;
		HasInitializer = true;
		break;
	case 'R':
		HasInitializer = true;
		break;
	case 'l':
		IsLeftFold = true;
		break;
	case 'r':
		break;
	}
	ADV();

	const OperatorInfo *Op = parse_operator_info(p);
	if (!Op) {
		TRACE_RETURN_FAILURE();
	}
	if (!(Op->Kind == Binary || (Op->Kind == Member && Op->Name[strlen(Op->Name) - 1] == '*'))) {
		TRACE_RETURN_FAILURE();
	}

	DemNode *Pack = NULL;
	CALL_RULE_N(Pack, rule_expression);
	if (!Pack) {
		TRACE_RETURN_FAILURE();
	}

	DemNode *init = NULL;
	if (HasInitializer) {
		CALL_RULE_N(init, rule_expression);
		if (!init) {
			TRACE_RETURN_FAILURE();
		}
	}
	if (init && IsLeftFold) {
		swap((void **)&Pack, (void **)&init);
	}

	TRACE_RETURN_SUCCESS;
}

bool rule_prefix_expression(DemParser *p, const DemNode *parent, DemResult *r, const OperatorInfo *op) {
	RULE_HEAD(expression);
	AST_APPEND_STR(op->Name);
	AST_APPEND_STR("(");
	MUST_MATCH(CALL_RULE(rule_expression));
	AST_APPEND_STR(")");
	TRACE_RETURN_SUCCESS;
}

bool rule_binary_expression(DemParser *p, const DemNode *parent, DemResult *r, const OperatorInfo *op) {
	RULE_HEAD(expression);
	AST_APPEND_STR("(");
	MUST_MATCH(CALL_RULE(rule_expression));
	AST_APPEND_STR(op->Name);
	MUST_MATCH(CALL_RULE(rule_expression));
	AST_APPEND_STR(")");
	TRACE_RETURN_SUCCESS;
}

bool rule_expression(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(expression);

	const OperatorInfo *Op = parse_operator_info(p);
	if (Op) {
		switch (Op->Kind) {
		case Prefix: return rule_prefix_expression(p, parent, r, Op);
		case Postfix:
			if (READ('_')) {
				return rule_prefix_expression(p, parent, r, Op);
			}
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(Op->Name);
			TRACE_RETURN_SUCCESS;
		case Binary: return rule_binary_expression(p, parent, r, Op);
		case Array: // ix: arr[idx]
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("[");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("]");
			TRACE_RETURN_SUCCESS;
		case Member: // dt/pt: expr.name / expr->name
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(Op->Name);
			MUST_MATCH(CALL_RULE(rule_base_unresolved_name));
			TRACE_RETURN_SUCCESS;
		case New: // nw/na
		case Del: // dl/da
			if (READ_STR("gs")) {
				AST_APPEND_STR("::");
			}
			AST_APPEND_STR(Op->Name);
			if (Op->Kind == New) {
				while (PEEK() != '_') {
					AST_APPEND_STR(" ");
					MUST_MATCH(CALL_RULE(rule_expression));
				}
				MUST_MATCH(READ('_') && AST_APPEND_STR(" "));
				MUST_MATCH(CALL_RULE(rule_type));
				if (PEEK() != 'E') {
					MUST_MATCH(CALL_RULE(rule_initializer));
				}
				MUST_MATCH(READ('E'));
			} else {
				AST_APPEND_STR(" ");
				MUST_MATCH(CALL_RULE(rule_expression));
			}
			TRACE_RETURN_SUCCESS;
		case Call: // cl: func(args)
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR("(");
			while (PEEK() != 'E') {
				if (node->children && VecPDemNode_len(node->children) > 1) {
					AST_APPEND_STR(", ");
				}
				MUST_MATCH(CALL_RULE(rule_expression));
			}
			MUST_MATCH(READ('E'));
			AST_APPEND_STR(")");
			TRACE_RETURN_SUCCESS;
		case CCast: // cv: (type)expr or (type)(args)
			AST_APPEND_STR("(");
			MUST_MATCH(CALL_RULE(rule_type));
			AST_APPEND_STR(")");
			if (READ('_')) {
				AST_APPEND_STR("(");
				while (PEEK() != 'E') {
					if (node->children && VecPDemNode_len(node->children) > 1) {
						AST_APPEND_STR(", ");
					}
					MUST_MATCH(CALL_RULE(rule_expression));
				}
				MUST_MATCH(READ('E'));
				AST_APPEND_STR(")");
			} else {
				MUST_MATCH(CALL_RULE(rule_expression));
			}
			TRACE_RETURN_SUCCESS;
		case Conditional: // qu: cond ? then : else
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(" ? ");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(" : ");
			MUST_MATCH(CALL_RULE(rule_expression));
			TRACE_RETURN_SUCCESS;
		case NameOnly:
			TRACE_RETURN_FAILURE();
		case NamedCast: // dc/sc/cc/rc: cast<type>(expr)
			AST_APPEND_STR(Op->Name);
			AST_APPEND_STR("<");
			MUST_MATCH(CALL_RULE(rule_type));
			AST_APPEND_STR(">(");
			MUST_MATCH(CALL_RULE(rule_expression));
			AST_APPEND_STR(")");
			TRACE_RETURN_SUCCESS;
		case OfIdOp: // st/sz/at/az/ti/te: sizeof/alignof/typeid
			AST_APPEND_STR(Op->Name);
			AST_APPEND_STR("(");
			if (Op->Flag) {
				MUST_MATCH(CALL_RULE(rule_type));
			} else {
				MUST_MATCH(CALL_RULE(rule_expression));
			}
			AST_APPEND_STR(")");
			TRACE_RETURN_SUCCESS;
		case Unnameable:
			TRACE_RETURN_FAILURE();
		}
		DEM_UNREACHABLE;
	}

	// Non-operator expressions
	TRY_MATCH(CALL_RULE(rule_expr_primary));
	TRY_MATCH(CALL_RULE(rule_template_param));
	TRY_MATCH(CALL_RULE(rule_function_param));
	TRY_MATCH(CALL_RULE(rule_fold_expression));
	TRY_MATCH(READ_STR("il") && CALL_MANY(rule_expression, "") && READ('E'));
	TRY_MATCH(READ_STR("tl") && CALL_RULE(rule_type) && CALL_MANY(rule_braced_expression, "") && READ('E'));
	TRY_MATCH(READ_STR("nx") && AST_APPEND_STR("noexcept(") && CALL_RULE(rule_expression) && AST_APPEND_STR(")"));
	TRY_MATCH(READ_STR("tw") && AST_APPEND_STR("throw ") && CALL_RULE(rule_expression));
	TRY_MATCH(READ_STR("tr") && AST_APPEND_STR("throw"));
	TRY_MATCH(READ_STR("sZ") && AST_APPEND_STR("sizeof...(") && (CALL_RULE(rule_template_param) || CALL_RULE(rule_function_param)) && AST_APPEND_STR(")"));
	TRY_MATCH(READ_STR("sP") && AST_APPEND_STR("sizeof...(") && CALL_MANY(rule_template_arg, "") && READ('E') && AST_APPEND_STR(")"));
	TRY_MATCH(READ_STR("sp") && CALL_RULE(rule_expression) && AST_APPEND_STR("..."));
	// NOTE: fl and fr are fold expressions, handled by rule_fold_expression above
	TRY_MATCH(CALL_RULE(rule_unresolved_name));

	RULE_FOOT(expression);
}

bool rule_simple_id(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(simple_id);
	TRY_MATCH((CALL_RULE(rule_source_name)) && (((CALL_RULE(rule_template_args))) || true));
	RULE_FOOT(simple_id);
}

bool rule_template_param(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_param);
	if (!(READ('T'))) {
		TRACE_RETURN_FAILURE();
	}
	ut64 level = 0;
	if (READ('L')) {
		if (!(parse_non_neg_integer(p, &level) && READ('_'))) {
			TRACE_RETURN_FAILURE();
		}
		level++;
	}
	ut64 index = 0;
	if (!READ('_')) {
		if (!(parse_non_neg_integer(p, &index) && READ('_'))) {
			TRACE_RETURN_FAILURE();
		}
		index++;
	}

	DemNode *t = template_param_get(p, level, index);
	if (!t) {
		// If substitution failed, create a forward reference
		// Use a placeholder that will be resolved later
		ForwardTemplateRef fwd_ref = {
			.node = NULL,
			.level = level,
			.index = index
		};
		node->fwd_template_ref = malloc(sizeof(ForwardTemplateRef));
		if (!node->fwd_template_ref) {
			TRACE_RETURN_FAILURE();
		}
		*(node->fwd_template_ref) = fwd_ref;
		node->tag = CP_DEM_TYPE_KIND_fwd_template_ref;
		VecF(PForwardTemplateRef, append)(&p->forward_template_refs, &node->fwd_template_ref);
		if (p->trace) {
			fprintf(stderr, "[template_param] Created forward ref L%ld_%ld\n",
				level, index);
		}
	} else {
		DemNode_copy(node, t);
	}

	TRACE_RETURN_SUCCESS;
}

bool rule_discriminator(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(discriminator);
	if (READ('_')) {
		// matched two "_"
		if (READ('_')) {
			ut64 numlt10 = 0;
			if (parse_non_neg_integer(p, &numlt10)) {
				// do something
				TRACE_RETURN_SUCCESS;
			}
		} else {
			// matched single "_"
			ut64 numlt10 = 0;
			if (parse_non_neg_integer(p, &numlt10)) {
				// do something
				TRACE_RETURN_SUCCESS;
			}
		}
	}
	TRACE_RETURN_FAILURE();
	RULE_FOOT(discriminator);
}

bool rule_initializer(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(initializer);
	if (!READ_STR("pi")) {
		TRACE_RETURN_FAILURE();
	}
	AST_APPEND_STR(" (");
	while (PEEK() != 'E') {
		if (node->children && VecPDemNode_len(node->children) > 0) {
			AST_APPEND_STR(", ");
		}
		MUST_MATCH(CALL_RULE(rule_expression));
	}
	MUST_MATCH(READ('E'));
	AST_APPEND_STR(")");
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(initializer);
}

bool rule_abi_tag(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(abi_tag);
	// will generate "[abi:<source_name>]"
	TRY_MATCH(READ('B') && AST_APPEND_STR("[abi:") && CALL_RULE(rule_source_name) && AST_APPEND_STR("]"));
	RULE_FOOT(abi_tag);
}

bool rule_call_offset(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(call_offset);
	if (READ('h')) {
		if (!READ('n')) {
			TRACE_RETURN_FAILURE();
		}
		ut64 x = 0;
		if (!parse_non_neg_integer(p, &x)) {
			TRACE_RETURN_FAILURE();
		}
		AST_APPENDF("non-virtual thunk to %lz", x);
		TRACE_RETURN_SUCCESS;
	}
	if (READ('v')) {
		MUST_MATCH(CALL_RULE(rule_number) && READ('_') && CALL_RULE(rule_number) && READ('_'));
		AST_APPEND_STR("virtual thunk to ");
		TRACE_RETURN_SUCCESS;
	}
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
bool rule_special_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(special_name);
	// TC <derived-type> <offset> _ <base-type>   # construction vtable
	MATCH_AND_DO(
		READ_STR("TC") && CALL_RULE(rule_type),
		{
			ut64 offset = 0;
			if (!parse_non_neg_integer(p, &offset)) {
				TRACE_RETURN_FAILURE();
			}
			if (!READ('_') || !CALL_RULE(rule_type)) {
				TRACE_RETURN_FAILURE();
			}
			AST_APPEND_STR("construction vtable for ");
			// base class
			AST_APPEND_STR("-in-");
			// derived class
		});
	TRY_MATCH(READ_STR("Tc") && (CALL_RULE(rule_call_offset)) && (CALL_RULE(rule_call_offset)) && (CALL_RULE(rule_encoding)));
	DemNode *child_node = NULL;
	MATCH_AND_DO(
		READ_STR("GR") && CALL_RULE(rule_name) && parse_seq_id(p, &child_node) && READ('_'),
		{
			AST_APPEND_NODE(DemNode_clone(child_node));
			AST_APPEND_STR("reference temporary for ");
		});
	TRY_MATCH(READ('T') && (CALL_RULE(rule_call_offset)) && (CALL_RULE(rule_encoding)));
	TRY_MATCH(READ_STR("GR") && AST_APPEND_STR("reference temporary for ") && (CALL_RULE(rule_name)) && READ('_'));
	TRY_MATCH(READ_STR("TV") && AST_APPEND_STR("vtable for ") && (CALL_RULE(rule_type)));
	TRY_MATCH(READ_STR("TT") && AST_APPEND_STR("VTT structure for ") && (CALL_RULE(rule_type)));
	TRY_MATCH(READ_STR("TI") && AST_APPEND_STR("typeinfo for ") && (CALL_RULE(rule_type)));
	TRY_MATCH(READ_STR("TS") && AST_APPEND_STR("typeinfo name for ") && (CALL_RULE(rule_type)));
	TRY_MATCH(READ_STR("GV") && AST_APPEND_STR("guard variable for ") && (CALL_RULE(rule_name)));
	TRY_MATCH(READ_STR("GTt") && (CALL_RULE(rule_encoding)));
	// TODO: GI <module-name> v
	RULE_FOOT(special_name);
}

bool rule_function_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(function_type);
	// This rule only handles F...E (bare function type)
	// P prefix is handled in the type rule, which properly inserts * for function pointers
	context_save(0);
	MUST_MATCH(parse_cv_qualifiers(p, &node->fn_ty.cv_qualifiers));
	CALL_RULE_N(node->fn_ty.exception_spec, rule_exception_spec);
	MUST_MATCH(((READ_STR("Dx")) || true) && READ('F') && ((READ('Y')) || true));
	CALL_RULE_N(node->fn_ty.ret, rule_type);

	DemResult param_result = { 0 };
	if (!match_many(p, node, &param_result, rule_type, ", ")) {
		TRACE_RETURN_FAILURE();
	}

	MUST_MATCH(parse_ref_qualifiers(p, &node->fn_ty.ref_qualifiers));
	MUST_MATCH(READ('E'));

	node->fn_ty.params = param_result.output;
	AST_APPEND_TYPE;
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(function_type);
}

bool rule_function_param(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(function_param);
	CvQualifiers qualifiers = { 0 };
	TRY_MATCH(READ_STR("fL") && (CALL_RULE(rule_number)) && READ('p') &&
		parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") && (CALL_RULE(rule_number)) &&
		READ('_'));
	TRY_MATCH(READ_STR("fL") && (CALL_RULE(rule_number)) && READ('p') &&
		parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") && READ('_'));
	TRY_MATCH(READ_STR("fp") && parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") &&
		(CALL_RULE(rule_number)) && READ('_'));
	TRY_MATCH(READ_STR("fp") && parse_cv_qualifiers(p, &qualifiers) && AST_APPEND_STR(" ") && READ('_'));
	TRY_MATCH(READ_STR("fPT"));
	RULE_FOOT(function_param);
}

bool rule_builtin_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(builtin_type);
	TRY_MATCH(READ_STR("DF") && AST_APPEND_STR("_Float") && (CALL_RULE(rule_number)) && READ('_'));
	TRY_MATCH(READ_STR("DF") && AST_APPEND_STR("_Float") && (CALL_RULE(rule_number)) && READ('x') && AST_APPEND_STR("x"));
	TRY_MATCH(READ_STR("DF") && AST_APPEND_STR("std::bfloat") && (CALL_RULE(rule_number)) && READ('b') && AST_APPEND_STR("_t"));
	TRY_MATCH(READ_STR("DB") && AST_APPEND_STR("signed _BitInt(") && (CALL_RULE(rule_number)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ_STR("DB") && AST_APPEND_STR("signed _BitInt(") && (CALL_RULE(rule_expression)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ_STR("DU") && AST_APPEND_STR("unsigned _BitInt(") && (CALL_RULE(rule_number)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ_STR("DU") && AST_APPEND_STR("unsigned _BitInt(") && (CALL_RULE(rule_expression)) && AST_APPEND_STR(")") && READ('_'));
	TRY_MATCH(READ('u') && (CALL_RULE(rule_source_name)) && (((CALL_RULE(rule_template_args))) || true));
	TRY_MATCH(READ_STR("DS") && READ_STR("DA") && AST_APPEND_STR("_Sat _Accum"));
	TRY_MATCH(READ_STR("DS") && READ_STR("DR") && AST_APPEND_STR("_Sat _Fract"));
	TRY_MATCH(READ('v') && AST_APPEND_STR("void"));
	TRY_MATCH(READ('w') && AST_APPEND_STR("wchar_t"));
	TRY_MATCH(READ('b') && AST_APPEND_STR("bool"));
	TRY_MATCH(READ('c') && AST_APPEND_STR("char"));
	TRY_MATCH(READ('a') && AST_APPEND_STR("signed char"));
	TRY_MATCH(READ('h') && AST_APPEND_STR("unsigned char"));
	TRY_MATCH(READ('s') && AST_APPEND_STR("short"));
	TRY_MATCH(READ('t') && AST_APPEND_STR("unsigned short"));
	TRY_MATCH(READ('i') && AST_APPEND_STR("int"));
	TRY_MATCH(READ('j') && AST_APPEND_STR("unsigned int"));
	TRY_MATCH(READ('l') && AST_APPEND_STR("long"));
	TRY_MATCH(READ('m') && AST_APPEND_STR("unsigned long"));
	TRY_MATCH(READ('x') && AST_APPEND_STR("long long"));
	TRY_MATCH(READ('y') && AST_APPEND_STR("unsigned long long"));
	TRY_MATCH(READ('n') && AST_APPEND_STR("__int128"));
	TRY_MATCH(READ('o') && AST_APPEND_STR("unsigned __int128"));
	TRY_MATCH(READ('f') && AST_APPEND_STR("float"));
	TRY_MATCH(READ('d') && AST_APPEND_STR("double"));
	TRY_MATCH(READ('e') && AST_APPEND_STR("long double"));
	TRY_MATCH(READ('g') && AST_APPEND_STR("__float128"));
	TRY_MATCH(READ('z') && AST_APPEND_STR("..."));
	TRY_MATCH(READ_STR("Dd") && AST_APPEND_STR("decimal64"));
	TRY_MATCH(READ_STR("De") && AST_APPEND_STR("decimal128"));
	TRY_MATCH(READ_STR("Df") && AST_APPEND_STR("decimal32"));
	TRY_MATCH(READ_STR("Dh") && AST_APPEND_STR("half"));
	TRY_MATCH(READ_STR("Di") && AST_APPEND_STR("char32_t"));
	TRY_MATCH(READ_STR("Ds") && AST_APPEND_STR("char16_t"));
	TRY_MATCH(READ_STR("Du") && AST_APPEND_STR("char8_t"));
	TRY_MATCH(READ_STR("Da") && AST_APPEND_STR("auto"));
	TRY_MATCH(READ_STR("Dc") && AST_APPEND_STR("decltype(auto)"));
	TRY_MATCH(READ_STR("Dn") && AST_APPEND_STR("std::nullptr_t"));
	TRY_MATCH(READ_STR("DA") && AST_APPEND_STR("_Accum"));
	TRY_MATCH(READ_STR("DR") && AST_APPEND_STR("_Fract"));
	RULE_FOOT(builtin_type);
}

bool rule_source_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(source_name);
	/* positive number providing length of name followed by it */
	ut64 name_len = 0;
	const char *name = NULL;
	if (!parse_base_source_name(p, &name, &name_len)) {
		TRACE_RETURN_FAILURE();
	}
	if (strcmp(name, "_GLOBAL__N") == 0) {
		node = PRIMITIVE_TYPE("(anonymous namespace)");
	} else {
		PRIMITIVE_TYPEN(name, name_len);
	}
	TRACE_RETURN_SUCCESS;
}

bool rule_class_enum_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(class_enum_type);
	TRY_MATCH(((READ_STR("Ts") || READ_STR("Tu") || READ_STR("Te")) || true) && (CALL_RULE(rule_name)));
	RULE_FOOT(class_enum_type);
}

bool rule_mangled_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(mangled_name);
	// Handle internal linkage prefix: _ZL is treated as _Z (L is ignored)
	TRY_MATCH(READ_STR("_ZL") && (CALL_RULE(rule_encoding)) &&
		(((READ('.') && (CALL_RULE(rule_vendor_specific_suffix))) ||
			 (READ('_') && (CALL_RULE(rule_vendor_specific_suffix)))) ||
			true));
	TRY_MATCH(READ_STR("_Z") && (CALL_RULE(rule_encoding)) &&
		(((READ('.') && (CALL_RULE(rule_vendor_specific_suffix))) ||
			 (READ('_') && (CALL_RULE(rule_vendor_specific_suffix)))) ||
			true));
	RULE_FOOT(mangled_name);
}

bool rule_qualified_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(qualified_type);
	if (PEEK() == 'U') {
		MUST_MATCH(parse_base_source_name(p, &node->vendor_ext_qualified_ty.vendor_ext.buf, &node->vendor_ext_qualified_ty.vendor_ext.len));
		if (PEEK() == 'I') {
			MUST_MATCH(CALL_RULE_N(node->vendor_ext_qualified_ty.template_args, rule_template_args));
		}
		MUST_MATCH(CALL_RULE_N(node->vendor_ext_qualified_ty.inner_type, rule_qualified_type));
		node->tag = CP_DEM_TYPE_KIND_vendor_ext_qualified_type;
		TRACE_RETURN_SUCCESS;
	}

	if (!parse_cv_qualifiers(p, &node->qualified_ty.qualifiers)) {
		TRACE_RETURN_FAILURE();
	}
	MUST_MATCH(CALL_RULE_N(node->qualified_ty.inner_type, rule_type));
	TRACE_RETURN_SUCCESS;
}

bool rule_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(type);
	TRY_MATCH(CALL_RULE(rule_builtin_type));
	TRY_MATCH(CALL_RULE(rule_function_type));
	switch (PEEK()) {
	case 'r':
	case 'V':
	case 'K':
	case 'U': {
		PASSTHRU_RULE(rule_qualified_type);
		break;
	}
	case 'M':
		PASSTHRU_RULE(rule_pointer_to_member_type);
		break;
	case 'A':
		PASSTHRU_RULE(rule_array_type);
		break;
	case 'C':
		ADV();
		MUST_MATCH(CALL_RULE(rule_type));
		AST_APPEND_STR(" complex");
		break;
	case 'G':
		ADV();
		MUST_MATCH(CALL_RULE(rule_type));
		AST_APPEND_STR(" imaginary");
		break;
	case 'P':
	case 'R':
	case 'O': {
		ut32 subtag = 0;
		// Process pointer/reference types
		switch (PEEK()) {
		case 'P':
			subtag = POINTER_TYPE;
			break;
		case 'R':
			subtag = REFERENCE_TYPE;
			break;
		case 'O':
			subtag = RVALUE_REFERENCE_TYPE;
			break;
		default:
			DEM_UNREACHABLE;
		}
		ADV();
		MUST_MATCH(CALL_RULE(rule_type));
		node->subtag = subtag;
		break;
	}
	case 'D':
		// Dp <type>       # pack expansion (C++0x)
		if (PEEK_AT(1) == 'p') {
			context_save(0);
			ADV_BY(2);
			CTX_MUST_MATCH(0, CALL_RULE(rule_type));
			break;
		}
		if (PEEK_AT(1) == 't' || PEEK_AT(1) == 'T') {
			MUST_MATCH(CALL_RULE(rule_decltype));
			break;
		}
		// fallthrough
	case 'T': {
		if (strchr("sue", PEEK_AT(1)) != NULL) {
			MUST_MATCH(CALL_RULE(rule_class_enum_type));
			break;
		}
		MUST_MATCH(CALL_RULE(rule_template_param));
		if (PEEK() == 'I' && !p->not_parse_template_args) {
			AST_APPEND_TYPE;
			CALL_RULE(rule_template_args);
		}
		break;
	}
	case 'S': {
		if (PEEK_AT(1) != 't') {
			bool is_subst = false;
			DemNode *result = NULL;
			CALL_RULE_N_VA(result, rule_unscoped_name, &is_subst);
			if (!result) {
				TRACE_RETURN_FAILURE();
			}
			if (PEEK() == 'I' && (!is_subst || !p->not_parse_template_args)) {
				if (!is_subst) {
					AST_APPEND_TYPE1(result);
				}
				DemNode *ta = NULL;
				CALL_RULE_N(ta, rule_template_args);
				if (!ta) {
					DemNode_dtor(result);
					TRACE_RETURN_FAILURE();
				}
				node->tag = CP_DEM_TYPE_KIND_name_with_template_args;
				node->name_with_template_args.name = result;
				node->name_with_template_args.template_args = ta;
			} else if (is_subst) {
				DemNode_dtor(node);
				node = result;
				TRACE_RETURN_SUCCESS;
			}
		}
		// fallthrough
	}
	default:
		PASSTHRU_RULE(rule_class_enum_type);
		break;
	}
	if (CUR() > save_pos_rule) {
		AST_APPEND_TYPE;
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(type);
}

bool rule_base_unresolved_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(base_unresolved_name);
	TRY_MATCH((CALL_RULE(rule_simple_id)));
	if (READ_STR("dn")) {
		MUST_MATCH(CALL_RULE(rule_destructor_name));
		TRACE_RETURN_SUCCESS;
	}
	READ_STR("on");
	MUST_MATCH(CALL_RULE(rule_operator_name));
	if (PEEK() == 'I') {
		MUST_MATCH(CALL_RULE(rule_template_args));
	}
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(base_unresolved_name);
}

bool rule_local_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(local_name);
	if (!READ('Z')) {
		TRACE_RETURN_FAILURE();
	}
	context_save(0);
	CTX_MUST_MATCH(0, CALL_RULE(rule_encoding) && READ('E'));
	if (READ('d')) {
		CALL_RULE(rule_number);
		CTX_MUST_MATCH(0, READ('_') && CALL_RULE(rule_name));
		TRACE_RETURN_SUCCESS;
	}
	if (READ('s')) {
		CALL_RULE(rule_discriminator);
		TRACE_RETURN_SUCCESS;
	}
	CTX_MUST_MATCH(0, CALL_RULE(rule_name));
	CALL_RULE(rule_discriminator);
	TRACE_RETURN_SUCCESS;
}

bool rule_substitution(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(substitution);
	if (!READ('S')) {
		TRACE_RETURN_FAILURE();
	}

	switch (PEEK()) {
	case 't': {
		ADV();
		PRIMITIVE_TYPE("std");
		TRACE_RETURN_SUCCESS;
	}
	case 'a': {
		ADV();
		PRIMITIVE_TYPE("std::allocator");
		TRACE_RETURN_SUCCESS;
	}
	case 'b': {
		ADV();
		PRIMITIVE_TYPE("std::basic_string");
		TRACE_RETURN_SUCCESS;
	}
	case 's': {
		ADV();
		if (PEEK() == 'C' || PEEK() == 'D') {
			PRIMITIVE_TYPE("std::basic_string<char, std::char_traits<char>, std::allocator<char>>");
		} else {
			PRIMITIVE_TYPE("std::string");
		}
		TRACE_RETURN_SUCCESS;
	}
	case 'i': {
		ADV();
		PRIMITIVE_TYPE("std::istream");
		TRACE_RETURN_SUCCESS;
	}
	case 'o': {
		ADV();
		PRIMITIVE_TYPE("std::ostream");
		TRACE_RETURN_SUCCESS;
	}
	case 'd': {
		ADV();
		PRIMITIVE_TYPE("std::iostream");
		TRACE_RETURN_SUCCESS;
	}
	default: {
		DemNode *child_node = NULL;
		if (!parse_seq_id(p, &child_node)) {
			TRACE_RETURN_FAILURE();
		}
		DemNode_copy(node, child_node);
		TRACE_RETURN_SUCCESS;
		break;
	}
	}
	RULE_FOOT(substitution);
}

bool rule_float(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(float);
	while (IS_DIGIT(PEEK()) || ('a' <= PEEK() && PEEK() <= 'f')) {
		ADV();
	}
	RULE_FOOT(float);
}

bool rule_destructor_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(destructor_name);
	TRY_MATCH(CALL_RULE(rule_unresolved_type));
	TRY_MATCH(CALL_RULE(rule_simple_id));
	RULE_FOOT(destructor_name);
}

bool rule_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(name);
	if (PEEK() == 'N') {
		PASSTHRU_RULE(rule_nested_name);
		TRACE_RETURN_FAILURE();
	}
	if (PEEK() == 'Z') {
		PASSTHRU_RULE(rule_local_name);
		TRACE_RETURN_FAILURE();
	}

	DemNode *result = NULL;
	bool is_subst = false;
	CALL_RULE_N_VA(result, rule_unscoped_name, &is_subst);
	if (!result) {
		TRACE_RETURN_FAILURE();
	}

	// If unscoped_name parsed successfully, check for template_args
	if (PEEK() == 'I') {
		if (!is_subst) {
			AST_APPEND_TYPE1(AST(0));
		}
		DemNode *ta = NULL;
		CALL_RULE_N(ta, rule_template_args);
		if (!ta) {
			DemNode_dtor(result);
			TRACE_RETURN_FAILURE();
		}
		node->tag = CP_DEM_TYPE_KIND_name_with_template_args;
		node->name_with_template_args.name = result;
		node->name_with_template_args.template_args = ta;
		TRACE_RETURN_SUCCESS;
	}
	if (is_subst) {
		DemNode_dtor(result);
		TRACE_RETURN_FAILURE();
	}
	DemNode_move(node, result);
	TRACE_RETURN_SUCCESS;
}

static bool is_endswith_template_args(DemNode *node) {
	if (!node) {
		return false;
	}
	PDemNode *tail_ptr = VecF(PDemNode, len)(node->children) > 0 ? VecF(PDemNode, tail)(node->children) : NULL;
	DemNode *tail_node = tail_ptr ? *tail_ptr : NULL;
	return (tail_node && tail_node->tag == CP_DEM_TYPE_KIND_template_args);
}

bool rule_nested_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(nested_name);
	if (!READ('N')) {
		TRACE_RETURN_FAILURE();
	}
	CvQualifiers cv_quals = { 0 };
	RefQualifiers ref_qual = { 0 };
	parse_cv_qualifiers(p, &cv_quals);
	parse_ref_qualifiers(p, &ref_qual);

	DemNode *ast_node = NULL;
	while (!READ('E')) {
		if (PEEK() == 'T') {
			if (ast_node != NULL) {
				goto fail;
			}
			CALL_RULE_N(ast_node, rule_template_param);
		} else if (PEEK() == 'I') {
			if (ast_node == NULL) {
				TRACE_RETURN_FAILURE();
			}
			if (is_endswith_template_args(ast_node)) {
				goto fail;
			}
			DemNode *ta = NULL;
			MUST_MATCH(CALL_RULE_N(ta, rule_template_args));
			ast_node = make_name_with_template_args(save_pos_rule, CUR(), ast_node, ta);
		} else if (PEEK() == 'D' && (PEEK_AT(1) == 't' || PEEK_AT(1) == 'T')) {
			if (ast_node != NULL) {
				goto fail;
			}
			CALL_RULE_N(ast_node, rule_decltype);
		} else {
			// Skip 'L' prefix for internal linkage
			if (PEEK() == 'L') {
				ADV();
			}
			DemNode *module = NULL;
			if (PEEK() == 'S') {
				DemNode *subst = NULL;
				if (PEEK_AT(1) == 't') {
					subst = make_primitive_type(CUR(), CUR() + 2, "std", 3);
					ADV_BY(2);
				} else {
					CALL_RULE_N(subst, rule_substitution);
				}
				if (!subst || ast_node != NULL) {
					DemNode_dtor(subst);
					goto fail;
				}
				if (subst->tag == CP_DEM_TYPE_KIND_module_name) {
					module = subst;
				} else {
					ast_node = subst;
					continue;
				}
			}
			DemNode *qual_name = NULL;
			CALL_RULE_N_VA(qual_name, rule_unqualified_name, ast_node, module);
			if (!qual_name) {
				goto fail;
			}
			ast_node = qual_name;
		}
		if (ast_node == NULL) {
			TRACE_RETURN_FAILURE();
		}
		AST_APPEND_TYPE1(ast_node);
		READ('M');
	}
	if (ast_node == NULL || VecF(PDemNode, empty)(&p->detected_types)) {
		TRACE_RETURN_FAILURE();
	}
	DemNode **pop_node = VecF(PDemNode, pop)(&p->detected_types);
	if (pop_node) {
		DemNode_dtor(*pop_node);
	}
	DemNode_move(node, ast_node);
	TRACE_RETURN_SUCCESS;
fail:
	DemNode_dtor(ast_node);
	TRACE_RETURN_FAILURE();
}

bool is_template_param_decl(DemParser *p) {
	return PEEK() == 'T' && strchr("yptnk", PEEK_AT(1)) != NULL;
}

bool rule_template_arg(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_arg);
	switch (PEEK()) {
	case 'X': {
		ADV();
		MUST_MATCH(CALL_RULE(rule_expression) && READ('E'));
		TRACE_RETURN_SUCCESS;
	}
	case 'J': {
		ADV();
		while (!READ('E')) {
			DemResult child_r = { 0 };
			if (!rule_template_arg(p, node, &child_r)) {
				TRACE_RETURN_FAILURE();
			}
			AST_APPEND_NODE(child_r.output);
		}
		node->subtag = TEMPLATE_PARAMETER_PACK;
		TRACE_RETURN_SUCCESS;
	}
	case 'L': {
		if (PEEK_AT(1) == 'Z') {
			ADV_BY(2);
			MUST_MATCH(CALL_RULE(rule_encoding) && READ('E'));
			TRACE_RETURN_SUCCESS;
		}
		MUST_MATCH(CALL_RULE(rule_expr_primary));
		TRACE_RETURN_SUCCESS;
		break;
	}
	case 'T': {
		if (!is_template_param_decl(p)) {
			MUST_MATCH(CALL_RULE(rule_type));
			TRACE_RETURN_SUCCESS;
		}
		DEM_UNREACHABLE;
	}
	default:
		MUST_MATCH(CALL_RULE(rule_type));
		TRACE_RETURN_SUCCESS;
		break;
	}
	RULE_FOOT(template_arg);
}

static bool is_tag_templates(const DemNode *node) {
	if (!(node && node->parent)) {
		return false;
	}
	return node->tag == CP_DEM_TYPE_KIND_nested_name && node->parent->tag == CP_DEM_TYPE_KIND_function_type;
}

bool rule_template_args(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_args);
	if (!READ('I')) {
		TRACE_RETURN_FAILURE();
	}
	// Save and restore ctor/dtor flags to prevent them from leaking from template args
	bool saved_is_ctor = p->is_ctor;
	bool saved_is_dtor = p->is_dtor;
	p->is_ctor = false;
	p->is_dtor = false;
	const bool tag_templates = is_tag_templates(parent);
	if (tag_templates) {
		VecPNodeList_clear(&p->template_params);
		VecPNodeList_append(&p->template_params, &p->outer_template_params);
		VecPDemNode_clear(p->outer_template_params);
	}
	while (!READ('E')) {
		DemResult child_r = { 0 };
		if (!rule_template_arg(p, node, &child_r)) {
			p->is_ctor = saved_is_ctor;
			p->is_dtor = saved_is_dtor;
			TRACE_RETURN_FAILURE();
		}
		if (tag_templates) {
			DemNode *node_arg_cloned = (DemNode *)malloc(sizeof(DemNode));
			if (node_arg_cloned) {
				DemNode_init(node_arg_cloned);
				DemNode_copy(node_arg_cloned, child_r.output);
				VecF(PDemNode, append)(p->outer_template_params, &node_arg_cloned);
			}
		}
		AST_APPEND_NODE(child_r.output);
		if (READ('Q')) {
			DEM_UNREACHABLE;
		}
	}
	// Restore ctor/dtor flags
	p->is_ctor = saved_is_ctor;
	p->is_dtor = saved_is_dtor;
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(template_args);
}

bool rule_template_param_decl(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(template_param_decl);
	if (!READ('T')) {
		TRACE_RETURN_FAILURE();
	}
	// TODO: Handle different kinds of template parameters
	RULE_FOOT(template_param_decl);
}

bool rule_unnamed_type_name(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(unnamed_type_name);
	if (READ_STR("Ut")) {
		ut64 tidx = 0;
		if (!parse_non_neg_integer(p, &tidx)) {
			tidx = 0;
		}
		if (!READ('_')) {
			TRACE_RETURN_FAILURE();
		}
		TRACE_RETURN_SUCCESS;
	}
	if (READ_STR("Ul")) {
		while (is_template_param_decl(p)) {
			// TODO: Handle template_param_decl
			DEM_UNREACHABLE;
		}
		if (READ('Q')) {
			// TODO: Handle ConstraintExpr
			DEM_UNREACHABLE;
		}
		DemNode *params = NULL;
		if (!READ('v')) {
			CALL_MANY1_N(params, rule_type, ", ");
		}
		if (READ('Q')) {
			// TODO: Handle ConstraintExpr
			DEM_UNREACHABLE;
		}
		if (!READ('E')) {
			TRACE_RETURN_FAILURE();
		}
		if (!parse_number(p, &node->closure_ty_name.count, false)) {
			TRACE_RETURN_FAILURE();
		}
		if (!READ('_')) {
			TRACE_RETURN_FAILURE();
		}
		node->tag = CP_DEM_TYPE_KIND_closure_ty_name;
		node->closure_ty_name.params = params;
		TRACE_RETURN_SUCCESS;
	}
	RULE_FOOT(unnamed_type_name);
}

bool rule_pointer_to_member_type(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(pointer_to_member_type);
	if (!READ('M')) {
		TRACE_RETURN_FAILURE();
	}
	context_save(0);
	// Grammar: M <class-type> <member-type>
	// For member function pointers: M <class> <function-type>
	// For member data pointers: M <class> <data-type>
	CTX_MUST_MATCH(0, CALL_RULE(rule_type));
	CTX_MUST_MATCH(0, CALL_RULE(rule_type));
	TRACE_RETURN_SUCCESS;
	RULE_FOOT(pointer_to_member_type);
}

// Helper function to parse reference qualifiers directly into a struct
// Returns true if at least one qualifier was parsed
bool parse_ref_qualifier(DemParser *p, RefQualifiers *quals) {
	const char *start = p->cur;
	if (READ('R')) {
		quals->is_l_value = true;
	}
	if (READ('O')) {
		quals->is_r_value = true;
	}
	return p->cur != start;
}

bool rule_encoding(DemParser *p, const DemNode *parent, DemResult *r) {
	RULE_HEAD(encoding);
	// Override tag to function_type since encoding produces function signatures
	node->tag = CP_DEM_TYPE_KIND_function_type;
	// Handle special names (G=guard variable, T=typeinfo)
	if (PEEK() == 'G' || PEEK() == 'T') {
		MUST_MATCH(CALL_RULE(rule_special_name));
		TRACE_RETURN_SUCCESS;
	}
	context_save(0);
	// Parse: name, [return_type], parameters
	CTX_MUST_MATCH(0, CALL_RULE_N(node->fn_ty.name, rule_name));
	if (!resolve_forward_template_refs(p, node->fn_ty.name)) {
		context_restore(0);
		TRACE_RETURN_FAILURE();
	}
	bool has_template = is_endswith_template_args(node->fn_ty.name);
	if (has_template && !p->is_conversion_operator) {
		// Template functions must have an explicit return type
		// Exception: conversion operators don't have explicit return types
		CALL_RULE_N(node->fn_ty.ret, rule_type);
	}

	// Parse function parameters using match_many to create a many node
	// 'v' means void (no parameters), otherwise parse parameter list
	if (!READ('v')) {
		CALL_MANY1_N(node->fn_ty.params, rule_type, ", ");
		if (!node->fn_ty.params) {
			context_restore(0);
			TRACE_RETURN_FAILURE();
		}
	}

	TRACE_RETURN_SUCCESS;
}

void DemContext_deinit(DemContext *ctx) {
	if (!ctx) {
		return;
	}
	DemParser_deinit(&ctx->parser);
	DemResult_deinit(&ctx->result);
	dem_string_deinit(&ctx->output);
}

bool parse_rule(DemContext *ctx, const char *mangled, DemRule rule, CpDemOptions opts) {
	if (!mangled || !rule || !ctx) {
		return false;
	}
	// Enable tracing via environment variable or compile-time flag
#ifdef ENABLE_GRAPHVIZ_TRACE
	bool trace = true;
#else
	bool trace = (getenv("DEMANGLE_TRACE") != NULL);
#endif
	// Initialize DemParser
	DemParser parser = { 0 };
	DemParser_init(&parser, mangled);
	parser.trace = trace;
	DemResult dem_result = { 0 };
	if (!rule(&parser, NULL, &dem_result)) {
		ctx->parser = parser;
		ctx->result = dem_result;
		return false;
	}
	if (parser.trace && VecPDemNode_len(&parser.detected_types) > 0) {
		DemString buf = { 0 };
		vec_foreach_ptr_i(&parser.detected_types, i, sub_ptr, {
			DemNode *sub = sub_ptr ? *sub_ptr : NULL;
			dem_string_appendf(&buf, "[%lu] = ", i);
			ast_pp(sub, &buf);
			dem_string_append(&buf, "\n");
		});
		char *buf_str = dem_string_drain_no_free(&buf);
		fprintf(stderr, "# substitutions:\n%s\n", buf_str ? buf_str : "(null)");
		free(buf_str);
	}
	DemNode *output_node = dem_result.output;
	ast_pp(output_node, &ctx->output);
	ctx->parser = parser;
	ctx->result = dem_result;

	// Generate DOT graph if tracing is enabled
	if (trace && dem_result.output) {
		DotGraph dot_graph = { 0 };
		dot_graph_init(&dot_graph, mangled);
		if (dot_graph.enabled) {
			dot_graph_generate(&dot_graph, dem_result.output);
			dot_graph_finish(&dot_graph);
		}
		dot_graph_cleanup(&dot_graph);
	}

	return true;
}

/**
 *
 * @param mangled
 * @param opts
 * @return
 */
char *cp_demangle_v3(const char *mangled, CpDemOptions opts) {
	// Handle vendor-specific prefixes (Apple/Objective-C extensions)
	// These appear as multiple underscores before the actual _Z symbol
	const char *p = mangled;
	// Count leading underscores
	while (*p == '_') {
		p++;
	}
	// If we found a _Z after underscores, and there were underscores, process from the _Z
	if (*p == 'Z' && p > mangled) {
		// p points to 'Z', so p-1 points to '_', which is the start of "_Z"
		p = p - 1;
	}
	DemContext ctx = { 0 };
	if (!parse_rule(&ctx, p, rule_mangled_name, opts)) {
		DemContext_deinit(&ctx);
		return NULL;
	}
	char *result = dem_string_drain_no_free(&ctx.output);
	// Clear the output buffer so DemContext_deinit doesn't double-free it
	ctx.output = (DemString){ 0 };
	DemContext_deinit(&ctx);
	return result;
}
