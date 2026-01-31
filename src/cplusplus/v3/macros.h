// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_MACROS_H
#define V3_IMPL_MACROS_H

#include "../../demangler_util.h"
#include "types.h"
#include "../vec.h"

/**
 * \b Give current read position.
 */
#define CUR() (p->cur)

/**
 * \b Give position where string begins.
 */
#define BEG() (p->beg)

/**
 * \b Give position of NULL terminator.
 */
#define END() (p->end)

#define P_SIZE()      (size_t)(END() - BEG())
#define REMAIN_SIZE() (size_t)(END() - CUR())

/**
 * \b Check whether the provided position is in range of readable address.
 */
#define IN_RANGE(read_pos) ((read_pos) >= BEG() ? ((read_pos) < END() ? 1 : 0) : 0)

/**
 * \b Seek to given read position if it's in range.
 */
#define SEEK_TO(target_read_pos) (p->cur = IN_RANGE(target_read_pos) ? (target_read_pos) : CUR())

/**
 * Peek one character from current read position.
 */
#define PEEK() (IN_RANGE(CUR()) ? *p->cur : 0)

#define PEEK_AT(offset) (IN_RANGE(p->cur + (offset)) ? p->cur[(offset)] : 0)

/**
 * \b Read one character and advance.
 */
#define READ(ch)          (IN_RANGE(CUR()) ? ((*p->cur == ch) ? (ADV(), 1) : 0) : 0)
#define READ_OPTIONAL(ch) (READ(ch) || true)
#define SKIP_CH(ch) \
	do { \
		if (IN_RANGE(CUR()) && *p->cur == ch) { \
			ADV(); \
		} \
	} while (0)

static inline bool parse_string(DemParser *p, const char *s) {
	size_t s_sz = strlen(s);
	bool read_success = REMAIN_SIZE() >= s_sz && strncmp(CUR(), s, s_sz) == 0;
	if (read_success) {
		p->cur += s_sz;
	}
	return read_success;
}

/**
 * \b Read multiple characters in a string.
 */
#define READ_STR(s) parse_string(p, s)

/**
 * \b Advance current read position by one character.
 */
#define ADV() (IN_RANGE(CUR()) ? p->cur++ : NULL)

/**
 * \b Advance current read position by "n" characters.
 */
#define ADV_BY(n) (IN_RANGE(CUR() + n) ? (p->cur = p->cur + (n)) : NULL)

/**
 * Always evaluate to true, even if rule does not match.
 */
#define OPTIONAL(x) ((x) || true)

/**
 * \b Declare a new rule.
 */
#define DECL_RULE(x) \
	bool rule_##x(DemParser *p, DemResult *r)
#define DECL_RULE_STATIC(x) \
	static inline bool rule_##x(DemParser *p, DemResult *r)
/**
 * \b Declare a rule alias x for rule y.
 */
#define DECL_RULE_ALIAS(X, Y) \
	DECL_RULE_STATIC(X) { \
		return rule_##Y(p, r); \
	}

#define RULE_HEAD(X) \
	if (!IN_RANGE(CUR())) { \
		r->error = DEM_ERR_UNEXPECTED_END; \
		DemNode_dtor(r->output); \
		return false; \
	} \
	DemNode *node = NULL; \
	bool is_PASSTHRU = false; \
	DECLARE_MACRO_HELPERS(); \
	if (!r->output) { \
		node = (DemNode *)malloc(sizeof(DemNode)); \
		if (!node) { \
			r->error = DEM_ERR_OUT_OF_MEMORY; \
			return false; \
		} \
		DemNode_init(node); \
		node->val.buf = p->cur; \
	} else { \
		is_PASSTHRU = true; \
		node = r->output; \
	} \
	node->tag = CP_DEM_TYPE_KIND_##X; \
	context_save(rule);

#define RULE_FOOT(X) TRACE_RETURN_FAILURE();

// Parse context structure to hold saved state
typedef struct ParseContext {
	size_t saved_children_len;
	size_t saved_tag;
	size_t saved_types_len;
	const char *saved_pos;
} ParseContext;

// Save current parsing context
static inline ParseContext context_save_inline(DemParser *p, DemNode *node) {
	ParseContext ctx;
	ctx.saved_children_len = node->children ? VecPDemNode_len(node->children) : 0;
	ctx.saved_tag = node->tag;
	ctx.saved_types_len = VecPDemNode_len(&p->detected_types);
	ctx.saved_pos = p->cur;
	return ctx;
}

// Restore node context
static inline void context_restore_node_inline(DemNode *node, const ParseContext *ctx) {
	if (node) {
		if (node->children) {
			while (VecPDemNode_len(node->children) > ctx->saved_children_len) {
				PDemNode *node_ptr = VecPDemNode_pop(node->children);
				DemNode *child = node_ptr ? *node_ptr : NULL;
				if (child) {
					DemNode_dtor(child);
				}
			}
		}
		node->tag = ctx->saved_tag;
		node->val.buf = ctx->saved_pos;
	}
}

// Restore parser context
static inline void context_restore_parser_inline(DemParser *p, const ParseContext *ctx) {
	if (!p) {
		return;
	}
	while (VecPDemNode_len(&p->detected_types) > ctx->saved_types_len) {
		size_t last_idx = VecPDemNode_len(&p->detected_types) - 1;
		PDemNode *node_ptr = VecPDemNode_at(&p->detected_types, last_idx);
		DemNode *type_node = node_ptr ? *node_ptr : NULL;
		if (type_node) {
			DemNode_dtor(type_node);
		}
		VecPDemNode_pop(&p->detected_types);
	}
	p->cur = ctx->saved_pos;
}

// Full context restore
static inline void context_restore_inline(DemParser *p, DemNode *node, const ParseContext *ctx) {
	context_restore_node_inline(node, ctx);
	context_restore_parser_inline(p, ctx);
}

// Macro versions for compatibility
#define context_save(N) \
	__attribute__((unused)) ParseContext saved_ctx_##N = context_save_inline(p, node)

#define context_restore_node(N) \
	context_restore_node_inline(node, &saved_ctx_##N)

#define context_restore_parser(N) \
	context_restore_parser_inline(p, &saved_ctx_##N)

#define context_restore(N) \
	context_restore_inline(p, node, &saved_ctx_##N)

/* Macros for rules that use direct returns */
#define TRACE_RETURN_SUCCESS \
	do { \
		node->val.len = p->cur - node->val.buf; \
		r->output = node; \
		r->error = DEM_ERR_OK; \
		return true; \
	} while (0);

#define TRACE_RETURN_FAILURE() \
	do { \
		if (!is_PASSTHRU) { \
			if (node) { \
				DemNode_dtor(node); \
			} \
			r->output = NULL; \
		} else { \
			/* In PASSTHRU mode, we still need to clean up children we added */ \
			context_restore_node(rule); \
		} \
		r->error = DEM_ERR_INVALID_SYNTAX; \
		context_restore_parser(rule); \
		return false; \
	} while (0)

#define RETURN_SUCCESS_OR_FAIL(expr) \
	do { \
		if (expr) { \
			TRACE_RETURN_SUCCESS; \
		} else { \
			TRACE_RETURN_FAILURE(); \
		} \
	} while (0)

#define RETURN_SUCCESS_OR_FAIL(expr) \
	do { \
		if (expr) { \
			TRACE_RETURN_SUCCESS; \
		} else { \
			TRACE_RETURN_FAILURE(); \
		} \
	} while (0)

/**
 * \b Match for given rules in a recoverable manner.
 */
#define MATCH_AND_DO(rules, body) \
	do { \
		context_save(0); \
		if (rules) { \
			/* caller execute code */ \
			{ body }; \
			TRACE_RETURN_SUCCESS; \
		} else { \
			context_restore(0); \
			break; \
		} \
	} while (0)

#define TRY_MATCH(rules) MATCH_AND_DO(rules, {})

#define MUST_MATCH(rules) \
	do { \
		if ((rules)) { \
			node->val.len = p->cur - node->val.buf; \
		} else { \
			TRACE_RETURN_FAILURE(); \
		} \
	} while (0)

// Declare helper variables that the macros will use
#define DECLARE_MACRO_HELPERS() \
	__attribute__((unused)) DemResult _child_result_macro = { 0 }; \
	__attribute__((unused)) bool _macro_result = false

// Helper for PASSTHRU restore that also reinits the node
static inline void passthru_restore_inline(DemParser *p, DemNode *node, const ParseContext *ctx) {
	DemNode_deinit(node);
	DemNode_init(node);
	context_restore_inline(p, node, ctx);
}

#define PASSTHRU_RULE_VA(rule_fn, ...) \
	(r->output = node, \
		_macro_result = (rule_fn)(p, r, __VA_ARGS__), \
		(_macro_result ? (void)0 : passthru_restore_inline(p, node, &saved_ctx_rule)), \
		_macro_result)

#define PASSTHRU_RULE(rule_fn) \
	(r->output = node, \
		_macro_result = (rule_fn)(p, r), \
		(_macro_result ? (void)0 : passthru_restore_inline(p, node, &saved_ctx_rule)), \
		_macro_result)

#define CALL_RULE(rule_fn) \
	(_child_result_macro = (DemResult){ 0 }, \
		_macro_result = (rule_fn)(p, &_child_result_macro), \
		(_macro_result && _child_result_macro.output ? (AST_APPEND_NODE(_child_result_macro.output), _child_result_macro.output = NULL, (void)0) : (DemResult_deinit(&_child_result_macro), (void)0)), \
		_macro_result)

#define CALL_RULE_VA(rule_fn, ...) \
	(_child_result_macro = (DemResult){ 0 }, \
		_macro_result = (rule_fn)(p, &_child_result_macro, __VA_ARGS__), \
		(_macro_result && _child_result_macro.output ? (AST_APPEND_NODE(_child_result_macro.output), _child_result_macro.output = NULL, (void)0) : (DemResult_deinit(&_child_result_macro), (void)0)), \
		_macro_result)

#define CALL_RULE_N_VA(N, rule_fn, ...) \
	(_child_result_macro = (DemResult){ 0 }, \
		_macro_result = (rule_fn)(p, &_child_result_macro, __VA_ARGS__), \
		(_macro_result && _child_result_macro.output ? (N = _child_result_macro.output) : (DemResult_deinit(&_child_result_macro), N = NULL)), \
		_macro_result)

#define CALL_RULE_N(N, rule_fn) \
	(_child_result_macro = (DemResult){ 0 }, \
		_macro_result = (rule_fn)(p, &_child_result_macro), \
		(_macro_result && _child_result_macro.output ? (N = _child_result_macro.output) : (DemResult_deinit(&_child_result_macro), N = NULL)), \
		_macro_result)

// Helper macro for match_many/match_many1 calls
#define CALL_MANY(rule_fn, sep, stop)       CALL_RULE_VA(match_many, rule_fn, sep, stop)
#define CALL_MANY1(rule_fn, sep, stop)      CALL_RULE_VA(match_many1, rule_fn, sep, stop)
#define CALL_MANY_N(N, rule_fn, sep, stop)  CALL_RULE_N_VA(N, match_many, rule_fn, sep, stop)
#define CALL_MANY1_N(N, rule_fn, sep, stop) CALL_RULE_N_VA(N, match_many1, rule_fn, sep, stop)

static inline DemNode *Node_append(DemNode *node, DemNode *x) {
	if (!(node && x && node != x)) {
		return NULL;
	}
	if (!node->children) {
		node->children = VecPDemNode_ctor();
		if (!node->children) {
			return NULL;
		}
	}
	DemNode **res = VecPDemNode_append(node->children, &x);
	return res ? *res : NULL;
}

#define AST_APPEND_STR(s)     Node_append(node, make_primitive_type(CUR(), CUR(), s, strlen(s)))
#define AST_APPEND_STRN(s, N) Node_append(node, make_primitive_type(CUR(), CUR(), s, N))
#define AST_APPENDF(s, ...)   true //(dem_string_appendf(&node->dem, s, __VA_ARGS__))
#define PRIMITIVE_TYPE(s)     make_primitive_type_inplace(node, CUR(), CUR(), s, strlen(s))
#define PRIMITIVE_TYPEN(s, N) make_primitive_type_inplace(node, CUR(), CUR(), s, N)

#define AST_APPEND_TYPE     append_type(p, node)
#define AST_APPEND_TYPE1(T) append_type(p, (T))
#define AST_APPEND_NODE(X)  Node_append(node, (X))
#define AST_(X, I)          (VecPDemNode_at((X)->children, (I)) ? *VecPDemNode_at((X)->children, (I)) : NULL)
#define AST(I)              (AST_(node, I))

#define DEM_UNREACHABLE \
	do { \
		fprintf(stderr, "Reached unreachable code at %s:%d\n", __FILE__, __LINE__); \
		abort(); \
	} while (0)

#endif // V3_IMPL_MACROS_H
