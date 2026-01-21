// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef V3_IMPL_MACROS_H
#define V3_IMPL_MACROS_H

#include "../demangler_util.h"
#include "types.h"
#include "vec.h"

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

#define P_SIZE() (size_t)(END() - BEG())

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

/**
 * \b Read multiple characters in a string.
 */
#define READ_STR(s) \
	(IN_RANGE(CUR() + sizeof(s) - 1) ? (!strncmp(CUR(), s, sizeof(s) - 1) ? (ADV_BY(sizeof(s) - 1), 1) : 0) : 0)
#define READ_STR_OPTIONAL(s) (READ_STR(s) || true)

/**
 * \b Advance current read position by one character.
 */
#define ADV() (IN_RANGE(CUR()) ? p->cur++ : NULL)

/**
 * \b Advance current read position by "n" characters.
 */
#define ADV_BY(n) (IN_RANGE(CUR() + n) ? (p->cur = p->cur + (n)) : NULL)

/**
 * \b Save current read position.
 */
#define SAVE_POS(I) const char *save_pos_##I = CUR();

/**
 * \b Restore saved position.
 */
#define RESTORE_POS(I) SEEK_TO(save_pos_##I);

#define IS_CTOR() (p->is_ctor)
#define IS_DTOR() (p->is_dtor)

#define SET_CTOR() (p->is_dtor = false, (p->is_ctor = true))
#define SET_DTOR() (p->is_ctor = false, (p->is_dtor = true))

#define UNSET_CTOR() (p->is_dtor = false, m->is_ctor = false, true)
#define UNSET_DTOR() (p->is_ctor = false, m->is_dtor = false, true)

/**
 * Always evaluate to true, even if rule does not match.
 */
#define OPTIONAL(x) ((x) || true)

/**
 * \b Declare a new rule.
 */
#define DECL_RULE(x) \
	bool rule_##x(DemParser *p, const DemNode *parent, DemResult *r)
#define DECL_RULE_STATIC(x) \
	static inline bool rule_##x(DemParser *p, const DemNode *parent, DemResult *r)
/**
 * \b Declare a rule alias x for rule y.
 */
#define DECL_RULE_ALIAS(X, Y) \
	DECL_RULE_STATIC(X) { \
		return rule_##Y(p, parent, r); \
	}

#define RULE_HEAD(X) \
	if (!IN_RANGE(CUR())) { \
		r->error = DEM_ERR_UNEXPECTED_END; \
		DemNode_dtor(r->output); \
		return false; \
	} \
	DemNode *node = NULL; \
	bool is_PASSTHRU = false; \
	if (!r->output) { \
		node = (DemNode *)malloc(sizeof(DemNode)); \
		if (!node) { \
			r->error = DEM_ERR_OUT_OF_MEMORY; \
			return false; \
		} \
		DemNode_init(node); \
		node->parent = (DemNode *)parent; \
		node->val.buf = p->cur; \
	} else { \
		is_PASSTHRU = true; \
		node = r->output; \
	} \
	node->tag = CP_DEM_TYPE_KIND_##X; \
	context_save(rule);

#define RULE_FOOT(X) TRACE_RETURN_FAILURE();

#define context_save(N) \
	SAVE_POS(N); \
	size_t save_children_len_##N = node->children ? VecPDemNode_len(node->children) : 0; \
	size_t save_types_len_##N = VecPDemNode_len(&p->detected_types);

#define context_restore_node(N) \
	if (node->children) { \
		while (VecPDemNode_len(node->children) > save_children_len_##N) { \
			PDemNode *node_ptr = VecPDemNode_at(node->children, VecPDemNode_len(node->children) - 1); \
			DemNode *child = node_ptr ? *node_ptr : NULL; \
			if (child) { \
				DemNode_dtor(child); \
			} \
			VecPDemNode_pop(node->children); \
		} \
	}
#define context_restore_parser(N) \
	if (p) { \
		while (VecPDemNode_len(&p->detected_types) > save_types_len_##N) { \
			size_t last_idx = VecPDemNode_len(&p->detected_types) - 1; \
			PDemNode *node_ptr = VecPDemNode_at(&p->detected_types, last_idx); \
			DemNode *type_node = node_ptr ? *node_ptr : NULL; \
			if (type_node) { \
				DemNode_dtor(type_node); \
			} \
			VecPDemNode_pop(&p->detected_types); \
		} \
	}

#define context_restore(N) \
	context_restore_node(N); \
	context_restore_parser(N); \
	RESTORE_POS(N);

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
			/* In PASSTHRU mode, node is owned by parent, but we still need to clean up children we added */ \
			context_restore_node(rule); \
		} \
		r->error = DEM_ERR_INVALID_SYNTAX; \
		context_restore_parser(rule); \
		RESTORE_POS(rule); \
		return false; \
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

#define PASSTHRU_RULE_VA(rule_fn, ...) \
	do { \
		DemNode *save_output = r->output; \
		CpDemTypeKind save_tag = node->tag; \
		r->output = node; \
		bool _success = (rule_fn)(p, parent, r, __VA_ARGS__); \
		if ((_success)) { \
			TRACE_RETURN_SUCCESS; \
		} else { \
			if (!save_output && node) { \
				DemNode_deinit(node); \
				DemNode_init(node); \
				node->parent = (DemNode *)parent; \
				node->val.buf = p->cur; \
				node->tag = save_tag; \
			} \
			r->output = save_output; \
			context_restore(rule); \
			break; \
		} \
	} while (0)

#define PASSTHRU_RULE(rule_fn) \
	do { \
		DemNode *save_output = r->output; \
		CpDemTypeKind save_tag = node->tag; \
		r->output = node; \
		bool _success = (rule_fn)(p, parent, r); \
		if ((_success)) { \
			TRACE_RETURN_SUCCESS; \
		} else { \
			if (!save_output && node) { \
				DemNode_deinit(node); \
				DemNode_init(node); \
				node->parent = (DemNode *)parent; \
				node->val.buf = p->cur; \
				node->tag = save_tag; \
			} \
			r->output = save_output; \
			context_restore(rule); \
			break; \
		} \
	} while (0)

// Helper macro to call a rule and append its output as a child
#define CALL_RULE(rule_fn) \
	({ \
		DemResult _child_result = { 0 }; \
		bool _success = (rule_fn)(p, node, &_child_result); \
		if (_success && _child_result.output) { \
			AST_APPEND_NODE(_child_result.output); \
			_child_result.output = NULL; \
		} else { \
			DemResult_deinit(&_child_result); \
		} \
		_success; \
	})

#define CALL_RULE_N_VA(N, rule_fn, ...) \
	({ \
		DemResult _child_result = { 0 }; \
		bool _success = (rule_fn)(p, node, &_child_result, __VA_ARGS__); \
		if (_success && _child_result.output) { \
			N = _child_result.output; \
		} else { \
			DemResult_deinit(&_child_result); \
		} \
		_success; \
	})

#define CALL_RULE_N(N, rule_fn) \
	({ \
		DemResult _child_result = { 0 }; \
		bool _success = (rule_fn)(p, node, &_child_result); \
		if (_success && _child_result.output) { \
			N = _child_result.output; \
		} else { \
			DemResult_deinit(&_child_result); \
		} \
		_success; \
	})

// Helper macro for match_many/match_many1 calls
#define CALL_MATCH_MANY(rule_fn, sep) \
	({ \
		DemResult _child_result = { 0 }; \
		bool _success = match_many(p, node, &_child_result, (rule_fn), (sep)); \
		if (_success && _child_result.output) { \
			AST_APPEND_NODE(_child_result.output); \
		} else { \
			DemResult_deinit(&_child_result); \
		} \
		_success; \
	})

#define CALL_MATCH_MANY1(rule_fn, sep) \
	({ \
		DemResult _child_result = { 0 }; \
		bool _success = match_many1(p, node, &_child_result, (rule_fn), (sep)); \
		if (_success && _child_result.output) { \
			AST_APPEND_NODE(_child_result.output); \
		} else { \
			DemResult_deinit(&_child_result); \
		} \
		_success; \
	})

#define CTX_MUST_MATCH(I, rules) \
	do { \
		if ((rules)) { \
			node->val.len = p->cur - node->val.buf; \
		} else { \
			context_restore(I); \
			r->error = DEM_ERR_INVALID_SYNTAX; \
			TRACE_RETURN_FAILURE(); \
		} \
	} while (0)

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
