// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CPDEM_COMMON_H
#define CPDEM_COMMON_H

#include "cplusplus/demangle.h"
#include "cplusplus/v2/param.h"
#include "cplusplus/vec.h"
#include "demangler_util.h"

/**
 * \b String iterator
 **/
typedef struct StrIter {
	const char *beg; /**< \b Beginning position of string. */
	const char *end; /**< \b Ending of string (usually points to the null-terminator char). */
	const char *cur; /**< \b Current read position. */
} StrIter;

VecIMPL(DemString, dem_string_deinit);
typedef VecT(DemString) ClassNameVec;

typedef struct {
	StrIter original;
	CpDemOptions opts; // TODO: use options to simplify output while demangling

	ClassNameVec qualifiers;
	DemString base_name; // Used to identify base type in list of function params
	ParamVec func_params; // Names of all function params
	bool has_params; // There are cases where control never reaches `cpdem_func_params`

	DemString suffix; // anything that is to be put at the very end of demangled output
	DemString prefix; // a return type, or another keyword to be put before name
	DemString custom_operator; // A special case of operator "__op<L><TYPE>"

	bool has_global_name; /* __vt or _GLOBAL$I/D$, etc... */
	bool is_ctor;
	bool is_dtor;
	ut8 operator_type; // 0 if not an operator, otherwise a positive value
} CpDem;

CpDem *cpdem_init(CpDem *dem, const char *mangled, CpDemOptions opts);
void cpdem_fini(CpDem *dem);

/**
 * \b Give current read position.
 *
 * \return const char pointer to current read position.
 */
#define CUR() (dem->original.cur)

/**
 * \b Give position where string begins.
 *
 * \return const char pointer to beginning of mangled string.
 */
#define BEG() (dem->original.beg)

/**
 * \b Give position of NULL terminator.
 *
 * \return const char pointer to end of mangled string.
 */
#define END() (dem->original.end)

#define REMAIN_SIZE() (size_t)(END() - CUR())

/**
 * \b Check whether the provided position is in range of readable address.
 *
 * \p read_pos : char pointer to check for range.
 *
 * \return 1 if in range.
 * \return 0 otherwise.
 */
#define IN_RANGE(read_pos) ((read_pos) >= BEG() && (read_pos) < END())

/**
 * \b Seek to given read position if it's in range. This will change the current
 * read position to given target_read_pos.
 *
 * \p target_read_pos : char pointer specifying the target read position to seek to.
 *
 * \return target_read_pos on success.
 * \return CUR() otherwise.
 */
#define SEEK_TO(target_read_pos) \
	(dem->original.cur = IN_RANGE(target_read_pos) ? (target_read_pos) : CUR())

/**
 * Peek one character from current read position in demangling context.
 * This will NOT advance, unlike READ().
 *
 * \return char on success.
 * \return 0 if no more characters left
 */
#define PEEK() (IN_RANGE(CUR()) ? *dem->original.cur : 0)

/**
 * \b Read one character from current read position in demangling context
 * and then advance by one position.
 *
 * \return char on success.
 * \return 0 if no more characters left
 */
#define READ(ch) (IN_RANGE(CUR()) ? ((*dem->original.cur == ch) ? (ADV(), 1) : 0) : 0)

/**
 * \b Advance current read position by one character, if this next
 * position is in range, otherwise stay at current read position.
 *
 * \return updated read position on success.
 * \return NULL otherwise.
 */
#define ADV() (IN_RANGE(CUR() + 1) ? dem->original.cur++ : NULL)

/**
 * \b Advance current read position by "n" characters, if this next
 * position is in range, otherwise stay at current read position.
 *
 * \return updated read position on success.
 * \return NULL otherwise.
 */
#define ADV_BY(n) (IN_RANGE(CUR() + n) ? (dem->original.cur = dem->original.cur + (n)) : NULL)

/**
 * \b Save current read position in demangling context to restore it later.
 * This is used when we know that while matching a rule we might fail, and we'll
 * need to backtrack. For this we must remember the initial trial start pos.
 */
#define SAVE_POS() const char *_____trial_start_pos = CUR();

/**
 * \b Restore saved position
 */
#define RESTORE_POS() \
	do { \
		SEEK_TO(_____trial_start_pos); \
	} while (0)

/**
 * Reads a number from current demangling position to provided "var" variable.
 * Automatically will adjust next read position if numbe read is successful, otherwise, will
 * set var to -1
 */
#define READ_NUMBER(var) \
	do { \
		char *end = NULL; \
		(var) = strtoll(CUR(), &end, 10); \
		if (!end) { \
			(var) = -1; \
			break; \
		} \
		SEEK_TO(end); \
	} while (0)

static inline bool parse_string(CpDem *dem, const char *s) {
	if (!dem || !s) {
		return false;
	}
	size_t s_sz = strlen(s);
	bool read_success = REMAIN_SIZE() >= s_sz && strncmp(CUR(), s, s_sz) == 0;
	if (read_success) {
		CUR() += s_sz;
	}
	return read_success;
}

#endif // CPDEM_COMMON_H
