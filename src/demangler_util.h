// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef RZ_LIBDEMANGLE_UTIL_H
#define RZ_LIBDEMANGLE_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef int bool;
#define true  1
#define false 0

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#define RZ_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define RZ_NEW0(x)       (x *)calloc(1, sizeof(x))
#define RZ_NEW(x)        (x *)malloc(sizeof(x))
#define RZ_FREE(x) \
	{ \
		free((void *)x); \
		x = NULL; \
	}

typedef uint8_t ut8;
typedef uint16_t ut16;
typedef uint32_t ut32;
typedef uint64_t ut64;

typedef char st8;
typedef short st16;
typedef int st32;
typedef long long st64;

#define UT8_MAX  0xFFu
#define UT16_MAX 0xFFFFu
#define UT32_MAX 0xFFFFFFFFu
#define UT64_MAX 0xFFFFFFFFFFFFFFFFlu

#define IS_UPPER(c)       ((c) >= 'A' && (c) <= 'Z')
#define IS_LOWER(c)       ((c) >= 'a' && (c) <= 'z')
#define IS_DIGIT(x)       ((x) >= '0' && (x) <= '9')
#define IS_HEX_ALPHA(x)   ((x) >= 'a' && (x) <= 'f')
#define IS_HEX(x)         (IS_DIGIT(x) || IS_HEX_ALPHA(x))
#define IS_ALPHA(x)       (IS_UPPER(x) || IS_LOWER(x))
#define IS_PRINTABLE(x)   ((x) >= ' ' && (x) <= '~')
#define RZ_MIN(x, y)      (((x) > (y)) ? (y) : (x))
#define RZ_STR_ISEMPTY(x) (!(x) || !*(x))

#if __WINDOWS__
#define PFMT64x "I64x"
#define PFMT64u "I64u"
#define PFMTSZu "Iu"
#else
#define PFMT64x "llx"
#define PFMT64u "llu"
#define PFMTSZu "zu"
#endif

char *dem_str_ndup(const char *ptr, int len);
char *dem_str_newf(const char *fmt, ...);
char *dem_str_append(char *ptr, const char *string);
void dem_str_replace_char(char *string, size_t size, char ch, char rp);
char *dem_str_replace(char *str, const char *key, const char *val, int g);

typedef struct {
	char *buf;
	size_t len;
	size_t cap;
} DemString;

void dem_string_free(DemString *ds);
void dem_string_deinit(DemString *ds);
DemString *dem_string_new();
DemString *dem_string_new_with_capacity(size_t cap);
DemString *dem_string_init(DemString *ds);
DemString *dem_string_init_clone(DemString *dst, DemString *src);
char *dem_string_drain(DemString *ds);
bool dem_string_append(DemString *ds, const char *string);
bool dem_string_append_prefix_n(DemString *ds, const char *string, size_t size);
bool dem_string_append_n(DemString *ds, const char *string, size_t size);
bool dem_string_appendf(DemString *ds, const char *fmt, ...);
bool dem_string_append_char(DemString *ds, const char ch);
bool dem_string_concat(DemString *dst, DemString *src);
#define dem_string_buffer(d)            (d->buf)
#define dem_string_length(d)            (d->len)
#define dem_string_appends(d, s)        dem_string_append_n(d, s, strlen(s))
#define dem_string_appends_prefix(d, s) dem_string_append_prefix_n(d, s, strlen(s))

void dem_string_replace_char(DemString *ds, char ch, char rp);

typedef void (*DemListFree)(void *ptr);

typedef struct dem_list_iter_t {
	void *data;
	struct dem_list_iter_t *n, *p;
} DemListIter;

typedef struct dem_list_t {
	DemListIter *head;
	DemListIter *tail;
	DemListFree free;
	ut32 length;
	bool sorted;
} DemList;

#define dem_list_foreach_prev(list, it, pos) \
	if (list) \
		for (it = list->tail; it && (pos = it->data, 1); it = it->p)

#define dem_list_head(x) ((x) ? (x)->head : NULL)

DemList *dem_list_newf(DemListFree f);
DemListIter *dem_list_append(DemList *list, void *data);
void dem_list_free(DemList *list);
void *dem_list_get_n(const DemList *list, ut32 n);
ut32 dem_list_length(const DemList *list);
void dem_list_delete(DemList *list, DemListIter *iter);

#endif /* RZ_LIBDEMANGLE_UTIL_H */
