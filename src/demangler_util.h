// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef RZ_LIBDEMANGLE_UTIL_H
#define RZ_LIBDEMANGLE_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef int bool;
#define true 1
#define false 0

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#define RZ_NEW0(x) (x *)calloc(1, sizeof(x))
#define RZ_NEW(x)  (x *)malloc(sizeof(x))
#define RZ_FREE(x) \
	{ \
		free((void *)x); \
		x = NULL; \
	}

typedef uint8_t ut8;
typedef uint32_t ut32;

#define IS_UPPER(c)       ((c) >= 'A' && (c) <= 'Z')
#define IS_DIGIT(x)       ((x) >= '0' && (x) <= '9')
#define RZ_MIN(x, y)      (((x) > (y)) ? (y) : (x))
#define RZ_STR_ISEMPTY(x) (!(x) || !*(x))

char *dem_str_ndup(const char *ptr, int len);
char *dem_str_newf(const char *fmt, ...);
char *dem_str_append(char *ptr, const char *string);
void dem_str_replace_char(char *string, size_t size, char ch, char rp);
char *dem_str_replace(char *str, const char *key, const char *val, int g);

typedef struct {
	char *buf;
	size_t len;
} DemString;

void dem_string_free(DemString *ds);
DemString *dem_string_new();
char *dem_string_drain(DemString *ds);
bool dem_string_append(DemString *ds, const char *string);
bool dem_string_append_n(DemString *ds, const char *string, size_t size);
bool dem_string_appendf(DemString *ds, const char *fmt, ...);

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

#endif /* RZ_LIBDEMANGLE_UTIL_H */
