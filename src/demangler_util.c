// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangler_util.h"
#include <stdarg.h>
/* These are mostly copied from rz_util till the util itself is not a side lib */

#define dem_return_val_if_fail(expr, val) \
	do { \
		if (!(expr)) { \
			fprintf(stderr, "%s: assertion '%s' failed (line %d)\n", __FILE__, #expr, __LINE__); \
			return (val); \
		} \
	} while (0)

#define dem_return_if_fail(expr) \
	do { \
		if (!(expr)) { \
			fprintf(stderr, "%s: assertion '%s' failed (line %d)\n", __FILE__, #expr, __LINE__); \
			return; \
		} \
	} while (0)

void dem_str_replace_char(char *string, size_t size, char ch, char rp) {
	for (size_t i = 0; i < size; ++i) {
		if (string[i] == ch) {
			string[i] = rp;
		}
	}
}

char *dem_str_replace(char *str, const char *key, const char *val, int g) {
	dem_return_val_if_fail(str && key && val, NULL);

	int off, i, slen;
	char *newstr, *p = str;
	int klen = strlen(key);
	int vlen = strlen(val);
	slen = strlen(str);
	if (klen == 1 && vlen < 2) {
		dem_str_replace_char(str, slen, *key, *val);
		return str;
	}
	if (klen == vlen && !strcmp(key, val)) {
		return str;
	}
	char *q = str;
	for (;;) {
		p = strstr(q, key);
		if (!p) {
			break;
		}
		off = (int)(size_t)(p - str);
		if (vlen != klen) {
			int tlen = slen - (off + klen);
			slen += vlen - klen;
			if (vlen > klen) {
				newstr = realloc(str, slen + 1);
				if (!newstr) {
					RZ_FREE(str);
					break;
				}
				str = newstr;
			}
			p = str + off;
			memmove(p + vlen, p + klen, tlen + 1);
		}
		memcpy(p, val, vlen);
		i = off + vlen;
		q = str + i;
		if (!g) {
			break;
		}
	}
	return str;
}

char *dem_str_ndup(const char *ptr, int len) {
	if (len < 0) {
		return NULL;
	}
	char *out = malloc(len + 1);
	if (!out) {
		return NULL;
	}
	strncpy(out, ptr, len);
	out[len] = 0;
	return out;
}

char *dem_str_newf(const char *fmt, ...) {
	dem_return_val_if_fail(fmt, NULL);
	va_list ap, ap2;

	va_start(ap, fmt);
	if (!strchr(fmt, '%')) {
		va_end(ap);
		return strdup(fmt);
	}
	va_copy(ap2, ap);
	int ret = vsnprintf(NULL, 0, fmt, ap2);
	ret++;
	char *p = calloc(1, ret);
	if (p) {
		(void)vsnprintf(p, ret, fmt, ap);
	}
	va_end(ap2);
	va_end(ap);
	return p;
}

char *dem_str_append(char *ptr, const char *string) {
	if (string && !ptr) {
		return strdup(string);
	}
	if (RZ_STR_ISEMPTY(string)) {
		return ptr;
	}
	int plen = strlen(ptr);
	int slen = strlen(string);
	char *newptr = realloc(ptr, slen + plen + 1);
	if (!newptr) {
		free(ptr);
		return NULL;
	}
	ptr = newptr;
	memcpy(ptr + plen, string, slen + 1);
	return ptr;
}

void dem_string_free(DemString *ds) {
	if (!ds) {
		return;
	}
	dem_string_deinit(ds);
	free(ds);
}

DemString *dem_string_new_with_capacity(size_t cap) {
	if (cap < 1) {
		return NULL;
	}
	DemString *ds = RZ_NEW0(DemString);
	if (!ds) {
		return NULL;
	}
	ds->buf = malloc(cap);
	if (!ds->buf) {
		free(ds);
		return NULL;
	}
	ds->cap = cap;
	ds->buf[0] = 0;
	return ds;
}

DemString *dem_string_new() {
	return dem_string_new_with_capacity(256);
}

/**
 * Deinitialize given String object. This won't free the
 * given pointer
 *
 * \p ds DemString object to be deinited.
 */
void dem_string_deinit(DemString *ds) {
	if (!ds) {
		return;
	}
	free(ds->buf);
	memset(ds, 0, sizeof(DemString));
}

/**
 * \b Initialize given DemString object. To be used when allocated
 * memory is already available.
 *
 * \p ds DemString object to be initialized.
 *
 * \return ds on success.
 * \return NULL otherwise.
 */
DemString *dem_string_init(DemString *ds) {
	if (!ds) {
		return NULL;
	}

	memset(ds, 0, sizeof(DemString));

	return ds;
}

/**
 * \b Init clone of given src into given dst DemString object.
 *
 * \p dst Destination.
 * \p src Source.
 *
 * \return dst on success.
 * \return NULL otherwise.
 */
DemString *dem_string_init_clone(DemString *dst, DemString *src) {
	if (!dst || !src) {
		return NULL;
	}

	if (src->buf) {
		dst->buf = strdup(src->buf);
		dst->len = strlen(dst->buf);
		dst->cap = dst->len;
	} else {
		dem_string_init(dst);
	}

	return dst;
}

static bool dem_string_has_enough_capacity(DemString *ds, ssize_t size) {
	return size < 1 || ((ds->len + size) < ds->cap);
}

static bool dem_string_increase_capacity(DemString *ds, ssize_t size) {
	if (size < 0) {
		return false;
	} else if (dem_string_has_enough_capacity(ds, size)) {
		return true;
	}
	char *tmp = NULL;
	if (ds->cap < 1) {
		tmp = malloc(size + 1);
	} else {
		tmp = realloc(ds->buf, ds->cap + size + 1);
	}
	if (!tmp) {
		return false;
	}
	ds->cap += size + 1;
	ds->buf = tmp;
	return true;
}

/**
 * This will issue a free call on the provided DemString object.
 * Make sure not to use this on objects that have not been malloc'd
 *
 * \param ds DemString object to drain out to a char* buf.
 *
 * \return char array containing ds contnents.
 */
char *dem_string_drain(DemString *ds) {
	dem_return_val_if_fail(ds, NULL);
	char *ret = ds->buf;
	if ((ds->len + 1) < ds->cap) {
		// optimise memory space.
		ret = realloc(ret, ds->len + 1);
	}
	free(ds);
	return ret;
}

bool dem_string_append(DemString *ds, const char *string) {
	dem_return_val_if_fail(ds && string, false);
	size_t size = strlen(string);
	return dem_string_append_n(ds, string, size);
}

bool dem_string_append_prefix_n(DemString *ds, const char *string, size_t size) {
	dem_return_val_if_fail(ds && string, false);
	if (!size) {
		return true;
	} else if (!dem_string_increase_capacity(ds, size)) {
		return false;
	}
	memmove(ds->buf + size, ds->buf, ds->len);

	memcpy(ds->buf, string, size);
	ds->len += size;
	ds->buf[ds->len] = 0;
	return true;
}

bool dem_string_append_n(DemString *ds, const char *string, size_t size) {
	dem_return_val_if_fail(ds && string, false);
	if (!size) {
		return true;
	} else if (!dem_string_increase_capacity(ds, size)) {
		return false;
	}

	memcpy(ds->buf + ds->len, string, size);
	ds->len += size;
	ds->buf[ds->len] = 0;
	return true;
}

bool dem_string_concat(DemString *dst, DemString *src) {
	dem_return_val_if_fail(dst && src, false);
	if (!src->len) {
		return true;
	} else if (!dem_string_increase_capacity(dst, src->len)) {
		return false;
	}

	memcpy(dst->buf + dst->len, src->buf, src->len);
	dst->len += src->len;
	dst->buf[dst->len] = 0;
	return true;
}

bool dem_string_appendf(DemString *ds, const char *fmt, ...) {
	va_list ap1;
	va_list ap2;
	int size;
	bool res = true;
	dem_return_val_if_fail(ds && fmt, false);

	va_start(ap1, fmt);
	va_copy(ap2, ap1);
	size = vsnprintf(NULL, 0, fmt, ap1);
	if (size < 1) {
		// always success on empty strings
		goto dem_string_appendf_end;
	} else if (!dem_string_increase_capacity(ds, size)) {
		res = false;
		goto dem_string_appendf_end;
	}

	vsnprintf(ds->buf + ds->len, size + 1, fmt, ap2);
	ds->len += size;

dem_string_appendf_end:
	va_end(ap2);
	va_end(ap1);
	return res;
}

bool dem_string_append_char(DemString *ds, const char ch) {
	dem_return_val_if_fail(ds, false);
	if (!IS_PRINTABLE(ch)) {
		// ignore non printable chars.
		return false;
	} else if (!dem_string_increase_capacity(ds, 1)) {
		return false;
	}

	ds->buf[ds->len] = ch;

	ds->len++;
	ds->buf[ds->len] = 0;
	return true;
}

void dem_string_replace_char(DemString *ds, char ch, char rp) {
	if (!ds->buf) {
		return;
	}
	dem_str_replace_char(ds->buf, ds->len, ch, rp);
}

DemList *dem_list_newf(DemListFree f) {
	DemList *l = RZ_NEW0(DemList);
	if (l) {
		l->free = f;
	}
	return l;
}

DemListIter *dem_list_append(DemList *list, void *data) {
	DemListIter *item = NULL;

	dem_return_val_if_fail(list, NULL);

	item = RZ_NEW(DemListIter);
	if (!item) {
		return item;
	}
	if (list->tail) {
		list->tail->n = item;
	}
	item->data = data;
	item->p = list->tail;
	item->n = NULL;
	list->tail = item;
	if (!list->head) {
		list->head = item;
	}
	list->length++;
	list->sorted = false;
	return item;
}

ut32 dem_list_length(const DemList *list) {
	dem_return_val_if_fail(list, 0);
	return list->length;
}

void dem_list_split_iter(DemList *list, DemListIter *iter) {
	dem_return_if_fail(list);

	if (list->head == iter) {
		list->head = iter->n;
	}
	if (list->tail == iter) {
		list->tail = iter->p;
	}
	if (iter->p) {
		iter->p->n = iter->n;
	}
	if (iter->n) {
		iter->n->p = iter->p;
	}
	list->length--;
}

void dem_list_delete(DemList *list, DemListIter *iter) {
	dem_return_if_fail(list && iter);
	dem_list_split_iter(list, iter);
	if (list->free && iter->data) {
		list->free(iter->data);
	}
	iter->data = NULL;
	free(iter);
}

void dem_list_purge(DemList *list) {
	dem_return_if_fail(list);

	DemListIter *it = list->head;
	while (it) {
		DemListIter *next = it->n;
		dem_list_delete(list, it);
		it = next;
	}
	list->length = 0;
	list->head = list->tail = NULL;
}

void dem_list_free(DemList *list) {
	if (list) {
		dem_list_purge(list);
		free(list);
	}
}

void *dem_list_get_n(const DemList *list, ut32 n) {
	DemListIter *it;
	ut32 i;

	dem_return_val_if_fail(list, NULL);

	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			return it->data;
		}
	}
	return NULL;
}
