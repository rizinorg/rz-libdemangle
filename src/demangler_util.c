// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
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
	free(ds->buf);
	free(ds);
}

DemString *dem_string_new() {
	return RZ_NEW0(DemString);
}

static bool dem_string_realloc_no_len_update(DemString *ds, ssize_t size) {
	if (size < 0) {
		return false;
	}
	char *tmp = NULL;
	if (!ds->len) {
		tmp = malloc(size + 1);
	} else {
		tmp = realloc(ds->buf, ds->len + size + 1);
	}
	if (!tmp) {
		return false;
	}
	ds->buf = tmp;
	return true;
}

char *dem_string_drain(DemString *ds) {
	dem_return_val_if_fail(ds, NULL);
	char *ret = ds->buf;
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
	} else if (!dem_string_realloc_no_len_update(ds, size)) {
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
	} else if (!dem_string_realloc_no_len_update(ds, size)) {
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
	} else if (!dem_string_realloc_no_len_update(dst, src->len)) {
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
	} else if (!dem_string_realloc_no_len_update(ds, size)) {
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