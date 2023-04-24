// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangler_util.h"
#include <rz_libdemangle.h>
#include <ctype.h>

#define IS_NAME(x) (IS_LOWER(x) || IS_DIGIT(x) || (x) == '_')

static char *demangle_free_pascal_function(DemString *ds, char *mangled, size_t mangled_len) {
	char *next = mangled;
	char *end = mangled + mangled_len;
	char *tmp = strchr(next, '$');

	// <func_name>$<type0$type1>$$<ret_type>
	dem_string_append_n(ds, next, tmp - next);
	dem_string_appends(ds, "(");
	next = tmp + strlen("$");
	size_t n_arg = 0;

	while (next < end && *next != '$' && (tmp = strchr(next, '$')) && tmp > next && IS_NAME(tmp[-1])) {
		// <type0$type1>$$<ret_type>
		if (n_arg > 0) {
			dem_string_appends(ds, ",");
		}
		dem_string_append_n(ds, next, tmp - next);
		next = tmp + strlen("$");
		n_arg++;
	}

	if (next < end && (tmp = strchr(next, '$'))) {
		dem_string_appends(ds, ")");
		// $$<ret_type>
		next = tmp + strlen("$");
		if (next < end) {
			dem_string_append_n(ds, next, end - next);
			next = end;
		}
	} else {
		if (next < end) {
			// <type0> (sometimes it may not have a return type just args.)
			if (n_arg > 0) {
				dem_string_appends(ds, ",");
			}
			dem_string_append_n(ds, next, end - next);
		}
		dem_string_appends(ds, ")");
		next = end;
	}

	return next;
}

static void demangle_free_pascal_unit(DemString *ds, char *mangled, size_t mangled_len) {
	dem_string_appends(ds, "unit ");

	char *end = mangled + mangled_len;
	char *tmp = strstr(mangled, "_$");

	if (tmp && tmp < end) {
		dem_string_append_n(ds, mangled, tmp - mangled);
		dem_string_appends(ds, ".");
		mangled = tmp + strlen("_$");
		if ((tmp = strstr(mangled, "_$$_")) && tmp < end) {
			// <unit>_$$_<sub0>_$_<sub1>_$_..
			dem_string_append_n(ds, mangled, tmp - mangled);
			mangled = tmp + strlen("_$$_");
			while (mangled < end && (tmp = strstr(mangled, "_$_")) && tmp > mangled && tmp < end) {
				// <sub0>_$_<sub1>_$_..
				dem_string_appends(ds, ".");
				dem_string_append_n(ds, mangled, tmp - mangled);
				mangled = tmp + strlen("_$_");
			}
			if (mangled < end) {
				dem_string_appends(ds, ".");
				dem_string_append_n(ds, mangled, end - mangled);
			}
		} else {
			dem_string_append_n(ds, mangled, end - mangled);
		}
	} else {
		dem_string_append_n(ds, mangled, mangled_len);
	}

	dem_string_appends(ds, " ");
}

/**
 * \brief      Demangles freepascal 2.6.x to 3.2.x symbols
 *
 * \param      mangled      The mangled string
 * \param[in]  mangled_len  The mangled string length
 *
 * \return     Demangled string on success otherwise NULL
 */
static char *demangle_free_pascal(char *mangled, size_t mangled_len) {
	char *tmp = NULL;
	char *next = mangled;
	char *end = mangled + mangled_len;
	DemString *ds = NULL;
	bool unit = false;

	for (size_t i = 0; i < mangled_len; ++i) {
		char ch = tolower(mangled[i]);
		if (!IS_LOWER(ch) && !IS_DIGIT(ch) && ch != '_' && ch != '$') {
			goto demangle_fail;
		}
		mangled[i] = ch;
	}

	ds = dem_string_new();
	if (!ds) {
		goto demangle_fail;
	}

	if (next < end && (tmp = strstr(next, "$_$")) && tmp > next && IS_NAME(tmp[-1])) {
		// <unit>$_$<object>_$_<unit1>_$$_<func_name>$<type0$type1>$$<ret_type>
		demangle_free_pascal_unit(ds, next, tmp - next);
		unit = true;
		next = tmp + strlen("$_$");
		while ((tmp = strstr(next, "_$_")) && tmp > next && IS_NAME(tmp[-1])) {
			dem_string_append_n(ds, next, tmp - next);
			dem_string_appends(ds, ".");
			next = tmp + strlen("_$_");
		}
		if ((tmp = strstr(next, "_$$_")) && tmp == next) {
			// often <unit1> is empty, thus we can skip it.
			next += strlen("_$$_");
		}
	}

	if (next < end && (tmp = strstr(next, "_$$_")) && tmp > next && IS_NAME(tmp[-1])) {
		// <unit1>_$$_<func_name>$<type0$type1>$$<ret_type>
		if (!unit) {
			demangle_free_pascal_unit(ds, next, tmp - next);
		} else {
			demangle_free_pascal_function(ds, next, tmp - next);
			dem_string_appends(ds, "::");
		}
		next = tmp + strlen("_$$_");
	}

	if (next < end && (tmp = strchr(next, '$')) && tmp > next && IS_NAME(tmp[-1])) {
		next = demangle_free_pascal_function(ds, next, end - next);
	} else {
		// <func_name>
		dem_string_append(ds, next);
		dem_string_appends(ds, "()");
	}

	if (ds->len < 1) {
		goto demangle_fail;
	}

	free(mangled);
	return dem_string_drain(ds);

demangle_fail:
	dem_string_free(ds);
	free(mangled);
	return NULL;
}

/**
 * \brief Demangles pascal symbols
 *
 * Demangles pascal symbols
 */
RZ_API char *libdemangle_handler_pascal(const char *mangled) {
	if (!mangled || !strchr(mangled, '$')) {
		return NULL;
	}

	size_t length = strlen(mangled);
	if (length < 1) {
		return NULL;
	}

	char *copy = strdup(mangled);
	if (!copy) {
		return NULL;
	}

	return demangle_free_pascal(copy, length);
}
