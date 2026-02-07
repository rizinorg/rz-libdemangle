// SPDX-FileCopyrightText: 2025 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef TEST_CXX_CSV_RUNNER_H
#define TEST_CXX_CSV_RUNNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "demangler_util.h"

#ifndef CSV_PATH
#error "CSV_PATH must be defined"
#endif

#ifndef TEST_NAME
#error "TEST_NAME must be defined"
#endif

// Portable getline using DemString (works on MSVC which lacks POSIX getline)
static bool dem_fgetline(DemString *ds, FILE *f) {
	ds->len = 0;
	if (ds->buf) {
		ds->buf[0] = '\0';
	}

	bool got_data = false;
	int c;
	while ((c = fgetc(f)) != EOF) {
		got_data = true;
		char ch = (char)c;
		if (!dem_string_append_n(ds, &ch, 1)) {
			return false;
		}
		if (ch == '\n') {
			break;
		}
	}
	return got_data;
}

// Parse a CSV field in-place starting at *p.
// Handles quoted fields (with "" escape for literal quotes).
// Returns pointer to start of field content within the buffer,
// advances *p past the field and its trailing comma, and null-terminates the field.
// Returns NULL if no field is available.
static char *csv_parse_field(char **p) {
	char *s = *p;
	if (!s || *s == '\0' || *s == '\n' || *s == '\r') {
		return NULL;
	}
	if (*s == '"') {
		// Quoted field: read content between quotes, handle "" escapes in-place
		s++; // skip opening quote
		char *start = s;
		char *dst = s;
		while (*s) {
			if (*s == '"') {
				if (*(s + 1) == '"') {
					// escaped quote
					*dst++ = '"';
					s += 2;
				} else {
					// closing quote
					s++; // skip closing quote
					break;
				}
			} else {
				*dst++ = *s++;
			}
		}
		*dst = '\0';
		// skip trailing comma
		if (*s == ',') {
			s++;
		}
		*p = s;
		return start;
	}
	// Unquoted field
	char *start = s;
	while (*s && *s != ',' && *s != '\n' && *s != '\r') {
		s++;
	}
	if (*s == ',') {
		*s = '\0';
		s++;
	} else {
		// terminate at newline/CR/end
		*s = '\0';
	}
	*p = s;
	return start;
}

static int run_csv_tests(void) {
	FILE *f = fopen(CSV_PATH, "r");
	if (!f) {
		fprintf(stderr, "Failed to open CSV file: %s\n", CSV_PATH);
		return 1;
	}

	DemString ds = { 0 };

	// Skip header
	if (!dem_fgetline(&ds, f)) {
		dem_string_deinit(&ds);
		fclose(f);
		return 1;
	}

	int all_passed = 1;
	size_t test_count = 0;
	size_t line_no = 1; // header was line 1

	while (dem_fgetline(&ds, f)) {
		line_no++;
		if (ds.len == 0 || ds.buf[0] == '\n') {
			continue;
		}

		// Parse CSV fields in-place within ds.buf
		char *cursor = ds.buf;
		char *mangled = csv_parse_field(&cursor);
		if (!mangled || !mangled[0]) {
			continue;
		}

		char *demangled = csv_parse_field(&cursor);
		char *expected = (demangled && demangled[0]) ? demangled : NULL;

		char *result = libdemangle_handler_cxx(mangled, default_opts);
		test_count++;

		int passed = 0;
		if (!expected) {
			passed = (result == NULL);
		} else {
			passed = (result != NULL && strcmp(result, expected) == 0);
		}

		if (!passed) {
			all_passed = 0;
			fprintf(stderr, "FAIL [" TEST_NAME "] line %zu:\n", line_no);
			fprintf(stderr, "  mangled:  %s\n", mangled);
			fprintf(stderr, "  expected: %s\n", expected ? expected : "(null)");
			fprintf(stderr, "  got:      %s\n\n", result ? result : "(null)");
		}

		free(result);
	}

	dem_string_deinit(&ds);
	fclose(f);

	if (all_passed) {
		fprintf(stderr, "PASS [" TEST_NAME "]: %zu tests\n", test_count);
	} else {
		fprintf(stderr, "FAIL [" TEST_NAME "]: some tests failed\n");
	}

	return all_passed ? 0 : 1;
}

int main(void) {
	return run_csv_tests();
}

#endif // TEST_CXX_CSV_RUNNER_H
