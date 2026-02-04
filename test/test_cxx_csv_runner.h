// SPDX-FileCopyrightText: 2025 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef TEST_CXX_CSV_RUNNER_H
#define TEST_CXX_CSV_RUNNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"

#ifndef CSV_PATH
#error "CSV_PATH must be defined"
#endif

#ifndef TEST_NAME
#error "TEST_NAME must be defined"
#endif

typedef struct {
	char *mangled;
	char *demangled;
} test_case_t;

static test_case_t *test_cases = NULL;
static size_t test_count = 0;

// Parse CSV field, handling quoted fields with commas and escaped quotes
static char *read_csv_field(char **line, char *buffer, size_t buffer_size) {
	if (!*line || **line == '\0' || **line == '\n' || **line == '\r') {
		return NULL;
	}

	char *dst = buffer;
	char *src = *line;
	size_t written = 0;
	int in_quotes = 0;

	// Check if field starts with quote
	if (*src == '"') {
		in_quotes = 1;
		src++; // Skip opening quote
	}

	while (*src && written < buffer_size - 1) {
		if (in_quotes) {
			if (*src == '"') {
				// Check for escaped quote (two quotes in a row: "")
				if (*(src + 1) == '"') {
					*dst++ = '"';
					written++;
					src += 2;
				} else {
					// End of quoted field
					src++; // Skip closing quote
					in_quotes = 0;
					// Skip comma after closing quote
					if (*src == ',') {
						src++;
					}
					break;
				}
			} else {
				*dst++ = *src++;
				written++;
			}
		} else {
			if (*src == ',' || *src == '\n' || *src == '\r') {
				if (*src == ',') {
					src++;
				}
				break;
			}
			*dst++ = *src++;
			written++;
		}
	}

	*dst = '\0';
	*line = src;

	return (written > 0 || (dst != buffer)) ? buffer : NULL;
}

static int load_csv_tests(const char *csv_path) {
	FILE *f = fopen(csv_path, "r");
	if (!f) {
		fprintf(stderr, "Failed to open CSV file: %s\n", csv_path);
		return -1;
	}

	size_t capacity = 10000;
	test_cases = calloc(capacity, sizeof(test_case_t));
	if (!test_cases) {
		fclose(f);
		return -1;
	}

	char *line = NULL;
	size_t line_cap = 0;
	ssize_t line_len;
	char field_buffer[8192];

	// Skip header
	if (getline(&line, &line_cap, f) < 0) {
		free(line);
		fclose(f);
		return -1;
	}

	// Read test cases
	test_count = 0;
	while ((line_len = getline(&line, &line_cap, f)) >= 0) {
		if (line_len == 0 || line[0] == '\n') {
			continue;
		}

		// Expand capacity if needed
		if (test_count >= capacity) {
			capacity *= 2;
			test_case_t *new_cases = realloc(test_cases, capacity * sizeof(test_case_t));
			if (!new_cases) {
				free(line);
				fclose(f);
				return -1;
			}
			test_cases = new_cases;
		}

		// Parse CSV line
		char *line_ptr = line;
		char *mangled = read_csv_field(&line_ptr, field_buffer, sizeof(field_buffer));

		if (!mangled) {
			continue;
		}

		test_cases[test_count].mangled = strdup(mangled);

		// Read demangled field (might be empty)
		char *demangled = read_csv_field(&line_ptr, field_buffer, sizeof(field_buffer));
		test_cases[test_count].demangled = (demangled && demangled[0]) ? strdup(demangled) : NULL;

		test_count++;
	}

	free(line);
	fclose(f);
	return 0;
}

static void free_test_cases(void) {
	if (test_cases) {
		for (size_t i = 0; i < test_count; i++) {
			free(test_cases[i].mangled);
			free(test_cases[i].demangled);
		}
		free(test_cases);
		test_cases = NULL;
	}
}

static int run_csv_tests(void) {
	if (load_csv_tests(CSV_PATH) < 0) {
		return 1;
	}

	int all_passed = 1;

	for (size_t i = 0; i < test_count; i++) {
		test_case_t *tc = &test_cases[i];

		char *result = libdemangle_handler_cxx(tc->mangled, default_opts);

		int test_passed = 0;
		if (tc->demangled == NULL) {
			test_passed = (result == NULL);
		} else {
			test_passed = (result != NULL && strcmp(result, tc->demangled) == 0);
		}

		if (!test_passed) {
			all_passed = 0;
			fprintf(stderr, "FAIL [" TEST_NAME "] line %zu:\n", i + 2);
			fprintf(stderr, "  mangled:  %s\n", tc->mangled);
			fprintf(stderr, "  expected: %s\n", tc->demangled ? tc->demangled : "(null)");
			fprintf(stderr, "  got:      %s\n\n", result ? result : "(null)");
		}

		free(result);
	}

	free_test_cases();

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
