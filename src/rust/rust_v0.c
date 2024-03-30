// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file rust_v0.c
 *
 * Demangles symbols that follows the v0 scheme.
 * https://doc.rust-lang.org/rustc/symbol-mangling/v0.html
 *
 * To ensure the generation of these symbols by rustc, add
 * `-C symbol-mangling-version=v0` to the compiler flags.
 */

#include "rust.h"

#define RUST_MAX_RECURSION_LEVEL 512

// import the modified punycode for rust.
char *rust_punycode_to_utf8(const char *encoded, size_t length, size_t *decoded_len);

#define rust_v0_set_error(d) \
	do { \
		d->error = true; \
	} while (0)

#define rust_v0_errored(d) ((d)->error)

#define overflow_check_mul(d, a, b) \
	do { \
		if ((b) && (a) > (UT64_MAX / (b))) { \
			rust_v0_set_error((d)); \
			return 0; \
		} \
	} while (0)

#define overflow_check_add(d, a, b) \
	do { \
		if ((a) > (UT64_MAX - (b))) { \
			rust_v0_set_error((d)); \
			return 0; \
		} \
	} while (0)

#define rust_v0_print(d, s) \
	do { \
		if (d->demangled && !dem_string_appends(d->demangled, s)) { \
			rust_v0_set_error(d); \
		} \
	} while (0)

#define rust_v0_putc(d, c) \
	do { \
		if (d->demangled && !dem_string_append_char(d->demangled, c)) { \
			rust_v0_set_error(d); \
		} \
	} while (0)

#define rust_v0_printf(d, f, ...) \
	do { \
		if (d->demangled && !dem_string_appendf(d->demangled, f, __VA_ARGS__)) { \
			rust_v0_set_error(d); \
		} \
	} while (0)

#define rust_substr_is_empty(rs) ((rs)->size < 1)

typedef struct rust_substr_s {
	const char *token;
	size_t size;
	bool is_puny;
} rust_substr_t;

typedef struct rust_v0_s {
	const char *trail;
	const char *symbol;
	size_t symbol_size;
	size_t recursion_level;
	size_t bound_lifetimes;
	size_t current;
	bool error;
	bool hide_disambiguator;
	DemString *demangled;
} rust_v0_t;

static bool rust_v0_parse_path(rust_v0_t *v0, bool is_type, bool no_trail);
static void rust_v0_parse_type(rust_v0_t *v0);

static bool rust_v0_init(rust_v0_t *v0, const char *symbol, bool hide_disambiguator) {
	// https://doc.rust-lang.org/rustc/symbol-mangling/v0.html#vendor-specific-suffix
	if ((v0->trail = strchr(symbol, '.')) ||
		(v0->trail = strchr(symbol, '$'))) {
		v0->symbol_size = v0->trail - v0->symbol;
	} else {
		v0->symbol_size = strlen(symbol);
	}
	v0->recursion_level = 0;
	v0->bound_lifetimes = 0;
	v0->current = 0;
	v0->error = false;
	v0->symbol = symbol;
	v0->hide_disambiguator = hide_disambiguator;
	v0->demangled = dem_string_new_with_capacity(1024);
	return v0->demangled != NULL;
}

static char *rust_v0_fini(rust_v0_t *v0) {
	if (rust_v0_errored(v0)) {
		dem_string_free(v0->demangled);
		return NULL;
	}

	if (!RZ_STR_ISEMPTY(v0->trail)) {
		dem_string_appendf(v0->demangled, " (%s)", v0->trail);
	}
	return dem_string_drain(v0->demangled);
}

static char rust_v0_look(rust_v0_t *v0) {
	if (rust_v0_errored(v0) || v0->current >= v0->symbol_size) {
		// allow to fail without setting the error flag.
		return 0;
	}

	return v0->symbol[v0->current];
}

static char rust_v0_consume(rust_v0_t *v0) {
	if (rust_v0_errored(v0) || v0->current >= v0->symbol_size) {
		rust_v0_set_error(v0);
		return 0;
	}

	char c = v0->symbol[v0->current];
	v0->current++;
	return c;
}

static char rust_v0_consume_when(rust_v0_t *v0, char expected) {
	if (rust_v0_errored(v0) || v0->current >= v0->symbol_size || v0->symbol[v0->current] != expected) {
		// allow to fail without setting the error flag.
		return false;
	}

	v0->current += 1;
	return true;
}

static bool rust_v0_parse_basic_type(rust_v0_t *v0, char tag) {
	switch (tag) {
	case 'b':
		rust_v0_print(v0, "bool");
		break;
	case 'c':
		rust_v0_print(v0, "char");
		break;
	case 'e':
		rust_v0_print(v0, "str");
		break;
	case 'u': // unit
		rust_v0_print(v0, "()");
		break;
	case 'a':
		rust_v0_print(v0, "i8");
		break;
	case 's':
		rust_v0_print(v0, "i16");
		break;
	case 'l':
		rust_v0_print(v0, "i32");
		break;
	case 'x':
		rust_v0_print(v0, "i64");
		break;
	case 'n':
		rust_v0_print(v0, "i128");
		break;
	case 'i':
		rust_v0_print(v0, "isize");
		break;
	case 'h':
		rust_v0_print(v0, "u8");
		break;
	case 't':
		rust_v0_print(v0, "u16");
		break;
	case 'm':
		rust_v0_print(v0, "u32");
		break;
	case 'y':
		rust_v0_print(v0, "u64");
		break;
	case 'o':
		rust_v0_print(v0, "u128");
		break;
	case 'j':
		rust_v0_print(v0, "usize");
		break;
	case 'k':
		rust_v0_print(v0, "f16");
		break;
	case 'f':
		rust_v0_print(v0, "f32");
		break;
	case 'd':
		rust_v0_print(v0, "f64");
		break;
	case 'q':
		rust_v0_print(v0, "f128");
		break;
	case 'z': // never
		rust_v0_putc(v0, '!');
		break;
	case 'p': // placeholder
		rust_v0_putc(v0, '_');
		break;
	case 'v': // variadic
		rust_v0_print(v0, "...'");
		break;
	default:
		return false;
	}
	return true;
}
static uint64_t rust_v0_parse_base10(rust_v0_t *v0) {
	char digit = rust_v0_look(v0);
	if (!IS_DIGIT(digit)) {
		rust_v0_set_error(v0);
		return 0;
	}

	if (digit == '0') {
		rust_v0_consume(v0);
		return 0;
	}

	uint64_t value = 0;
	while (IS_DIGIT(digit)) {
		rust_v0_consume(v0);

		overflow_check_mul(v0, value, 10);
		value *= 10;

		uint64_t n = digit - '0';
		overflow_check_add(v0, value, n);
		value += n;

		// check next char.
		digit = rust_v0_look(v0);
	}

	return value;
}

static uint64_t rust_v0_parse_base62(rust_v0_t *v0) {
	if (rust_v0_consume_when(v0, '_')) {
		return 0;
	}

	uint64_t value = 0;
	uint64_t n = 0;
	char digit = rust_v0_consume(v0);
	while (digit != '_') {
		if (IS_DIGIT(digit)) {
			n = digit - '0';
		} else if (IS_LOWER(digit)) {
			n = 10 + (digit - 'a');
		} else if (IS_UPPER(digit)) {
			n = 10 + 26 + (digit - 'A');
		} else {
			rust_v0_set_error(v0);
			return 0;
		}

		overflow_check_mul(v0, value, 62);
		value *= 62;

		overflow_check_add(v0, value, n);
		value += n;

		// check next char.
		digit = rust_v0_consume(v0);
	}

	overflow_check_add(v0, value, 1);
	return value + 1;
}

static uint64_t rust_v0_parse_base62_optional(rust_v0_t *v0, char tag) {
	if (!rust_v0_consume_when(v0, tag)) {
		return 0;
	}

	uint64_t n = rust_v0_parse_base62(v0);
	if (rust_v0_errored(v0)) {
		rust_v0_set_error(v0);
		return 0;
	}

	overflow_check_add(v0, n, 1);
	return n + 1;
}

static void rust_v0_print_lifetime(rust_v0_t *v0, uint64_t lifetime) {
	if (!lifetime) {
		rust_v0_print(v0, "'_");
		return;
	} else if (lifetime - 1 >= v0->bound_lifetimes) {
		rust_v0_set_error(v0);
		return;
	}

	uint64_t depth = v0->bound_lifetimes - lifetime;
	rust_v0_putc(v0, '\'');
	if (depth < 26) {
		char ch = 'a' + depth;
		rust_v0_putc(v0, ch);
	} else {
		uint64_t z = depth - 26 + 1;
		rust_v0_printf(v0, "z%" PFMT64u, z);
	}
}

static void rust_v0_parse_binder_optional(rust_v0_t *v0) {
	uint64_t binder = rust_v0_parse_base62_optional(v0, 'G');
	if (rust_v0_errored(v0) || !binder) {
		return;
	} else if (binder >= v0->symbol_size - v0->bound_lifetimes) {
		rust_v0_set_error(v0);
		return;
	}

	rust_v0_print(v0, "for<");
	for (size_t i = 0; i < binder; ++i) {
		if (i > 0) {
			rust_v0_print(v0, ", ");
		}
		v0->bound_lifetimes++;
		rust_v0_print_lifetime(v0, 1);
	}
	rust_v0_print(v0, "> ");
}

static void rust_v0_parse_identifier(rust_v0_t *v0, rust_substr_t *substr) {
	bool is_puny = rust_v0_consume_when(v0, 'u');
	uint64_t size = rust_v0_parse_base10(v0);

	// Underscore resolves the ambiguity when identifier starts with a decimal
	// digit or another underscore.
	rust_v0_consume_when(v0, '_');

	if (rust_v0_errored(v0) || size > (v0->symbol_size - v0->current)) {
		rust_v0_set_error(v0);
		return;
	}

	substr->token = v0->symbol + v0->current;
	substr->size = size;
	substr->is_puny = is_puny;

	v0->current += size;
}

static void rust_v0_print_substr(rust_v0_t *v0, rust_substr_t *substr) {
	if (!v0->demangled) {
		// writing is disabled.
		return;
	}

	if (!substr->is_puny) {
		if (!dem_string_append_n(v0->demangled, substr->token, substr->size)) {
			rust_v0_set_error(v0);
		}
		return;
	}

	// then we add the decoded chars
	size_t utf8_len = 0;
	char *utf8 = rust_punycode_to_utf8(substr->token, substr->size, &utf8_len);
	if (!utf8 || !dem_string_append_n(v0->demangled, utf8, utf8_len)) {
		rust_v0_set_error(v0);
	}
	free(utf8);
}

static void rust_v0_demangleFnSig(rust_v0_t *v0) {
	size_t bound_lifetimes = v0->bound_lifetimes;
	rust_v0_parse_binder_optional(v0);

	if (rust_v0_consume_when(v0, 'U')) {
		rust_v0_print(v0, "unsafe ");
	}
	if (rust_v0_consume_when(v0, 'K')) {
		if (rust_v0_consume_when(v0, 'C')) {
			// extern C
			rust_v0_print(v0, "extern \"C\" ");
		} else {
			// extern other lang.
			rust_v0_print(v0, "extern \"");
			rust_substr_t abi = { 0 };
			rust_v0_parse_identifier(v0, &abi);
			if (rust_v0_errored(v0) || abi.is_puny) {
				rust_v0_set_error(v0);
				return;
			}
			// ABI are ascii only and `-` are replaced with `_` during mangling.
			for (size_t i = 0; i < abi.size; ++i) {
				const char ch = abi.token[i];
				rust_v0_putc(v0, ch == '_' ? '-' : ch);
			}
			rust_v0_print(v0, "\" ");
		}
	}

	rust_v0_print(v0, "fn(");
	for (size_t idx = 0; !v0->error && !rust_v0_consume_when(v0, 'E'); ++idx) {
		if (idx > 0) {
			rust_v0_print(v0, ", ");
		}
		rust_v0_parse_type(v0);
	}
	rust_v0_putc(v0, ')');

	if (!rust_v0_consume_when(v0, 'u')) {
		rust_v0_print(v0, " -> ");
		rust_v0_parse_type(v0);
	}

	// restore bound lifetime.
	v0->bound_lifetimes = bound_lifetimes;
}

static void rust_v0_parse_dynamic_trait(rust_v0_t *v0) {
	bool open = rust_v0_parse_path(v0, true, true);
	while (!v0->error && rust_v0_consume_when(v0, 'p')) {
		if (!open) {
			open = true;
			rust_v0_putc(v0, '<');
		} else {
			rust_v0_print(v0, ", ");
		}
		rust_substr_t name = { 0 };
		rust_v0_parse_identifier(v0, &name);
		if (rust_v0_errored(v0)) {
			return;
		}
		rust_v0_print_substr(v0, &name);
		rust_v0_print(v0, " = ");
		rust_v0_parse_type(v0);
	}
	if (open) {
		rust_v0_putc(v0, '>');
	}
}

static void rust_v0_parse_dynamic_bounds(rust_v0_t *v0) {
	size_t bound_lifetimes = v0->bound_lifetimes;

	rust_v0_print(v0, "dyn ");
	rust_v0_parse_binder_optional(v0);
	for (size_t idx = 0; !v0->error && !rust_v0_consume_when(v0, 'E'); ++idx) {
		if (idx > 0) {
			rust_v0_print(v0, " + ");
		}
		rust_v0_parse_dynamic_trait(v0);
	}
	// restore bound lifetime.
	v0->bound_lifetimes = bound_lifetimes;
}

uint64_t rust_v0_parse_hexadecimals(rust_v0_t *v0, rust_substr_t *hex) {
	size_t start = v0->current;
	uint64_t value = 0;

	char C = rust_v0_look(v0);
	if (!IS_HEX(C)) {
		rust_v0_set_error(v0);
		return 0;
	}

	if (rust_v0_consume_when(v0, '0')) {
		if (!rust_v0_consume_when(v0, '_')) {
			rust_v0_set_error(v0);
			return 0;
		}
	} else {
		while (!v0->error && !rust_v0_consume_when(v0, '_')) {
			C = rust_v0_consume(v0);

			// we allow to overflow, since this is always a best effort.
			value <<= 4;
			if (IS_DIGIT(C)) {
				value += C - '0';
			} else if (IS_HEX_ALPHA(C)) {
				value += 10 + (C - 'a');
			} else {
				rust_v0_set_error(v0);
				return 0;
			}
		}
	}

	if (rust_v0_errored(v0)) {
		return 0;
	}

	size_t end = v0->current - 1;
	hex->token = v0->symbol + start;
	hex->size = end - start;
	hex->is_puny = false;
	return value;
}

static void rust_v0_parse_const_signed(rust_v0_t *v0) {
	if (rust_v0_consume_when(v0, 'n')) {
		// this is there only for signed.
		rust_v0_putc(v0, '-');
	}

	rust_substr_t hex = { 0 };
	uint64_t numeric = rust_v0_parse_hexadecimals(v0, &hex);
	if (rust_v0_errored(v0)) {
		return;
	}

	if (hex.size <= 16) {
		rust_v0_printf(v0, "%" PFMT64u, numeric);
	} else {
		rust_v0_print(v0, "0x");
		rust_v0_print_substr(v0, &hex);
	}
}

static void rust_v0_parse_const_boolean(rust_v0_t *v0) {
	rust_substr_t hex = { 0 };
	uint64_t numeric = rust_v0_parse_hexadecimals(v0, &hex);

	if (rust_v0_errored(v0) || hex.size != 1) {
		rust_v0_set_error(v0);
		return;
	}

	// The numeric value must be a `1` or `0`
	switch (numeric) {
	case 0:
		rust_v0_print(v0, "false");
		break;
	case 1:
		rust_v0_print(v0, "true");
		break;
	default:
		rust_v0_set_error(v0);
		break;
	}
}

static void rust_v0_parse_const_char(rust_v0_t *v0) {
	rust_substr_t hex = { 0 };
	char C = (char)rust_v0_parse_hexadecimals(v0, &hex);

	if (rust_v0_errored(v0) || hex.size > 6) {
		rust_v0_set_error(v0);
		return;
	}

	switch (C) {
	case '\t':
		rust_v0_print(v0, "'\\t'");
		break;
	case '\r':
		rust_v0_print(v0, "'\\r'");
		break;
	case '\n':
		rust_v0_print(v0, "'\\n'");
		break;
	case '\\':
		rust_v0_print(v0, "'\\\\'");
		break;
	case '"':
		rust_v0_print(v0, "'\"'");
		break;
	case '\'':
		rust_v0_print(v0, "'\\''");
		break;
	default:
		if (IS_PRINTABLE(C)) {
			rust_v0_putc(v0, C);
		} else {
			rust_v0_print(v0, "'\\u{");
			rust_v0_print_substr(v0, &hex);
			rust_v0_print(v0, "}'");
		}
		break;
	}
}

static void rust_v0_parse_backref(rust_v0_t *v0, rust_v0_t *copy) {
	uint64_t backref = rust_v0_parse_base62(v0);
	if (rust_v0_errored(v0) || backref >= v0->current) {
		rust_v0_set_error(v0);
		return;
	}

	memcpy(copy, v0, sizeof(rust_v0_t));
	copy->current = backref;
}

static void rust_v0_parse_const(rust_v0_t *v0) {
	if (rust_v0_errored(v0) || v0->recursion_level >= RUST_MAX_RECURSION_LEVEL) {
		rust_v0_set_error(v0);
		return;
	}
	size_t recursion_level = v0->recursion_level;
	v0->recursion_level++;

	char type = rust_v0_consume(v0);
	switch (type) {
	case 'a': // i8
	case 's': // i16
	case 'l': // i32
	case 'x': // i64
	case 'n': // i128
	case 'i': // isize
	case 'h': // u8
	case 't': // u16
	case 'm': // u32
	case 'y': // u64
	case 'o': // u128
	case 'j': // usize
		rust_v0_parse_const_signed(v0);
		break;
	case 'b':
		rust_v0_parse_const_boolean(v0);
		break;
	case 'c':
		rust_v0_parse_const_char(v0);
		break;
	case 'p': // placeholder
		rust_v0_putc(v0, '_');
		break;
	case 'B': {
		rust_v0_t backref;
		rust_v0_parse_backref(v0, &backref);
		if (rust_v0_errored(v0)) {
			return;
		}
		// use the backref
		rust_v0_parse_const(&backref);
		break;
	}
	default:
		rust_v0_set_error(v0);
		break;
	}
	v0->recursion_level = recursion_level;
}

static void rust_v0_parse_type(rust_v0_t *v0) {
	if (rust_v0_errored(v0) || v0->recursion_level >= RUST_MAX_RECURSION_LEVEL) {
		rust_v0_set_error(v0);
		return;
	}

	size_t start = v0->current;
	char type = rust_v0_consume(v0);

	if (rust_v0_parse_basic_type(v0, type)) {
		// the tag was a basic type.
		return;
	}

	size_t recursion_level = v0->recursion_level;
	v0->recursion_level++;
	switch (type) {
	case 'A':
		rust_v0_putc(v0, '[');
		rust_v0_parse_type(v0);
		rust_v0_print(v0, "; ");
		rust_v0_parse_const(v0);
		rust_v0_putc(v0, ']');
		break;
	case 'S':
		rust_v0_putc(v0, '[');
		rust_v0_parse_type(v0);
		rust_v0_putc(v0, ']');
		break;
	case 'T': {
		rust_v0_putc(v0, '(');
		size_t idx = 0;
		for (; !v0->error && !rust_v0_consume_when(v0, 'E'); ++idx) {
			if (idx > 0) {
				rust_v0_print(v0, ", ");
			}
			rust_v0_parse_type(v0);
		}
		if (idx == 1) {
			rust_v0_putc(v0, ',');
		}
		rust_v0_putc(v0, ')');
		break;
	}
	case 'R':
	case 'Q': {
		rust_v0_putc(v0, '&');
		if (rust_v0_consume_when(v0, 'L')) {
			uint64_t lifetime = rust_v0_parse_base62(v0);
			if (lifetime) {
				rust_v0_print_lifetime(v0, lifetime);
				rust_v0_putc(v0, ' ');
			}
		}
		if (type == 'Q') {
			rust_v0_print(v0, "mut ");
		}
		rust_v0_parse_type(v0);
		break;
	}
	case 'P':
		rust_v0_print(v0, "*const ");
		rust_v0_parse_type(v0);
		break;
	case 'O':
		rust_v0_print(v0, "*mut ");
		rust_v0_parse_type(v0);
		break;
	case 'F':
		rust_v0_demangleFnSig(v0);
		break;
	case 'D': {
		rust_v0_parse_dynamic_bounds(v0);
		if (rust_v0_consume_when(v0, 'L')) {
			uint64_t lifetime = rust_v0_parse_base62(v0);
			if (lifetime) {
				rust_v0_print(v0, " + ");
				rust_v0_print_lifetime(v0, lifetime);
			}
		} else {
			rust_v0_set_error(v0);
		}
		break;
	}
	case 'B': {
		rust_v0_t backref;
		rust_v0_parse_backref(v0, &backref);
		if (rust_v0_errored(v0)) {
			return;
		}
		// use backref
		rust_v0_parse_type(&backref);
		break;
	}
	default:
		v0->current = start;
		rust_v0_parse_path(v0, true, false);
		break;
	}
	v0->recursion_level = recursion_level;
}

static void rust_v0_parse_generic_arg(rust_v0_t *v0) {
	if (rust_v0_consume_when(v0, 'L')) {
		uint64_t lifetime = rust_v0_parse_base62(v0);
		rust_v0_print_lifetime(v0, lifetime);
	} else if (rust_v0_consume_when(v0, 'K')) {
		rust_v0_parse_const(v0);
	} else {
		rust_v0_parse_type(v0);
	}
}

static void rust_v0_parse_path_no_print(rust_v0_t *v0, bool is_type) {
	// we disable writing to the output here.
	DemString *output = v0->demangled;
	v0->demangled = NULL;
	rust_v0_parse_base62_optional(v0, 's');
	rust_v0_parse_path(v0, is_type, false);
	v0->demangled = output;
}

static bool rust_v0_parse_path(rust_v0_t *v0, bool is_type, bool no_trail) {
	if (rust_v0_errored(v0) || v0->recursion_level >= RUST_MAX_RECURSION_LEVEL) {
		rust_v0_set_error(v0);
		return false;
	}
	size_t recursion_level = v0->recursion_level;
	v0->recursion_level++;
	bool ret = false;

	char tag = rust_v0_consume(v0);
	switch (tag) {
	case 'C': { // crate root
		rust_substr_t crate = { 0 };
		ut64 disambiguator = rust_v0_parse_base62_optional(v0, 's');
		rust_v0_parse_identifier(v0, &crate);
		if (rust_v0_errored(v0)) {
			goto end;
		}
		rust_v0_print_substr(v0, &crate);
		if (!v0->hide_disambiguator) {
			// https://doc.rust-lang.org/rustc/symbol-mangling/v0.html#path-crate-root
			rust_v0_printf(v0, "[%" PFMT64x "]", disambiguator);
		}
		break;
	}
	case 'M': { // <T> (inherent impl)
		rust_v0_parse_path_no_print(v0, is_type);
		rust_v0_putc(v0, '<');
		rust_v0_parse_type(v0);
		rust_v0_putc(v0, '>');
		break;
	}
	case 'X': { // <T as Trait> (trait impl)
		rust_v0_parse_path_no_print(v0, is_type);
		rust_v0_putc(v0, '<');
		rust_v0_parse_type(v0);
		rust_v0_print(v0, " as ");
		rust_v0_parse_path(v0, true, false);
		rust_v0_putc(v0, '>');
		break;
	}
	case 'Y': { // <T as Trait> (trait definition)
		rust_v0_putc(v0, '<');
		rust_v0_parse_type(v0);
		rust_v0_print(v0, " as ");
		rust_v0_parse_path(v0, true, false);
		rust_v0_putc(v0, '>');
		break;
	}
	case 'N': { // namespace ...::ident (nested path)
		char namespace = rust_v0_consume(v0);
		if (!IS_ALPHA(namespace)) {
			rust_v0_set_error(v0);
			goto end;
		}
		rust_v0_parse_path(v0, is_type, false);
		// https://doc.rust-lang.org/rustc/symbol-mangling/v0.html#disambiguator
		ut64 disambiguator = rust_v0_parse_base62_optional(v0, 's');
		rust_substr_t ident = { 0 };
		rust_v0_parse_identifier(v0, &ident);
		if (rust_v0_errored(v0)) {
			goto end;
		}

		if (IS_UPPER(namespace)) {
			// special namespaces
			rust_v0_print(v0, "::{");
			if (namespace == 'C') {
				rust_v0_print(v0, "closure");
			} else if (namespace == 'S') {
				rust_v0_print(v0, "shim");
			} else {
				rust_v0_putc(v0, namespace);
			}
			if (!rust_substr_is_empty(&ident)) {
				rust_v0_putc(v0, ':');
				rust_v0_print_substr(v0, &ident);
			}
			rust_v0_printf(v0, "#%" PFMT64u "}", disambiguator);
		} else if (!rust_substr_is_empty(&ident)) {
			// internal namespaces.
			rust_v0_print(v0, "::");
			rust_v0_print_substr(v0, &ident);
		}
		break;
	}
	case 'I': { // ...<T, U> (generic args)
		rust_v0_parse_path(v0, is_type, false);
		if (!is_type) {
			rust_v0_print(v0, "::");
		}
		rust_v0_putc(v0, '<');
		for (size_t idx = 0; !v0->error && !rust_v0_consume_when(v0, 'E'); ++idx) {
			if (idx > 0) {
				rust_v0_print(v0, ", ");
			}
			rust_v0_parse_generic_arg(v0);
		}
		if (no_trail) {
			ret = true;
			goto end;
		}
		rust_v0_putc(v0, '>');
		break;
	}
	case 'B': { // backref
		rust_v0_t backref;
		rust_v0_parse_backref(v0, &backref);
		if (rust_v0_errored(v0)) {
			goto end;
		}
		// use the backref
		ret = rust_v0_parse_path(&backref, is_type, no_trail);
		break;
	}
	default:
		rust_v0_set_error(v0);
		break;
	}

end:
	v0->recursion_level = recursion_level;
	return ret;
}

/**
 * \brief      Demangles rust v0 mangled strings.
 *
 * \param[in]  sym   The mangled symbol
 *
 * \return     On success a valid pointer is returned, otherwise NULL.
 */
char *rust_demangle_v0(const char *sym, bool simplify) {
	if (!sym || *sym != '_') {
		return false;
	}

	while (*sym == '_') {
		// skip underscores.
		sym++;
	}

	rust_v0_t v0 = { 0 };
	// rust v0 symbols always starts with `_R`
	if (sym[0] != 'R' || !rust_v0_init(&v0, sym + 1, simplify)) {
		return NULL;
	}

	rust_v0_parse_path(&v0, false, false);

	return rust_v0_fini(&v0);
}
