// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangler_util.h"
#include <rz_libdemangle.h>
#include <stdarg.h>

#define ERR(ctx, ret) \
	do { \
		(ctx)->err = true; \
		return (ret); \
	} while (0)

typedef struct DDemangleContext_t {
	DemString *demangled;
	DemString *attr;
	size_t curr;
	bool in_template_arg;
	bool err;
} DDemangleContext;

typedef struct DDemangleCtxRef_t {
	size_t len;
	size_t attr_len;
	size_t curr;
	bool err;
} DDemangleCtxRef;

typedef enum {
	TYPE_CTOR_NONE = 0,
	TYPE_CTOR_CONST = 1 << 1,
	TYPE_CTOR_IMMUTABLE = 1 << 2,
	TYPE_CTOR_SHARED = 1 << 3,
	TYPE_CTOR_INOUT = 1 << 4
} TypeCtor;

typedef enum {
	FUNC_ATTR_NONE = 0,
	FUNC_ATTR_PURE = 1 << 1,
	FUNC_ATTR_NOTHROW = 1 << 2,
	FUNC_ATTR_REF = 1 << 3,
	FUNC_ATTR_PROPERTY = 1 << 4,
	FUNC_ATTR_TRUSTED = 1 << 5,
	FUNC_ATTR_SAFE = 1 << 6,
	FUNC_ATTR_NOGC = 1 << 7,
	FUNC_ATTR_RETURN = 1 << 8,
	FUNC_ATTR_SCOPE = 1 << 9,
	FUNC_ATTR_LIVE = 1 << 10,
	FUNC_ATTR_RETURN_SCOPE = 1 << 11,
	FUNC_ATTR_SCOPE_RETURN = 1 << 12
} FuncAttributes;

static bool parseTypeImpl(const char *mangled, DDemangleContext *ctx);
static bool parseValueImpl(const char *mangled, DDemangleContext *ctx, const char *type_name, char type_char);
static bool parseTemplateArgImpl(const char *mangled, DDemangleContext *ctx);
static bool parseQualifiedName(const char *mangled, DDemangleContext *ctx);
static bool parseSymbolName(const char *mangled, DDemangleContext *ctx);

static DDemangleCtxRef createCtxRef(DDemangleContext *ctx) {
	DDemangleCtxRef ref = {
		.len = 0,
		.attr_len = 0,
		.curr = 0,
		.err = false
	};
	if (!ctx) {
		return ref;
	}
	ref.curr = ctx->curr;
	ref.err = ctx->err;
	if (ctx->demangled) {
		ref.len = ctx->demangled->len;
	}
	if (ctx->attr) {
		ref.attr_len = ctx->attr->len;
	}
	return ref;
}

static void ctxRestore(DDemangleContext *ctx, DDemangleCtxRef ref) {
	if (!ctx) {
		return;
	}
	ctx->curr = ref.curr;
	ctx->err = ref.err;

	if (ctx->demangled) {
		ctx->demangled->len = ref.len;
		if (ctx->demangled->buf) {
			ctx->demangled->buf[ref.len] = '\0';
		}
	}

	if (ctx->attr) {
		ctx->attr->len = ref.attr_len;
		if (ctx->attr->buf) {
			ctx->attr->buf[ref.attr_len] = '\0';
		}
	}
}

static char lookAhead(const char *mangled, DDemangleContext *ctx, size_t n) {
	if (!mangled || !ctx || ctx->curr + n > strlen(mangled)) {
		return '\0';
	}

	return mangled[ctx->curr + n];
}

static char consumeN(const char *mangled, DDemangleContext *ctx, size_t n) {
	if (!mangled || !ctx || ctx->curr + n > strlen(mangled)) {
		return '\0';
	}

	char ret = mangled[ctx->curr];
	ctx->curr += n;
	return ret;
}

static char consume(const char *mangled, DDemangleContext *ctx) {
	return consumeN(mangled, ctx, 1);
}

static bool consumeIf(const char *mangled, DDemangleContext *ctx, char expected) {
	if (!mangled || !ctx) {
		return false;
	}

	if (lookAhead(mangled, ctx, 0) == expected) {
		ctx->curr++;
		return true;
	}

	return false;
}

static bool consumeWhile(const char *mangled, DDemangleContext *ctx, char expected) {
	if (!mangled || !ctx) {
		return false;
	}

	bool consumed = false;
	while (lookAhead(mangled, ctx, 0) == expected) {
		ctx->curr++;
		consumed = true;
	}

	return consumed;
}

static size_t consumeDigits(const char *mangled, DDemangleContext *ctx) {
	size_t ret = 0;
	if (!mangled || !ctx) {
		return 0;
	}

	while (IS_DIGIT(lookAhead(mangled, ctx, 0))) {
		size_t digit = (size_t)(lookAhead(mangled, ctx, 0) - '0');
		if (ret > (SIZE_MAX - digit) / 10) {
			ERR(ctx, 0);
		}
		ret = ret * 10 + digit;
		ctx->curr++;
	}

	return ret;
}

static char consumeHexDigit(const char *mangled, DDemangleContext *ctx) {
	char ret = 0;
	if (!mangled || !ctx) {
		return 0;
	}

	char c = lookAhead(mangled, ctx, 0);
	if (IS_HEX(c)) {
		ret = c;
	} else {
		return 0;
	}

	ctx->curr++;
	return ret;
}

static bool demangleAppend(DDemangleContext *ctx, const char *fmt, ...) {
	if (!ctx || !fmt || ctx->err || !ctx->demangled) {
		return false;
	}

	va_list args;
	va_start(args, fmt);
	bool res = dem_string_appendv(ctx->demangled, fmt, args);
	va_end(args);
	if (!res) {
		ERR(ctx, false);
	}
	return res;
}

static bool isCallConvention(char c) {
	switch (c) {
	case 'F':
	case 'U':
	case 'W':
	case 'R':
	case 'Y':
		return true;
	default:
		return false;
	}
}

static TypeCtor parseModifier(const char *mangled, DDemangleContext *ctx) {
	TypeCtor res = TYPE_CTOR_NONE;
	switch (lookAhead(mangled, ctx, 0)) {
	case 'y':
		consume(mangled, ctx);
		return TYPE_CTOR_IMMUTABLE;
	case 'O':
		consume(mangled, ctx);
		res |= TYPE_CTOR_SHARED;
		switch (lookAhead(mangled, ctx, 0)) {
		case 'x':
			consume(mangled, ctx);
			res |= TYPE_CTOR_CONST;
			break;
		case 'N':
			if (lookAhead(mangled, ctx, 1) == 'g') {
				consumeN(mangled, ctx, 2);
				res |= TYPE_CTOR_INOUT;
				if (lookAhead(mangled, ctx, 0) == 'x') {
					consume(mangled, ctx);
					res |= TYPE_CTOR_CONST;
				}
			}
			break;
		default:
			break;
		}
		return res;
	case 'N':
		if (lookAhead(mangled, ctx, 1) == 'g') {
			consumeN(mangled, ctx, 2);
			res |= TYPE_CTOR_INOUT;
			if (lookAhead(mangled, ctx, 0) == 'x') {
				consume(mangled, ctx);
				res |= TYPE_CTOR_CONST;
			}
		}
		return res;
	case 'x':
		consume(mangled, ctx);
		res |= TYPE_CTOR_CONST;
		return res;
	default:
		return res;
	}
}

static FuncAttributes parseFuncAttrs(const char *mangled, DDemangleContext *ctx) {
	FuncAttributes result = FUNC_ATTR_NONE;
	while (lookAhead(mangled, ctx, 0) == 'N') {
		switch (lookAhead(mangled, ctx, 1)) {
		case 'a':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_PURE;
			continue;
		case 'b':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_NOTHROW;
			continue;
		case 'c':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_REF;
			continue;
		case 'd':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_PROPERTY;
			continue;
		case 'e':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_TRUSTED;
			continue;
		case 'f':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_SAFE;
			continue;
		case 'g':
		case 'h':
		case 'k':
		case 'n':
			return result;
		case 'i':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_NOGC;
			continue;
		case 'j':
			consumeN(mangled, ctx, 2);
			if (lookAhead(mangled, ctx, 0) == 'N' && lookAhead(mangled, ctx, 1) == 'l') {
				result |= FUNC_ATTR_RETURN_SCOPE;
				consumeN(mangled, ctx, 2);
			} else {
				result |= FUNC_ATTR_RETURN;
			}
			continue;
		case 'l':
			consumeN(mangled, ctx, 2);
			if (lookAhead(mangled, ctx, 0) == 'N' && lookAhead(mangled, ctx, 1) == 'j') {
				result |= FUNC_ATTR_SCOPE_RETURN;
				consumeN(mangled, ctx, 2);
			} else {
				result |= FUNC_ATTR_SCOPE;
			}
			continue;
		case 'm':
			consumeN(mangled, ctx, 2);
			result |= FUNC_ATTR_LIVE;
			continue;
		default:
			ctx->err = true;
			return FUNC_ATTR_NONE;
		}
	}
	return result;
}

static void writeModifiers(TypeCtor modifiers, DemString *dest) {
	if ((modifiers & TYPE_CTOR_IMMUTABLE) == TYPE_CTOR_IMMUTABLE) {
		dem_string_appendf(dest, "immutable ");
	}
	if ((modifiers & TYPE_CTOR_SHARED) == TYPE_CTOR_SHARED) {
		dem_string_appendf(dest, "shared ");
	}
	if ((modifiers & TYPE_CTOR_INOUT) == TYPE_CTOR_INOUT) {
		dem_string_appendf(dest, "inout ");
	}
	if ((modifiers & TYPE_CTOR_CONST) == TYPE_CTOR_CONST) {
		dem_string_appendf(dest, "const ");
	}
}

static void writeFuncAttrs(FuncAttributes attrs, DemString *dest) {
	if ((attrs & FUNC_ATTR_PURE) == FUNC_ATTR_PURE) {
		dem_string_appendf(dest, "pure ");
	}
	if ((attrs & FUNC_ATTR_NOTHROW) == FUNC_ATTR_NOTHROW) {
		dem_string_appendf(dest, "nothrow ");
	}
	if ((attrs & FUNC_ATTR_REF) == FUNC_ATTR_REF) {
		dem_string_appendf(dest, "ref ");
	}
	if ((attrs & FUNC_ATTR_PROPERTY) == FUNC_ATTR_PROPERTY) {
		dem_string_appendf(dest, "@property ");
	}
	if ((attrs & FUNC_ATTR_NOGC) == FUNC_ATTR_NOGC) {
		dem_string_appendf(dest, "@nogc ");
	}
	if ((attrs & FUNC_ATTR_RETURN_SCOPE) == FUNC_ATTR_RETURN_SCOPE) {
		dem_string_appendf(dest, "return scope ");
	}
	if ((attrs & FUNC_ATTR_SCOPE_RETURN) == FUNC_ATTR_SCOPE_RETURN) {
		dem_string_appendf(dest, "scope return ");
	}
	if ((attrs & FUNC_ATTR_RETURN) == FUNC_ATTR_RETURN) {
		dem_string_appendf(dest, "return ");
	}
	if ((attrs & FUNC_ATTR_SCOPE) == FUNC_ATTR_SCOPE) {
		dem_string_appendf(dest, "scope ");
	}
	if ((attrs & FUNC_ATTR_LIVE) == FUNC_ATTR_LIVE) {
		dem_string_appendf(dest, "@live ");
	}
	if ((attrs & FUNC_ATTR_TRUSTED) == FUNC_ATTR_TRUSTED) {
		dem_string_appendf(dest, "@trusted ");
	}
	if ((attrs & FUNC_ATTR_SAFE) == FUNC_ATTR_SAFE) {
		dem_string_appendf(dest, "@safe ");
	}
}

static bool parseType(const char *mangled, DDemangleContext *ctx) {
	DemString *saved_attr = ctx->attr;
	ctx->attr = dem_string_new();
	bool res = parseTypeImpl(mangled, ctx);
	dem_string_free(ctx->attr);
	ctx->attr = saved_attr;
	return res;
}

static bool parseValue(const char *mangled, DDemangleContext *ctx, const char *type_name, char type_char) {
	DemString *saved_attr = ctx->attr;
	ctx->attr = dem_string_new();
	bool res = parseValueImpl(mangled, ctx, type_name, type_char);
	dem_string_free(ctx->attr);
	ctx->attr = saved_attr;
	return res;
}

static bool parseTemplateArg(const char *mangled, DDemangleContext *ctx) {
	DemString *saved_attr = ctx->attr;
	ctx->attr = dem_string_new();
	bool res = parseTemplateArgImpl(mangled, ctx);
	dem_string_free(ctx->attr);
	ctx->attr = saved_attr;
	return res;
}

static size_t parseBackRef(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return 0;
	}

	if (lookAhead(mangled, ctx, 0) != 'Q') {
		ctx->err = true;
		return 0;
	}

	size_t q = ctx->curr;
	size_t pos = 0;
	consume(mangled, ctx);
	while (1) {
		char c = lookAhead(mangled, ctx, 0);
		if (IS_UPPER(c)) {
			pos = pos * 26 + (c - 'A');
			consume(mangled, ctx);
		} else if (IS_LOWER(c)) {
			pos = pos * 26 + (c - 'a');
			consume(mangled, ctx);
			break;
		} else {
			break;
		}
	}
	if (pos == 0 || pos > q) {
		ERR(ctx, 0);
	}
	return q - pos;
}

static bool expandBackRefType(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	size_t pos = parseBackRef(mangled, ctx);
	if (ctx->err || pos >= ctx->curr) {
		return false;
	}

	size_t saved_curr = ctx->curr;
	ctx->curr = pos;
	bool res = parseType(mangled, ctx);
	ctx->curr = saved_curr;
	return res;
}

static bool expandBackRefSymbol(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	size_t pos = parseBackRef(mangled, ctx);
	if (ctx->err || pos >= ctx->curr) {
		return false;
	}

	size_t ref_curr = ctx->curr;
	ctx->curr = pos;
	bool res = parseSymbolName(mangled, ctx);
	ctx->curr = ref_curr;
	return res;
}

static bool parseNameStart(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	if (lookAhead(mangled, ctx, 0) == '_' || IS_ALPHA(lookAhead(mangled, ctx, 0))) {
		consume(mangled, ctx);
	} else {
		return false;
	}

	return true;
}

static bool parseNameChar(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}
	if (IS_DIGIT(lookAhead(mangled, ctx, 0)) || lookAhead(mangled, ctx, 0) == '_' || IS_ALPHA(lookAhead(mangled, ctx, 0))) {
		consume(mangled, ctx);
		return true;
	}
	return false;
}

static bool parseName(const char *mangled, DDemangleContext *ctx, size_t len) {
	if (!mangled || !ctx || ctx->err || len == 0) {
		return false;
	}

	if (!parseNameStart(mangled, ctx)) {
		return false;
	}

	while (len > 1) {
		if (!parseNameChar(mangled, ctx)) {
			return false;
		}
		len--;
	}
	return true;
}

static bool parseLName(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	size_t len = consumeDigits(mangled, ctx);
	if (len == 0) {
		demangleAppend(ctx, "__anonymous");
		return true;
	}

	if (lookAhead(mangled, ctx, 0) == '_' && lookAhead(mangled, ctx, 1) == '_' && lookAhead(mangled, ctx, 2) == 'S') {
		consumeN(mangled, ctx, 3);
		consumeDigits(mangled, ctx);
	} else {
		size_t start = ctx->curr;
		if (!parseName(mangled, ctx, len)) {
			ERR(ctx, false);
		}
		if (len + start <= strlen(mangled)) {
			demangleAppend(ctx, "%.*s", (int)len, mangled + start);
		}
	}
	return true;
}

static bool parseTemplateID(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	if (lookAhead(mangled, ctx, 0) == '_' && lookAhead(mangled, ctx, 1) == '_') {
		switch (lookAhead(mangled, ctx, 2)) {
		case 'T':
		case 'U':
			consumeN(mangled, ctx, 3);
			return true;
		default:
			ERR(ctx, false);
		}
	} else if (lookAhead(mangled, ctx, 0) == 'T' || lookAhead(mangled, ctx, 0) == 'U') {
		consume(mangled, ctx);
		return true;
	}

	ERR(ctx, false);
}

static bool parseMangledName(const char *mangled, DDemangleContext *ctx, bool displayType) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	DDemangleCtxRef ref = createCtxRef(ctx);
	if (lookAhead(mangled, ctx, 0) == '_' && lookAhead(mangled, ctx, 1) == 'D') {
		consumeN(mangled, ctx, 2);
		DemString *original = ctx->demangled;
		DemString *qual_name = dem_string_new();
		ctx->demangled = qual_name;
		if (!parseQualifiedName(mangled, ctx)) {
			ctx->demangled = original;
			dem_string_free(qual_name);
			ctxRestore(ctx, ref);
			return false;
		}

		DemString *type_str = dem_string_new();
		ctx->demangled = type_str;
		if (lookAhead(mangled, ctx, 0) == 'M') {
			consume(mangled, ctx);
		}

		if (lookAhead(mangled, ctx, 0) != '\0' && !consumeIf(mangled, ctx, 'Z') && !parseType(mangled, ctx)) {
			ctx->demangled = original;
			dem_string_free(qual_name);
			dem_string_free(type_str);
			ctxRestore(ctx, ref);
			return false;
		}

		ctx->demangled = original;
		if (displayType) {
			if (ctx->attr->len > 0) {
				dem_string_concat(ctx->demangled, ctx->attr);
			}
			dem_string_concat(ctx->demangled, type_str);
			if (type_str->len > 0 && type_str->buf[type_str->len - 1] != ' ') {
				demangleAppend(ctx, " ");
			}
		}

		dem_string_concat(ctx->demangled, qual_name);
		dem_string_free(type_str);
		dem_string_free(qual_name);
	} else {
		ERR(ctx, false);
	}
	return true;
}

static bool parseHexFloat(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	if (lookAhead(mangled, ctx, 0) == 'N' && lookAhead(mangled, ctx, 1) == 'A' && lookAhead(mangled, ctx, 2) == 'N') {
		consumeN(mangled, ctx, 3);
		return demangleAppend(ctx, "real.nan");
	} else if (lookAhead(mangled, ctx, 0) == 'I' && lookAhead(mangled, ctx, 1) == 'N' && lookAhead(mangled, ctx, 2) == 'F') {
		consumeN(mangled, ctx, 3);
		return demangleAppend(ctx, "real.infinity");
	} else if (lookAhead(mangled, ctx, 0) == 'N' && lookAhead(mangled, ctx, 1) == 'I' && lookAhead(mangled, ctx, 2) == 'N' && lookAhead(mangled, ctx, 3) == 'F') {
		consumeN(mangled, ctx, 4);
		return demangleAppend(ctx, "-real.infinity");
	}

	bool is_neg = false;
	if (lookAhead(mangled, ctx, 0) == 'N') {
		is_neg = true;
		consume(mangled, ctx);
	}

	if (is_neg) {
		demangleAppend(ctx, "-0x");
	} else {
		demangleAppend(ctx, "0x");
	}

	bool has_digits = false;
	while (IS_HEX(lookAhead(mangled, ctx, 0))) {
		has_digits = true;
		demangleAppend(ctx, "%c", consumeHexDigit(mangled, ctx));
	}

	if (!has_digits) {
		ERR(ctx, false);
	}

	if (lookAhead(mangled, ctx, 0) == 'P') {
		consume(mangled, ctx);
		demangleAppend(ctx, "p");
		if (lookAhead(mangled, ctx, 0) == 'N') {
			demangleAppend(ctx, "-");
			consume(mangled, ctx);
		} else {
			demangleAppend(ctx, "+");
		}
		demangleAppend(ctx, "%zu", consumeDigits(mangled, ctx));
	}

	return true;
}

static bool parseValueImpl(const char *mangled, DDemangleContext *ctx, const char *type_name, char type_char) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	switch (lookAhead(mangled, ctx, 0)) {
	case 'n':
		consume(mangled, ctx);
		if (type_char != 'N') {
			demangleAppend(ctx, "null");
		} else {
			demangleAppend(ctx, "typeof(null)");
		}
		break;
	case 'i':
	case 'N':
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9': {
		bool is_neg = false;
		if (lookAhead(mangled, ctx, 0) == 'i') {
			consume(mangled, ctx);
		} else if (lookAhead(mangled, ctx, 0) == 'N') {
			is_neg = true;
			consume(mangled, ctx);
		}

		size_t val = consumeDigits(mangled, ctx);
		if (type_char == 'b') {
			if (val) {
				demangleAppend(ctx, "true");
			} else {
				demangleAppend(ctx, "false");
			}
		} else if (type_char == 'a' || type_char == 'u' || type_char == 'w') {
			switch (val) {
			case '\'':
				demangleAppend(ctx, "'\\''");
				break;
			case '\\':
				demangleAppend(ctx, "'\\\\'");
				break;
			case '\a':
				demangleAppend(ctx, "'\\a'");
				break;
			case '\b':
				demangleAppend(ctx, "'\\b'");
				break;
			case '\f':
				demangleAppend(ctx, "'\\f'");
				break;
			case '\n':
				demangleAppend(ctx, "'\\n'");
				break;
			case '\r':
				demangleAppend(ctx, "'\\r'");
				break;
			case '\t':
				demangleAppend(ctx, "'\\t'");
				break;
			case '\v':
				demangleAppend(ctx, "'\\v'");
				break;
			default:
				if (type_char == 'a') {
					if (val >= 0x20 && val < 0x7F) {
						demangleAppend(ctx, "'%c'", val);
					} else {
						demangleAppend(ctx, "\\x%02x", (unsigned int)val);
					}
				} else if (type_char == 'u') {
					demangleAppend(ctx, "'\\u%04x'", (unsigned int)val);
				} else if (type_char == 'w') {
					demangleAppend(ctx, "'\\U%08x'", (unsigned int)val);
				}
			}
		} else {
			if (is_neg) {
				demangleAppend(ctx, "-");
			}
			demangleAppend(ctx, "%zu", val);
			if (type_char == 'h' || type_char == 't' || type_char == 'k') {
				demangleAppend(ctx, "u");
			} else if (type_char == 'm') {
				demangleAppend(ctx, "uL");
			} else if (type_char == 'l') {
				demangleAppend(ctx, "L");
			}
		}
		break;
	}

	case 'e':
		consume(mangled, ctx);
		if (!parseHexFloat(mangled, ctx)) {
			return false;
		}
		if (type_char == 'f') {
			demangleAppend(ctx, "f");
		} else if (type_char == 'e') {
			demangleAppend(ctx, "L");
		}
		break;
	case 'c':
		consume(mangled, ctx);
		if (!parseHexFloat(mangled, ctx)) {
			return false;
		}
		demangleAppend(ctx, "+");
		if (lookAhead(mangled, ctx, 0) == 'c') {
			consume(mangled, ctx);
			if (!parseHexFloat(mangled, ctx)) {
				return false;
			}
		} else {
			ERR(ctx, false);
		}
		break;
	case 'a':
	case 'w':
	case 'd': {
		char type = lookAhead(mangled, ctx, 0);
		consume(mangled, ctx);
		size_t n = consumeDigits(mangled, ctx);
		if (ctx->err || lookAhead(mangled, ctx, 0) != '_') {
			ERR(ctx, false);
		}
		consume(mangled, ctx);
		demangleAppend(ctx, "\"");
		for (size_t i = 0; i < n; i++) {
			char c1 = consumeHexDigit(mangled, ctx);
			int a = 0, b = 0;
			if (!c1) {
				ERR(ctx, false);
			}
			char c2 = consumeHexDigit(mangled, ctx);
			if (!c2) {
				ERR(ctx, false);
			}

			if (IS_DIGIT(c1)) {
				a = c1 - '0';
			} else if (IS_LOWER(c1)) {
				a = c1 - 'a' + 10;
			} else if (IS_UPPER(c1)) {
				a = c1 - 'A' + 10;
			}

			if (IS_DIGIT(c2)) {
				b = c2 - '0';
			} else if (IS_LOWER(c2)) {
				b = c2 - 'a' + 10;
			} else if (IS_UPPER(c2)) {
				b = c2 - 'A' + 10;
			}

			char v = ((a << 4) | b);
			if (' ' <= v && v <= '~') {
				demangleAppend(ctx, "%c", v);
			} else {
				demangleAppend(ctx, "\\x%02x", (unsigned char)v);
			}
		}
		demangleAppend(ctx, "\"");
		if (type == 'w') {
			demangleAppend(ctx, "w");
		} else if (type == 'd') {
			demangleAppend(ctx, "d");
		}
		break;
	}
	case 'A': {
		if (type_char == 'H') {
			consume(mangled, ctx);
			demangleAppend(ctx, "[");
			size_t n = consumeDigits(mangled, ctx);
			if (ctx->err) {
				return false;
			}
			for (size_t i = 0; i < n; i++) {
				if (i > 0) {
					demangleAppend(ctx, ", ");
				}
				if (!parseValue(mangled, ctx, NULL, '\0')) {
					ERR(ctx, false);
				}
				demangleAppend(ctx, ":");
				if (!parseValue(mangled, ctx, NULL, '\0')) {
					ERR(ctx, false);
				}
			}
			demangleAppend(ctx, "]");
			break;
		}

		consume(mangled, ctx);
		demangleAppend(ctx, "[");
		size_t n = consumeDigits(mangled, ctx);
		if (ctx->err) {
			return false;
		}

		for (size_t i = 0; i < n; i++) {
			if (i > 0) {
				demangleAppend(ctx, ", ");
			}
			if (!parseValue(mangled, ctx, NULL, '\0')) {
				ERR(ctx, false);
			}
		}
		demangleAppend(ctx, "]");
		break;
	}
	case 'H': {
		consume(mangled, ctx);
		demangleAppend(ctx, "[");
		size_t n = consumeDigits(mangled, ctx);
		if (ctx->err) {
			return false;
		}
		for (size_t i = 0; i < n; i++) {
			if (i > 0) {
				demangleAppend(ctx, ", ");
			}
			if (!parseValue(mangled, ctx, NULL, '\0')) {
				ERR(ctx, false);
			}
			demangleAppend(ctx, ":");
			if (!parseValue(mangled, ctx, NULL, '\0')) {
				ERR(ctx, false);
			}
		}
		demangleAppend(ctx, "]");
		break;
	}
	case 'S': {
		consume(mangled, ctx);
		if (type_name && strlen(type_name) > 0) {
			demangleAppend(ctx, "%s", type_name);
		}

		demangleAppend(ctx, "(");
		size_t n = consumeDigits(mangled, ctx);
		if (ctx->err) {
			return false;
		}

		for (size_t i = 0; i < n; i++) {
			if (i > 0) {
				demangleAppend(ctx, ", ");
			}
			if (!parseValue(mangled, ctx, NULL, '\0')) {
				ERR(ctx, false);
			}
		}
		demangleAppend(ctx, ")");
		break;
	}
	case 'f':
		consume(mangled, ctx);
		if (!parseMangledName(mangled, ctx, false)) {
			ERR(ctx, false);
		}
		break;
	default:
		ERR(ctx, false);
	}
	return true;
}

static bool parseTemplateArgImpl(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	bool prev = ctx->in_template_arg;
	ctx->in_template_arg = true;
	DDemangleCtxRef ref = createCtxRef(ctx);
	if (lookAhead(mangled, ctx, 0) == 'H') {
		consume(mangled, ctx);
	}

	switch (lookAhead(mangled, ctx, 0)) {
	case 'T':
		consume(mangled, ctx);
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			ctx->in_template_arg = prev;
			return false;
		}
		break;
	case 'V': {
		consume(mangled, ctx);
		char type_char = lookAhead(mangled, ctx, 0);
		if (type_char == 'Q') {
			size_t saved_curr = ctx->curr;
			size_t pos = parseBackRef(mangled, ctx);
			if (!ctx->err && pos < ctx->curr) {
				type_char = mangled[pos];
			}
			ctx->err = false;
			ctx->curr = saved_curr;
		}

		DemString *saved = ctx->demangled;
		DemString *type_str = dem_string_new();
		ctx->demangled = type_str;
		if (!parseType(mangled, ctx)) {
			ctx->demangled = saved;
			dem_string_free(type_str);
			ctxRestore(ctx, ref);
			ctx->in_template_arg = prev;
			return false;
		}

		ctx->demangled = saved;
		if (!parseValue(mangled, ctx, type_str->buf, type_char)) {
			dem_string_free(type_str);
			ctxRestore(ctx, ref);
			ctx->in_template_arg = prev;
			return false;
		}
		dem_string_free(type_str);
		break;
	}
	case 'S':
		consume(mangled, ctx);
		if (lookAhead(mangled, ctx, 0) == '_' && lookAhead(mangled, ctx, 1) == 'D') {
			consumeN(mangled, ctx, 2);
			DemString *str = dem_string_new();
			DemString *saved = ctx->demangled;
			if (!parseQualifiedName(mangled, ctx)) {
				dem_string_free(str);
				ctxRestore(ctx, ref);
				ctx->in_template_arg = prev;
				return false;
			}

			ctx->demangled = str;
			if (!consumeIf(mangled, ctx, 'Z')) {
				parseType(mangled, ctx);
			}

			ctx->demangled = saved;
			dem_string_free(str);
		} else {
			if (!parseQualifiedName(mangled, ctx)) {
				ctxRestore(ctx, ref);
				ctx->in_template_arg = prev;
				return false;
			}
		}
		break;
	case 'X':
		consume(mangled, ctx);
		if (!parseLName(mangled, ctx)) {
			ctxRestore(ctx, ref);
			ctx->in_template_arg = prev;
			return false;
		}
		break;
	default:
		ctx->in_template_arg = prev;
		return false;
	}
	ctx->in_template_arg = prev;
	return true;
}

static bool parseTemplateArgs(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	bool parsed = false;
	while (1) {
		DDemangleCtxRef ref = createCtxRef(ctx);
		if (parsed) {
			demangleAppend(ctx, ", ");
		}
		if (parseTemplateArg(mangled, ctx)) {
			parsed = true;
		} else {
			ctxRestore(ctx, ref);
			break;
		}
	}
	return parsed;
}

static bool parseTemplateInstanceName(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	DDemangleCtxRef ref = createCtxRef(ctx);
	if (parseTemplateID(mangled, ctx)) {
		if (parseSymbolName(mangled, ctx)) {
			demangleAppend(ctx, "!(");
			bool has_args = parseTemplateArgs(mangled, ctx);
			(void)has_args;
			if (consumeIf(mangled, ctx, 'Z')) {
				demangleAppend(ctx, ")");
				return true;
			}
		}
	}

	ctxRestore(ctx, ref);
	ERR(ctx, false);
}

static bool parseSymbolName(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	if (lookAhead(mangled, ctx, 0) == '0') {
		consume(mangled, ctx);
	} else if (IS_DIGIT(lookAhead(mangled, ctx, 0))) {
		if (!parseLName(mangled, ctx)) {
			return false;
		}
	} else if (lookAhead(mangled, ctx, 0) == 'Q') {
		if (!expandBackRefSymbol(mangled, ctx)) {
			return false;
		}
	} else if (lookAhead(mangled, ctx, 0) == '_' || lookAhead(mangled, ctx, 0) == 'T' || lookAhead(mangled, ctx, 0) == 'U') {
		if (!parseTemplateInstanceName(mangled, ctx)) {
			return false;
		}
	} else {
		ERR(ctx, false);
	}

	return true;
}

static bool parseCallingConvention(const char *mangled, DDemangleContext *ctx, DemString *dest) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	switch (lookAhead(mangled, ctx, 0)) {
	case 'F':
		consume(mangled, ctx);
		break;
	case 'U':
		consume(mangled, ctx);
		if (dest) {
			dem_string_appendf(dest, "extern (C) ");
		} else {
			demangleAppend(ctx, "extern (C) ");
		}
		break;
	case 'W':
		consume(mangled, ctx);
		if (dest) {
			dem_string_appendf(dest, "extern (Windows) ");
		} else {
			demangleAppend(ctx, "extern (Windows) ");
		}
		break;
	case 'R':
		consume(mangled, ctx);
		if (dest) {
			dem_string_appendf(dest, "extern (C++) ");
		} else {
			demangleAppend(ctx, "extern (C++) ");
		}
		break;
	case 'Y':
		consume(mangled, ctx);
		if (dest) {
			dem_string_appendf(dest, "extern (Objective-C) ");
		} else {
			demangleAppend(ctx, "extern (Objective-C) ");
		}
		break;
	default:
		return false;
	}
	return true;
}

static bool parseParameter(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	DDemangleCtxRef ref = createCtxRef(ctx);
	char c = lookAhead(mangled, ctx, 0);
	char c1 = lookAhead(mangled, ctx, 1);
	char c2 = lookAhead(mangled, ctx, 2);
	char c3 = lookAhead(mangled, ctx, 3);
	if (c == 'M' && c1 == 'N' && c2 == 'k' && c3 == 'J') {
		consumeN(mangled, ctx, 4);
		demangleAppend(ctx, "scope return out ");
	} else if (c == 'M' && c1 == 'N' && c2 == 'k' && c3 == 'K') {
		consumeN(mangled, ctx, 4);
		demangleAppend(ctx, "scope return ref ");
	} else if (c == 'N' && c1 == 'k' && c2 == 'J') {
		consumeN(mangled, ctx, 3);
		demangleAppend(ctx, "return out ");
	} else if (c == 'N' && c1 == 'k' && c2 == 'K') {
		consumeN(mangled, ctx, 3);
		demangleAppend(ctx, "return ref ");
	} else if (c == 'N' && c1 == 'k' && c2 == 'M' && c3 == 'J') {
		consumeN(mangled, ctx, 4);
		demangleAppend(ctx, "return scope out ");
	} else if (c == 'N' && c1 == 'k' && c2 == 'M' && c3 == 'K') {
		consumeN(mangled, ctx, 4);
		demangleAppend(ctx, "return scope ref ");
	} else if (c == 'N' && c1 == 'k' && c2 == 'M') {
		consumeN(mangled, ctx, 3);
		demangleAppend(ctx, "return scope ");
	} else if (c == 'M') {
		consume(mangled, ctx);
		demangleAppend(ctx, "scope ");
	} else if (c == 'N' && c1 == 'k') {
		consumeN(mangled, ctx, 2);
		demangleAppend(ctx, "return ");
	}

	switch (lookAhead(mangled, ctx, 0)) {
	case 'I':
		consume(mangled, ctx);
		demangleAppend(ctx, "in ");
		if (lookAhead(mangled, ctx, 0) == 'K') {
			consume(mangled, ctx);
			demangleAppend(ctx, "ref ");
		}
		break;
	case 'J':
		consume(mangled, ctx);
		demangleAppend(ctx, "out ");
		break;
	case 'K':
		consume(mangled, ctx);
		demangleAppend(ctx, "ref ");
		break;
	case 'L':
		consume(mangled, ctx);
		demangleAppend(ctx, "lazy ");
		break;
	}

	if (!parseType(mangled, ctx)) {
		ctxRestore(ctx, ref);
		return false;
	}
	return true;
}

static bool parseParameters(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}
	bool parsed = false;
	while (1) {
		char c = lookAhead(mangled, ctx, 0);
		if (c == 'X' || c == 'Y' || c == 'Z') {
			break;
		}

		DDemangleCtxRef ref = createCtxRef(ctx);
		if (parsed) {
			demangleAppend(ctx, ", ");
		}
		if (parseParameter(mangled, ctx)) {
			parsed = true;
		} else {
			ctxRestore(ctx, ref);
			break;
		}
	}
	return parsed;
}

static bool parseParamClose(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	switch (lookAhead(mangled, ctx, 0)) {
	case 'X':
		consume(mangled, ctx);
		demangleAppend(ctx, "...)");
		break;
	case 'Y':
		consume(mangled, ctx);
		demangleAppend(ctx, ", ...)");
		break;
	case 'Z':
		consume(mangled, ctx);
		demangleAppend(ctx, ")");
		break;
	default:
		return false;
	}
	return true;
}

static bool parseTypeFunctionNoReturn(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	FuncAttributes attrs = parseFuncAttrs(mangled, ctx);
	demangleAppend(ctx, "(");
	parseParameters(mangled, ctx);
	if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
		ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
		ctx->demangled->len--;
	}

	if (!parseParamClose(mangled, ctx)) {
		return false;
	}
	if (attrs != FUNC_ATTR_NONE) {
		demangleAppend(ctx, " ");
		writeFuncAttrs(attrs, ctx->demangled);
		if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
			ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
			ctx->demangled->len--;
		}
	}
	return true;
}

static bool parseTypeFunction(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}
	if (!parseCallingConvention(mangled, ctx, NULL)) {
		ERR(ctx, false);
	}

	DemString *saved = ctx->demangled;
	DemString *args_str = dem_string_new();
	ctx->demangled = args_str;
	demangleAppend(ctx, "function");
	if (!parseTypeFunctionNoReturn(mangled, ctx)) {
		ctx->demangled = saved;
		dem_string_free(args_str);
		return false;
	}

	DemString *ret_str = dem_string_new();
	ctx->demangled = ret_str;
	if (!parseType(mangled, ctx)) {
		ctx->demangled = saved;
		dem_string_free(args_str);
		dem_string_free(ret_str);
		return false;
	}

	ctx->demangled = saved;
	dem_string_concat(ctx->demangled, ret_str);
	demangleAppend(ctx, " ");
	dem_string_concat(ctx->demangled, args_str);
	dem_string_free(args_str);
	dem_string_free(ret_str);
	return true;
}

static bool parseTypeImpl(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	DDemangleCtxRef ref = createCtxRef(ctx);
	char c = lookAhead(mangled, ctx, 0);
	if (c == 'x') {
		consume(mangled, ctx);
		demangleAppend(ctx, "const(");
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		demangleAppend(ctx, ")");
		return true;
	} else if (c == 'y') {
		consume(mangled, ctx);
		demangleAppend(ctx, "immutable(");
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		demangleAppend(ctx, ")");
		return true;
	} else if (c == 'O') {
		consume(mangled, ctx);
		demangleAppend(ctx, "shared(");
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		demangleAppend(ctx, ")");
		return true;
	} else if (c == 'N' && lookAhead(mangled, ctx, 1) == 'g') {
		consumeN(mangled, ctx, 2);
		demangleAppend(ctx, "inout(");
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		demangleAppend(ctx, ")");
		return true;
	}

	if (lookAhead(mangled, ctx, 0) == 'Q') {
		return expandBackRefType(mangled, ctx);
	}

	switch (lookAhead(mangled, ctx, 0)) {
	case 'A':
		consume(mangled, ctx);
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
			ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
			ctx->demangled->len--;
		}
		demangleAppend(ctx, "[]");
		break;
	case 'P':
		consume(mangled, ctx);
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
			ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
			ctx->demangled->len--;
		}
		demangleAppend(ctx, "*");
		break;
	case 'G': {
		consume(mangled, ctx);
		bool has_digits = IS_DIGIT(lookAhead(mangled, ctx, 0));
		size_t size = 0;
		if (has_digits) {
			size = consumeDigits(mangled, ctx);
		} else {
			ERR(ctx, false);
		}
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
			ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
			ctx->demangled->len--;
		}
		demangleAppend(ctx, "[%zu]", size);
		break;
	}
	case 'H':
		consume(mangled, ctx);
		DemString *key_str = dem_string_new();
		DemString *saved = ctx->demangled;
		ctx->demangled = key_str;
		if (!parseType(mangled, ctx)) {
			ctx->demangled = saved;
			dem_string_free(key_str);
			ctxRestore(ctx, ref);
			return false;
		}
		ctx->demangled = saved;
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
			ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
			ctx->demangled->len--;
		}
		demangleAppend(ctx, "[");
		dem_string_concat(ctx->demangled, key_str);
		demangleAppend(ctx, "]");
		dem_string_free(key_str);
		break;
	case 'F':
	case 'U':
	case 'W':
	case 'R':
	case 'Y':
		return parseTypeFunction(mangled, ctx);
	case 'N':
		if (lookAhead(mangled, ctx, 1) == 'n') {
			consumeN(mangled, ctx, 2);
			demangleAppend(ctx, "noreturn");
			return true;
		} else if (lookAhead(mangled, ctx, 1) != 'h') {
			return false;
		}
		consumeN(mangled, ctx, 2);
		demangleAppend(ctx, "__vector(");
		if (!parseType(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		demangleAppend(ctx, ")");
		break;
	case 'I':
	case 'C':
	case 'S':
	case 'E':
	case 'T':
		consume(mangled, ctx);
		if (!parseQualifiedName(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		break;
	case 'D': {
		consume(mangled, ctx);
		TypeCtor type_modifiers = parseModifier(mangled, ctx);
		if (lookAhead(mangled, ctx, 0) == 'Q') {
			size_t pos = parseBackRef(mangled, ctx);
			if (ctx->err || pos >= ctx->curr) {
				return false;
			}

			size_t saved_curr = ctx->curr;
			ctx->curr = pos;
			if (!parseCallingConvention(mangled, ctx, NULL)) {
				ctx->curr = saved_curr;
				return false;
			}
			DemString *saved_demangled = ctx->demangled;
			DemString *args_str = dem_string_new();
			ctx->demangled = args_str;
			demangleAppend(ctx, "delegate");
			if (!parseTypeFunctionNoReturn(mangled, ctx)) {
				ctx->curr = saved_curr;
				ctx->demangled = saved_demangled;
				dem_string_free(args_str);
				return false;
			}

			DemString *ret_str = dem_string_new();
			ctx->demangled = ret_str;
			if (!parseType(mangled, ctx)) {
				ctx->curr = saved_curr;
				ctx->demangled = saved_demangled;
				dem_string_free(args_str);
				dem_string_free(ret_str);
				return false;
			}

			ctx->curr = saved_curr;
			if (type_modifiers != TYPE_CTOR_NONE) {
				dem_string_appendf(args_str, " ");
				writeModifiers(type_modifiers, args_str);
				if (args_str->len > 0 && args_str->buf[args_str->len - 1] == ' ') {
					args_str->buf[args_str->len - 1] = '\0';
					args_str->len--;
				}
			}

			ctx->demangled = saved_demangled;
			dem_string_concat(ctx->demangled, ret_str);
			demangleAppend(ctx, " ");
			dem_string_concat(ctx->demangled, args_str);
			dem_string_free(args_str);
			dem_string_free(ret_str);
		} else {
			if (!parseCallingConvention(mangled, ctx, NULL)) {
				return false;
			}

			DemString *saved_demangled = ctx->demangled;
			DemString *args_str = dem_string_new();
			ctx->demangled = args_str;
			demangleAppend(ctx, "delegate");
			if (!parseTypeFunctionNoReturn(mangled, ctx)) {
				ctx->demangled = saved_demangled;
				dem_string_free(args_str);
				return false;
			}

			if (type_modifiers != TYPE_CTOR_NONE) {
				demangleAppend(ctx, " ");
				writeModifiers(type_modifiers, ctx->demangled);
				if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
					ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
					ctx->demangled->len--;
				}
			}

			DemString *ret_str = dem_string_new();
			ctx->demangled = ret_str;
			if (!parseType(mangled, ctx)) {
				ctx->demangled = saved_demangled;
				dem_string_free(args_str);
				dem_string_free(ret_str);
				return false;
			}

			ctx->demangled = saved_demangled;
			dem_string_concat(ctx->demangled, ret_str);
			demangleAppend(ctx, " ");
			dem_string_concat(ctx->demangled, args_str);
			dem_string_free(args_str);
			dem_string_free(ret_str);
		}
		break;
	}
	case 'v':
		consume(mangled, ctx);
		demangleAppend(ctx, "void");
		break;
	case 'g':
		consume(mangled, ctx);
		demangleAppend(ctx, "byte");
		break;
	case 'h':
		consume(mangled, ctx);
		demangleAppend(ctx, "ubyte");
		break;
	case 's':
		consume(mangled, ctx);
		demangleAppend(ctx, "short");
		break;
	case 't':
		consume(mangled, ctx);
		demangleAppend(ctx, "ushort");
		break;
	case 'i':
		consume(mangled, ctx);
		demangleAppend(ctx, "int");
		break;
	case 'k':
		consume(mangled, ctx);
		demangleAppend(ctx, "uint");
		break;
	case 'l':
		consume(mangled, ctx);
		demangleAppend(ctx, "long");
		break;
	case 'm':
		consume(mangled, ctx);
		demangleAppend(ctx, "ulong");
		break;
	case 'f':
		consume(mangled, ctx);
		demangleAppend(ctx, "float");
		break;
	case 'd':
		consume(mangled, ctx);
		demangleAppend(ctx, "double");
		break;
	case 'e':
		consume(mangled, ctx);
		demangleAppend(ctx, "real");
		break;
	case 'o':
		consume(mangled, ctx);
		demangleAppend(ctx, "ifloat");
		break;
	case 'p':
		consume(mangled, ctx);
		demangleAppend(ctx, "idouble");
		break;
	case 'j':
		consume(mangled, ctx);
		demangleAppend(ctx, "ireal");
		break;
	case 'q':
		consume(mangled, ctx);
		demangleAppend(ctx, "cfloat");
		break;
	case 'r':
		consume(mangled, ctx);
		demangleAppend(ctx, "cdouble");
		break;
	case 'c':
		consume(mangled, ctx);
		demangleAppend(ctx, "creal");
		break;
	case 'b':
		consume(mangled, ctx);
		demangleAppend(ctx, "bool");
		break;
	case 'a':
		consume(mangled, ctx);
		demangleAppend(ctx, "char");
		break;
	case 'u':
		consume(mangled, ctx);
		demangleAppend(ctx, "wchar");
		break;
	case 'w':
		consume(mangled, ctx);
		demangleAppend(ctx, "dchar");
		break;
	case 'n':
		consume(mangled, ctx);
		break;
	case 'Z':
		consume(mangled, ctx);
		break;
	case 'z':
		switch (lookAhead(mangled, ctx, 1)) {
		case 'i':
			consumeN(mangled, ctx, 2);
			demangleAppend(ctx, "cent");
			break;
		case 'k':
			consumeN(mangled, ctx, 2);
			demangleAppend(ctx, "ucent");
			break;
		default: return false;
		}
		break;
	case 'B':
		consume(mangled, ctx);
		demangleAppend(ctx, "tuple!(");
		if (!parseParameters(mangled, ctx)) {
			ctxRestore(ctx, ref);
			return false;
		}
		if (lookAhead(mangled, ctx, 0) == 'Z') {
			consume(mangled, ctx);
		} else {
			return false;
		}
		break;
	default:
		return false;
	}
	return true;
}

static bool parseSymbolFunctionName(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	DDemangleCtxRef ref = createCtxRef(ctx);
	if (!parseSymbolName(mangled, ctx)) {
		ctxRestore(ctx, ref);
		return false;
	}

	DDemangleCtxRef ref_after_name = createCtxRef(ctx);
	DemString *saved_attr = ctx->attr;
	ctx->attr = dem_string_new();
	TypeCtor modifiers = TYPE_CTOR_NONE;
	bool m = false;
	if (lookAhead(mangled, ctx, 0) == 'M') {
		consume(mangled, ctx);
		m = true;
		modifiers = parseModifier(mangled, ctx);
	}

	if (isCallConvention(lookAhead(mangled, ctx, 0))) {
		if (ctx->in_template_arg) {
			if ((modifiers & TYPE_CTOR_CONST) == TYPE_CTOR_CONST) {
				demangleAppend(ctx, "const ");
				modifiers &= ~TYPE_CTOR_CONST;
			}
			if ((modifiers & TYPE_CTOR_INOUT) == TYPE_CTOR_INOUT) {
				demangleAppend(ctx, "inout ");
				modifiers &= ~TYPE_CTOR_INOUT;
			}
			if ((modifiers & TYPE_CTOR_SHARED) == TYPE_CTOR_SHARED) {
				demangleAppend(ctx, "shared ");
				modifiers &= ~TYPE_CTOR_SHARED;
			}
			if ((modifiers & TYPE_CTOR_IMMUTABLE) == TYPE_CTOR_IMMUTABLE) {
				demangleAppend(ctx, "immutable ");
				modifiers &= ~TYPE_CTOR_IMMUTABLE;
			}
		}

		writeModifiers(modifiers, ctx->attr);
		parseCallingConvention(mangled, ctx, ctx->attr);
		FuncAttributes attrs = parseFuncAttrs(mangled, ctx);
		writeFuncAttrs(attrs, ctx->attr);
		demangleAppend(ctx, "(");
		parseParameters(mangled, ctx);
		if (ctx->demangled->len > 0 && ctx->demangled->buf[ctx->demangled->len - 1] == ' ') {
			ctx->demangled->buf[ctx->demangled->len - 1] = '\0';
			ctx->demangled->len--;
		}

		if (!parseParamClose(mangled, ctx)) {
			ctxRestore(ctx, ref_after_name);
			ctx->err = false;
			dem_string_free(ctx->attr);
			ctx->attr = saved_attr;
			if (ctx->attr) {
				ctx->attr->len = 0;
				if (ctx->attr->buf) {
					ctx->attr->buf[0] = '\0';
				}
			}
			return true;
		}

		if (saved_attr) {
			saved_attr->len = 0;
			if (saved_attr->buf) {
				saved_attr->buf[0] = '\0';
			}
			dem_string_concat(saved_attr, ctx->attr);
		}
		dem_string_free(ctx->attr);
		ctx->attr = saved_attr;
		return true;
	} else if (m) {
		ctxRestore(ctx, ref_after_name);
		ctx->err = false;
		dem_string_free(ctx->attr);
		ctx->attr = saved_attr;
		if (ctx->attr) {
			ctx->attr->len = 0;
			if (ctx->attr->buf) {
				ctx->attr->buf[0] = '\0';
			}
		}
		return true;
	}

	dem_string_free(ctx->attr);
	ctx->attr = saved_attr;
	if (ctx->attr) {
		ctx->attr->len = 0;
		if (ctx->attr->buf) {
			ctx->attr->buf[0] = '\0';
		}
	}
	return true;
}

static bool parseQualifiedName(const char *mangled, DDemangleContext *ctx) {
	if (!mangled || !ctx || ctx->err) {
		return false;
	}

	bool parsed = false;
	while (1) {
		DDemangleCtxRef ref = createCtxRef(ctx);
		if (parsed) {
			demangleAppend(ctx, ".");
		}
		if (parseSymbolFunctionName(mangled, ctx)) {
			parsed = true;
		} else {
			ctxRestore(ctx, ref);
			break;
		}
	}
	return parsed;
}

DEM_LIB_EXPORT char *libdemangle_handler_d(const char *mangled, RzDemangleOpts opts) {
	DDemangleContext *ctx = malloc(sizeof(DDemangleContext));
	if (!ctx) {
		return NULL;
	}

	ctx->demangled = dem_string_new();
	ctx->attr = dem_string_new();
	ctx->curr = 0;
	ctx->err = false;
	ctx->in_template_arg = false;
	if (!mangled) {
		dem_string_free(ctx->demangled);
		dem_string_free(ctx->attr);
		RZ_FREE(ctx);
		return NULL;
	}

	char *res = NULL;
	consumeWhile(mangled, ctx, ' ');
	if (parseMangledName(mangled, ctx, true)) {
		res = dem_string_drain(ctx->demangled);
	} else {
		dem_string_free(ctx->demangled);
	}
	dem_string_free(ctx->attr);
	RZ_FREE(ctx);
	return res;
}
