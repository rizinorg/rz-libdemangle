// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangler_util.h"
#include <rz_libdemangle.h>
#include <ctype.h>

#define startwith(x, c) (!strncmp(x, c, strlen(c)))
#define borland_cxx_operator(pfx, op) \
	{ pfx, (sizeof(pfx) - 1), op, (sizeof(op) - 1) }

typedef struct borland_repl_s {
	const char *pfx;
	size_t pfx_len;
	const char *str;
	size_t str_len;
} borland_repl_t;

borland_repl_t cxx_operators[] = {
	borland_cxx_operator("bxor", "operator^"),
	borland_cxx_operator("bsubs", "operator[]"),
	borland_cxx_operator("bsub", "operator-"),
	borland_cxx_operator("brxor", "operator^="),
	borland_cxx_operator("brsh", "operator>>"),
	borland_cxx_operator("brrsh", "operator>>="),
	borland_cxx_operator("brplu", "operator+="),
	borland_cxx_operator("bror", "operator|="),
	borland_cxx_operator("brmul", "operator*="),
	borland_cxx_operator("brmod", "operator%="),
	borland_cxx_operator("brmin", "operator-="),
	borland_cxx_operator("brlsh", "operator<<="),
	borland_cxx_operator("brdiv", "operator/="),
	borland_cxx_operator("brand", "operator&="),
	borland_cxx_operator("bor", "operator|"),
	borland_cxx_operator("bnot", "operator!"),
	borland_cxx_operator("bneq", "operator!="),
	borland_cxx_operator("bmul", "operator*"),
	borland_cxx_operator("bmod", "operator%"),
	borland_cxx_operator("blss", "operator<"),
	borland_cxx_operator("blsh", "operator<<"),
	borland_cxx_operator("blor", "operator||"),
	borland_cxx_operator("bleq", "operator<="),
	borland_cxx_operator("bland", "operator&&"),
	borland_cxx_operator("bind", "operator*"),
	borland_cxx_operator("binc", "operator++"),
	borland_cxx_operator("bgtr", "operator>"),
	borland_cxx_operator("bgeq", "operator>="),
	borland_cxx_operator("beql", "operator=="),
	borland_cxx_operator("bdiv", "operator/"),
	borland_cxx_operator("bdec", "operator--"),
	borland_cxx_operator("bcoma", "operator,"),
	borland_cxx_operator("bcmp", "operator~"),
	borland_cxx_operator("bcall", "operator()"),
	borland_cxx_operator("basg", "operator="),
	borland_cxx_operator("barwm", "operator->*"),
	borland_cxx_operator("barow", "operator->"),
	borland_cxx_operator("band", "operator&"),
	borland_cxx_operator("badr", "operator&"),
	borland_cxx_operator("badd", "operator+"),
};

borland_repl_t cxx_mem_operators[] = {
	borland_cxx_operator("bnew", "operator new(unsigned int)"),
	borland_cxx_operator("bnwa", "operator new[](unsigned int)"),
	borland_cxx_operator("bdele", "operator delete(void *)"),
	borland_cxx_operator("bdla", "operator delete[](void *)"),
};

bool borland_delphi_procedure_call_type(DemString *ds, const char *begin, const char *end) {
	if (begin >= end) {
		return false;
	}
	switch (begin[0]) {
	case 'r':
		dem_string_appends_prefix(ds, "__fastcall ");
		break;
	case 's':
		dem_string_appends_prefix(ds, "__stdcall ");
		break;
	default:
		return false;
	}

	return true;
}

size_t borland_delphi_parse_len(const char *begin, const char *end, const char **leftovers) {
	if (begin[0] == '0') {
		// a number must start with a non-zero digit.
		return 0;
	}

	size_t number = 0;
	for (; begin < end && IS_DIGIT(begin[0]); ++begin) {
		number *= 10;
		number += begin[0] - '0';
	}
	*leftovers = begin;
	return number;
}

char *borland_delphi_basic_type(const char *begin, const char *end, const char **leftovers) {
	if (begin >= end) {
		return NULL;
	}

	DemString *ds = dem_string_new();
	if (!ds) {
		return NULL;
	}

	if (begin[0] == 'u') {
		dem_string_appends(ds, "unsigned ");
		begin++;
		if (begin >= end) {
			goto fail;
		}
	} else if (begin[0] == 'z') {
		dem_string_appends(ds, "signed ");
		begin++;
		if (begin >= end) {
			goto fail;
		}
	}

	switch (begin[0]) {
	case 'o':
		dem_string_appends(ds, "bool");
		break;
	case 'c':
		dem_string_appends(ds, "char");
		break;
	case 'b':
		dem_string_appends(ds, "wchar_t");
		break;
	case 'C':
		dem_string_appends(ds, "char16_t");
		break;
	case 'e':
		dem_string_appends(ds, "...");
		break;
	case 's':
		if (startwith(begin, "sCi")) {
			dem_string_appends(ds, "char32_t");
			begin += 2;
		} else {
			dem_string_appends(ds, "short");
		}
		break;
	case 'i':
		dem_string_appends(ds, "int");
		break;
	case 'l':
		dem_string_appends(ds, "long");
		break;
	case 'j':
		dem_string_appends(ds, "long long");
		break;
	case 'f':
		dem_string_appends(ds, "float");
		break;
	case 'd':
		dem_string_appends(ds, "double");
		break;
	case 'g':
		dem_string_appends(ds, "long double");
		break;
	case 'v':
		dem_string_appends(ds, "void");
		break;
	case 'N':
		dem_string_appends(ds, "nullptr_t");
		break;
	default:
		goto fail;
	}
	*leftovers = begin + 1;
	return dem_string_drain(ds);

fail:
	dem_string_free(ds);
	return NULL;
}

char *borland_delphi_type(const char *begin, const char *end, const char **leftovers);

char *borland_delphi_custom_type(const char *begin, const char *end, const char **leftovers) {
	if (begin >= end) {
		return NULL;
	}

	size_t length = borland_delphi_parse_len(begin, end, &begin);
	if (length < 1 || begin + length > end) {
		return NULL;
	}

	DemString *ds = dem_string_new();
	if (!ds) {
		return NULL;
	}

	char *subtype = NULL;
	const char *type_beg = begin;
	const char *type_end = begin + length;
	bool to_add = false,
	     opened = false,
	     first_type = true,
	     is_pointer = false,
	     parse_digit = false;
	for (; begin < type_end; ++begin) {
		if (parse_digit && IS_DIGIT(begin[0])) {
			if (begin[-1] == 'p') {
				is_pointer = true;
			}
			// custom subtype.
			subtype = borland_delphi_custom_type(begin, type_end, &begin);
			if (!subtype) {
				goto fail;
			}
			if (!first_type) {
				dem_string_appends(ds, ", ");
			}
			dem_string_append(ds, subtype);
			free(subtype);
			first_type = false;
			type_beg = begin;
			begin--;

			if (is_pointer) {
				dem_string_appends(ds, " *");
				is_pointer = false;
			}
			continue;
		}

		switch (begin[0]) {
		case '%':
			// expect template end
			dem_string_append_n(ds, type_beg, begin - type_beg);
			type_beg = begin + 1;
			if (opened) {
				if (is_pointer) {
					dem_string_appends(ds, " *");
					is_pointer = false;
				}
				dem_string_appends(ds, ">");
			}
			to_add = false;
			continue;
		case '@': {
			// expected special encoded chars
			dem_string_append_n(ds, type_beg, begin - type_beg);
			type_beg = begin + 1;
			dem_string_appends(ds, "::");
			to_add = false;
			continue;
		}
		case '$':
			// expect template begin
			dem_string_append_n(ds, type_beg, begin - type_beg);
			type_beg = begin + 1;
			to_add = false;
			opened = true;

			// append template open delimiter
			dem_string_appends(ds, "<");

			if (type_beg[0] == 't') {
				// unknown and cannot find its mapping..
				// but seems to be used always before a type.
				type_beg++;
			}
			parse_digit = true;

			subtype = borland_delphi_type(type_beg, type_end, &begin);
			if (!subtype) {
				goto fail;
			}
			dem_string_append(ds, subtype);
			free(subtype);
			type_beg = begin;
			begin--;
			first_type = false;
			continue;
		default:
			to_add = true;
		}
	}

	if (to_add) {
		// add any missing char..
		dem_string_append_n(ds, type_beg, begin - type_beg);
		begin = type_end;
	}

	if (is_pointer) {
		dem_string_appends(ds, " *");
	}

	size_t clen = dem_string_length(ds);
	if (clen < 1) {
		goto fail;
	}

	*leftovers = begin;
	return dem_string_drain(ds);

fail:
	dem_string_free(ds);
	return NULL;
}

char *borland_delphi_array(const char *begin, const char *end, const char **leftovers) {
	if (begin >= end) {
		return NULL;
	}

	int size = borland_delphi_parse_len(begin, end, &begin);
	if (size < 1) {
		return NULL;
	}

	DemString *ds = dem_string_new();
	if (!ds) {
		return NULL;
	}

	dem_string_appendf(ds, " [%d]", size);

	while (begin < end || begin[0] != '$') {
		if ((begin + 1) >= end) {
			goto fail;
		}
		begin++;
		if (begin[0] == 'a') {
			size = borland_delphi_parse_len(begin + 1, end, &begin);
			if (size < 1) {
				goto fail;
			}
			dem_string_appendf(ds, "[%d]", size);
			continue;
		} else if (IS_DIGIT(begin[0])) {
			// custom ctype.
			char *ctype = borland_delphi_custom_type(begin, end, &begin);
			if (!ctype) {
				goto fail;
			}
			dem_string_appends_prefix(ds, ctype);
			free(ctype);
		} else {
			char *ctype = borland_delphi_basic_type(begin, end, &begin);
			if (!ctype) {
				goto fail;
			}
			dem_string_appends_prefix(ds, ctype);
			free(ctype);
		}
		break;
	}

	*leftovers = begin;
	return dem_string_drain(ds);

fail:
	dem_string_free(ds);
	return NULL;
}

char *borland_delphi_type(const char *begin, const char *end, const char **leftovers) {
	if (begin >= end) {
		return NULL;
	}

	bool is_const = false, is_volatile = false, is_reference = false, is_rvalue_ref = false, is_function = false;
	char *ctype = NULL;
	DemString *prefix = dem_string_new();
	DemString *suffix = dem_string_new();
	if (!prefix || !suffix) {
		goto fail;
	}

	for (; begin < end; ++begin) {
		switch (begin[0]) {
		case 'p':
			if (begin[1] == 'q') {
				is_function = true;
			} else {
				dem_string_appends(suffix, " *");
				if (is_volatile) {
					dem_string_appends(suffix, " volatile");
					is_volatile = false;
				}
				if (is_const) {
					dem_string_appends(suffix, " const");
					is_const = false;
				}
			}
			continue;
		case 'q':
			is_function = true;
			continue;
		case 'r':
			is_reference = true;
			continue;
		case 'h':
			is_rvalue_ref = true;
			continue;
		case 'x':
			is_const = true;
			continue;
		case 'w':
			is_volatile = true;
			continue;
		case 'V':
			// unknown and not printable..
			continue;
		}

		if (!is_reference && !is_rvalue_ref) {
			if (is_volatile) {
				dem_string_appends(prefix, "volatile ");
				is_volatile = false;
			}
			if (is_const) {
				dem_string_appends(prefix, "const ");
				is_const = false;
			}
		}

		if (IS_DIGIT(begin[0])) {
			ctype = borland_delphi_custom_type(begin, end, &begin);
			if (!ctype) {
				goto fail;
			}
			dem_string_append(prefix, ctype);
			free(ctype);
		} else if (begin[0] == 'a') {
			ctype = borland_delphi_array(begin + 1, end, &begin);
			if (!ctype) {
				goto fail;
			}
			dem_string_append(prefix, ctype);
			free(ctype);
		} else {
			ctype = borland_delphi_basic_type(begin, end, &begin);
			if (!ctype) {
				goto fail;
			}
			dem_string_append(prefix, ctype);
			free(ctype);
		}
		break;
	}

	if (is_function) {
		dem_string_appends_prefix(prefix, ")(");
		if (is_const) {
			dem_string_appends_prefix(prefix, " const");
			is_const = false;
		}
		if (is_volatile) {
			dem_string_appends_prefix(prefix, " volatile");
			is_volatile = false;
		}
		if (is_reference) {
			dem_string_appends_prefix(prefix, "(&");
		} else if (is_rvalue_ref) {
			dem_string_appends_prefix(prefix, "(&&");
		} else {
			dem_string_appends_prefix(prefix, "(*");
		}

		if (begin < end && begin[0] == '$') {
			// append operator return type
			char *type = borland_delphi_type(begin + 1, end, &begin);
			if (!type) {
				goto fail;
			}
			dem_string_appends_prefix(prefix, " ");
			dem_string_appends_prefix(prefix, type);
			free(type);
		}
	} else {
		if (is_reference) {
			dem_string_appends(suffix, " &");
			if (is_volatile) {
				dem_string_appends(suffix, " volatile");
				is_volatile = false;
			}
			if (is_const) {
				dem_string_appends(suffix, " const");
				is_const = false;
			}
		} else if (is_rvalue_ref) {
			dem_string_appends(suffix, " &&");
			if (is_volatile) {
				dem_string_appends(suffix, " volatile");
				is_volatile = false;
			}
			if (is_const) {
				dem_string_appends(suffix, " const");
				is_const = false;
			}
		}
	}

	dem_string_concat(prefix, suffix);
	dem_string_free(suffix);

	if (is_function) {
		dem_string_appends(prefix, ")");
	}

	*leftovers = begin;
	return dem_string_drain(prefix);

fail:
	dem_string_free(suffix);
	dem_string_free(prefix);
	return NULL;
}

bool borland_delphi_class(DemString *ds, const char *begin, const char *end, const char **leftovers) {
	const char *tmp = NULL, *last_obj = NULL;
	bool has_class = false;
	bool has_class_tor = false;
	while ((tmp = strchr(begin, '@')) && tmp < end) {
		const char *dollar = strchr(begin, '$');
		if (dollar && dollar < tmp) {
			break;
		}
		// @class...
		if (has_class) {
			dem_string_appends(ds, "::");
		}
		dem_string_append_n(ds, begin, tmp - begin);
		last_obj = begin;
		begin = tmp + 1;
		has_class = true;
	}

	if (has_class) {
		dem_string_appends(ds, "::");
	}

	if (!(tmp = strchr(begin, '$'))) {
		if (begin < end) {
			dem_string_append_n(ds, begin, end - begin);
		}
		return false;
	}

	if (startwith(tmp, "$cntr")) {
		// $cntr | default constructor with no parameters
		dem_string_appendf(ds, "%.*s", (int)(begin - last_obj - 1), last_obj);
		begin = tmp + 5; // @ + strlen("$cntr")
		has_class_tor = true;
	} else if (startwith(tmp, "$bdtr") || startwith(tmp, "$dqdt")) {
		// $bdtr | default destructor with no parameters
		// $dqdt | destructor with parameters using the double register calling convention
		dem_string_appendf(ds, "~%.*s", (int)(begin - last_obj - 1), last_obj);
		begin = tmp + (IS_DIGIT(tmp[5]) ? 6 : 5); // @ + strlen("$cntr")
		has_class_tor = true;
	} else if (startwith(tmp, "$bctr") || startwith(tmp, "$qctr")) {
		/**
		 * - $bctr | constructor with parameters using the fastcall calling convention
		 * - $qctr | constructor with parameters using the register calling convention
		 */
		dem_string_appendf(ds, "%.*s", (int)(begin - last_obj - 1), last_obj);
		begin = tmp + (IS_DIGIT(tmp[5]) ? 6 : 5); // @ + strlen("$bctr")
		has_class_tor = true;
	} else if (startwith(tmp, "$dqctr")) {
		// $dqctr | constructor with parameters using the double register calling convention
		dem_string_appendf(ds, "%.*s", (int)(begin - last_obj - 1), last_obj);
		begin = tmp + 6; // @ + strlen("$dqctr")
		has_class_tor = true;
	}
	if (!(tmp = strchr(begin, '$'))) {
		if (has_class_tor) {
			dem_string_appends(ds, "()");
		}
		if (begin < end) {
			dem_string_append_n(ds, begin, end - begin);
		}
		return false;
	}
	*leftovers = begin;

	return true;
}

const char *borland_delphi_get_type(DemList *types, const char *begin, const char *end, const char **leftovers) {
	size_t idx = 10;
	if (IS_LOWER(begin[0])) {
		// offset +10
		idx += begin[0] - 'a';
		*leftovers = begin + 1;
	} else {
		idx = borland_delphi_parse_len(begin, end, leftovers);
	}
	if (idx < 1) {
		return NULL;
	}
	return (const char *)dem_list_get_n(types, idx - 1);
}

/**
 * \brief   Demangles borland delphi symbols
 *
 * \param   mangled   The mangled string
 *
 * \return  Demangled string on success otherwise NULL
 */
char *demangle_borland_delphi(const char *mangled) {
	if (!mangled || mangled[0] != '@') {
		return NULL;
	}

	size_t mangled_len = strlen(mangled);
	if (mangled_len < 3) {
		return NULL;
	}

	bool is_template = false;
	const char *begin = mangled + 1, *tmp = NULL;
	const char *end = mangled + mangled_len;
	DemList *types = dem_list_newf(free);
	DemString *prefix = dem_string_new();
	DemString *suffix = dem_string_new();
	if (!prefix || !suffix || !types) {
		goto demangle_fail;
	}

	if (begin[0] == '%') {
		is_template = true;
		begin++;
		if (begin >= end) {
			goto demangle_fail;
		}
	}

	if (!borland_delphi_class(prefix, begin, end, &begin)) {
		goto finish;
	}

	if (begin[0] == '%') {
		is_template = true;
		begin++;
		if (begin >= end) {
			goto demangle_fail;
		}
	}

	tmp = strchr(begin, '$');
	dem_string_append_n(prefix, begin, tmp - begin);
	begin = tmp + 1;

	for (size_t k = 0; k < RZ_ARRAY_SIZE(cxx_mem_operators); ++k) {
		borland_repl_t *op = &cxx_mem_operators[k];
		if (!strncmp(begin, op->pfx, op->pfx_len)) {
			dem_string_append_n(prefix, op->str, op->str_len);
			begin += op->pfx_len;
			goto finish;
		}
	}

	for (size_t k = 0; k < RZ_ARRAY_SIZE(cxx_operators); ++k) {
		borland_repl_t *op = &cxx_operators[k];
		if (!strncmp(begin, op->pfx, op->pfx_len)) {
			dem_string_append_n(prefix, op->str, op->str_len);
			begin += op->pfx_len;
			if (!(begin = strchr(begin, '$'))) {
				dem_string_appends(prefix, "()");
				if (begin < end) {
					dem_string_append_n(prefix, begin, end - begin);
				}
				goto finish;
			}
			begin++;
			break;
		}
	}

	if (is_template) {
		dem_string_appends(prefix, "<");
		for (int n = 0; begin < end && begin[0] != '%'; n++) {
			if (n > 0) {
				dem_string_appends(prefix, ", ");
			}
			if (begin[0] == 't') {
				const char *ctype = borland_delphi_get_type(types, begin + 1, end, &begin);
				if (!ctype) {
					goto demangle_fail;
				}
				dem_string_append(prefix, ctype);
			} else {
				bool is_custom = IS_DIGIT(begin[0]);
				char *type = borland_delphi_type(begin, end, &begin);
				if (!type) {
					goto demangle_fail;
				}
				dem_string_append(prefix, type);
				if (is_custom) {
					dem_list_append(types, type);
				} else {
					free(type);
				}
			}
		}
		dem_string_appends(prefix, ">");
		begin++;

		// append any missing function name
		while (begin < end && begin[0] == '@') {
			dem_string_appends(prefix, "::");
			begin++;
			tmp = strchr(begin, '@');
			if (!tmp) {
				tmp = strchr(begin, '$');
				if (!tmp) {
					goto demangle_fail;
				}
			}
			dem_string_append_n(prefix, begin, tmp - begin);
			begin = tmp;
		}

		// must end in $
		if (begin >= end || (begin[0] != '$')) {
			goto demangle_fail;
		}
		begin++;
	}

	if (begin >= end) {
		goto demangle_fail;
	}
	for (; begin < end; ++begin) {
		switch (begin[0]) {
		case 'x':
			dem_string_appends(suffix, " const");
			continue;
		case 'w':
			dem_string_appends(suffix, " volatile");
			continue;
		case 'o':
			tmp = borland_delphi_type(begin + 1, strchr(begin, '$'), &begin);
			if (!tmp) {
				goto demangle_fail;
			}
			dem_string_appendf(prefix, "operator %s", tmp);
			free((void *)tmp);
			continue;
		case 'q':
			goto procedure;
		default:
			goto demangle_fail;
		}
	}

procedure:
	if (begin >= end) {
		goto demangle_fail;
	}
	// what follows is a procedure call.
	bool first_type = true;
	dem_string_appends(prefix, "(");
	for (tmp = begin + 1; tmp < end && tmp[0] != '$'; ++tmp) {
		if (!first_type) {
			dem_string_appends(prefix, ", ");
		}

		if (tmp[0] == 'q') {
			tmp++;
			if (!borland_delphi_procedure_call_type(prefix, tmp, end)) {
				goto demangle_fail;
			}
			continue; // we haven't appended yet any arg type
		} else if (tmp[0] == 't') {
			const char *ctype = borland_delphi_get_type(types, tmp + 1, end, &tmp);
			if (!ctype) {
				goto demangle_fail;
			}
			dem_string_append(prefix, ctype);
			tmp--;
		} else {
			bool is_custom = IS_DIGIT(tmp[0]);
			char *type = borland_delphi_type(tmp, end, &tmp);
			if (!type) {
				goto demangle_fail;
			}
			dem_string_append(prefix, type);
			if (is_custom) {
				dem_list_append(types, type);
			} else {
				free(type);
			}
			tmp--;
		}
		first_type = false;
	}
	dem_string_appends(prefix, ")");

	if (tmp < end && tmp[0] == '$') {
		// append operator return type
		char *type = borland_delphi_type(tmp + 1, end, &tmp);
		if (!type) {
			goto demangle_fail;
		}
		dem_string_appends_prefix(prefix, " ");
		dem_string_appends_prefix(prefix, type);
		free(type);
	}

	begin = tmp;

finish:
	dem_string_concat(prefix, suffix);
	dem_string_free(suffix);
	dem_list_free(types);
	return dem_string_drain(prefix);

demangle_fail:
	dem_string_free(prefix);
	dem_string_free(suffix);
	dem_list_free(types);
	return NULL;
}
