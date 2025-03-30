// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangler_util.h"
#include "borland.h"
#include "cxx.h"
#include <rz_libdemangle.h>

#if WITH_GPL
// ansidecl.h makes a mess with the definition of
// const. thus we directly avoid to import the
// demangle.h header and instead define the data here.
#define DMGL_PARAMS (1 << 0) | (1 << 1) /* Include function args and ANSI qualifiers */

char *cplus_demangle_v3(const char *mangled, int options);
char *cplus_demangle_v2(const char *mangled, int options);

#define PRFX(x) \
	{ x, strlen(x) }

typedef struct cxx_prefix_t {
	const char *name;
	uint32_t size;
} CxxPrefix;

typedef struct cxx_replace_pair_t {
	const char *replace;
	const char *search;
} CxxReplacePair;

#define STD_CTOR_DTOR(r, t) \
	{ "std::" r "::" r, "std::" r "::" t }, \
	{ "std::" r "::~" r, "std::" r "::~" t }

#define STD_BASIC_CHAR(r, k) \
	{ "std::" r, "std::basic_" k "<char, std::char_traits<char> >" }, \
		{ "std::" r, "std::basic_" k "<char, std::char_traits<char > >" }, \
		STD_CTOR_DTOR(r, "basic_" k), \
		{ "std::w" r, "std::basic_" k "<wchar_t, std::char_traits<wchar_t> >" }, \
		{ "std::w" r, "std::basic_" k "<wchar_t, std::char_traits<wchar_t > >" }, \
		STD_CTOR_DTOR("w" r, "basic_" k)

#define STD_BASIC_WITH_ALLOC_TYPED(r, k, t) \
	{ "std::" r, "std::basic_" k "<" t ", std::char_traits<" t ">, std::allocator<" t "> >" }, \
		{ "std::" r, "std::basic_" k "<" t ", std::char_traits<" t ">, std::allocator<" t " > >" }, \
		STD_CTOR_DTOR(r, "basic_" k)

#define STD_BASIC_WITH_ALLOC_CHAR(r, k) \
	STD_BASIC_WITH_ALLOC_TYPED(r, k, "char"), \
		STD_BASIC_WITH_ALLOC_TYPED("w" r, k, "wchar_t")

#define STD_BASIC_REGEX(p, t) \
	{ "std::" p "regex", "std::basic_regex<" t ", std::regex_traits<" t "> >" }, \
		{ "std::" p "csub_match", "std::sub_match<" t " const*>" }, \
		{ "std::" p "ssub_match", "std::sub_match<std::" p "string>" }, \
		{ "std::" p "csub_match", "std::sub_match<iterator<" t "> >" }, \
		{ "std::" p "ssub_match", "std::sub_match<std::" p "string::const_iterator>" }, \
		{ "std::" p "cmatch", "std::match_results<iterator<" t ">, std::allocator<std::" p "csub_match > >" }, \
		{ "std::" p "smatch", "std::match_results<std::" p "string::const_iterator, std::allocator<std::" p "csub_match > >" }, \
		{ "std::" p "cmatch", "std::match_results<" t " const*, std::allocator<std::" p "csub_match > >" }, \
		{ "std::" p "smatch", "std::match_results<std::" p "string, std::allocator<std::" p "csub_match > >" }, \
		{ "std::__detail::_Executor<" t ",", "std::__detail::_Executor<" t " const*, std::allocator<std::" p "csub_match >, std::regex_traits<" t ">," }, \
		{ "std::__detail::_Executor<" t ",", "std::__detail::_Executor<iterator<" t ">, std::allocator<std::" p "csub_match >, std::regex_traits<" t ">," }, \
		{ "std::regex_match<" t ">", "std::regex_match<" t ", std::allocator<std::" p "csub_match >, std::regex_traits<" t "> >" }, \
		{ "std::regex_match<" t ">", "std::regex_match<" t " const*, std::allocator<std::" p "csub_match >, " t ", std::regex_traits<" t "> >" }, \
		{ "std::regex_match<" t ">", "std::regex_match<iterator<" t ">, std::allocator<std::" p "csub_match >, " t ", std::regex_traits<" t "> >" }, \
		{ "std::regex_match<std::" p "string>", "std::regex_match<std::char_traits<" t ">, std::allocator<" t ">, std::allocator<std::" p "csub_match >, " t ", std::regex_traits<" t "> >" }, \
		{ "std::regex_search<" t ">", "std::regex_search<" t ", std::allocator<std::" p "csub_match >, std::regex_traits<" t "> >" }, \
		{ "std::regex_search<" t ">", "std::regex_search<" t " const*, std::allocator<std::" p "csub_match >, " t ", std::regex_traits<" t "> >" }, \
		{ "std::regex_search<" t ">", "std::regex_search<iterator<" t ">, std::allocator<std::" p "csub_match >, " t ", std::regex_traits<" t "> >" }, \
		{ "std::regex_search<std::" p "string>", "std::regex_search<std::char_traits<" t ">, std::allocator<" t ">, std::allocator<std::" p "csub_match >, " t ", std::regex_traits<" t "> >" }

static const CxxReplacePair cplus_typedefs[] = {
	STD_BASIC_WITH_ALLOC_CHAR("string", "string"),
	STD_BASIC_WITH_ALLOC_TYPED("u8string", "string", "char8_t"),
	STD_BASIC_WITH_ALLOC_TYPED("u16string", "string", "char16_t"),
	STD_BASIC_WITH_ALLOC_TYPED("u32string", "string", "char32_t"),
	STD_BASIC_WITH_ALLOC_CHAR("stringstream", "stringstream"),
	STD_BASIC_WITH_ALLOC_CHAR("istringstream", "istringstream"),
	STD_BASIC_WITH_ALLOC_CHAR("ostringstream", "ostringstream"),
	STD_BASIC_WITH_ALLOC_CHAR("stringbuf", "stringbuf"),
	STD_BASIC_CHAR("ios", "ios"),
	STD_BASIC_CHAR("istream", "istream"),
	STD_BASIC_CHAR("ostream", "ostream"),
	STD_BASIC_CHAR("iostream", "iostream"),
	STD_BASIC_CHAR("fstream", "fstream"),
	STD_BASIC_CHAR("ifstream", "ifstream"),
	STD_BASIC_CHAR("ofstream", "ofstream"),
	STD_BASIC_CHAR("streambuf", "streambuf"),
	STD_BASIC_CHAR("filebuf", "filebuf"),
	// other
	{ "std::ios_base::openmode", "std::_Ios_Openmode" },
	{ "std::ios_base::fmtflags", "std::_Ios_Fmtflags" },
	{ "std::list::const_iterator", "std::_List_const_iterator" },
	{ "std::list::iterator", "std::_List_iterator" },
	{ "std::forward_list::const_iterator", "std::_Fwd_list_const_iterator" },
	{ "std::forward_list::iterator", "std::_Fwd_list_iterator" },
	{ "std::deque::iterator", "std::_Deque_iterator" },
	{ "iterator", "__normal_iterator" },
	// known iterators
	{ "iterator<char>", "iterator<char const*, std::string >" },
	{ "iterator<wchar_t>", "iterator<wchar_t const*, std::wstring >" },
	// usually operators
	{ "<char>", "<char, std::char_traits<char>, iterator<char> >" },
	{ "<wchar_t>", "<wchar_t, std::char_traits<wchar_t>, iterator<wchar_t> >" },
	// regex
	STD_BASIC_REGEX("w", "wchar_t"),
	STD_BASIC_REGEX("", "char"),
	STD_CTOR_DTOR("regex", "basic_regex"),
};

static size_t cplus_find_type_length(const char *input) {
	size_t length = strlen(input);
	for (size_t i = 0, template = 0; i < length; ++i) {
		if (template <1 && input[i] == ',') {
			return i;
		} else if (template > 0 && input[i] == '>') {
			template --;
		} else if (input[i] == '<') {
			template ++;
		}
	}
	return 0;
}

static char *cplus_replace_std_map(char *input) {
	char *p = strstr(input, "std::map<");
	if (!p) {
		return input;
	}
	p += strlen("std::map<");
	size_t length = cplus_find_type_length(p);
	if (length < 1) {
		return input;
	}
	char *ktype = dem_str_ndup(p, length);
	p += strlen(ktype) + 2; // `<type, `
	length = cplus_find_type_length(p);
	if (length < 1) {
		free(ktype);
		return input;
	}

	char *vtype = dem_str_ndup(p, length);
	char *replace = dem_str_newf("std::map<%s, %s>", ktype, vtype);
	char *search = dem_str_newf("std::map<%s, %s, std::less<%s >, std::allocator<std::pair<%s const, %s > > >", ktype, vtype, ktype, ktype, vtype);
	char *output = dem_str_replace(input, search, replace, 1);
	free(search);
	// sometimes std::pair has an extra space
	search = dem_str_newf("std::map<%s, %s, std::less<%s >, std::allocator<std::pair<%s const, %s> > >", ktype, vtype, ktype, ktype, vtype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	free(replace);
	free(ktype);
	free(vtype);
	return output;
}

static char *cplus_replace_std_multimap(char *input) {
	char *p = strstr(input, "std::multimap<");
	if (!p) {
		return input;
	}
	p += strlen("std::multimap<");
	size_t length = cplus_find_type_length(p);
	if (length < 1) {
		return input;
	}
	char *ktype = dem_str_ndup(p, length);
	p += strlen(ktype) + 2; // `<type, `
	length = cplus_find_type_length(p);
	if (length < 1) {
		free(ktype);
		return input;
	}

	char *vtype = dem_str_ndup(p, length);
	char *replace = dem_str_newf("std::multimap<%s, %s>", ktype, vtype);
	char *search = dem_str_newf("std::multimap<%s, %s, std::less<%s>, std::allocator<std::pair<%s const, %s > > >", ktype, vtype, ktype, ktype, vtype);
	char *output = dem_str_replace(input, search, replace, 1);
	free(search);
	// sometimes std::pair has an extra space
	search = dem_str_newf("std::multimap<%s, %s, std::less<%s>, std::allocator<std::pair<%s const, %s> > >", ktype, vtype, ktype, ktype, vtype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	search = dem_str_newf("std::multimap<%s, %s, std::greater<%s>, std::allocator<std::pair<%s const, %s>> >", ktype, vtype, ktype, ktype, vtype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	// sometimes std::pair has an extra space
	search = dem_str_newf("std::multimap<%s, %s, std::greater<%s>, std::allocator<std::pair<%s const, %s> > >", ktype, vtype, ktype, ktype, vtype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	free(replace);
	free(ktype);
	free(vtype);
	return output;
}

static char *cplus_replace_std_set(char *input) {
	char *p = strstr(input, "std::set<");
	if (!p) {
		return input;
	}
	p += strlen("std::set<");
	size_t length = cplus_find_type_length(p);
	if (length < 1) {
		return input;
	}
	char *ktype = dem_str_ndup(p, length);
	char *replace = dem_str_newf("std::set<%s>", ktype);
	char *search = dem_str_newf("std::set<%s, std::less<%s>, std::allocator<%s> >", ktype, ktype, ktype);
	char *output = dem_str_replace(input, search, replace, 1);
	free(search);
	// sometimes std::allocator has an extra space
	search = dem_str_newf("std::set<%s, std::less<%s>, std::allocator<%s > >", ktype, ktype, ktype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	free(replace);
	free(ktype);
	return output;
}

static char *cplus_replace_std_multiset(char *input) {
	char *p = strstr(input, "std::multiset<");
	if (!p) {
		return input;
	}
	p += strlen("std::multiset<");
	size_t length = cplus_find_type_length(p);
	if (length < 1) {
		return input;
	}
	char *ktype = dem_str_ndup(p, length);
	char *replace = dem_str_newf("std::multiset<%s>", ktype);
	char *search = dem_str_newf("std::multiset<%s, std::less<%s>, std::allocator<%s> >", ktype, ktype, ktype);
	char *output = dem_str_replace(input, search, replace, 1);
	free(search);
	// sometimes std::allocator has an extra space
	search = dem_str_newf("std::multiset<%s, std::less<%s>, std::allocator<%s > >", ktype, ktype, ktype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	search = dem_str_newf("std::multiset<%s, std::greater<%s>, std::allocator<%s> >", ktype, ktype, ktype);
	output = dem_str_replace(input, search, replace, 1);
	free(search);
	// sometimes std::allocator has an extra space
	search = dem_str_newf("std::multiset<%s, std::greater<%s>, std::allocator<%s > >", ktype, ktype, ktype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	free(replace);
	free(ktype);
	return output;
}

static char *cplus_replace_std_unordered(char *input, const char *prefix) {
	char *p = strstr(input, prefix);
	if (!p) {
		return input;
	}
	p += strlen(prefix);
	size_t length = cplus_find_type_length(p);
	if (length < 1) {
		return input;
	}
	char *ktype = dem_str_ndup(p, length);
	char *replace = dem_str_newf("%s%s>", prefix, ktype);
	char *search = dem_str_newf("%s%s, std::hash<%s>, std::equal_to<%s>, std::allocator<%s > >", prefix, ktype, ktype, ktype, ktype);
	char *output = dem_str_replace(input, search, replace, 1);
	free(search);
	// sometimes std::pair has an extra space
	search = dem_str_newf("%s%s, std::hash<%s>, std::equal_to<%s>, std::allocator<%s> >", prefix, ktype, ktype, ktype, ktype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	free(replace);
	free(ktype);
	return output;
}

static char *cplus_replace_std_unordered_pair(char *input, const char *prefix) {
	char *p = strstr(input, prefix);
	if (!p) {
		return input;
	}
	p += strlen(prefix);
	size_t length = cplus_find_type_length(p);
	if (length < 1) {
		return input;
	}
	char *ktype = dem_str_ndup(p, length);
	p += strlen(ktype) + 2; // `<type, `
	length = cplus_find_type_length(p);
	if (length < 1) {
		free(ktype);
		return input;
	}

	char *vtype = dem_str_ndup(p, length);
	char *replace = dem_str_newf("%s%s, %s>", prefix, ktype, vtype);
	char *search = dem_str_newf("%s%s, %s, std::hash<%s >, std::equal_to<%s >, std::allocator<std::pair<%s const, %s > > >", prefix, ktype, vtype, ktype, ktype, ktype, vtype);
	char *output = dem_str_replace(input, search, replace, 1);
	free(search);
	// sometimes std::pair has an extra space
	search = dem_str_newf("%s%s, %s, std::hash<%s >, std::equal_to<%s >, std::allocator<std::pair<%s const, %s> > >", prefix, ktype, vtype, ktype, ktype, ktype, vtype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	free(replace);
	free(ktype);
	free(vtype);
	return output;
}

static char *cplus_replace_std_alloc(char *input, const char *old_prefix, const char *new_prefix) {
	char *p = strstr(input, old_prefix);
	if (!p) {
		return input;
	}
	p += strlen(old_prefix);
	size_t length = cplus_find_type_length(p);
	if (!length) {
		return input;
	}
	char *vtype = dem_str_ndup(p, length);
	char *replace = dem_str_newf("%s%s>", new_prefix, vtype);
	char *search = dem_str_newf("%s%s, std::allocator<%s> >", old_prefix, vtype, vtype);
	char *output = dem_str_replace(input, search, replace, 1);
	free(search);
	search = dem_str_newf("%s%s, std::allocator<%s > >", old_prefix, vtype, vtype);
	output = dem_str_replace(output, search, replace, 1);
	free(search);
	free(replace);
	free(vtype);
	return output;
}

static char *cplus_replace_std_iterator(char *input, const char *prefix, const char *suffix) {
	char *p = strstr(input, prefix);
	if (!p) {
		return input;
	}
	p += strlen(prefix);
	size_t length = cplus_find_type_length(p);
	if (length < 1) {
		return input;
	}
	char *vtype = NULL;
	char *ktype = dem_str_ndup(p, length);
	p += strlen(ktype) + 2; // `<type, `
	length = cplus_find_type_length(p);
	if (length > 0) {
		vtype = dem_str_ndup(p, length);
		if (!strncmp(vtype, "std::char_traits<", strlen("std::char_traits<"))) {
			RZ_FREE(vtype);
		}
	}

	char *search = NULL;
	char *output = input;
	char *replace = dem_str_newf("%s%s>", prefix, ktype);

	if (vtype) {
		search = dem_str_newf("%s%s, %s, std::char_traits<%s>%s>", prefix, ktype, vtype, vtype, suffix);
	} else {
		search = dem_str_newf("%s%s, std::char_traits<%s>%s>", prefix, ktype, ktype, suffix);
	}
	output = dem_str_replace(output, search, replace, 1);
	free(search);

	if (vtype) {
		search = dem_str_newf("%s%s, %s, std::char_traits<%s >%s>", prefix, ktype, vtype, vtype, suffix);
	} else {
		search = dem_str_newf("%s%s, std::char_traits<%s >%s>", prefix, ktype, ktype, suffix);
	}
	output = dem_str_replace(output, search, replace, 1);
	free(search);

	free(replace);
	free(ktype);
	free(vtype);
	return output;
}

static char *cplus_replace_std_typedefs(char *input) {
	if (!strstr(input, "std::")) {
		return dem_str_replace(input, "__gnu_cxx::", "", 1);
	}
	char *output = dem_str_replace(input, "std::__1::", "std::", 1); // LLVM
	output = dem_str_replace(output, "std::__cxx11::", "std::", 1); // GCC
	output = dem_str_replace(output, "__gnu_cxx::", "", 1); // GCC
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cplus_typedefs); i++) {
		const char *search = cplus_typedefs[i].search;
		const char *replace = cplus_typedefs[i].replace;
		output = dem_str_replace(output, search, replace, 1);
	}
	output = cplus_replace_std_alloc(output, "std::list<", "std::list<");
	output = cplus_replace_std_alloc(output, "std::_List_base<", "std::list<");
	output = cplus_replace_std_alloc(output, "std::forward_list<", "std::forward_list<");
	output = cplus_replace_std_alloc(output, "std::_Fwd_list_<", "std::forward_list<");
	output = cplus_replace_std_alloc(output, "std::deque<", "std::deque<");
	output = cplus_replace_std_alloc(output, "std::_Deque_base<", "std::deque<");
	output = cplus_replace_std_alloc(output, "std::vector<", "std::vector<");
	output = cplus_replace_std_alloc(output, "std::_Vector_base<", "std::vector<");
	output = cplus_replace_std_set(output);
	output = cplus_replace_std_multiset(output);
	output = cplus_replace_std_map(output);
	output = cplus_replace_std_multimap(output);
	output = cplus_replace_std_unordered(output, "std::unordered_set<");
	output = cplus_replace_std_unordered(output, "std::unordered_multiset<");
	output = cplus_replace_std_unordered_pair(output, "std::unordered_map<");
	output = cplus_replace_std_unordered_pair(output, "std::unordered_multimap<");
	output = cplus_replace_std_iterator(output, "std::istream_iterator<", ", long");
	output = cplus_replace_std_iterator(output, "std::ostream_iterator<", " ");
	output = cplus_replace_std_iterator(output, "std::istreambuf_iterator<", " ");
	output = cplus_replace_std_iterator(output, "std::ostreambuf_iterator<", " ");

	return output;
}

char *demangle_gpl_cxx(const char *str, bool simplify) {
	uint32_t i;
	CxxPrefix prefixes[] = {
		PRFX("__symbol_stub1_"),
		PRFX("stub."),
	};
	char *tmpstr = strdup(str);
	if (!tmpstr) {
		return NULL;
	}
	char *p = tmpstr;

	while (p[0] == p[1] && *p == '_') {
		p++;
	}
	for (i = 0; i < RZ_ARRAY_SIZE(prefixes); i++) {
		if (!strncmp(p, prefixes[i].name, prefixes[i].size)) {
			p += prefixes[i].size;
			break;
		}
	}
	// remove CXXABI suffix
	char *cxxabi = strstr(p, "@@CXXABI");
	char *glibcxx = strstr(p, "@GLIBCXX");
	if (cxxabi) {
		*cxxabi = '\0';
	} else if (glibcxx) {
		if (p < glibcxx && glibcxx[-1] == '@') {
			glibcxx[-1] = '\0';
		} else {
			*glibcxx = '\0';
		}
	}

	char *block_invoke = find_block_invoke(p);
	if (block_invoke) {
		block_invoke[0] = 0;
	} else {
		uint32_t len = strlen(p);
		uint32_t _ptrlen = strlen("_ptr");
		if (len > _ptrlen && !strncmp(p + len - _ptrlen, "_ptr", _ptrlen)) {
			// remove _ptr from the end
			*(p + len - _ptrlen) = '\0';
		} else if (len > 1 && IS_DIGIT(*(p + len - 1))) {
			// removes version sequences like _5_2 or _18_4 etc... from the end
			bool expect_digit = true;
			bool expect_underscore = false;
			for (i = len - 1; i > 0; i--) {
				if (expect_digit && IS_DIGIT(p[i])) {
					if (p[i - 1] == '_') {
						expect_underscore = true;
						expect_digit = false;
					} else if (!IS_DIGIT(p[i - 1])) {
						break;
					}
				} else if (expect_underscore && p[i] == '_') {
					p[i] = '\0';
					if (!IS_DIGIT(p[i - 1])) {
						break;
					} else {
						expect_underscore = false;
						expect_digit = true;
					}
				}
			}
		}
	}

	char *out = cplus_demangle_v3(p, DMGL_PARAMS);
	if (!out) {
		free(tmpstr);
		return NULL;
	}

	if (simplify) {
		out = cplus_replace_std_typedefs(out);
	}
	if (block_invoke) {
		DemString *ds = dem_string_new();
		dem_string_append(ds, out);
		dem_string_appendf(ds, " %s", block_invoke + 1);
		free(out);
		out = dem_string_drain(ds);
	}
	free(tmpstr);

	return out;
}
#endif

char *find_block_invoke(char *p) {
	const size_t kwlen = strlen("_block_invoke");
	char *last = NULL;
	char *next = p;
	while ((next = strstr(next, "_block_invoke"))) {
		last = next;
		next += kwlen;
	}
	return last;
}

DEM_LIB_EXPORT char *libdemangle_handler_cxx(const char *symbol, RzDemangleOpts opts) {
	char *result = demangle_borland_delphi(symbol);
	if (result) {
		return result;
	}

#if WITH_GPL
	result = cplus_demangle_v2(symbol, DMGL_PARAMS);
	if (result) {
		return result;
	}
	return demangle_gpl_cxx(symbol, opts & RZ_DEMANGLE_OPT_SIMPLIFY);
#else
	return NULL;
#endif
}
