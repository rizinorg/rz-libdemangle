// SPDX-FileCopyrightText: 2015-2016 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "microsoft_demangle.h"
#include <ctype.h>

#define MICROSOFT_NAME_LEN            (256)
#define MICROSOFR_CLASS_NAMESPACE_LEN (256)
#define IMPOSSIBLE_LEN                (MICROSOFT_NAME_LEN + MICROSOFR_CLASS_NAMESPACE_LEN)

typedef struct SAbbrState {
	DemList *types;
	DemList *names;
} SAbbrState;

typedef enum EObjectType {
	eObjectTypeStaticClassMember = 2,
	eObjectTypeGlobal = 3,
	eObjectTypeMax = 99
} EObjectType;

///////////////////////////////////////////////////////////////////////////////
// State machine for parsing type codes data types
///////////////////////////////////////////////////////////////////////////////
typedef enum ETCStateMachineErr {
	eTCStateMachineErrOK,
	eTCStateMachineErrUncorrectTypeCode,
	eTCStateMachineErrUnsupportedTypeCode,
	eTCStateMachineErrAlloc,
	eTCStateMachineErrMax
} ETCStateMachineErr;

typedef enum ETCState { // TC - type code
	eTCStateStart = 0,
	eTCStateEnd,
	eTCStateA,
	eTCStateB,
	eTCStateC,
	eTCStateD,
	eTCStateE,
	eTCStateF,
	eTCStateG,
	eTCStateH,
	eTCStateI,
	eTCStateJ,
	eTCStateK,
	eTCStateM,
	eTCStateN,
	eTCStateO,
	eTCStateP,
	eTCStateQ,
	eTCStateR,
	eTCStateS,
	eTCStateT,
	eTCStateU,
	eTCStateV,
	eTCStateW,
	eTCStateX,
	eTCStateZ,
	eTCState_,
	eTCState$,
	eTCStateMax
} ETCState;

typedef struct STypeCodeStr {
	char *type_str;
	char type_str_buf[MICROSOFT_NAME_LEN];
	size_t type_str_len;
	size_t curr_pos;
} STypeCodeStr;

struct SStateInfo;
typedef void (*state_func)(SAbbrState *abbr, struct SStateInfo *, STypeCodeStr *type_code_str);

typedef struct SStateInfo {
	ETCState state;
	const char *buff_for_parsing;
	size_t amount_of_read_chars;
	ETCStateMachineErr err;
} SStateInfo;

typedef struct SStrInfo {
	char *str_ptr;
	size_t len;
} SStrInfo;

typedef struct SDataType {
	char *left;
	char *right;
} SDataType;

static inline void sdatatype_fini(SDataType *data_type) {
	if (!data_type) {
		return;
	}
	RZ_FREE(data_type->left);
	RZ_FREE(data_type->right);
}

static void sstrinfo_free(SStrInfo *sstrinfo) {
	if (!sstrinfo) {
		return;
	}
	free(sstrinfo->str_ptr);
	free(sstrinfo);
}

#define DECL_STATE_ACTION(action) static void tc_state_##action(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str);
DECL_STATE_ACTION(start)
DECL_STATE_ACTION(end)
DECL_STATE_ACTION(A)
DECL_STATE_ACTION(B)
DECL_STATE_ACTION(C)
DECL_STATE_ACTION(D)
DECL_STATE_ACTION(E)
DECL_STATE_ACTION(F)
DECL_STATE_ACTION(G)
DECL_STATE_ACTION(H)
DECL_STATE_ACTION(I)
DECL_STATE_ACTION(J)
DECL_STATE_ACTION(K)
DECL_STATE_ACTION(M)
DECL_STATE_ACTION(N)
DECL_STATE_ACTION(O)
DECL_STATE_ACTION(P)
DECL_STATE_ACTION(Q)
DECL_STATE_ACTION(R)
DECL_STATE_ACTION(S)
DECL_STATE_ACTION(T)
DECL_STATE_ACTION(U)
DECL_STATE_ACTION(V)
DECL_STATE_ACTION(W)
DECL_STATE_ACTION(X)
DECL_STATE_ACTION(Z)
DECL_STATE_ACTION(_)
DECL_STATE_ACTION($)
#undef DECL_STATE_ACTION

#define NAME(action) tc_state_##action
static state_func const state_table[eTCStateMax] = {
	NAME(start),
	NAME(end),
	NAME(A),
	NAME(B),
	NAME(C),
	NAME(D),
	NAME(E),
	NAME(F),
	NAME(G),
	NAME(H),
	NAME(I),
	NAME(J),
	NAME(K),
	NAME(M),
	NAME(N),
	NAME(O),
	NAME(P),
	NAME(Q),
	NAME(R),
	NAME(S),
	NAME(T),
	NAME(U),
	NAME(V),
	NAME(W),
	NAME(X),
	NAME(Z),
	NAME(_),
	NAME($),
};
#undef NAME
///////////////////////////////////////////////////////////////////////////////
// End of data types for state machine which parse type codes
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// State machine for parsing type codes functions
///////////////////////////////////////////////////////////////////////////////

static void init_state_struct(SStateInfo *state, const char *buff_for_parsing);
static EDemanglerErr get_type_code_string(SAbbrState *abbr, const char *sym, size_t *amount_of_read_chars, char **str_type_code);
static bool init_type_code_str_struct(STypeCodeStr *type_code_str);
static void free_type_code_str_struct(STypeCodeStr *type_code_str);
static char *type_code_str_get(STypeCodeStr *type_code_str);
static size_t get_template(SAbbrState *abbr, const char *buf, SStrInfo *str_info, bool memorize);
static char *get_num(SStateInfo *state);
static EDemanglerErr parse_data_type(SAbbrState *abbr, const char *sym, SDataType *demangled_type, size_t *len);
static size_t get_namespace_and_name(SAbbrState *abbr, const char *buf, STypeCodeStr *type_code_str, size_t *amount_of_names, bool memorize);
static inline EDemanglerErr get_storage_class(const char encoded, const char **storage_class);
static inline size_t get_ptr_modifier(const char *encoded, SDataType *ptr_modifier);
static EDemanglerErr parse_function(SAbbrState *abbr, const char *sym, STypeCodeStr *type_code_str, char **demangled_function, size_t *chars_read);
static EDemanglerErr parse_microsoft_mangled_name(SAbbrState *abbr, const char *sym, char **demangled_name, size_t *chars_read);
static EDemanglerErr parse_microsoft_rtti_mangled_name(SAbbrState *abbr, const char *sym, char **demangled_name, size_t *chars_read);

static void run_state(SAbbrState *abbr, SStateInfo *state_info, STypeCodeStr *type_code_str) {
	state_table[state_info->state](abbr, state_info, type_code_str);
}

#define copy_string(type_code_str, str_for_copy) copy_string_n(type_code_str, str_for_copy, str_for_copy ? strlen(str_for_copy) : 0)

static bool copy_string_n(STypeCodeStr *type_code_str, const char *str_for_copy, size_t copy_len) {
	if (!copy_len) {
		return true;
	}
	size_t free_space = type_code_str->type_str_len - type_code_str->curr_pos - 1;

	if (free_space < copy_len) {
		size_t newlen = type_code_str->type_str_len + copy_len;
		if (newlen < type_code_str->type_str_len) {
			return false;
		}
		newlen *= 2;
		if (newlen < type_code_str->type_str_len) {
			return false;
		}
		type_code_str->type_str_len = newlen;
		char *type_str;
		if (type_code_str->type_str != type_code_str->type_str_buf) {
			type_str = realloc(type_code_str->type_str, newlen);
		} else {
			type_str = malloc(newlen);
			if (!type_str) {
				return false;
			}
			memcpy(type_str, type_code_str->type_str, type_code_str->curr_pos);
		}
		if (!type_str) {
			return false;
		}
		type_code_str->type_str = type_str;
		if (!type_code_str->type_str) {
			return false;
		}
	}

	char *dst = type_code_str->type_str + type_code_str->curr_pos;
	if (str_for_copy) {
		memcpy(dst, str_for_copy, copy_len);
	} else {
		memset(dst, 0, copy_len);
	}
	type_code_str->curr_pos += copy_len;
	if (type_code_str->type_str) {
		type_code_str->type_str[type_code_str->curr_pos] = '\0';
	}
	return true;
}

static int get_template_params(SAbbrState *abbr, const char *sym, size_t *amount_of_read_chars, char **str_type_code) {
	SStateInfo state;
	init_state_struct(&state, sym);
	const char template_param[] = "template-parameter-";
	char *tmp, *res = NULL;
	const char *const start_sym = sym;
	if (!strncmp(sym, "?", 1)) {
		// anonymous template param
		state.amount_of_read_chars += 1;
		state.buff_for_parsing += 1;
		res = get_num(&state);
		if (res) {
			tmp = dem_str_newf("%s%s", template_param, res);
			free(res);
			res = tmp;
		}
	} else {
		if (strncmp(sym, "$", 1)) {
			return eDemanglerErrUncorrectMangledSymbol;
		}
		sym++;
		state.amount_of_read_chars += 2;
		state.buff_for_parsing += 2;
		char *a, *b, *c;
		switch (*sym) {
		case '0':
			// Signed integer
			a = get_num(&state);
			if (a) {
				int signed_a = atoi(a);
				res = dem_str_newf("%d", signed_a);
				free(a);
			}
			break;
		case '1': {
			STypeCodeStr str;
			EDemanglerErr err;
			if (!*(++sym) || !(*sym == '?')) {
				return eDemanglerErrUncorrectMangledSymbol;
			}
			if (!init_type_code_str_struct(&str)) {
				return eDemanglerErrMemoryAllocation;
			}
			size_t ret = get_namespace_and_name(abbr, ++sym, &str, NULL, true);
			if (!ret) {
				free_type_code_str_struct(&str);
				return eDemanglerErrUncorrectMangledSymbol;
			}
			sym += ret;
			if (!*sym) {
				free_type_code_str_struct(&str);
				return eDemanglerErrUncorrectMangledSymbol;
			}
			SDataType data_type = { 0 };
			if (isdigit((int)*++sym)) {
				err = parse_data_type(abbr, sym, &data_type, &ret);
				*str_type_code = dem_str_newf("&%s %s%s", data_type.left, str.type_str, data_type.right);
				sdatatype_fini(&data_type);
			} else {
				char *tmp = NULL;
				err = parse_function(abbr, sym, &str, &tmp, &ret);
				*str_type_code = dem_str_newf("&%s", tmp);
				free(tmp);
			}
			sym += ret;
			*amount_of_read_chars = sym - start_sym;
			free_type_code_str_struct(&str);
			return err;
		}
		case '2':
			// real value a ^ b
			a = get_num(&state);
			b = get_num(&state);
			if (a && b) {
				int signed_b = atoi(b);
				res = dem_str_newf("%sE%d", a, signed_b);
			}
			free(a);
			free(b);
			break;
		case 'D':
			// anonymous template param
			res = get_num(&state);
			if (res) {
				tmp = dem_str_newf("%s%s", template_param, res);
				free(res);
				res = tmp;
			}
			break;
		case 'F':
			// Signed {a, b}
			a = get_num(&state);
			b = get_num(&state);
			if (a && b) {
				int signed_a = atoi(a);
				int signed_b = atoi(b);
				res = dem_str_newf("{%d, %d}", signed_a, signed_b);
			}
			free(a);
			free(b);
			break;
		case 'G':
			// Signed {a, b, c}
			a = get_num(&state);
			b = get_num(&state);
			c = get_num(&state);
			if (a && b && c) {
				int signed_a = atoi(a);
				int signed_b = atoi(b);
				int signed_c = atoi(c);
				res = dem_str_newf("{%d, %d, %d}", signed_a, signed_b, signed_c);
			}
			free(a);
			free(b);
			free(c);
			break;
		case 'H':
			// Unsigned integer
			res = get_num(&state);
			break;
		case 'I':
			// Unsigned {x, y}
			a = get_num(&state);
			b = get_num(&state);
			if (a && b) {
				res = dem_str_newf("{%s, %s}", a, b);
			}
			free(a);
			free(b);
			break;
		case 'J':
			// Unsigned {x, y, z}
			a = get_num(&state);
			b = get_num(&state);
			c = get_num(&state);
			if (a && b && c) {
				res = dem_str_newf("{%s, %s, %s}", a, b, c);
			}
			free(a);
			free(b);
			free(c);
			break;
		case 'Q':
			// anonymous non-type template parameter
			res = get_num(&state);
			if (res) {
				tmp = dem_str_newf("non-type-%s%s", template_param, res);
				free(res);
				res = tmp;
			}
			break;
		case 'S':
			// empty non-type parameter pack
			res = strdup("");
			break;
		default:
			break;
		}
	}

	if (!res) {
		return eDemanglerErrUnsupportedMangling;
	}

	*str_type_code = res;
	*amount_of_read_chars = state.amount_of_read_chars;

	return eDemanglerErrOK;
}

static inline ut16 read_be16(const void *src) {
	const ut8 *s = (const ut8 *)src;
	return (((ut16)s[0]) << 8) | (((ut16)s[1]) << 0);
}

static ssize_t utf16be_to_utf8_impl(const char *utf16be, size_t utf16be_len, char *utf8, size_t utf8_len) {
	char *const outstart = utf8;
	char *const outend = utf8 + utf8_len;
	const ut16 *in = (const ut16 *)utf16be;
	ut32 c, d;
	int bits;

	const size_t inlen = utf16be_len / 2;
	const ut16 *const inend = in + inlen;
	while ((in < inend) && (utf8 - outstart + 5 < utf8_len)) {
		c = read_be16(in++);
		if ((c & 0xFC00) == 0xD800) { /* surrogates */
			if (in >= inend) { /* (in > inend) shouldn't happen */
				break;
			}
			d = read_be16(in++);
			if ((d & 0xFC00) == 0xDC00) {
				c &= 0x03FF;
				c <<= 10;
				c |= d & 0x03FF;
				c += 0x10000;
			} else {
				return -1;
			}
		}

		/* assertion: c is a single UTF-4 value */
		if (utf8 >= outend) {
			break;
		}
		if (c < 0x80) {
			*utf8++ = c;
			bits = -6;
		} else if (c < 0x800) {
			*utf8++ = ((c >> 6) & 0x1F) | 0xC0;
			bits = 0;
		} else if (c < 0x10000) {
			*utf8++ = ((c >> 12) & 0x0F) | 0xE0;
			bits = 6;
		} else {
			*utf8++ = ((c >> 18) & 0x07) | 0xF0;
			bits = 12;
		}

		for (; bits >= 0; bits -= 6) {
			if (utf8 >= outend) {
				break;
			}
			*utf8++ = ((c >> bits) & 0x3F) | 0x80;
		}
	}
	return utf8 - outstart;
}

static EDemanglerErr utf16be_to_utf8(const char *utf16be, size_t utf16be_len, char **utf8, size_t *utf8_len) {
	const size_t utf8_len_tmp = utf16be_len * 4;
	*utf8 = malloc(utf8_len_tmp);
	if (!*utf8) {
		return eDemanglerErrMemoryAllocation;
	}
	ssize_t res = utf16be_to_utf8_impl(utf16be, utf16be_len, *utf8, utf8_len_tmp);
	if (res < 0) {
		free(*utf8);
		return eDemanglerErrUncorrectMangledSymbol;
	}
	*utf8_len = res;
	return eDemanglerErrOK;
}

static size_t get_operator_code(SAbbrState *abbr, const char *buf, DemList *names_l, bool memorize) {
	// C++ operator code (one character, or two if the first is '_')
#define SET_OPERATOR_CODE(str) \
	{ \
		str_info = malloc(sizeof(SStrInfo)); \
		if (!str_info) \
			break; \
		str_info->len = strlen(str); \
		str_info->str_ptr = strdup(str); \
		dem_list_append(names_l, str_info); \
	}
	SStrInfo *str_info;
	size_t read_len = 1;
	switch (*++buf) {
	case '0': SET_OPERATOR_CODE("constructor"); break;
	case '1': SET_OPERATOR_CODE("~destructor"); break;
	case '2': SET_OPERATOR_CODE("operator new"); break;
	case '3': SET_OPERATOR_CODE("operator delete"); break;
	case '4': SET_OPERATOR_CODE("operator="); break;
	case '5': SET_OPERATOR_CODE("operator>>"); break;
	case '6': SET_OPERATOR_CODE("operator<<"); break;
	case '7': SET_OPERATOR_CODE("operator!"); break;
	case '8': SET_OPERATOR_CODE("operator=="); break;
	case '9': SET_OPERATOR_CODE("operator!="); break;
	case 'A': SET_OPERATOR_CODE("operator[]"); break;
	case 'B': SET_OPERATOR_CODE("operator #{return_type}"); break;
	case 'C': SET_OPERATOR_CODE("operator->"); break;
	case 'D': SET_OPERATOR_CODE("operator*"); break;
	case 'E': SET_OPERATOR_CODE("operator++"); break;
	case 'F': SET_OPERATOR_CODE("operator--"); break;
	case 'G': SET_OPERATOR_CODE("operator-"); break;
	case 'H': SET_OPERATOR_CODE("operator+"); break;
	case 'I': SET_OPERATOR_CODE("operator&"); break;
	case 'J': SET_OPERATOR_CODE("operator->*"); break;
	case 'K': SET_OPERATOR_CODE("operator/"); break;
	case 'L': SET_OPERATOR_CODE("operator%"); break;
	case 'M': SET_OPERATOR_CODE("operator<"); break;
	case 'N': SET_OPERATOR_CODE("operator<="); break;
	case 'O': SET_OPERATOR_CODE("operator>"); break;
	case 'P': SET_OPERATOR_CODE("operator>="); break;
	case 'Q': SET_OPERATOR_CODE("operator,"); break;
	case 'R': SET_OPERATOR_CODE("operator()"); break;
	case 'S': SET_OPERATOR_CODE("operator~"); break;
	case 'T': SET_OPERATOR_CODE("operator^"); break;
	case 'U': SET_OPERATOR_CODE("operator|"); break;
	case 'V': SET_OPERATOR_CODE("operator&"); break;
	case 'W': SET_OPERATOR_CODE("operator||"); break;
	case 'X': SET_OPERATOR_CODE("operator*="); break;
	case 'Y': SET_OPERATOR_CODE("operator+="); break;
	case 'Z': SET_OPERATOR_CODE("operator-="); break;
	case '$': {
		str_info = malloc(sizeof(SStrInfo));
		if (!str_info) {
			goto fail;
		}
		size_t i = get_template(abbr, buf + 1, str_info, memorize);
		if (!i) {
			RZ_FREE(str_info);
			goto fail;
		}
		dem_list_append(names_l, str_info);
		read_len += i;
		break;
	}
	case '_':
		switch (*++buf) {
		case '0': SET_OPERATOR_CODE("operator/="); break;
		case '1': SET_OPERATOR_CODE("operator%="); break;
		case '2': SET_OPERATOR_CODE("operator>>="); break;
		case '3': SET_OPERATOR_CODE("operator<<="); break;
		case '4': SET_OPERATOR_CODE("operator&="); break;
		case '5': SET_OPERATOR_CODE("operator|="); break;
		case '6': SET_OPERATOR_CODE("operator^="); break;
		case '7': SET_OPERATOR_CODE("vftable"); break;
		case '8': SET_OPERATOR_CODE("vbtable"); break;
		case '9': SET_OPERATOR_CODE("vcall"); break;
		case 'A': SET_OPERATOR_CODE("typeof"); break;
		case 'B': SET_OPERATOR_CODE("local_static_guard"); break;
		case 'C':
			if (*++buf != '@') {
				goto fail;
			}
			if (*++buf != '_') {
				goto fail;
			}
			buf++;
			read_len += 3;
			bool is_double_byte;
			if (*buf == '0') {
				is_double_byte = false;
			} else if (*buf == '1') {
				is_double_byte = true;
			} else {
				goto fail;
			}
			buf++;
			read_len++;
			const char *const str_buf_start = buf;
			SStateInfo state_info;
			init_state_struct(&state_info, buf);
			char *len = get_num(&state_info);
			if (!len) {
				goto fail;
			}
			free(len);
			buf += state_info.amount_of_read_chars;
			init_state_struct(&state_info, buf);
			char *checksum = get_num(&state_info);
			buf += state_info.amount_of_read_chars;
			DemString *s = dem_string_new();
			if (!s) {
				free(checksum);
				goto fail;
			}
			dem_string_append(s, "`string'::");
			if (checksum) {
				dem_string_appendf(s, "%s::\"", checksum);
				free(checksum);
			} else {
				dem_string_append(s, "\"");
			}
			DemString *unicode = NULL;
			if (is_double_byte) {
				unicode = dem_string_new();
				if (!unicode) {
					dem_string_free(s);
					goto fail;
				}
			}
			char c[2];
			int high = 0;
			const char *encoded = ",/\\:. \v\n'-";
			while (*buf && *buf != '@') {
				if (*buf == '?') {
					buf++;
					if (*buf == '$') {
						buf++;
						if (buf[0] < 'A' || buf[0] > 'P' ||
							buf[1] < 'A' || buf[1] > 'P') {
							dem_string_free(s);
							dem_string_free(unicode);
							goto fail;
						}
						const char nibble_high = (*buf++ - 'A');
						const char nibble_low = (*buf - 'A');
						c[high] = nibble_high | nibble_low;
					} else if (isdigit((int)*buf)) {
						c[high] = encoded[*buf - '0'];
					} else if ((*buf > 'a' && *buf < 'p') || (*buf > 'A' && *buf < 'P')) {
						c[high] = *buf + 0x80;
					} else {
						dem_string_free(unicode);
						dem_string_free(s);
						goto fail;
					}
				} else {
					c[high] = *buf;
				}
				buf++;
				if (is_double_byte) {
					high++;
					if (high > 1) {
						if (!c[0] && !c[1]) {
							break;
						}
						if (!dem_string_append_n(unicode, c, 2)) {
							dem_string_free(unicode);
							dem_string_free(s);
							goto fail;
						}
						high = 0;
					}
				} else {
					if (!c[0]) {
						break;
					}
					if (!dem_string_append_n(s, c, 1)) {
						dem_string_free(s);
						goto fail;
					}
				}
			}
			if (is_double_byte) {
				size_t utf16_len = unicode->len;
				char *utf16 = dem_string_drain(unicode);
				char *utf8_buf = NULL;
				size_t utf8_len = 0;
				if (utf16be_to_utf8(utf16, utf16_len, &utf8_buf, &utf8_len) != eDemanglerErrOK) {
					free(utf16);
					dem_string_free(s);
					goto fail;
				}
				free(utf16);
				if (!dem_string_append_n(s, utf8_buf, utf8_len)) {
					free(utf8_buf);
					dem_string_free(s);
					goto fail;
				}
				free(utf8_buf);
			}
			dem_string_append_n(s, "\"", 1);
			if (*buf == '@' && buf[1]) {
				buf++;
				init_state_struct(&state_info, buf);
				char *unk = get_num(&state_info);
				if (unk) {
					buf += state_info.amount_of_read_chars - 1;
					dem_string_appendf(s, "::%s", unk);
					free(unk);
				}
			}
			char *str = dem_string_drain(s);
			if (!str) {
				goto fail;
			}
			SET_OPERATOR_CODE(str);
			free(str);
			read_len += buf - str_buf_start;
			break;
		case 'D': SET_OPERATOR_CODE("vbase_dtor"); break;
		case 'E': SET_OPERATOR_CODE("vector_dtor"); break;
		case 'F': SET_OPERATOR_CODE("default_ctor_closure"); break;
		case 'G': SET_OPERATOR_CODE("scalar_dtor"); break;
		case 'H': SET_OPERATOR_CODE("vector_ctor_iter"); break;
		case 'I': SET_OPERATOR_CODE("vector_dtor_iter"); break;
		case 'J': SET_OPERATOR_CODE("vector_vbase_ctor_iter"); break;
		case 'K': SET_OPERATOR_CODE("virtual_displacement_map"); break;
		case 'L': SET_OPERATOR_CODE("eh_vector_ctor_iter"); break;
		case 'M': SET_OPERATOR_CODE("eh_vector_dtor_iter"); break;
		case 'N': SET_OPERATOR_CODE("eh_vector_vbase_ctor_iter"); break;
		case 'O': SET_OPERATOR_CODE("copy_ctor_closure"); break;
		case 'R':
			buf++;
			read_len++;
			switch (*buf++) {
			case '0': {
				size_t len;
				char *str = NULL;
				if (!*buf++) {
					goto fail;
				}
				if (parse_microsoft_rtti_mangled_name(abbr, buf, &str, &len) != eDemanglerErrOK) {
					goto fail;
				}
				read_len += len + 1;
				str = dem_str_append(str, " `RTTI Type Descriptor'");
				SET_OPERATOR_CODE(str);
				free(str);
				break;
			}
			case '1': {
				SStateInfo state;
				init_state_struct(&state, buf);
				char *a = get_num(&state);
				char *b = get_num(&state);
				char *c = get_num(&state);
				char *d = get_num(&state);
				if (!a || !b || !c || !d) {
					free(a);
					free(b);
					free(c);
					free(d);
					goto fail;
				}
				read_len += state.amount_of_read_chars;
				char *tmp = dem_str_newf("`RTTI Base Class Descriptor at (%s,%s,%s,%s)'", a, b, c, d);
				SET_OPERATOR_CODE(tmp);
				free(tmp);
				free(a);
				free(b);
				free(c);
				free(d);
				break;
			}
			case '2': SET_OPERATOR_CODE("`RTTI Base Class Array'"); break;
			case '3': SET_OPERATOR_CODE("`RTTI Class Hierarchy Descriptor'"); break;
			case '4': SET_OPERATOR_CODE("`RTTI Complete Object Locator'"); break;
			default: goto fail;
			}
			break;
		case 'S': SET_OPERATOR_CODE("local_vftable"); break;
		case 'T': SET_OPERATOR_CODE("local_vftable_ctor_closure"); break;
		case 'U': SET_OPERATOR_CODE("operator new[]"); break;
		case 'V': SET_OPERATOR_CODE("operator delete[]"); break;
		case 'X': SET_OPERATOR_CODE("placement_new_closure"); break;
		case 'Y': SET_OPERATOR_CODE("placement_delete_closure"); break;
		case '_':
			buf++;
			read_len++;
			switch (*buf++) {
			case 'A': SET_OPERATOR_CODE("managed_vector_ctor_iter"); break;
			case 'B': SET_OPERATOR_CODE("managed_vector_dtor_iter"); break;
			case 'C': SET_OPERATOR_CODE("eh_vector_copy_ctor_iter"); break;
			case 'D': SET_OPERATOR_CODE("eh_vector_vbase_copy_ctor_iter"); break;
			case 'E': {
				const char *end;
				const char *op = "dynamic initializer";
				char *name;
				size_t name_len;
				goto get_name;
			case 'F':
				op = "dynamic atexit destructor";
			get_name:
				end = strchr(buf, '@');
				if (!end) {
					goto fail;
				}
				name_len = end - buf;
				read_len += name_len + 1;
				name = malloc(name_len + 1);
				if (!name) {
					goto fail;
				}
				memcpy(name, buf, name_len);
				name[name_len] = '\0';
				char *tmp = dem_str_newf("`%s for '%s''", op, name);
				free(name);
				SET_OPERATOR_CODE(tmp);
				free(tmp);
				break;
			}
			case 'G': SET_OPERATOR_CODE("vector_copy_ctor_iter"); break;
			case 'H': SET_OPERATOR_CODE("vector_vbase_copy_ctor_iter"); break;
			case 'I': SET_OPERATOR_CODE("managed_vector_copy_ctor_iter"); break;
			case 'J': SET_OPERATOR_CODE("local_static_thread_guard"); break;
			case 'K': SET_OPERATOR_CODE("user_defined_literal_op"); break;
			default: goto fail;
			}
			break;
		default: goto fail;
		}
		read_len++;
		break;
	default: goto fail;
	}
	if (*buf) {
		read_len++;
	}
	return read_len;
#undef SET_OPERATOR_CODE
fail:
	dem_list_free(names_l);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
static size_t get_template(SAbbrState *abbr, const char *buf, SStrInfo *str_info, bool memorize) {
	size_t len = 0;
	char *str_type_code = NULL;
	STypeCodeStr type_code_str;
	// DemListIter *it = NULL;
	DemList *saved_abbr_names = abbr->names; // save current abbr names, this
	DemList *new_abbr_names = dem_list_newf(free);
	memset(str_info, 0, sizeof(*str_info));
	if (!init_type_code_str_struct(&type_code_str)) {
		goto get_template_err;
	}

	if (*buf == '?') {
		DemList *names_l = dem_list_newf((DemListFree)sstrinfo_free);
		if (!names_l) {
			goto get_template_err;
		}
		size_t i = get_operator_code(abbr, buf, names_l, memorize);
		if (!i) {
			goto get_template_err;
		}
		len += i;
		buf += i;
		SStrInfo *name = dem_list_head(names_l)->data;
		copy_string_n(&type_code_str, name->str_ptr, name->len);
		dem_list_free(names_l);
	} else {
		char *tmp = strchr(buf, '@');
		if (!tmp) {
			goto get_template_err;
		}

		// get/copy template len/name
		len += (tmp - buf + 1);
		copy_string_n(&type_code_str, buf, len - 1);
		dem_list_append(new_abbr_names, dem_str_ndup(buf, len - 1));
		buf += len;
	}

	copy_string(&type_code_str, "<");

	abbr->names = new_abbr_names;
	bool first = true;
	// get identifier
	size_t i = 0;
	while (*buf != '@') {
		if (get_type_code_string(abbr, buf, &i, &str_type_code) != eDemanglerErrOK) {
			if (get_template_params(abbr, buf, &i, &str_type_code) != eDemanglerErrOK) {
				RZ_FREE(str_type_code);
				goto get_template_err;
			}
		}
		if (!RZ_STR_ISEMPTY(str_type_code)) {
			if (!first) {
				copy_string(&type_code_str, ", ");
			}
			copy_string(&type_code_str, str_type_code);
			first = false;
		}
		buf += i;
		len += i;
		RZ_FREE(str_type_code);
	}
	if (*buf != '@') {
		goto get_template_err;
	}
	len++;

get_template_err:
	if (type_code_str.curr_pos) {
		copy_string(&type_code_str, ">");
		str_info->str_ptr = type_code_str_get(&type_code_str);
		str_info->len = type_code_str.curr_pos;
	}

	dem_list_free(new_abbr_names);
	abbr->names = saved_abbr_names; // restore global list with name abbr.

	if (memorize && str_info->str_ptr) {
		dem_list_append(abbr->names, strdup(str_info->str_ptr));
	}
	return len;
}

///////////////////////////////////////////////////////////////////////////////
/// \brief get_namespace_and_name
/// \param buf Current buffer position with mangled name
/// \param type_code_str String with got name and namespaces
/// \param amount_of_names Amount of names that was in list
/// \return Return amount of processed chars
///
static size_t get_namespace_and_name(SAbbrState *abbr, const char *buf, STypeCodeStr *type_code_str, size_t *amount_of_names, bool memorize) {
	const char *curr_pos = NULL, *prev_pos = NULL, *tmp = NULL;
	DemList /* <SStrInfo *> */ *names_l = NULL;
	DemListIter *it = NULL;

	if (RZ_STR_ISEMPTY(buf)) {
		return 0;
	}

	size_t len = 0, read_len = 0, tmp_len = 0;

	names_l = dem_list_newf((DemListFree)sstrinfo_free);

	if (*buf == '?') {
		size_t res = get_operator_code(abbr, buf, names_l, memorize);
		if (!res) {
			return 0;
		}
		memorize = true;
		buf += res;
		read_len += res;
	}

	prev_pos = buf;
	curr_pos = strchr(buf, '@');

	// hack for nested templates
	// think about how better to fix this...
	len = curr_pos - prev_pos;
	if (len == 0) {
		goto get_namespace_and_name_err;
	}

	while (curr_pos != NULL) {
		len = curr_pos - prev_pos;
		tmp = prev_pos;

		if ((len == 0) && (*(curr_pos) == '@')) {
			break;
		}

		// TODO:maybe add check of name correctness? like name can not start
		//		with number
		if ((len <= 0) || (len >= MICROSOFT_NAME_LEN)) {
			goto get_namespace_and_name_err;
		}

		// check if it is a template
		if ((*tmp == '?') && (*(tmp + 1) == '$')) {
			size_t i = 0;
			SStrInfo *str_info = RZ_NEW0(SStrInfo);
			if (!str_info) {
				break;
			}
			i = get_template(abbr, tmp + 2, str_info, memorize);
			if (!i) {
				RZ_FREE(str_info);
				goto get_namespace_and_name_err;
			}
			dem_list_append(names_l, str_info);

			prev_pos = tmp + i + 2;
			curr_pos = strchr(prev_pos, '@');
			read_len += i + 2;
			continue;
		}

		if ((*tmp == '?') && (*(tmp + 1) == 'Q')) {
			STypeCodeStr str;
			if (!init_type_code_str_struct(&str)) {
				break;
			}
			size_t i = get_namespace_and_name(abbr, tmp + 2, &str, NULL, true);
			read_len += i + 2;
			if (!i || *(tmp + i + 2) != '@') {
				free_type_code_str_struct(&str);
				break;
			}
			prev_pos = tmp + i + 3;
			curr_pos = strchr(prev_pos, '@');
			read_len++;
			SStrInfo *str_info = RZ_NEW0(SStrInfo);
			if (!str_info) {
				break;
			}
			str_info->str_ptr = dem_str_newf("[%s]", str.type_str);
			str_info->len = strlen(str_info->str_ptr);
			dem_list_append(names_l, str_info);
			free_type_code_str_struct(&str);
			continue;
		}

		// Nested name or numbered namespace
		if (*tmp == '?') {
			tmp++;
			read_len++;
			// Optional sequence number or numbered namespace
			bool nested_name = false;
			char *num = NULL;
			if (*tmp != '?') {
				SStateInfo state;
				init_state_struct(&state, tmp);
				num = get_num(&state);
				if (!num) {
					break;
				}
				tmp += state.amount_of_read_chars;
				read_len += state.amount_of_read_chars;
				if (*tmp == '?' && tmp[1] == '?') {
					tmp += 2;
					read_len += 2;
					nested_name = true;
				}
			} else {
				tmp++;
				read_len++;
				nested_name = true;
			}
			char *demangled = NULL;
			if (nested_name) {
				parse_microsoft_mangled_name(abbr, tmp, &demangled, &len);
				tmp += len;
				read_len += len;
			}
			SStrInfo *str_info = RZ_NEW0(SStrInfo);
			if (!str_info) {
				free(num);
				break;
			}
			if (num && demangled) {
				str_info->str_ptr = dem_str_newf("`%s'::`%s'", demangled, num);
			} else if (demangled) {
				str_info->str_ptr = dem_str_newf("`%s'", demangled);
			} else if (num) {
				str_info->str_ptr = dem_str_newf("`%s'", num);
			} else {
				str_info->str_ptr = strdup("");
			}
			if (!str_info->str_ptr) {
				RZ_FREE(str_info);
				free(num);
				break;
			}
			str_info->len = strlen(str_info->str_ptr);
			dem_list_append(names_l, str_info);
			if (demangled) {
				dem_list_append(abbr->names, strdup(str_info->str_ptr));
			}
			free(demangled);
			free(num);
			prev_pos = tmp;
			curr_pos = strchr(tmp, '@');
			continue;
		}

		bool abbreviation = false;
		if (isdigit((ut8)*tmp)) {
			abbreviation = true;
			tmp = dem_list_get_n(abbr->names, *tmp - '0');
			if (!tmp) {
				break;
			}
			len = 1;
		} else {
			char *tmpname = malloc(len + 1);
			if (!tmpname) {
				break;
			}
			memset(tmpname, 0, len + 1);
			memcpy(tmpname, prev_pos, len);
			dem_list_append(abbr->names, tmpname);
			tmp = tmpname;
		}
		SStrInfo *str_info = RZ_NEW0(SStrInfo);
		if (!str_info) {
			break;
		}
		str_info->str_ptr = strdup(tmp);
		str_info->len = strlen(tmp);

		dem_list_append(names_l, str_info);

		memorize = true;

		read_len += len;
		if (abbreviation) {
			if (*(prev_pos + 1) == '@') {
				prev_pos = curr_pos;
			} else {
				prev_pos++;
			}
		} else {
			prev_pos = curr_pos + 1;
			curr_pos = strchr(curr_pos + 1, '@');
			if (curr_pos) {
				read_len++;
			}
		}
	}

get_namespace_and_name_err:
	tmp_len = dem_list_length(names_l);
	if (amount_of_names) {
		*amount_of_names = tmp_len;
	}
	SStrInfo *str_info;
	dem_list_foreach_prev(names_l, it, str_info) {
		copy_string_n(type_code_str, str_info->str_ptr, str_info->len);

		if (--tmp_len) {
			copy_string(type_code_str, "::");
		}
	}
	dem_list_free(names_l);

	return read_len;
}

#define SINGLEQUOTED_A           'A'
#define SINGLEQUOTED_B           'B'
#define SINGLEQUOTED_C           'C'
#define SINGLEQUOTED_D           'D'
#define SINGLEQUOTED_E           'E'
#define SINGLEQUOTED_F           'F'
#define SINGLEQUOTED_G           'G'
#define SINGLEQUOTED_H           'H'
#define SINGLEQUOTED_I           'I'
#define SINGLEQUOTED_J           'J'
#define SINGLEQUOTED_K           'K'
#define SINGLEQUOTED_L           'L'
#define SINGLEQUOTED_M           'M'
#define SINGLEQUOTED_N           'N'
#define SINGLEQUOTED_O           'O'
#define SINGLEQUOTED_P           'P'
#define SINGLEQUOTED_Q           'Q'
#define SINGLEQUOTED_R           'R'
#define SINGLEQUOTED_S           'S'
#define SINGLEQUOTED_T           'T'
#define SINGLEQUOTED_U           'U'
#define SINGLEQUOTED_V           'V'
#define SINGLEQUOTED_W           'W'
#define SINGLEQUOTED_X           'X'
#define SINGLEQUOTED_Y           'Y'
#define SINGLEQUOTED_Z           'Z'
#define SINGLEQUOTED__           '_'
#define SINGLEQUOTED_$           '$'
#define CHAR_WITH_QUOTES(letter) (SINGLEQUOTED_##letter)

#define DEF_STATE_ACTION(action) static void tc_state_##action(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str)
#define GO_TO_NEXT_STATE(state, new_state) \
	{ \
		(state)->amount_of_read_chars++; \
		(state)->buff_for_parsing++; \
		(state)->state = eTCStateEnd; \
	}
#define ONE_LETTER_ACTION(action, type) \
	static void tc_state_##action(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str) { \
		if (copy_string(type_code_str, type) == 0) { \
			state->err = eTCStateMachineErrAlloc; \
		} \
		state->state = eTCStateEnd; \
	}

ONE_LETTER_ACTION(C, "signed char")
ONE_LETTER_ACTION(D, "char")
ONE_LETTER_ACTION(E, "unsigned char")
ONE_LETTER_ACTION(F, "short int")
ONE_LETTER_ACTION(G, "unsigned short int")
ONE_LETTER_ACTION(H, "int")
ONE_LETTER_ACTION(I, "unsigned int")
ONE_LETTER_ACTION(J, "long int")
ONE_LETTER_ACTION(K, "unsigned long int")
ONE_LETTER_ACTION(M, "float")
ONE_LETTER_ACTION(N, "double")
ONE_LETTER_ACTION(O, "long double")
ONE_LETTER_ACTION(X, "void")
ONE_LETTER_ACTION(Z, "varargs ...")

DEF_STATE_ACTION(_) {
#define PROCESS_CASE(letter, type_str) \
	case CHAR_WITH_QUOTES(letter): \
		copy_string(type_code_str, type_str); \
		break;

	switch (*(state->buff_for_parsing)) {
		PROCESS_CASE(D, "__int8")
		PROCESS_CASE(E, "unsigned __int8")
		PROCESS_CASE(F, "__int16")
		PROCESS_CASE(G, "unsigned __int16")
		PROCESS_CASE(H, "__int32")
		PROCESS_CASE(I, "unsigned __int32")
		PROCESS_CASE(J, "__int64")
		PROCESS_CASE(K, "unsigned __int64")
		PROCESS_CASE(L, "__int128")
		PROCESS_CASE(M, "unsigned __int128")
		PROCESS_CASE(N, "bool")
		PROCESS_CASE(Q, "char8_t")
		PROCESS_CASE(S, "char16_t")
		PROCESS_CASE(T, "long double(80 bit precision)")
		PROCESS_CASE(U, "char32_t")
		PROCESS_CASE(W, "wchar_t")
		PROCESS_CASE(Z, "long double(64 bit precision)")
	default:
		state->err = eTCStateMachineErrUncorrectTypeCode;
		break;
	}

	state->amount_of_read_chars++;
	state->buff_for_parsing++;
	state->state = eTCStateEnd;
#undef PROCESS_CASE
}

///////////////////////////////////////////////////////////////////////////////
// isdigit need to check is it need to do deabbreviation of names
// +2 -> skipp @@  ( the end of class, union,...
// or +2 -> skip abbreviated_num + '@'
#define GET_USER_DEF_TYPE_NAME(data_struct_str) \
	{ \
		copy_string(type_code_str, data_struct_str); \
\
		check_len = get_namespace_and_name(abbr, state->buff_for_parsing, type_code_str, NULL, true); \
		if (check_len) { \
			state->amount_of_read_chars += check_len; \
			state->buff_for_parsing += check_len; \
			if (*state->buff_for_parsing) { \
				state->buff_for_parsing++; \
				state->amount_of_read_chars++; \
			} \
		} else { \
			state->err = eTCStateMachineErrUncorrectTypeCode; \
		} \
	}

DEF_STATE_ACTION(T) {
#define PROCESS_CASE(case_string, type_str) \
	{ \
		check_len = strlen(case_string); \
		if (strncmp(state->buff_for_parsing, case_string, check_len) == 0) { \
			copy_string(type_code_str, type_str); \
			state->buff_for_parsing += check_len; \
			state->amount_of_read_chars += check_len; \
			return; \
		} \
	}

	size_t check_len = 0;

	state->state = eTCStateEnd;

	PROCESS_CASE("__m64@@", "__m64");
	PROCESS_CASE("__m128@@", "__m128");
	PROCESS_CASE("__m128i@@", "__m128i");
	PROCESS_CASE("__m256@@", "__m256");
	PROCESS_CASE("__m256i@@", "__m256i");
	PROCESS_CASE("__m512@@", "__m512");
	PROCESS_CASE("__m512i@@", "__m512i");

	GET_USER_DEF_TYPE_NAME("union ");
#undef PROCESS_CASE
}

DEF_STATE_ACTION(U) {
#define PROCESS_CASE(case_string, type_str) \
	{ \
		check_len = strlen(case_string); \
		if (strncmp(state->buff_for_parsing, case_string, check_len) == 0) { \
			copy_string(type_code_str, type_str); \
			state->amount_of_read_chars += check_len; \
			state->buff_for_parsing += check_len; \
			return; \
		} \
	}

	size_t check_len = 0;

	state->state = eTCStateEnd;

	PROCESS_CASE("__m128d@@", "__m128d");
	PROCESS_CASE("__m256d@@", "__m256d");
	PROCESS_CASE("__m512d@@", "__m512d");

	GET_USER_DEF_TYPE_NAME("struct ");
#undef PROCESS_CASE
}

DEF_STATE_ACTION(W) {
	// W4X@@ -> enum X, W4X@Y@@ -> enum Y::X
	size_t check_len = 0;
	state->state = eTCStateEnd;

	if (*state->buff_for_parsing != '4') {
		state->err = eTCStateMachineErrUncorrectTypeCode;
		return;
	}

	state->buff_for_parsing++;
	state->amount_of_read_chars++;

	GET_USER_DEF_TYPE_NAME("enum ");
}

DEF_STATE_ACTION(V) {
	// VX@@ -> class X
	size_t check_len = 0;
	state->state = eTCStateEnd;

	GET_USER_DEF_TYPE_NAME("class ");
}

#undef GET_USER_DEF_TYPE_NAME

static char *get_num(SStateInfo *state) {
	char *ptr = NULL;
	bool negative = false;
	if (*state->buff_for_parsing == '?') {
		negative = true;
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	}
	if (*state->buff_for_parsing == '@') {
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
		return strdup("0");
	}
	if (*state->buff_for_parsing >= '0' && *state->buff_for_parsing <= '8') {
		ptr = malloc(2);
		if (!ptr) {
			return NULL;
		}
		ptr[0] = *state->buff_for_parsing + 1;
		ptr[1] = '\0';
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	} else if (*state->buff_for_parsing == '9') {
		ptr = strdup("10");
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	} else if (*state->buff_for_parsing >= 'A' && *state->buff_for_parsing <= 'P') {
		ut32 ret = 0;

		if (state->buff_for_parsing[1] == '0' && state->buff_for_parsing[2] == 'x' && isxdigit(state->buff_for_parsing[3])) {
			size_t chars = 0;
			state->buff_for_parsing += 3;
			state->amount_of_read_chars += 3;
			while (isxdigit(*state->buff_for_parsing)) {
				state->buff_for_parsing++;
				state->amount_of_read_chars++;
				chars++;
			}
			ret = strtoul(state->buff_for_parsing - chars, NULL, 16);
		} else {
			while (*state->buff_for_parsing >= 'A' && *state->buff_for_parsing <= 'P') {
				ret *= 16;
				ret += *state->buff_for_parsing - 'A';
				state->buff_for_parsing++;
				state->amount_of_read_chars++;
			}
		}

		ptr = dem_str_newf("%u", ret);
		if (*state->buff_for_parsing && *state->buff_for_parsing == '@') {
			state->buff_for_parsing++;
			state->amount_of_read_chars++;
		}
	}
	if (negative && ptr) {
		char *tmp = ptr;
		ptr = dem_str_newf("-%s", tmp);
		free(tmp);
	}
	return ptr;
}

static inline void parse_type_modifier(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str, const char *modifier_str) {
	size_t i = 0;
	EDemanglerErr err = eDemanglerErrOK;
	char *tmp = NULL;
	STypeCodeStr tmp_str;
	STypeCodeStr storage_class;
	bool is_pin_ptr = false;
	char clr_type = '\0';

	state->state = eTCStateEnd;

	if (!init_type_code_str_struct(&tmp_str)) {
		state->err = eTCStateMachineErrAlloc;
		return;
	}
	if (!init_type_code_str_struct(&storage_class)) {
		free_type_code_str_struct(&tmp_str);
		state->err = eTCStateMachineErrAlloc;
		return;
	}

	STypeCodeStr mod_left;
	STypeCodeStr mod_right;
	if (!init_type_code_str_struct(&mod_left) ||
		!init_type_code_str_struct(&mod_right)) {
		state->err = eTCStateMachineErrAlloc;
		goto MODIFIER_err;
	}

	SDataType mod = { 0 };
	i = get_ptr_modifier(state->buff_for_parsing, &mod);
	copy_string(&mod_left, mod.left);
	copy_string(&mod_right, mod.right);
	sdatatype_fini(&mod);

	state->buff_for_parsing += i;
	state->amount_of_read_chars += i;

	if (*state->buff_for_parsing == '$') {
		state->buff_for_parsing++;
		switch (*state->buff_for_parsing++) {
		case 'A':
			clr_type = '^';
			break;
		case 'B': // cli::pin_ptr<T>
			is_pin_ptr = true;
			break;
		case 'C':
			clr_type = '%';
			break;
		case '\0':
			state->err = eTCStateMachineErrUncorrectTypeCode;
			goto MODIFIER_err;
		default:
			state->err = eTCStateMachineErrUnsupportedTypeCode;
			break;
		}
		state->amount_of_read_chars += 2;
	}

	do {
		i = get_ptr_modifier(state->buff_for_parsing, &mod);
		state->buff_for_parsing += i;
		state->amount_of_read_chars += i;

		const char *storage_class_str;
		err = get_storage_class(*state->buff_for_parsing, &storage_class_str);
		if (storage_class_str) {
			copy_string(&storage_class, storage_class_str);
		}
		if (err == eDemanglerErrOK) {
			state->buff_for_parsing++;
			state->amount_of_read_chars++;
		}
		copy_string(&mod_left, mod.left);
		copy_string(&mod_right, mod.right);
		sdatatype_fini(&mod);
	} while (i);

	if (*state->buff_for_parsing == 'Y') {
		char *n1;
		int num;

		state->buff_for_parsing++;
		state->amount_of_read_chars++;
		if (!(n1 = get_num(state))) {
			goto MODIFIER_err;
		}
		num = atoi(n1);
		RZ_FREE(n1);

		if (*storage_class.type_str || *mod_left.type_str || *mod_right.type_str || *modifier_str) {
			copy_string(&tmp_str, "(");
			copy_string_n(&tmp_str, storage_class.type_str, storage_class.curr_pos);
			copy_string_n(&tmp_str, mod_left.type_str, mod_left.curr_pos);
			const char last_char = tmp_str.type_str[tmp_str.curr_pos - 1];
			if (last_char != ' ' && last_char != '(') {
				copy_string(&tmp_str, " ");
			}
			copy_string(&tmp_str, modifier_str);
			copy_string_n(&tmp_str, mod_right.type_str, mod_right.curr_pos);
			copy_string(&tmp_str, ")");
		}

		while (num--) {
			n1 = get_num(state);
			if (!n1) {
				break;
			}
			copy_string(&tmp_str, "[");
			copy_string(&tmp_str, n1);
			copy_string(&tmp_str, "]");
			RZ_FREE(n1);
		}
	}

	if (tmp_str.curr_pos == 0) {
		copy_string_n(&tmp_str, storage_class.type_str, storage_class.curr_pos);
		copy_string_n(&tmp_str, mod_left.type_str, mod_left.curr_pos);
		if (tmp_str.curr_pos && tmp_str.type_str[tmp_str.curr_pos - 1] != ' ') {
			copy_string(&tmp_str, " ");
		}
		if (clr_type && *modifier_str != '\0') {
			copy_string_n(&tmp_str, &clr_type, 1);
			const char *rest_of_mod_str = modifier_str + (*(modifier_str + 1) == '&' ? 2 : 1);
			copy_string(&tmp_str, rest_of_mod_str);
		} else {
			if (is_pin_ptr && *modifier_str) {
				while (*++modifier_str == ' ') {
				};
			}
			copy_string(&tmp_str, modifier_str);
		}
		copy_string_n(&tmp_str, mod_right.type_str, mod_right.curr_pos);
	}

	if (!strncmp(state->buff_for_parsing, "__Z", 3)) {
		// TODO: no idea what this means
		state->buff_for_parsing += 3;
		state->amount_of_read_chars += 3;
	}

	err = get_type_code_string(abbr, state->buff_for_parsing, &i, &tmp);
	if (err != eDemanglerErrOK) {
		state->err = eTCStateMachineErrUnsupportedTypeCode;
		goto MODIFIER_err;
	}

	state->amount_of_read_chars += i;
	state->buff_for_parsing += i;
	if (is_pin_ptr) {
		copy_string(type_code_str, "cli::pin_ptr<");
	}
	copy_string(type_code_str, tmp);
	if (type_code_str->curr_pos && type_code_str->type_str[type_code_str->curr_pos - 1] != ' ' && tmp_str.type_str[0] != ' ') {
		copy_string(type_code_str, " ");
	}
	copy_string_n(type_code_str, tmp_str.type_str, tmp_str.curr_pos);
	if (is_pin_ptr) {
		copy_string(type_code_str, ">");
	}

MODIFIER_err:
	RZ_FREE(tmp);
	sdatatype_fini(&mod);
	free_type_code_str_struct(&tmp_str);
	free_type_code_str_struct(&storage_class);
	free_type_code_str_struct(&mod_left);
	free_type_code_str_struct(&mod_right);
}

DEF_STATE_ACTION(S) {
	parse_type_modifier(abbr, state, type_code_str, "* const volatile");
}

static inline const char *get_calling_convention(char calling_convention) {
	switch (calling_convention) {
	case 'A': return "__cdecl";
	case 'B': return "__cdecl __declspec(dllexport)";
	case 'C': return "__pascal";
	case 'D': return "__pascal __declspec(dllexport)";
	case 'E': return "__thiscall";
	case 'F': return "__thiscall __declspec(dllexport)";
	case 'G': return "__stdcall";
	case 'H': return "__stdcall __declspec(dllexport)";
	case 'I': return "__fastcall";
	case 'J': return "__fastcall __declspec(dllexport)";
	case 'K': return "default (none given)";
	case 'L': return "default (none given) __declspec(dllexport)";
	case 'M': return "__clrcall";
	case 'N': return "__clrcall __declspec(dllexport)";
	case 'O': return "__eabi";
	case 'P': return "__eabi __declspec(dllexport)";
	case 'Q': return "__vectorcall";
	case 'R': return "__vectorcall __declspec(dllexport)";
	case 'S': return "__swift_1";
	case 'T': return "__swift_1 __declspec(dllexport)";
	case 'U': return "__swift_2";
	case 'V': return "__swift_2 __declspec(dllexport)";
	case 'W': return "__swift_3";
	default: return NULL;
	}
}

static EDemanglerErr parse_function_args(SAbbrState *abbr, const char *sym, char **demangled_args, size_t *read_chars) {
	EDemanglerErr err = eDemanglerErrOK;
	const char *curr_pos = sym;
	size_t len = 0;

	STypeCodeStr func_str;
	if (!init_type_code_str_struct(&func_str)) {
		return eDemanglerErrMemoryAllocation;
	}

	copy_string(&func_str, "(");

	// Function arguments
	while (*curr_pos && *curr_pos != 'Z') {
		if (*curr_pos != '@') {
			char *tmp;
			bool is_abbr_type = false;
			if (len) {
				copy_string(&func_str, ", ");
			}
			err = get_type_code_string(abbr, curr_pos, &len, &tmp);
			if (err != eDemanglerErrOK) {
				// abbreviation of type processing
				if ((*curr_pos >= '0') && (*curr_pos <= '9')) {
					free(tmp);
					tmp = dem_list_get_n(abbr->types, (ut32)(*curr_pos - '0'));
					if (!tmp) {
						err = eDemanglerErrUncorrectMangledSymbol;
						break;
					}
					err = eDemanglerErrOK;
					len = 1;
					is_abbr_type = true;
				} else {
					err = eDemanglerErrUncorrectMangledSymbol;
					free(tmp);
					break;
				}
			}
			curr_pos += len;

			if (len > 1) {
				dem_list_append(abbr->types, strdup(tmp));
			}

			copy_string(&func_str, tmp);

			if (tmp && strncmp(tmp, "void", 4) == 0 && strlen(tmp) == 4) {
				// arguments list is void
				if (!is_abbr_type) {
					free(tmp);
				}
				break;
			}
			if (!is_abbr_type) {
				free(tmp);
			}
		} else {
			curr_pos++;
		}
	}

	while (*curr_pos == '@') {
		curr_pos++;
	}

	if (*curr_pos != 'Z') {
		err = eDemanglerErrUncorrectMangledSymbol;
	}

	copy_string(&func_str, ")");

	if (demangled_args) {
		*demangled_args = strdup(func_str.type_str);
	}

	free_type_code_str_struct(&func_str);

	if (read_chars) {
		*read_chars = curr_pos - sym + 1;
	}

	return err;
}

// TODO: use parse_function() instead
static void parse_function_pointer(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str, const char *pointer_str) {
	const char *call_conv = NULL;
	const char *storage = NULL;
	char *ret_type = NULL;
	size_t i = 0;
	EDemanglerErr err;

	state->state = eTCStateEnd;

	// Calling convention
	call_conv = get_calling_convention(*state->buff_for_parsing++);
	if (!call_conv) {
		// XXX unify error messages into a single enum
		state->err = eTCStateMachineErrUncorrectTypeCode;
		return;
	}

	state->amount_of_read_chars += 2; // '6' + call_conv

	// return type
	if (*state->buff_for_parsing == '?') {
		err = get_storage_class(*++state->buff_for_parsing, &storage);
		if (err != eDemanglerErrOK) {
			state->err = eTCStateMachineErrUncorrectTypeCode;
			return;
		}
		state->buff_for_parsing++;
		state->amount_of_read_chars += 2;
	}
	err = get_type_code_string(abbr, state->buff_for_parsing, &i, &ret_type);
	if (err != eDemanglerErrOK) {
		state->err = eTCStateMachineErrUnsupportedTypeCode;
		return;
	}

	copy_string(type_code_str, ret_type);
	if (storage) {
		copy_string(type_code_str, " ");
		copy_string(type_code_str, storage);
	}
	copy_string(type_code_str, " (");
	RZ_FREE(ret_type);

	copy_string(type_code_str, call_conv);
	copy_string(type_code_str, " ");
	copy_string(type_code_str, pointer_str);
	copy_string(type_code_str, ")");

	state->amount_of_read_chars += i;
	state->buff_for_parsing += i;

	char *demangled_args = NULL;
	if (parse_function_args(abbr, state->buff_for_parsing, &demangled_args, &i) != eDemanglerErrOK) {
		free(demangled_args);
		state->err = eTCStateMachineErrUncorrectTypeCode;
		return;
	}
	state->amount_of_read_chars += i;
	state->buff_for_parsing += i;
	copy_string(type_code_str, demangled_args);
	free(demangled_args);
	return;
}

static void parse_pointer(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str, const char *pointer_str) {
	if (isdigit((ut8)*state->buff_for_parsing)) {
		ut8 digit = *state->buff_for_parsing++;
		if (digit == '6' || digit == '7') {
			parse_function_pointer(abbr, state, type_code_str, pointer_str);
			return;
		} else if (digit == '8' || digit == '9') {
			STypeCodeStr func_str;
			if (!init_type_code_str_struct(&func_str)) {
				state->err = eTCStateMachineErrAlloc;
				return;
			};
			size_t read = get_namespace_and_name(abbr, state->buff_for_parsing, &func_str, NULL, true);
			if (!read || !*(state->buff_for_parsing + read) || *(state->buff_for_parsing + read) != '@') {
				state->err = eTCStateMachineErrUncorrectTypeCode;
				free_type_code_str_struct(&func_str);
				return;
			}
			read++;
			state->amount_of_read_chars += read;
			state->buff_for_parsing += read;
			copy_string(&func_str, "::");
			copy_string(&func_str, pointer_str);
			SDataType data_type = { 0 };
			size_t ptr_mod_cnt = get_ptr_modifier(state->buff_for_parsing, &data_type);
			state->buff_for_parsing += ptr_mod_cnt;
			state->amount_of_read_chars += ptr_mod_cnt;
			const char *storage;
			if (get_storage_class(*state->buff_for_parsing++, &storage) != eDemanglerErrOK) {
				state->err = eTCStateMachineErrUncorrectTypeCode;
				free_type_code_str_struct(&func_str);
				sdatatype_fini(&data_type);
				return;
			}
			state->amount_of_read_chars++;
			copy_string(type_code_str, data_type.left);
			parse_function_pointer(abbr, state, type_code_str, func_str.type_str);
			free_type_code_str_struct(&func_str);
			if (storage) {
				copy_string(type_code_str, " ");
				copy_string(type_code_str, storage);
			}
			copy_string(type_code_str, data_type.right);
			sdatatype_fini(&data_type);
			state->state = eTCStateEnd;
			return;
		}
	}
	parse_type_modifier(abbr, state, type_code_str, pointer_str);
}

#define PARSE_POINTER(pointer_str) parse_pointer(abbr, state, type_code_str, pointer_str)

DEF_STATE_ACTION(P) {
	PARSE_POINTER("*");
}

DEF_STATE_ACTION(R) {
	PARSE_POINTER("* volatile");
}

DEF_STATE_ACTION(Q) {
	PARSE_POINTER("* const");
}

DEF_STATE_ACTION(A) {
	PARSE_POINTER("&");
}

DEF_STATE_ACTION(B) {
	PARSE_POINTER("& volatile");
}

DEF_STATE_ACTION($) {
	if (*(state->buff_for_parsing++) != '$') {
		state->err = eTCStateMachineErrUncorrectTypeCode;
		return;
	}
	state->amount_of_read_chars += 2;
	switch (*state->buff_for_parsing++) {
	case 'A':
		state->state = eTCStateP;
		break;
	case 'B':
		parse_type_modifier(abbr, state, type_code_str, "");
		break;
	case 'C':
		parse_type_modifier(abbr, state, type_code_str, "");
		break;
	case 'F':
		state->state = eTCStateP;
		break;
	case 'Q':
		parse_type_modifier(abbr, state, type_code_str, "&&");
		state->state = eTCStateEnd;
		break;
	case 'R':
		parse_type_modifier(abbr, state, type_code_str, "&& volatile");
		state->state = eTCStateEnd;
		break;
	case 'T':
		copy_string(type_code_str, "std::nullptr_t");
		state->state = eTCStateEnd;
		break;
	case 'V':
		state->state = eTCStateEnd;
		break;
	case 'Z':
		state->state = eTCStateEnd;
		break;
	default:
		state->err = eTCStateMachineErrUncorrectTypeCode;
		break;
	}
}

#undef ONE_LETTER_ACTION
#undef GO_TO_NEXT_STATE
#undef DEF_STATE_ACTION

static void tc_state_start(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str) {
#define ONE_LETTER_STATE(letter) \
	case CHAR_WITH_QUOTES(letter): \
		state->state = eTCState##letter; \
		break;

	switch (*(state->buff_for_parsing)) {
		ONE_LETTER_STATE(A)
		ONE_LETTER_STATE(B)
		ONE_LETTER_STATE(C)
		ONE_LETTER_STATE(D)
		ONE_LETTER_STATE(E)
		ONE_LETTER_STATE(F)
		ONE_LETTER_STATE(G)
		ONE_LETTER_STATE(H)
		ONE_LETTER_STATE(I)
		ONE_LETTER_STATE(J)
		ONE_LETTER_STATE(K)
		ONE_LETTER_STATE(M)
		ONE_LETTER_STATE(N)
		ONE_LETTER_STATE(O)
		ONE_LETTER_STATE(P)
		ONE_LETTER_STATE(Q)
		ONE_LETTER_STATE(R)
		ONE_LETTER_STATE(S)
		ONE_LETTER_STATE(T)
		ONE_LETTER_STATE(U)
		ONE_LETTER_STATE(V)
		ONE_LETTER_STATE(W)
		ONE_LETTER_STATE(X)
		ONE_LETTER_STATE(Z)
		ONE_LETTER_STATE(_)
		ONE_LETTER_STATE($)
	default:
		// eprintf("[uncorrect type] error while parsing type\n");

		state->state = eTCStateEnd;
		state->err = eTCStateMachineErrUncorrectTypeCode;
		break;
	}

	state->amount_of_read_chars++;
	state->buff_for_parsing++;
#undef ONE_LETTER_STATE
}

static void tc_state_end(SAbbrState *abbr, SStateInfo *state, STypeCodeStr *type_code_str) {
	return;
}

static void init_state_struct(SStateInfo *state, const char *buff_for_parsing) {
	state->state = eTCStateStart;
	state->buff_for_parsing = buff_for_parsing;
	state->amount_of_read_chars = 0;
	state->err = eTCStateMachineErrOK;
}

static bool init_type_code_str_struct(STypeCodeStr *type_code_str) {
	type_code_str->type_str_len = MICROSOFT_NAME_LEN;
	type_code_str->type_str = type_code_str->type_str_buf;
	*type_code_str->type_str = '\0';
	type_code_str->curr_pos = 0;
	return true;
}

static void free_type_code_str_struct(STypeCodeStr *type_code_str) {
	if (type_code_str->type_str && type_code_str->type_str != type_code_str->type_str_buf) {
		RZ_FREE(type_code_str->type_str);
	}
	type_code_str->type_str_len = 0;
}

static char *type_code_str_get(STypeCodeStr *type_code_str) {
	char *ret;
	if (type_code_str->type_str == type_code_str->type_str_buf) {
		ret = malloc(type_code_str->curr_pos + 1);
		if (!ret) {
			return NULL;
		}
		memcpy(ret, type_code_str->type_str, type_code_str->curr_pos);
		ret[type_code_str->curr_pos] = '\0';
	} else {
		ret = type_code_str->type_str;
	}
	type_code_str->type_str = NULL;
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
// End of machine functions for parsing type codes
///////////////////////////////////////////////////////////////////////////////

static EDemanglerErr get_type_code_string(SAbbrState *abbr, const char *sym, size_t *amount_of_read_chars, char **str_type_code) {
	EDemanglerErr err = eDemanglerErrOK;
	STypeCodeStr type_code_str;
	SStateInfo state;

	if (!init_type_code_str_struct(&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto get_type_code_string_err;
	}

	init_state_struct(&state, sym);

	while (state.state != eTCStateEnd) {
		run_state(abbr, &state, &type_code_str);
		if (state.err != eTCStateMachineErrOK) {
			*str_type_code = NULL;
			*amount_of_read_chars = 0;
			switch (state.err) {
			case eTCStateMachineErrUncorrectTypeCode:
				err = eDemanglerErrUncorrectMangledSymbol;
				break;
			case eTCStateMachineErrUnsupportedTypeCode:
				err = eDemanglerErrUnsupportedMangling;
			default:
				break;
			}
			goto get_type_code_string_err;
		}
	}

	*str_type_code = type_code_str_get(&type_code_str);
	*amount_of_read_chars = state.amount_of_read_chars;

get_type_code_string_err:
	free_type_code_str_struct(&type_code_str);
	return err;
}

static inline size_t get_ptr_modifier(const char *encoded, SDataType *ptr_modifier) {
	const char *tmp = encoded;
	if (!ptr_modifier->left) {
		ptr_modifier->left = strdup("");
	}
	if (!ptr_modifier->right) {
		ptr_modifier->right = strdup("");
	}
#define SET_PTR_MODIFIER(letter, modifier_left, modifier_right) \
	case letter: \
		ptr_modifier->left = dem_str_append(ptr_modifier->left, modifier_left); \
		ptr_modifier->right = dem_str_append(ptr_modifier->right, modifier_right); \
		break;

	bool ref = false;
	bool refref = false;
	while (*tmp) {
		switch (*tmp++) {
			SET_PTR_MODIFIER('E', "", " __ptr64")
			SET_PTR_MODIFIER('F', " __unaligned", "")
			SET_PTR_MODIFIER('I', "", " __restrict")
		case 'G':
			ref = true;
			break;
		case 'H':
			refref = true;
			break;
		default:
			if (ref) {
				ptr_modifier->right = dem_str_append(ptr_modifier->right, "&");
				if (refref) {
					ptr_modifier->right = dem_str_append(ptr_modifier->right, " ");
				}
			}
			if (refref) {
				ptr_modifier->right = dem_str_append(ptr_modifier->right, "&&");
			}
			return tmp - encoded - 1;
		}
	}
	return tmp - encoded;
#undef SET_PTR_MODIFIER
}

static inline EDemanglerErr get_storage_class(const char encoded, const char **storage_class) {
	switch (encoded) {
	case 'A':
		*storage_class = NULL;
		break; // non-const
	case 'B':
	case 'J':
		*storage_class = "const";
		break;
	case 'C':
	case 'G':
	case 'K':
		*storage_class = "volatile";
		break;
	case 'D':
	case 'H':
	case 'L':
		*storage_class = "const volatile";
		break;
	default:
		*storage_class = NULL;
		return eDemanglerErrUncorrectMangledSymbol;
	}
	return eDemanglerErrOK;
}

static EDemanglerErr parse_data_type(SAbbrState *abbr, const char *sym, SDataType *data_type, size_t *len) {
	EDemanglerErr err = eDemanglerErrOK;
	size_t i;
	const char *curr_pos = sym;
	SDataType modifier = { 0 };
	const char *storage_class = NULL;
	char *tmp;
	if (len) {
		*len = 0;
	}
	if (!data_type) {
		return eDemanglerErrInternal;
	}
	data_type->left = data_type->right = NULL;
	// Data type and access level
	switch (*curr_pos) {
	// Data
	case '0': // Private static member
	case '1': // Protected static member
	case '2': // Public static member
	case '3': // Normal variable
	case '4': // Normal variable
	case '5': // Normal variable
		switch (*curr_pos) {
		case '0':
			modifier.left = strdup("private: static ");
			break;
		case '1':
			modifier.left = strdup("protected: static ");
			break;
		case '2':
			modifier.left = strdup("public: static ");
			break;
		default:
			break;
		}
		curr_pos++;
		i = 0;
		err = get_type_code_string(abbr, curr_pos, &i, &tmp);
		if (err != eDemanglerErrOK) {
			sdatatype_fini(&modifier);
			return err;
		}

		curr_pos += i;
		curr_pos += get_ptr_modifier(curr_pos, &modifier);
		if (get_storage_class(*curr_pos, &storage_class) != eDemanglerErrOK) {
			sdatatype_fini(&modifier);
			free(tmp);
			return eDemanglerErrUncorrectMangledSymbol;
		}
		curr_pos++;

		data_type->right = strdup("");
		if (storage_class) {
			data_type->left = dem_str_newf("%s%s %s%s", modifier.left, tmp, storage_class, modifier.right);
		} else {
			data_type->left = dem_str_newf("%s%s%s", modifier.left, tmp, modifier.right);
		}
		free(tmp);
		sdatatype_fini(&modifier);
		break;
	case '6': // compiler generated static
	case '7': // compiler generated static
		curr_pos++;
		curr_pos += get_ptr_modifier(curr_pos, &modifier);
		if (get_storage_class(*curr_pos, &storage_class) != eDemanglerErrOK) {
			sdatatype_fini(&modifier);
			return eDemanglerErrUncorrectMangledSymbol;
		}
		curr_pos++;

		if (storage_class) {
			data_type->left = dem_str_newf("%s%s%s", storage_class, modifier.left, modifier.right);
		} else {
			data_type->left = dem_str_newf("%s%s", modifier.left, modifier.right);
		}
		sdatatype_fini(&modifier);
		if (*curr_pos != '@') {
			STypeCodeStr str;
			if (!init_type_code_str_struct(&str)) {
				return eDemanglerErrMemoryAllocation;
			}
			size_t i = get_namespace_and_name(abbr, curr_pos, &str, NULL, true);
			if (!i) {
				free_type_code_str_struct(&str);
				return eDemanglerErrUncorrectMangledSymbol;
			}
			curr_pos += i;
			if (*curr_pos && *(curr_pos + 1) != '@') {
				STypeCodeStr str2;
				if (!init_type_code_str_struct(&str2)) {
					free_type_code_str_struct(&str);
					return eDemanglerErrMemoryAllocation;
				}
				i = get_namespace_and_name(abbr, curr_pos + 1, &str2, NULL, true);
				if (!i) {
					free_type_code_str_struct(&str);
					free_type_code_str_struct(&str2);
					return eDemanglerErrUncorrectMangledSymbol;
				}
				curr_pos += i + 1;
				data_type->right = dem_str_newf("{for `%s's `%s'}", str.type_str, str2.type_str);
				free_type_code_str_struct(&str2);
			} else {
				data_type->right = dem_str_newf("{for `%s'}", str.type_str);
			}
			free_type_code_str_struct(&str);
		} else {
			data_type->right = strdup("");
		}
		if (*curr_pos == '@') {
			curr_pos++;
		}
		break;
	case '8':
	case '9':
		curr_pos++;
		break;
	default:
		return eDemanglerErrUncorrectMangledSymbol;
	}
	if (len) {
		*len = curr_pos - sym;
	}
	return eDemanglerErrOK;
}

static EDemanglerErr parse_function_type(const char *sym, SDataType *data_type,
	size_t *len, bool *is_static, bool *is_implicit_this_pointer) {
	const char *curr_pos = sym;
	*is_static = *is_implicit_this_pointer = false;
#define SET_THUNK_MODIFIER(letter, modifier_str) \
	case letter: { \
		SStateInfo state; \
		init_state_struct(&state, curr_pos); \
		char *num = get_num(&state); \
		if (!num) { \
			return eDemanglerErrUncorrectMangledSymbol; \
		} \
		data_type->left = strdup(modifier_str); \
		data_type->right = dem_str_newf("`adjustor{%s}'", num); \
		free(num); \
		*is_implicit_this_pointer = true; \
		curr_pos += state.amount_of_read_chars; \
		break; \
	}

#define SET_ACCESS_MODIFIER(letter, flag_set, modifier_str) \
	case letter: \
		data_type->left = strdup(modifier_str); \
		*flag_set = true; \
		break;

	/* Functions */
	switch (*curr_pos++) {
		SET_ACCESS_MODIFIER('A', is_implicit_this_pointer, "private");
		SET_ACCESS_MODIFIER('B', is_implicit_this_pointer, "private");
		SET_ACCESS_MODIFIER('C', is_static, "private: static");
		SET_ACCESS_MODIFIER('D', is_static, "private: static");
		SET_ACCESS_MODIFIER('E', is_implicit_this_pointer, "private virtual");
		SET_ACCESS_MODIFIER('F', is_implicit_this_pointer, "private virtual");
		SET_THUNK_MODIFIER('G', "[thunk]:private virtual");
		SET_THUNK_MODIFIER('H', "[thunk]:private virtual");
		SET_ACCESS_MODIFIER('I', is_implicit_this_pointer, "protected");
		SET_ACCESS_MODIFIER('J', is_implicit_this_pointer, "protected");
		SET_ACCESS_MODIFIER('K', is_static, "protected: static");
		SET_ACCESS_MODIFIER('L', is_static, "protected: static");
		SET_ACCESS_MODIFIER('M', is_implicit_this_pointer, "protected virtual");
		SET_ACCESS_MODIFIER('N', is_implicit_this_pointer, "protected virtual");
		SET_THUNK_MODIFIER('O', "[thunk]:protected virtual");
		SET_THUNK_MODIFIER('P', "[thunk]:protected virtual");
		SET_ACCESS_MODIFIER('Q', is_implicit_this_pointer, "public");
		SET_ACCESS_MODIFIER('R', is_implicit_this_pointer, "public");
		SET_ACCESS_MODIFIER('S', is_static, "public: static");
		SET_ACCESS_MODIFIER('T', is_static, "public: static");
		SET_ACCESS_MODIFIER('U', is_implicit_this_pointer, "public virtual");
		SET_ACCESS_MODIFIER('V', is_implicit_this_pointer, "public virtual");
		SET_THUNK_MODIFIER('W', "[thunk]:public virtual");
		SET_THUNK_MODIFIER('X', "[thunk]:public virtual");
	case 'Y': // near
	case 'Z': // far
		break;
	default:
		return eDemanglerErrUncorrectMangledSymbol;
	}
#undef SET_ACCESS_MODIFIER
	if (len) {
		*len = curr_pos - sym;
	}
	if (!data_type->left) {
		data_type->left = strdup("");
	}
	if (!data_type->right) {
		data_type->right = strdup("");
	}
	return eDemanglerErrOK;
}

static EDemanglerErr parse_function(SAbbrState *abbr, const char *sym, STypeCodeStr *type_code_str, char **demangled_function, size_t *chars_read) {
	EDemanglerErr err = eDemanglerErrOK;
	bool is_implicit_this_pointer;
	bool is_static;
	const char *memb_func_access_code = NULL;
	const char *call_conv = NULL;
	char *demangled_args = NULL;
	char *ret_type = NULL;
	SDataType data_type = { 0 };
	SDataType this_pointer_modifier = { 0 };
	const char *curr_pos = sym;
	bool __64ptr = false;
	size_t len;

	STypeCodeStr func_str;
	if (!init_type_code_str_struct(&func_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_function_err;
	}

	if (!strncmp(curr_pos, "$$F", 3)) {
		// Managed function (Managed C++ or C++/CLI)
		curr_pos += 3;
	}

	err = parse_function_type(curr_pos, &data_type, &len, &is_static, &is_implicit_this_pointer);
	if (err != eDemanglerErrOK) {
		goto parse_function_err;
	}

	curr_pos += len;

	if (*curr_pos == 'E') {
		__64ptr = true;
		curr_pos++;
	}

	if (*curr_pos == '$') {
		curr_pos++;
		if (*curr_pos) {
			curr_pos++;
		}
	}

	if (!*curr_pos) {
		goto print_function;
	}

	// member function access code
	if (is_implicit_this_pointer) {
		curr_pos += get_ptr_modifier(curr_pos, &this_pointer_modifier);
		err = get_storage_class(*curr_pos, &memb_func_access_code);
		if (err != eDemanglerErrOK) {
			goto parse_function_err;
		}
		curr_pos++;
	}

	// currently does not use because I can not find real example of
	// where to use this
	// just read in http://www.agner.org/optimize/calling_conventions.pdf
	// that this is possible
	// when some find the case where it is used please remove this (void)*
	// lines
	(void)is_static;

	// Calling convention
	call_conv = get_calling_convention(*curr_pos);
	if (!call_conv) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_function_err;
	}
	curr_pos++;

	// get storage class code for return
	if (*curr_pos == '?') {
		err = get_storage_class(*++curr_pos, &memb_func_access_code);
		if (err != eDemanglerErrOK) {
			goto parse_function_err;
		}
		curr_pos++;
	}

	// Return type, or @ if 'void'
	if (*curr_pos == '@') {
		ret_type = strdup("void");
		curr_pos++;
	} else {
		err = get_type_code_string(abbr, curr_pos, &len, &ret_type);
		if (err != eDemanglerErrOK) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto parse_function_err;
		}

		curr_pos += len;
	}
	err = parse_function_args(abbr, curr_pos, &demangled_args, &len);
	if (err != eDemanglerErrOK) {
		goto parse_function_err;
	}

	curr_pos += len;

print_function:

	if (!RZ_STR_ISEMPTY(data_type.left)) {
		copy_string(&func_str, data_type.left);
		if (!strstr(data_type.left, "static")) {
			copy_string(&func_str, ": ");
		} else {
			copy_string(&func_str, " ");
		}
	}

	if (ret_type) {
		copy_string(&func_str, ret_type);
		copy_string(&func_str, " ");
	}

	if (call_conv) {
		copy_string(&func_str, call_conv);
		copy_string(&func_str, " ");
	}

	if (type_code_str->type_str) {
		copy_string_n(&func_str, type_code_str->type_str, type_code_str->curr_pos);
	}

	if (!RZ_STR_ISEMPTY(data_type.right)) {
		copy_string(&func_str, data_type.right);
	}

	copy_string(&func_str, demangled_args);
	RZ_FREE(demangled_args);

	if (memb_func_access_code) {
		copy_string(&func_str, memb_func_access_code);
	}

	copy_string(&func_str, this_pointer_modifier.left);

	if (__64ptr) {
		copy_string(&func_str, " __ptr64");
	}

	copy_string(&func_str, this_pointer_modifier.right);

	if (ret_type) {
		if (strstr(func_str.type_str, "#{return_type}")) {
			func_str.type_str = type_code_str_get(&func_str);
			func_str.type_str = dem_str_replace(func_str.type_str, "#{return_type}", ret_type, 0);
			func_str.curr_pos -= strlen("#{return_type}") - strlen(ret_type);
		}
	}

	// need to be free by user
	if (func_str.type_str) {
		*demangled_function = type_code_str_get(&func_str);
	}

parse_function_err:
	if (chars_read) {
		*chars_read = curr_pos - sym;
	}
	sdatatype_fini(&data_type);
	sdatatype_fini(&this_pointer_modifier);
	free_type_code_str_struct(&func_str);
	free(ret_type);
	free(demangled_args);
	return err;
}

///////////////////////////////////////////////////////////////////////////////
/// public mangled name of global object:
/// <public name> ::= ?<name>@[<namespace>@](0->inf)@3<type><storage class>
/// mangled name of a static class member object:
/// <public name> ::= ?<name>@[<classname>@](1->inf)@2<type><storage class>
///////////////////////////////////////////////////////////////////////////////
static EDemanglerErr parse_microsoft_mangled_name(SAbbrState *abbr, const char *sym, char **demangled_name, size_t *chars_read) {
	STypeCodeStr type_code_str;
	EDemanglerErr err = eDemanglerErrOK;

	const char *curr_pos = sym;

	if (!init_type_code_str_struct(&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_microsoft_mangled_name_err;
	}
	size_t i;
	size_t len = get_namespace_and_name(abbr, curr_pos, &type_code_str, &i, false);
	if (!len) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos += len;

	if (!*curr_pos) {
		*demangled_name = type_code_str_get(&type_code_str);
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos++;

	if (!strncmp(curr_pos, "$$F", 3)) {
		// Managed function (Managed C++ or C++/CLI)
		curr_pos += 3;
	}

	if (curr_pos[0] == '_') {
		// TODO: __based()
		curr_pos++;
	}

	if (isdigit(*curr_pos)) {
		SDataType data_type = { 0 };
		err = parse_data_type(abbr, curr_pos, &data_type, &len);
		if (err != eDemanglerErrOK) {
			sdatatype_fini(&data_type);
			goto parse_microsoft_mangled_name_err;
		}
		curr_pos += len;
		*demangled_name = NULL;
		if (data_type.left) {
			*demangled_name = dem_str_newf("%s ", data_type.left);
		}
		*demangled_name = dem_str_append(*demangled_name, type_code_str.type_str);
		*demangled_name = dem_str_append(*demangled_name, data_type.right);
		sdatatype_fini(&data_type);
	} else if (isalpha(*curr_pos)) {
		err = parse_function(abbr, curr_pos, &type_code_str, demangled_name, &len);
		curr_pos += len;
	} else {
		err = eDemanglerErrUncorrectMangledSymbol;
	}

parse_microsoft_mangled_name_err:
	free_type_code_str_struct(&type_code_str);
	if (chars_read) {
		*chars_read = curr_pos - sym;
	}
	return err;
}

static EDemanglerErr parse_microsoft_rtti_mangled_name(SAbbrState *abbr, const char *sym, char **demangled_name, size_t *chars_read) {
	EDemanglerErr err = eDemanglerErrOK;
	char *type = NULL;
	const char *storage = NULL;
	if (chars_read) {
		*chars_read = 0;
	}
	if (RZ_STR_ISEMPTY(sym)) {
		return eDemanglerErrUncorrectMangledSymbol;
	}
	err = get_storage_class(*sym++, &storage);
	if (err != eDemanglerErrOK) {
		return err;
	}
	size_t len;
	err = get_type_code_string(abbr, sym, &len, &type);
	if (err != eDemanglerErrOK) {
		return err;
	}
	if (storage) {
		*demangled_name = dem_str_newf("%s %s", type, storage);
	} else {
		*demangled_name = dem_str_newf("%s", type);
	}
	if (chars_read) {
		*chars_read = len + 1;
	}
	free(type);
	return err;
}

///////////////////////////////////////////////////////////////////////////////
EDemanglerErr microsoft_demangle(SDemangler *demangler, char **demangled_name) {
	EDemanglerErr err = eDemanglerErrOK;
	//	DemListIter *it = NULL;
	//	char *tmp = NULL;

	// TODO: need refactor... maybe remove the static variable somewhere?
	SAbbrState abbr;
	abbr.types = dem_list_newf(free);
	abbr.names = dem_list_newf(free);

	if (!demangler || !demangled_name) {
		err = eDemanglerErrMemoryAllocation;
		goto microsoft_demangle_err;
	}

	if (!strncmp(demangler->symbol, ".?", 2)) {
		err = parse_microsoft_rtti_mangled_name(&abbr, demangler->symbol + 2, demangled_name, NULL);
	} else {
		err = parse_microsoft_mangled_name(&abbr, demangler->symbol + 1, demangled_name, NULL);
	}

microsoft_demangle_err:
	dem_list_free(abbr.names);
	dem_list_free(abbr.types);
	return err;
}
