// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>

// Suppress GCC-specific warnings from macros in vec.h and param.h
// These warnings are triggered when macros check addresses of stack-allocated variables
#ifdef __GNUC__
#ifndef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
#pragma GCC diagnostic ignored "-Wunused-value"
#endif
#endif

#include "cplusplus/v2/common.h"

// See issue :
//   https://github.com/rizinorg/rz-libdemangle/issues/8
//
// For name mangling scheme for GNU v2 ABI, see section 8.4 (Gnu v2 name mangling)
//   https://github.com/rizinorg/rizin/files/6154867/calling_conventions.pdf
//
// A better formatted document can be found here :
//   https://kb.brightprogrammer.in/s/15fd1dd9-d47d-4ec1-9339-7c111db41ab5
//
// For name mangling scheme for GNU v3 ABI, see
//   https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling-structure

static char *cpdem_get_demangled(CpDem *dem);
static CpDem *cpdem_public_name(CpDem *dem);

/* if base name comes with qualifiers then it's a class */
#define IS_BASE_NAME_A_TYPE(dem) ((dem)->qualifiers.length && (dem)->base_name->length)

/* is constructor, destructor or an operator */
#define IS_XTOR(dem) \
	((dem)->is_ctor || (dem)->is_dtor || (dem)->operator_type || (dem)->custom_operator.len)

/* Is current character a terminator */
#define IS_TERM(dem) ((PEEK() == '.') || (PEEK() == '$'))

/* note how names are sorted in reverse order of length,
 * this allows to be certain of which operator it is. */
static const struct {
	const char *from;
	const char *to;
	size_t len;
} operators_map[] = {
	/* dummy entry to make sure indices start from 1
	 * this let's me store information that whether this declaration is an operator
	 * or not, and the operator ID, in the same variable. */
	{ 0 },

	{ .from = "_aad_", .to = "operator&=", .len = 5 },
	{ .from = "_adv_", .to = "operator/=", .len = 5 },
	{ .from = "_aer_", .to = "operator^=", .len = 5 },
	{ .from = "_als_", .to = "operator<<=", .len = 5 },
	{ .from = "_aml_", .to = "operator*=", .len = 5 },
	{ .from = "_amd_", .to = "operator%=", .len = 5 },
	{ .from = "_ami_", .to = "operator-=", .len = 5 },
	{ .from = "_aor_", .to = "operator|=", .len = 5 },
	{ .from = "_apl_", .to = "operator+=", .len = 5 },
	{ .from = "_ars_", .to = "operator>>=", .len = 5 },

	{ .from = "_aa_", .to = "operator&&", .len = 4 },
	{ .from = "_ad_", .to = "operator&", .len = 4 },
	{ .from = "_as_", .to = "operator=", .len = 4 },

	{ .from = "_cl_", .to = "operator()", .len = 4 },
	{ .from = "_co_", .to = "operator~", .len = 4 },
	{ .from = "_cm_", .to = "operator,", .len = 4 },

	{ .from = "_dl_", .to = "operator delete", .len = 4 },
	{ .from = "_dv_", .to = "operator/", .len = 4 },

	{ .from = "_eq_", .to = "operator==", .len = 4 },
	{ .from = "_er_", .to = "operator^", .len = 4 },

	{ .from = "_ge_", .to = "operator>=", .len = 4 },
	{ .from = "_gt_", .to = "operator>", .len = 4 },

	{ .from = "_le_", .to = "operator<=", .len = 4 },
	{ .from = "_ls_", .to = "operator<<", .len = 4 },
	{ .from = "_lt_", .to = "operator<", .len = 4 },

	{ .from = "_md_", .to = "operator%", .len = 4 },
	{ .from = "_mi_", .to = "operator-", .len = 4 },
	{ .from = "_ml_", .to = "operator*", .len = 4 },
	{ .from = "_mm_", .to = "operator--", .len = 4 },

	{ .from = "_ne_", .to = "operator!=", .len = 4 },
	{ .from = "_nt_", .to = "operator!", .len = 4 },
	{ .from = "_nw_", .to = "operator new", .len = 4 },

	{ .from = "_oo_", .to = "operator||", .len = 4 },
	/* explicitly matched : {.from = "__op<L>TYPE_", .to = "operator", .len = 3}, */
	{ .from = "_or_", .to = "operator|", .len = 4 },

	{ .from = "_pl_", .to = "operator+", .len = 4 },
	{ .from = "_pp_", .to = "operator++", .len = 4 },

	{ .from = "_rf_", .to = "operator->", .len = 4 },
	{ .from = "_rm_", .to = "operator->*", .len = 4 },
	{ .from = "_rs_", .to = "operator>>", .len = 4 },

	{ .from = "_vc_", .to = "operator[]", .len = 4 },
	{ .from = "_vd_", .to = "operator delete[]", .len = 4 },
	{ .from = "_vn_", .to = "operator new[]", .len = 4 },
};

#define OPERATOR_MAP_SIZE (sizeof(operators_map) / sizeof(operators_map[0]))

/**
 * \b Takes a mangled input, and returns corresponding demangled form.
 * This is an internal method is not to be used directly in general use case,
 * until unless you know what you're doing.
 *
 * The returned string is allocated new. It is the responsibility of caller to
 * free the returned string.
 *
 * \p mangled : Mangled input.
 * \p opts : Options for demangling.
 *
 * \return Demangled output on success.
 * \return NULL otherwise.
 */
char *cp_demangle_v2(const char *mangled, CpDemOptions opts) {
	if (!mangled) {
		fprintf(stderr, "invalid arguments\n");
		return NULL;
	}

	CpDem dem = { 0 };
	if (!cpdem_init(&dem, mangled, opts)) {
		return NULL;
	}

	if (!cpdem_public_name(&dem)) {
		cpdem_fini(&dem);
		return NULL;
	}

	char *res = NULL;
	if (!(res = cpdem_get_demangled(&dem))) {
		cpdem_fini(&dem);
		return NULL;
	}

	cpdem_fini(&dem);
	return res;
}

static ut64 cpdem_get_qualifier_count(CpDem *dem);
static CpDem *cpdem_qualifiers_list(CpDem *dem);
static CpDem *cpdem_name(CpDem *dem);
static CpDem *cpdem_class_names(CpDem *dem, ClassNameVec *class_names, ut64 qualifiers_count);
static CpDem *cpdem_param_type(CpDem *dem, ParamVec *params);
static CpDem *cpdem_func_params(CpDem *dem);
static CpDem *cpdem_template_param_type(CpDem *dem, ParamVec *params);
static CpDem *cpdem_template_class(CpDem *dem, DemString *tclass_name);
static CpDem *cpdem_custom_type_name(CpDem *dem, DemString *name);
static CpDem *cpdem_template_function_keep_parsing(CpDem *dem);

char *cpdem_get_demangled(CpDem *dem) {
	if (!dem) {
		return NULL;
	}

	// append name first
	DemString demangled = { 0 };
	dem_string_init(&demangled);

	/* add prefix if present */
	if (dem->prefix.len) {
		dem_string_concat(&demangled, &dem->prefix);
		dem_string_append_char(&demangled, ' ');
	}

	/* add all qualifiers */
	if (dem->qualifiers.length) {
		vec_foreach_ptr(DemString, &dem->qualifiers, q, {
			dem_string_concat(&demangled, q);
			dem_string_append_n(&demangled, "::", 2);
		});

		if (IS_XTOR(dem)) {
			/* when adding into constructor or destructor, we don't need template params,
			 * make sure to not add that, but stopping at "<" */
			DemString *last_qualifier = VecDemString_tail(&dem->qualifiers);
			char *buf = last_qualifier->buf;
			size_t buf_len = last_qualifier->len;
			if (dem->is_ctor) {
				char *name_end = memchr(buf, '<', buf_len);
				name_end = name_end ? name_end : buf + buf_len;
				dem_string_append_n(&demangled, buf, name_end - buf);
			} else if (dem->is_dtor) {
				char *name_end = memchr(buf, '<', buf_len);
				name_end = name_end ? name_end : buf + buf_len;
				dem_string_append_char(&demangled, '~');
				dem_string_append_n(&demangled, buf, name_end - buf);
			}
		} else {
			dem_string_concat(&demangled, &dem->base_name);
		}
	} else {
		/* if there are no qualifiers, then there surely is a base name */
		dem_string_concat(&demangled, &dem->base_name);
	}

	if (dem->operator_type) {
		dem_string_append(&demangled, operators_map[dem->operator_type].to);
	} else if (dem->custom_operator.len) {
		dem_string_append_n(&demangled, "operator ", 9);
		dem_string_concat(&demangled, &dem->custom_operator);
	}

	// append all params if they exist
	if (dem->has_params) {
		dem_string_append_char(&demangled, '(');
		param_vec_append_to_dem_string(&dem->func_params, &demangled);
		dem_string_append_char(&demangled, ')');
	}

	/* add suffix if present */
	if (dem->suffix.len) {
		dem_string_append_char(&demangled, ' ');
		dem_string_concat(&demangled, &dem->suffix);
	}

	char *res = dem_str_ndup(demangled.buf, demangled.len);
	dem_string_deinit(&demangled);

	return res;
}

CpDem *cpdem_public_name(CpDem *dem) {
	if (!dem) {
		return NULL;
	}

	/* special names */
	if (PEEK() == '_') {
		const char *trial_start_pos = CUR();
		ADV(); /* skip _ */

		/* _ <qualifiers list> <list term> <name> */
		if (IN_RANGE(CUR() + 3) && (!strncmp(CUR(), "vt", 2) || !strncmp(CUR(), "_vt", 3))) {
			bool has_vt = false;
			/* match past  "_vt$" or "_vt." or "__vt_" */
			if (PEEK() == 'v') {
				ADV_BY(2);
				if (IS_TERM(dem)) {
					ADV();
					dem_string_append(&dem->suffix, "virtual table");
					has_vt = true;
				} else {
					SEEK_TO(trial_start_pos);
				}
			} else {
				ADV_BY(3);
				if (PEEK() == '_') {
					ADV();
					dem_string_append(&dem->suffix, "virtual table");
					has_vt = true;
				} else {
					SEEK_TO(trial_start_pos);
				}
			}

			if (has_vt) {
				while (PEEK()) {
					ClassNameVec class_names = { 0 };
					DemString custom_name = { 0 };

					/* it can be a base name, or a class name, or a custom type name */
					if (cpdem_class_names(dem, &class_names, 1)) {
						DemString *cname = VecDemString_head(&class_names);
						dem_string_concat(&dem->base_name, cname);
						dem_string_deinit(cname);
						VecDemString_deinit(&class_names);

						if (IS_TERM(dem)) {
							dem_string_append_n(&dem->base_name, "::", 2);
							ADV();
						}
					} else if (cpdem_name(dem)) {
						VecDemString_deinit(&class_names);
						if (IS_TERM(dem)) {
							dem_string_append_n(&dem->base_name, "::", 2);
							ADV();
						}
					} else if (cpdem_custom_type_name(dem, &custom_name)) {
						VecDemString_deinit(&class_names);
						dem_string_concat(&dem->base_name, &custom_name);
						dem_string_deinit(&custom_name);

						if (IS_TERM(dem)) {
							dem_string_append_n(&dem->base_name, "::", 2);
							ADV();
						}
					} else {
						VecDemString_deinit(&class_names);
						dem_string_deinit(&custom_name);
						break;
					}
				}

				if (PEEK()) {
					return NULL;
				} else {
					return dem;
				}
			}
		} else if (IN_RANGE(CUR() + 8) && !strncmp(CUR(), "_thunk_", 7)) {
			SEEK_TO(CUR() + 7);

			const char *delta_start = CUR();
			const char *delta_end = strchr(CUR(), '_');
			SEEK_TO(delta_end + 1);

			dem_string_append(&dem->prefix, "virtual function thunk (delta:-");
			dem_string_append_n(&dem->prefix, delta_start, delta_end - delta_start);
			dem_string_append(&dem->prefix, ") for");

			/* let it continue */
		} else if (IN_RANGE(CUR() + 3) && !strncmp(CUR(), "_t", 2)) {
			ADV_BY(2);

			/* type_info [node | function] */
			char ch = PEEK();
			if ((ch == 'i' || ch == 'f')) {
				ADV();
				ClassNameVec class_names = { 0 };
				if (cpdem_class_names(dem, &class_names, 1)) {
					dem_string_append(
						&dem->suffix,
						((ch == 'i') ? "type_info node" : "type_info function"));

					dem_string_concat(&dem->base_name, VecDemString_tail(&class_names));
					VecDemString_deinit(&class_names);
					return dem;
				} else {
					VecDemString_deinit(&class_names);
					ParamVec types = { 0 };
					VecParam_init(&types);
					if (cpdem_param_type(dem, &types) && types.length) {
						dem_string_append(
							&dem->suffix,
							((ch == 'i') ? "type_info node" : "type_info function"));

						Param *first_param = VecParam_head(&types);
						DemString ti = first_param->name;
						dem_string_concat(&dem->base_name, &ti);
						VecParam_deinit(&types);
						return dem;
					} else {
						SEEK_TO(trial_start_pos);
						VecParam_deinit(&types);
						/* continue parsing from beginning */
					}
				}
			} else {
				SEEK_TO(trial_start_pos);
				/* continue parsing from beginning */
			}
		} else if (parse_string(dem, "GLOBAL_$") || parse_string(dem, "_GLOBAL__")) {
			if (PEEK() == 'I') {
				ADV_BY(2); /* skip I$ */
				dem_string_append(&dem->prefix, "global constructors keyed to");
				dem->has_global_name = true;
			} else if (PEEK() == 'D') {
				ADV_BY(2); /* skip I$ */
				dem_string_append(&dem->prefix, "global destructors keyed to");
				dem->has_global_name = true;
			} else {
				/* I don't identify you */
				return NULL;
			}

			/* continue from here to parse names, qualifiers, etc... like usual */
		} else if (cpdem_qualifiers_list(dem)) {
			if (IS_TERM(dem) && ADV()) {
				dem_string_append(&dem->base_name, CUR());
				return dem;
			}
		} else {
			SEEK_TO(trial_start_pos);
		}
	}

	/* <name> */
	if (!dem->has_global_name) {
		if (!cpdem_name(dem)) {
			return NULL;
		}
	}

	bool has_global_name_with_qualifiers = false;

	/* there may be one or two _ depending on scanned name */
	if (IS_XTOR(dem)) {
		/* skip _ */
		if (PEEK() == '_') {
			ADV();
		} else {
			return NULL;
		}
	} else {
		/* an extra _ will be here only if this is not a special name */
		if (dem->has_global_name && PEEK() == '_') {
			ADV(); /* skip _ */
			has_global_name_with_qualifiers = true;
		} else if (dem->has_global_name) {
			/* do nothing */
		} else if (PEEK() == '_') {
			ADV(); /* skip _ */
			if (PEEK() == '_') {
				ADV(); /* skip _ */
			} else {
				return NULL;
			}
		} else {
			return NULL;
		}
	}

	switch (PEEK()) {
	/* <name> __F [<parameter type>]+ */
	case 'F':
		ADV();
		return cpdem_func_params(dem);

	/* <name> __H */
	case 'H':
		ADV();
		/* this will continue to get the template parameters, function parameters and return type */
		return cpdem_template_function_keep_parsing(dem);

	/* <name> __C */
	case 'C': {
		/* function marked as const, meaning won't change any of the arguments passed to it */
		ADV();
		dem_string_append_n(&dem->suffix, "const", 5);
		if (cpdem_qualifiers_list(dem)) {
			cpdem_func_params(dem);
			return dem;
		} else {
			return NULL;
		}
	}

	/* <name> __ <qualifiers list> [<parameter type>]+ */
	/* [ _ <qualifiers list> <list term> ] <name> */
	/* <name> */
	default:
		if (has_global_name_with_qualifiers) {
			/* _ <qualifiers list> <list term> <name> */
			if (cpdem_qualifiers_list(dem)) {
				if (IS_TERM(dem)) {
					ADV();
					if (!cpdem_name(dem)) {
						return NULL;
					}
				} else {
					return NULL;
				}
			} else {
				return NULL;
			}
		} else if (dem->has_global_name) {
			if (!cpdem_name(dem)) {
				return NULL;
			}
		} else {
			if (cpdem_qualifiers_list(dem)) {
				/* <name> __ <qualifiers list> [<parameter type>]+ */
				/* function params are optional here, therefore we won't check if they return anything or not */
				cpdem_func_params(dem);
			} else {
				return NULL;
			}
		}

		return dem;
	}

	return dem;
}

static ut64 cpdem_get_qualifier_count(CpDem *dem) {
	if (!dem) {
		return 0;
	}

	ut64 qualifier_count = 0;

	/* if more than 1 qualifier */
	/* Q */
	if (PEEK() == 'Q') {
		ADV();

		char *end = NULL;

		/* if more than 9 qualifiers */
		/* Q _ */
		if (PEEK() == '_') {
			ADV();

			/* Q _ <qualifiers count> _ */
			qualifier_count = strtoull(CUR(), &end, 10);
			if (!end || !IN_RANGE(end) || *end != '_' || !qualifier_count) {
				return 0;
			}
		} else if (PEEK() >= '0' && PEEK() <= '9') {
			/* single digit count */
			/* Q <qualifiers count> */
			qualifier_count = PEEK() - '0';
			ADV();
		} else {
			return 0;
		}

		/* update current position */
		SEEK_TO(end);
	} else if ((PEEK() >= '0' && PEEK() <= '9') || PEEK() == 't') {
		/* if just one qualifier, then length of qualifier comes first */
		qualifier_count = 1;
	} else {
		/* this was a mistake, and this is not a qualifier, backtrack */
		return 0;
	}

	return qualifier_count;
}

CpDem *cpdem_qualifiers_list(CpDem *dem) {
	if (!dem) {
		return NULL;
	}

	ut64 qualifier_count = cpdem_get_qualifier_count(dem);
	if (!qualifier_count) {
		return NULL;
	}

	/* get each qualifier */
	/* <qualifiers count> [<name length> <class name>]+ */
	return cpdem_class_names(dem, &dem->qualifiers, qualifier_count);
}

CpDem *cpdem_name(CpDem *dem) {
	if (!dem) {
		return NULL;
	}

	if (PEEK() == '_') {
		const char *trial_start_pos = CUR();
		ADV();

		// destructor
		if (PEEK() == '$' || PEEK() == '.') {
			ADV();
			dem->is_dtor = true;
			return dem;
		} else if (PEEK() == '_') {
			// opreator TYPE()
			// __op<L>TYPE_ : L is length and TYPE is name of type of length <L> characters
			if (IN_RANGE(CUR() + 4) && !strncmp(CUR(), "_op", 3)) {
				// read past _op
				ADV_BY(3);

				ParamVec params = { 0 };
				VecParam_init(&params);

				/* NOTE: for now, this method will match more strings than it should.
				 * If the provided string is correct, then the output will be correct,
				 * if however the given input is incorrect, then it'll output wrong demangled output,
				 * instead of return NULL (rejection) */

				if (cpdem_param_type(dem, &params) && params.length) {
					if (PEEK() == '_') {
						ADV();
						Param *p = VecParam_head(&params);
						param_append_to_dem_string(p, &dem->custom_operator);
						VecParam_deinit(&params);
						return dem;
					} else {
						/* restore to iniital parsing position and try for a normal name */
						SEEK_TO(trial_start_pos);
						VecParam_deinit(&params);
						goto parse_name;
					}
				}
			} else {
				// any other operator
				// try to match through each one, and if fails then it's a constructor
				// note that index starts from 1
				for (size_t x = 1; x < OPERATOR_MAP_SIZE; x++) {
					if (IN_RANGE(CUR() + operators_map[x].len) &&
						!strncmp(CUR(), operators_map[x].from, operators_map[x].len)) {
						ADV_BY(operators_map[x].len);
						dem->operator_type = x;
						return dem;
					}
				}
			}

			// constructor
			dem->is_ctor = true;
			return dem;
		} else {
			// restore initial position, because this is a name now, not an operator
			// this name begins with underscore
			SEEK_TO(trial_start_pos);
		}
	}

parse_name:
	/* name cannot start with non alpha numeric or "_" */
	if (!IS_ALPHA(PEEK()) && (PEEK() != '_')) {
		return NULL;
	}

	/* match <name> if operator match didn't work */
	while (PEEK()) {
		const char *cur = CUR();
		if (IN_RANGE(CUR() + 2) && (cur[0] == '_' && (cur[1] == '_' || dem->has_global_name))) {
			/* depeneding on whether decl has a special name or not,
			 * there will be an extra _ or a qualifier following up */
			char next_char = dem->has_global_name ? cur[1] : cur[2];

			switch (next_char) {
			case 'C': /* const function */
			case 'F': /* function params */
			case 'H': /* template function */
			case 'Q': /* qualifier list */
			case 't': /* template class */

			/* a sigle qualifier starts */
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
				return dem;
			}

			default: {
				/* add this character to name */
				break;
			}
			}
		} else if (IS_TERM(dem)) {
			return dem;
		}

		dem_string_append_char(&dem->base_name, PEEK());
		ADV();
	}

	return dem;
}

CpDem *cpdem_class_names(CpDem *dem, ClassNameVec *class_names, ut64 qualifiers_count) {
	if (!dem || !class_names || !qualifiers_count) {
		return NULL;
	}

	/* get each qualifier and append in qualifier name vector */
	VecDemString_reserve(class_names, qualifiers_count);

	while (qualifiers_count--) {
		DemString name = { 0 };
		dem_string_init(&name);

		switch (PEEK()) {
		/* template class */
		case 't': {
			ADV();
			if (!cpdem_template_class(dem, &name)) {
				dem_string_deinit(&name);
				return NULL;
			}
			break;
		}

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
			if (!cpdem_custom_type_name(dem, &name)) {
				dem_string_deinit(&name);
				return NULL;
			}
			break;
		}

		default: {
			dem_string_deinit(&name);
			return NULL;
		}
		}

		VecDemString_append(class_names, &name);
	}

	return dem;
}

/**
 * \b Get parameter type at current read position, demangle it and add to param vec.
 *    There are different types of parameter vectors. So the caller passes their own
 *    parameter vector to append the demangled parameter to.
 *
 * ParamVec is required because of types that get repeated many times. In
 * that case many entries need to be appended at once.
 *
 * \p dem    Demangling context.
 * \p params Parameter vector to append demangled parameter to.
 *
 * \return dem on success.
 * \return NULL otherwise.
 */
CpDem *cpdem_param_type(CpDem *dem, ParamVec *params) {
	if (!dem || !params) {
		return NULL;
	}

	Param param = { 0 };
	param_init(&param);

#define ADD_PARAM(x) \
	dem_string_append(&param.name, x) ? (VecParam_append(params, &param) ? dem : (param_deinit(&param), NULL)) : (param_deinit(&param), NULL)

	/** read a custom type from current read position and add it to params vector if success */
#define ADD_NAMED_PARAM() \
	cpdem_custom_type_name(dem, &param.name) ? (VecParam_append(params, &param) ? dem : (param_deinit(&param), NULL)) : (param_deinit(&param), NULL)

#define ADD_QUALIFIER_LIST() \
	do { \
		ut64 qualifiers_count = cpdem_get_qualifier_count(dem); \
		if (!qualifiers_count) { \
			param_deinit(&param); \
			return NULL; \
		} \
\
		ClassNameVec qualifiers = { 0 }; \
		VecDemString_init(&qualifiers); \
		if (!cpdem_class_names(dem, &qualifiers, qualifiers_count)) { \
			param_deinit(&param); \
			return NULL; \
		} \
\
		vec_foreach_ptr(DemString, &qualifiers, q, { \
			dem_string_concat(&param.name, q); \
			dem_string_append_n(&param.name, "::", 2); \
			dem_string_deinit(q); \
		}); \
\
		/* HACK: to remove last two extraneous ":" (colon) symbols */ \
		param.name.buf[--param.name.len] = 0; \
		param.name.buf[--param.name.len] = 0; \
		VecDemString_deinit(&qualifiers); \
\
		VecParam_append(params, &param); \
	} while (0)

#define MATCH_TYPE() \
	case 'b': { \
		ADV(); \
		return ADD_PARAM("bool"); \
	} \
	case 'c': { \
		ADV(); \
		return ADD_PARAM("char"); \
	} \
	case 'd': { \
		ADV(); \
		return ADD_PARAM("double"); \
	} \
	case 'e': { \
		ADV(); \
		return ADD_PARAM("..."); \
	} \
	case 'f': { \
		ADV(); \
		return ADD_PARAM("float"); \
	} \
	case 'i': { \
		ADV(); \
		return ADD_PARAM("int"); \
	} \
	case 'l': { \
		ADV(); \
		return ADD_PARAM("long"); \
	} \
	case 'r': { \
		ADV(); \
		return ADD_PARAM("long double"); \
	} \
	case 's': { \
		ADV(); \
		return ADD_PARAM("short"); \
	} \
	case 't': { \
		ADV(); \
		if (cpdem_template_class(dem, &param.name)) { \
			VecParam_append(params, &param); \
			return dem; \
		} else { \
			param_deinit(&param); \
			return NULL; \
		} \
	} \
	case 'v': { \
		ADV(); \
		return ADD_PARAM("void"); \
	} \
	case 'w': { \
		ADV(); \
		return ADD_PARAM("wchar_t"); \
	} \
	case 'x': { \
		ADV(); \
		return ADD_PARAM("long long"); \
	} \
	case 'U': { \
		ADV(); \
		switch (PEEK()) { \
			/* Uc */ \
		case 'c': \
			ADV(); \
			return ADD_PARAM("unsigned char"); \
			/* Us */ \
		case 's': \
			ADV(); \
			return ADD_PARAM("unsigned short"); \
			/* Ui */ \
		case 'i': \
			ADV(); \
			return ADD_PARAM("unsigned int"); \
			/* Ul */ \
		case 'l': \
			ADV(); \
			return ADD_PARAM("unsigned long"); \
			/* Ux */ \
		case 'x': \
			ADV(); \
			return ADD_PARAM("unsigned long long"); \
		default: \
			param_deinit(&param); \
			return NULL; \
		} \
		break; \
	} \
	case 'Q': { \
		ADD_QUALIFIER_LIST(); \
		return dem; \
	} \
	case 'S': { \
		ADV(); \
		switch (PEEK()) { \
			/* Sc */ \
		case 'c': \
			ADV(); \
			return ADD_PARAM("signed char"); \
		default: \
			param_deinit(&param); \
			return NULL; \
		} \
		break; \
	} \
	case 'J': { \
		ADV(); \
		switch (PEEK()) { \
		/* Jf */ \
		case 'f': \
			ADV(); \
			return ADD_PARAM("__complex__ float"); \
		/* Jd */ \
		case 'd': \
			ADV(); \
			return ADD_PARAM("__complex__ double"); \
		default: \
			param_deinit(&param); \
			return NULL; \
		} \
		break; \
	} \
	case '0': \
	case '1': \
	case '2': \
	case '3': \
	case '4': \
	case '5': \
	case '6': \
	case '7': \
	case '8': \
	case '9': { \
		return ADD_NAMED_PARAM(); \
	} \
	default: { \
		/* we tried all combinations but this is an invalid type, cannot continue */ \
		param_deinit(&param); \
		return NULL; \
	}

	st64 num_reps = 1;
	st64 typeidx = -1;
	bool is_ref = false;
	bool is_ptr = false;

	switch (PEEK()) {
		/* X */
		MATCH_TYPE();

	/* G<LX>X */
	case 'G': {
		ADV();

		/* there are two types of cases for G
		 * - G<LX>X               (ADD_NAMED_PARAM())
		 * - GQ2<qualifiers>      (ADD_QUALIFIER_LIST())
		 * G will never appear in case of pointers, references or in template paramter list
		 * */
		switch (PEEK()) { MATCH_TYPE(); }

		break;
	}

	/* R - References */
	case 'R': {
	case_r:
		ADV(); /* skip R */
		param_append_to(&param, suffix, "&");
		is_ref = true;

		switch (PEEK()) {
			MATCH_TYPE();

		case 'R': {
			goto case_r;
		}

		case 'P': {
			goto logic_intersection_between_case_r_and_p;
		}

		case 'T': {
			goto logic_intersection_between_case_r_and_t;
		}

		case 'C': {
			goto logic_intersection_between_case_r_and_c;
		}

		case 'V': {
			goto logic_intersection_between_case_r_and_v;
		}
		}
	}

	/* P - Pointers */
	case 'P': {
	case_p:
	logic_intersection_between_case_r_and_p:
		ADV(); /* skip P */

		/* need to prepend it this way, because we might already have & in the suffix */
		param_prepend_to(&param, suffix, "*");
		is_ptr = true;

		switch (PEEK()) {
			/* PX or RPX */
			MATCH_TYPE();

		case 'P': {
			goto case_p;
		}

		/* pointer to arrays of fixed size */
		case 'A': {
			param.suffix.len = 0;
			param_append_to(&param, suffix, "(*)");
		case_a:
			ADV(); /* skip A */

			/* array size */
			st64 arrsz = 0;
			READ_NUMBER(arrsz);
			if (arrsz < 0) {
				param_deinit(&param);
				return NULL;
			}

			const char *val_str = dem_str_newf("%" PRIu64, arrsz + 1);

			/* add array length */
			param_append_to(&param, suffix, "[");
			param_append_to(&param, suffix, val_str);
			param_append_to(&param, suffix, "]");
			free((void *)val_str);

			if (PEEK() == '_') {
				ADV();
			} else {
				param_deinit(&param);
				return NULL;
			}

			switch (PEEK()) {
				MATCH_TYPE();
			case 'A':
				goto case_a;
			}

			break;
		}

		case 'F': {
			/* pointer to a function */
			ADV(); /* skip F */

			/* get all params */
			ParamVec pf_params = { 0 };
			VecParam_init(&pf_params);
			while (PEEK() && cpdem_param_type(dem, &pf_params)) {
			}
			DemString param_list = { 0 };
			dem_string_append_char(&param_list, '(');
			param_vec_append_to_dem_string(&pf_params, &param_list);
			dem_string_append_char(&param_list, ')');
			VecParam_deinit(&pf_params);

			/* get return type */
			DemString return_type = { 0 };
			if (PEEK() == '_') {
				ADV();
				ParamVec pf_return_type = { 0 };
				VecParam_init(&pf_return_type);
				cpdem_param_type(dem, &pf_return_type);
				if (pf_return_type.length) {
					Param *rp = VecParam_head(&pf_return_type);
					param_append_to_dem_string(rp, &return_type);
					VecParam_deinit(&pf_return_type);
				} else {
					dem_string_deinit(&return_type);
					dem_string_deinit(&param_list);
					VecParam_deinit(&pf_return_type);
					param_deinit(&param);
					return NULL;
				}
			} else {
				dem_string_append(&return_type, "void");
			}

			/* HACK: if return type is a function pointer itself, split it and patch it here
			 * there may be a better way to do it, but it works for now. */
			if (strstr(return_type.buf, "(*)")) {
				char *pivot = strstr(return_type.buf, "(*)");

				/* get return type of functor */
				char *ftor_ret_type = return_type.buf;
				ut64 ftor_ret_type_len = pivot - ftor_ret_type - 1;

				/* get param list of functor */
				char *ftor_param_list = pivot + 3;
				ut64 ftor_param_list_len =
					return_type.buf + return_type.len - ftor_param_list;

				dem_string_append_n(&param.name, ftor_ret_type, ftor_ret_type_len);
				dem_string_append_n(&param.name, " (*(*)", 6);
				dem_string_concat(&param.name, &param_list);
				dem_string_append_char(&param.name, ')');
				dem_string_append_n(&param.name, ftor_param_list, ftor_param_list_len);
			} else {
				dem_string_concat(&param.name, &return_type);
				dem_string_append_n(&param.name, " (*)", 4);
				dem_string_concat(&param.name, &param_list);
			}

			/* remove any suffix or prefix */
			param.suffix.len = param.prefix.len = 0;

			dem_string_deinit(&return_type);
			dem_string_deinit(&param_list);

			VecParam_append(params, &param);
			return dem;
		}

		case 'T': {
			goto logic_intersection_between_p_and_t_or_r_and_p_and_t;
		}

		case 'C': {
			goto logic_intersection_between_case_p_and_c;
		}

		/* PVX */
		case 'V': {
			goto logic_intersection_between_case_p_and_v;
		}
		}

		break;
	}

	/* C */
	case 'C': {
	logic_intersection_between_case_r_and_c:
	logic_intersection_between_case_p_and_c:
		ADV(); /* skip C */
		param_append_to(&param, prefix, "const");

		switch (PEEK()) {
			/* CX */
			MATCH_TYPE();

		case 'P': {
			goto case_p;
		}

		/* CVX */
		case 'V': {
			goto logic_intersection_between_case_c_and_v;
		}
		}
		break;
	}

	/* V */
	case 'V': {
	logic_intersection_between_case_r_and_v:
	logic_intersection_between_case_p_and_v:
	logic_intersection_between_case_c_and_v:
		ADV(); /* skip V */
		param_append_to(&param, prefix, "volatile");

		switch (PEEK()) {
			/* VX */
			MATCH_TYPE();
		}
		break;
	}

		/* repeated names */
	case 'N': {
		ADV(); /* skip N */

		/* get number of repetitions to copy here */
		READ_NUMBER(num_reps);
		if (num_reps <= 0) {
			param_deinit(&param);
			return NULL;
		}

		/* if length is more than single digit in it's string form, then there will be a "_" just after it */
		if (PEEK() == '_') {
			ADV();
		} else {
			/* we over-read, and there's a two digit number present here, first digit for num_reps and second for typeidx */
			SEEK_TO(CUR() - 2);
			num_reps = PEEK() - '0';
			ADV();
		}

		/* next we're expecting a number that indexes into parameter vector to refer to a type already demangled */
		if (PEEK() >= '0' && PEEK() <= '9') {
			goto logic_intersection_between_case_n_and_t;
		}
	}
	/* T - reference back to a repeated type */
	case 'T': {
	logic_intersection_between_case_r_and_t:
	logic_intersection_between_p_and_t_or_r_and_p_and_t:
		ADV(); /* skip T */

	logic_intersection_between_case_n_and_t:
		/* get type index to copy here */
		READ_NUMBER(typeidx);
		if (typeidx < 0 || (ut64)typeidx > dem->func_params.length) {
			param_deinit(&param);
			return NULL;
		}

		/* if length is more than single digit in it's string form, then there will be a "_" just after it */
		if (PEEK() == '_') {
			ADV();
		}

		/* deinit this one, because we'll be directly initing clones */
		param_deinit(&param);

		/* create base typename is to be provided for index 0 in list of recognized types */
		char *base_typename = NULL;
		if (dem->qualifiers.length) {
			DemString tname = { 0 };
			vec_foreach_ptr(DemString, &dem->qualifiers, q, {
				dem_string_concat(&tname, q);
				dem_string_append_n(&tname, "::", 2);
			});

			/* HACK: to remove extraneous "::" */
			tname.buf[--tname.len] = 0;
			tname.buf[--tname.len] = 0;

			base_typename = dem_str_ndup(tname.buf, tname.len);
			dem_string_deinit(&tname);
		}

		/* refer back to param list */
		if (base_typename && (typeidx == 0)) {
			/* the very first type is name of function itself, it should be considered at index 0 */
			for (ut64 r = 0; r < (ut64)num_reps; r++) {
				Param p = { 0 };
				param_init(&p);

				/* if we fell down from R */
				if (is_ref) {
					/* num_reps will be 1 in this case */
					param_append_to(&p, suffix, "&");
				}

				/* if we fell down from P */
				if (is_ptr) {
					/* num_reps will be 1 in this case */
					param_prepend_to(&p, suffix, "*");
				}

				param_append_to(&p, name, base_typename);
				VecParam_append(params, &p);
			}
		} else {
			/* if base name is considered as first type then assume array index starts at 1 in vector */
			if (base_typename) {
				typeidx--;
			}

			/* for each rep, make clone of a type at previous index and put it at the end in the param vec */
			for (ut64 r = 0; r < (ut64)num_reps; r++) {
				Param p = { 0 };
				param_init_clone(&p, VecParam_at(params, typeidx));

				/* if we fell down from R */
				if (is_ref) {
					/* num_reps will be 1 in this case */
					param_append_to(&p, suffix, "&");
				}

				/* if we fell down from P */
				if (is_ptr) {
					/* num_reps will be 1 in this case */
					param_prepend_to(&p, suffix, "*");
				}

				VecParam_append(params, &p);
			}
		}

		if (base_typename) {
			free(base_typename);
		}

		break;
	}
	}

	return dem;
}

/**
 * \b Parse as many parameter types as possible.
 *
 * \param dem Demangling context.
 *
 * \return dem on success.
 * \return NULL on failure.
 */
CpDem *cpdem_func_params(CpDem *dem) {
	if (!dem) {
		return NULL;
	}

	dem->has_params = true;

	/* parse as many params as possible */
	while (PEEK() && cpdem_param_type(dem, &dem->func_params)) {
	}

	return dem;
}

CpDem *cpdem_template_param_type(CpDem *dem, ParamVec *params) {
	if (!dem || !params) {
		return NULL;
	}

	switch (PEEK()) {
	case 'Z': {
		ADV();

		/* parse a single parameter type */
		if (!cpdem_param_type(dem, params)) {
			return NULL;
		}

		break;
	}

	default: {
		/* parse a single parameter type */
		if (!cpdem_param_type(dem, params)) {
			return NULL;
		}

		/* store before and after read positions of value */
		const char *pos_before_val = CUR();
		st64 val = 0;
		READ_NUMBER(val);
		const char *pos_after_val = CUR();

		/* make it as if string is clear */
		Param *param = VecParam_tail(params);
		param->name.len = param->prefix.len = param->suffix.len = 0;

		if (!strcmp(param->name.buf, "bool")) {
			/* if the type is bool, then value will be converted to true/false */
			dem_string_append(&param->name, val ? "true" : "false");
		} else {
			/* no need to convert value back to string, we already have that */
			size_t val_string_len = pos_after_val - pos_before_val;
			dem_string_append_n(&param->name, pos_before_val, val_string_len);
		}
	}
	}

	return dem;
}

CpDem *cpdem_template_class(CpDem *dem, DemString *tclass_name) {
	if (!dem || !tclass_name) {
		return NULL;
	}

	/* get custom type name first */
	DemString class_name = { 0 };
	if (!cpdem_custom_type_name(dem, &class_name)) {
		dem_string_deinit(&class_name);
		return NULL;
	}

	/* number of template parameters */
	st64 numtp = 0;
	READ_NUMBER(numtp);
	if (numtp < 0) {
		return NULL;
	}

	ParamVec tparams = { 0 };
	VecParam_init(&tparams);

	/* parse each template parameter */
	while (numtp--) {
		if (!cpdem_template_param_type(dem, &tparams)) {
			VecParam_deinit(&tparams);
			return NULL;
		}
	}

	/* merge class name and template parameters */
	dem_string_concat(tclass_name, &class_name);
	dem_string_append_char(tclass_name, '<');
	param_vec_append_to_dem_string(&tparams, tclass_name);
	dem_string_append_char(tclass_name, '>');

	/* release temp resources */
	dem_string_deinit(&class_name);
	VecParam_deinit(&tparams);

	return dem;
}

/**
 * Read a custom type name from mangled character array.
 *
 * \param dem       : Demanling context.
 * \param name : DemString object to append name to.
 *
 * \return dem on success;
 * \return NULL otherwise.
 */
CpDem *cpdem_custom_type_name(CpDem *dem, DemString *name) {
	if (!dem || !name) {
		return NULL;
	}

	if (PEEK() >= '0' && PEEK() <= '9') {
		char *end = NULL;
		ut64 typename_len = strtoull(CUR(), &end, 10);
		if (!dem || !IN_RANGE(end) || !typename_len || !IN_RANGE(CUR() + typename_len)) {
			return NULL;
		}
		SEEK_TO(end);

		dem_string_append_n(name, CUR(), typename_len);
		ADV_BY(typename_len);
	} else {
		return NULL;
	}

	return dem;
}

CpDem *cpdem_template_function_keep_parsing(CpDem *dem) {
	if (!dem) {
		return NULL;
	}

	/* get number of template paramters following this */
	st64 tparam_count;
	READ_NUMBER(tparam_count);
	if (tparam_count <= 0) {
		return NULL;
	}

	/* get all template paramter types */
	ParamVec tparams = { 0 };
	VecParam_init(&tparams);
	while (tparam_count-- && cpdem_template_param_type(dem, &tparams)) {
	}
	if (tparam_count > 0) {
		goto cleanup_and_return;
	}

	dem_string_append_char(&dem->base_name, '<');
	param_vec_append_to_dem_string(&tparams, &dem->base_name);
	dem_string_append_char(&dem->base_name, '>');

	/* we expect an _ */
	if (PEEK() == '_') {
		ADV();
	} else {
		goto cleanup_and_return;
	}

	/* optional qualifier list */
	cpdem_qualifiers_list(dem);

	dem->has_params = true;

	/* while we don't reach the return type as next character to be parsed */
	while (PEEK() && PEEK() != '_') {
		/* we can exect an entry like X<N>1 if this is not a template parameter index */
		if (!cpdem_param_type(dem, &dem->func_params)) {
			/* it is possibly a reference to a template paramter type */
			if (PEEK() == 'X') {
				/* refer back to type from list of template parameters */
				const char *idx_start = CUR() + 1;
				const char *idx_end = strchr(idx_start, 'X');
				idx_end = idx_end ? idx_end : strchr(idx_start, '_');

				/* the format is [X<tparam_idx>1]+ _ <return_type> */
				if (idx_end && idx_end[-1] == '1') {
					idx_end -= 1;
					char *idx_str = dem_str_ndup(idx_start, idx_end - idx_start);
					st64 tparam_idx = strtoll(idx_str, NULL, 10);
					free(idx_str);
					if (tparam_idx >= 0) {
						Param tp_clone = { 0 };
						param_init_clone(&tp_clone, VecParam_at(&tparams, tparam_idx));
						VecParam_append(&dem->func_params, &tp_clone);
					} else {
						goto cleanup_and_return;
					}

					SEEK_TO(idx_end + 1);
				} else {
					goto cleanup_and_return;
				}
			} else {
				goto cleanup_and_return;
			}
		}
	}

	/* return type is expected and is a must */
	/* we expect an _ */
	if (PEEK() == '_') {
		ADV();
	} else {
		goto cleanup_and_return;
	}

	ParamVec tpf_ret_type = { 0 };
	VecParam_init(&tpf_ret_type);
	if (cpdem_param_type(dem, &tpf_ret_type) && tpf_ret_type.length) {
		Param *return_type = VecParam_at(&tpf_ret_type, 0);
		param_append_to_dem_string(return_type, &dem->prefix);
	} else {
		goto cleanup_and_return;
	}

	VecParam_deinit(&tpf_ret_type);
	VecParam_deinit(&tparams);
	return dem;

cleanup_and_return:
	VecParam_deinit(&tpf_ret_type);
	VecParam_deinit(&dem->func_params);
	VecParam_deinit(&tparams);
	return NULL;
}

// Restore GCC diagnostic settings
#ifdef __GNUC__
#ifndef __clang__
#pragma GCC diagnostic pop
#endif
#endif
