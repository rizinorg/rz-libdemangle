// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include "demangler_util.h"
#include <rz_libdemangle.h>

typedef struct {
	const char *search;
	const char *replace;
} java_replace_t;

#define is_native_type(x) ((x) && !IS_UPPER(x))
#define is_varargs(x)     ((x)[0] == '.' && (x)[1] == '.' && (x)[2] == '.')

// The following table contains the list of java classes that can be simplified
// to save memory and making the demangled string more readable.
static java_replace_t java_replace_table[] = {
	{ "java/lang/Boolean", "Boolean" },
	{ "java/lang/Byte", "Byte" },
	{ "java/lang/Character", "Character" },
	{ "java/lang/Class", "Class" },
	{ "java/lang/ClassLoader", "ClassLoader" },
	{ "java/lang/ClassValue", "ClassValue" },
	{ "java/lang/Compiler", "Compiler" },
	{ "java/lang/Double", "Double" },
	{ "java/lang/Enum", "Enum" },
	{ "java/lang/Exception", "Exception" },
	{ "java/lang/Float", "Float" },
	{ "java/lang/InheritableThreadLocal", "InheritableThreadLocal" },
	{ "java/lang/Integer", "Integer" },
	{ "java/lang/Long", "Long" },
	{ "java/lang/Math", "Math" },
	{ "java/lang/Number", "Number" },
	{ "java/lang/Object", "Object" },
	{ "java/lang/Package", "Package" },
	{ "java/lang/Process", "Process" },
	{ "java/lang/ProcessBuilder", "ProcessBuilder" },
	{ "java/lang/Runtime", "Runtime" },
	{ "java/lang/RuntimePermission", "RuntimePermission" },
	{ "java/lang/SecurityManager", "SecurityManager" },
	{ "java/lang/Short", "Short" },
	{ "java/lang/StackTraceElement", "StackTraceElement" },
	{ "java/lang/StrictMath", "StrictMath" },
	{ "java/lang/String", "String" },
	{ "java/lang/StringBuffer", "StringBuffer" },
	{ "java/lang/StringBuilder", "StringBuilder" },
	{ "java/lang/System", "System" },
	{ "java/lang/Thread", "Thread" },
	{ "java/lang/ThreadGroup", "ThreadGroup" },
	{ "java/lang/ThreadLocal", "ThreadLocal" },
	{ "java/lang/Throwable", "Throwable" },
	{ "java/lang/Void", "Void" },
};

static bool demangle_type(char *type, DemString *sb, size_t *used) {
	bool array = false, varargs = false, subtype = false;
	char *end = NULL, *tmp = NULL;
	size_t type_len = 1;

	if (is_varargs(type)) {
		varargs = true;
		type += 3;
	}
	if (type[0] == '[') {
		array = true;
		type++;
	}

	switch (type[0]) {
	case 'L':
		if (!(end = strchr(type, ';'))) {
			return false;
		}
		if ((tmp = strchr(type, '<')) && tmp < end) {
			if (!strstr(tmp + 1, ">")) {
				return false;
			}
			end = tmp;
			subtype = true;
		}

		end[0] = 0;
		type_len = strlen(type);
		dem_string_append_n(sb, type + 1, type_len - 1);
		type_len++;
		type = end + 1;
		break;
	case 'B':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "byte");
		break;
	case 'C':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "char");
		break;
	case 'D':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "double");
		break;
	case 'F':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "float");
		break;
	case 'I':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "int");
		break;
	case 'J':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "long");
		break;
	case 'S':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "short");
		break;
	case 'V':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "void");
		break;
	case 'Z':
		if (is_native_type(type[1])) {
			return false;
		}
		dem_string_append(sb, "boolean");
		break;
	case 'T': // templates
		if (is_native_type(type[1]) && type[1] != ';') {
			return false;
		}
		dem_string_append(sb, "T");
		break;
	default:
		return false;
	}
	if (subtype) {
		dem_string_append(sb, "<");
		if (*type == '*') {
			dem_string_append(sb, "T");
		} else {
			bool comma = false;
			end = strstr(type, ">");
			end[0] = 0;
			while (*type && type != end) {
				if (*type == ';') {
					type++;
					continue;
				} else if (comma) {
					dem_string_append(sb, ", ");
				}
				size_t len = 0;
				if (!demangle_type(type, sb, &len)) {
					return false;
				}
				type += len;
				type_len += len;
				comma = true;
			}
		}
		dem_string_append(sb, ">");
	}
	if (varargs) {
		dem_string_append(sb, "...");
		type_len += 3;
	}
	if (array) {
		if (!varargs) {
			dem_string_append(sb, "[]");
		}
		type_len++;
	}
	if (used) {
		*used = type_len;
	}
	return true;
}

static char *demangle_method(char *name, char *arguments, char *return_type) {
	// example: Lsome/class/Object;.myMethod([F)I
	// name = Lsome/class/Object;.myMethod
	// args = [F
	// rett = I
	DemString *sb = NULL;
	size_t args_length = 0;

	sb = dem_string_new();
	if (!sb) {
		goto demangle_method_bad;
	}

	arguments[0] = 0;
	arguments++;
	args_length = return_type - arguments;

	return_type[0] = 0;
	return_type++;

	if (!demangle_type(return_type, sb, NULL)) {
		goto demangle_method_bad;
	}

	dem_string_append(sb, " ");

	const char *t = NULL;
	if (name[0] == 'L' && (t = strchr(name, ';')) && !demangle_type(name, sb, NULL)) {
		goto demangle_method_bad;
	} else if (name[0] == 'L' && t) {
		dem_string_append(sb, t + 1);
	} else {
		dem_string_append(sb, name);
	}

	dem_string_append(sb, "(");
	for (size_t pos = 0, used = 0; pos < args_length;) {
		if (!demangle_type(arguments + pos, sb, &used)) {
			goto demangle_method_bad;
		}
		pos += used;
		if (pos < args_length) {
			dem_string_append(sb, ", ");
		}
	}
	dem_string_append(sb, ")");

	free(name);
	dem_string_replace_char(sb, '/', '.');
	return dem_string_drain(sb);

demangle_method_bad:
	dem_string_free(sb);
	free(name);
	return NULL;
}

static char *demangle_class_object(char *object, char *name) {
	// example: Lsome/class/Object;.myMethod.I
	// object = Lsome/class/Object;
	// name   = myMethod.I
	DemString *sb = NULL;
	char *type = NULL;

	sb = dem_string_new();
	if (!sb) {
		goto demangle_class_object_bad;
	}

	name[0] = 0;
	name++;

	type = strchr(name, '.');

	if (!demangle_type(object, sb, NULL)) {
		goto demangle_class_object_bad;
	}

	if (type) {
		type[0] = 0;
		type++;
		dem_string_appendf(sb, ".%s:", name);
		if (!demangle_type(type, sb, NULL)) {
			goto demangle_class_object_bad;
		}
	} else {
		dem_string_appendf(sb, ".%s", name);
	}

	free(object);
	dem_string_replace_char(sb, '/', '.');
	return dem_string_drain(sb);

demangle_class_object_bad:
	dem_string_free(sb);
	free(object);
	return NULL;
}

static char *demangle_object_with_type(char *name, char *object) {
	// example: myMethod.Lsome/class/Object;
	// name   = myMethod
	// object = Lsome/class/Object;
	DemString *sb = dem_string_new();
	if (!sb) {
		goto demangle_object_with_type_bad;
	}

	object[0] = 0;
	object++;

	dem_string_appendf(sb, "%s:", name);
	if (!demangle_type(object, sb, NULL)) {
		goto demangle_object_with_type_bad;
	}

	free(name);
	dem_string_replace_char(sb, '/', '.');
	return dem_string_drain(sb);

demangle_object_with_type_bad:
	dem_string_free(sb);
	free(name);
	return NULL;
}

static char *demangle_any(char *mangled) {
	DemString *sb = dem_string_new();
	if (!sb) {
		return NULL;
	}

	if (!demangle_type(mangled, sb, NULL)) {
		free(mangled);
		dem_string_free(sb);
		return NULL;
	}
	free(mangled);

	dem_string_replace_char(sb, '/', '.');
	return dem_string_drain(sb);
}

/**
 * \brief Demangles java classes/methods/fields
 *
 * Demangles java classes/methods/fields
 *
 * Supported formats:
 * - Lsome/class/Object;                some.class.Object.myField
 * - F                                  float
 * - Lsome/class/Object;.myField.I      some.class.Object.myField:int
 * - myField.I                          myField:int
 * - Lsome/class/Object;.myMethod([F)I  int some.class.Object.myMethod(float[])
 */
RZ_API char *libdemangle_handler_java(const char *mangled) {
	if (!mangled) {
		return NULL;
	}

	char *name = NULL;
	char *arguments = NULL;
	char *return_type = NULL;

	name = strdup(mangled);
	if (!name) {
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(java_replace_table); ++i) {
		if (!name) {
			return NULL;
		}
		java_replace_t *rpl = &java_replace_table[i];
		name = dem_str_replace(name, rpl->search, rpl->replace, 1);
	}

	if ((arguments = strchr(name, '(')) && (return_type = strchr(arguments, ')'))) {
		return demangle_method(name, arguments, return_type);
	} else if (name[0] == 'L' && (arguments = strchr(name, '.'))) {
		return demangle_class_object(name, arguments);
	} else if ((arguments = strchr(name, '.'))) {
		return demangle_object_with_type(name, arguments);
	}
	return demangle_any(name);
}
