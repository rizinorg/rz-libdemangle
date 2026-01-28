// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_V3_H
#define RZ_LIBDEMANGLE_V3_H
#include "macros.h"
#include "demangle.h"
#include "types.h"

char *demangle_rule(const char *mangled, DemRule rule, CpDemOptions opts);

bool rule_operator_name(DemParser *p, DemResult *r, NameState *ns);
bool rule_nested_name(DemParser *p, DemResult *r, NameState *ns);
bool rule_name(DemParser *p, DemResult *r, NameState *ns);
bool rule_local_name(DemParser *p, DemResult *r, NameState *ns);
bool rule_template_args_ex(DemParser *p, DemResult *r, bool tag_templates);

// Rule declarations
DECL_RULE(mangled_name);
DECL_RULE(encoding);
DECL_RULE(template_param);
DECL_RULE(decltype);
DECL_RULE(template_prefix);
DECL_RULE(source_name);
DECL_RULE(number);
DECL_RULE(unnamed_type_name);
DECL_RULE(type);
DECL_RULE(builtin_type);
DECL_RULE(expression);
DECL_RULE(unresolved_name);
DECL_RULE(function_param);
DECL_RULE(expr_primary);
DECL_RULE(float);
DECL_RULE(initializer);
DECL_RULE(braced_expression);
DECL_RULE(base_unresolved_name);
DECL_RULE(simple_id);
DECL_RULE(destructor_name);
DECL_RULE(unresolved_type);
DECL_RULE(unresolved_qualifier_level);
DECL_RULE(qualified_type);
DECL_RULE(qualifiers);
DECL_RULE(extended_qualifier);
DECL_RULE(function_type);
DECL_RULE(exception_spec);
DECL_RULE(class_enum_type);
DECL_RULE(array_type);
DECL_RULE(pointer_to_member_type);
DECL_RULE(template_template_param);
DECL_RULE(digit);
DECL_RULE(template_args);
DECL_RULE(template_arg);
DECL_RULE(substitution);
DECL_RULE(seq_id);
DECL_RULE(discriminator);
DECL_RULE(vendor_specific_suffix);
DECL_RULE(special_name);
DECL_RULE(call_offset);
DECL_RULE(nv_offset);
DECL_RULE(v_offset);

DECL_RULE(unscoped_template_name);

#endif // RZ_LIBDEMANGLE_V3_H
