// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LIBDEMANGLE_V3_H
#define RZ_LIBDEMANGLE_V3_H
#include "macros.h"
#include "demangle.h"

char *demangle_rule(const char *mangled, DemRule rule, CpDemOptions opts);

// Rule declarations
DECL_RULE(mangled_name);
DECL_RULE(encoding);
DECL_RULE(name);
DECL_RULE(unscoped_name);
DECL_RULE(nested_name);
DECL_RULE(cv_qualifiers);
DECL_RULE(ref_qualifier);
DECL_RULE(prefix);
DECL_RULE(template_param);
DECL_RULE(decltype);
DECL_RULE(template_prefix);
DECL_RULE(unqualified_name);
DECL_RULE(ctor_name);
DECL_RULE(dtor_name);
DECL_RULE(ctor_dtor_name);
DECL_RULE(source_name);
DECL_RULE(number);
DECL_RULE(unnamed_type_name);
DECL_RULE(abi_tag);
DECL_RULE(abi_tags);
DECL_RULE(operator_name);
DECL_RULE(type);
DECL_RULE(type_type);
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
DECL_RULE(local_name);
DECL_RULE(discriminator);
DECL_RULE(vendor_specific_suffix);
DECL_RULE(special_name);
DECL_RULE(call_offset);
DECL_RULE(nv_offset);
DECL_RULE(v_offset);
DECL_RULE(bare_function_type);

// Helper rules for new grammar implementation
DECL_RULE(prefix_or_template_prefix_start);
DECL_RULE(prefix_start_unit);
DECL_RULE(prefix_start_rr);
DECL_RULE(prefix_start);
DECL_RULE(prefix_nested_class_or_namespace);
DECL_RULE(closure_prefix_unit);
DECL_RULE(closure_prefix_rr);
DECL_RULE(closure_prefix);

DECL_RULE(unscoped_template_name);

// Rule aliases
DECL_RULE_ALIAS(top_level_cv_qualifiers, cv_qualifiers);
DECL_RULE_ALIAS(non_negative_number, number);
DECL_RULE_ALIAS(value_number, number);
DECL_RULE_ALIAS(value_float, float);
DECL_RULE_ALIAS(string_type, type);
DECL_RULE_ALIAS(pointer_type, type);
DECL_RULE_ALIAS(real_part_float, float);
DECL_RULE_ALIAS(imag_part_float, float);
DECL_RULE_ALIAS(field_source_name, source_name);
DECL_RULE_ALIAS(index_expression, expression);
DECL_RULE_ALIAS(range_begin_expression, expression);
DECL_RULE_ALIAS(range_end_expression, expression);
DECL_RULE_ALIAS(instantiation_dependent_expression, expression);
DECL_RULE_ALIAS(element_type, type);
DECL_RULE_ALIAS(instantiation_dependent_array_bound_expression, expression);
DECL_RULE_ALIAS(array_bound_number, number);
DECL_RULE_ALIAS(class_type, type);
DECL_RULE_ALIAS(function_encoding, encoding);
DECL_RULE_ALIAS(entity_name, name);
DECL_RULE_ALIAS(base_encoding, encoding);
DECL_RULE_ALIAS(offset_number, number);
DECL_RULE_ALIAS(virtual_offset_number, number);
DECL_RULE_ALIAS(function_name, name);
DECL_RULE_ALIAS(data_name, name);
DECL_RULE_ALIAS(signature_type, type);

#endif // RZ_LIBDEMANGLE_V3_H
