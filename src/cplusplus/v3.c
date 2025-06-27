// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Documentation for used grammar can be found at either of
 * - https://files.brightprogrammer.in/cxx-abi/
 * - https://itanium-cxx-abi.github.io/cxx-abi/
 */

#include "v3_impl/types.h"

// Include helper functions
#include "v3_impl/helpers.c"

// Include all rule implementations
#include "v3_impl/bare_function_type.c"
#include "v3_impl/call_offset.c"
#include "v3_impl/digit.c"
#include "v3_impl/discriminator.c"
#include "v3_impl/encoding.c"
#include "v3_impl/local_name.c"
#include "v3_impl/mangled_name.c"
#include "v3_impl/name.c"
#include "v3_impl/nested_name.c"
#include "v3_impl/number.c"
#include "v3_impl/nv_offset.c"
#include "v3_impl/seq_id.c"
#include "v3_impl/source_name.c"
#include "v3_impl/special_name.c"
#include "v3_impl/type.c"
#include "v3_impl/unscoped_name.c"
#include "v3_impl/unscoped_template_name.c"
#include "v3_impl/v_offset.c"
#include "v3_impl/vendor_specific_suffix.c"

// CV qualifiers and reference qualifiers
#include "v3_impl/cv_qualifiers.c"
#include "v3_impl/ref_qualifier.c"

// Prefix rules
#include "v3_impl/prefix.c"
#include "v3_impl/prefix_nested_class_or_namespace.c"
#include "v3_impl/prefix_or_template_prefix_start.c"
#include "v3_impl/prefix_start.c"
#include "v3_impl/prefix_start_rr.c"
#include "v3_impl/prefix_start_unit.c"
#include "v3_impl/template_prefix.c"

// ABI tags
#include "v3_impl/abi_tag.c"
#include "v3_impl/abi_tags.c"

// Template rules
#include "v3_impl/decltype.c"
#include "v3_impl/template_arg.c"
#include "v3_impl/template_args.c"
#include "v3_impl/template_param.c"
#include "v3_impl/template_template_param.c"

// Substitution
#include "v3_impl/substitution.c"

// Name rules
#include "v3_impl/ctor_dtor_name.c"
#include "v3_impl/operator_name.c"
#include "v3_impl/unnamed_type_name.c"
#include "v3_impl/unqualified_name.c"

// Type rules
#include "v3_impl/array_type.c"
#include "v3_impl/builtin_type.c"
#include "v3_impl/class_enum_type.c"
#include "v3_impl/exception_spec.c"
#include "v3_impl/extended_qualifier.c"
#include "v3_impl/function_type.c"
#include "v3_impl/pointer_to_member_type.c"
#include "v3_impl/qualified_type.c"
#include "v3_impl/qualifiers.c"

// Expression rules
#include "v3_impl/braced_expression.c"
#include "v3_impl/expr_primary.c"
#include "v3_impl/expression.c"
#include "v3_impl/float.c"
#include "v3_impl/initializer.c"

// Unresolved name rules
#include "v3_impl/base_unresolved_name.c"
#include "v3_impl/destructor_name.c"
#include "v3_impl/simple_id.c"
#include "v3_impl/unresolved_name.c"
#include "v3_impl/unresolved_qualifier_level.c"
#include "v3_impl/unresolved_type.c"

// Function parameter rules
#include "v3_impl/function_param.c"

// Closure prefix rules
#include "v3_impl/closure_prefix.c"
#include "v3_impl/closure_prefix_rr.c"
#include "v3_impl/closure_prefix_unit.c"

const char* cp_demangle_v3 (const char* mangled, CpDemOptions opts) {
    if (!mangled) {
        return NULL;
    }

    StrIter  si  = {.beg = mangled, .cur = mangled, .end = mangled + strlen (mangled) + 1};
    StrIter* msi = &si;

    DemString* dem = dem_string_new();

    Meta  meta = {0};
    Meta* m    = &meta;

    if (RULE (mangled_name)) {
#if DBG_PRINT_DETECTED_TYPES
        dem_string_append (dem, " || ");
        vec_foreach_ptr (&m->detected_types, t, {
            dem_string_append_n (dem, "\n[", 2);
            dem_string_concat (dem, t);
            dem_string_append_n (dem, "]", 1);
        });
#endif
#if DBG_PRINT_DETECTED_TPARAMS
        dem_string_append (dem, " || ");
        m->template_params.data     += m->template_idx_start;
        m->template_params.length   -= m->template_idx_start;
        m->template_params.capacity -= m->template_idx_start;
        vec_foreach_ptr (&m->template_params, t, {
            dem_string_append_n (dem, "\n", 1);
            dem_string_concat (dem, t);
        });
        m->template_params.length   += m->template_idx_start;
        m->template_params.capacity += m->template_idx_start;
        m->template_params.data     -= m->template_idx_start;
#endif
        vec_deinit (&meta.detected_types);
        return dem_string_drain (dem);
    } else {
        vec_deinit (&meta.detected_types);
        dem_string_free (dem);
        return NULL;
    }

    return NULL;
}