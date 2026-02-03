// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "common.h"

CpDem *cpdem_init(CpDem *dem, const char *mangled, CpDemOptions opts) {
	if (!dem || !mangled) {
		return NULL;
	}

	memset(dem, 0, sizeof(CpDem));
	dem->original =
		((StrIter){ .beg = mangled, .end = mangled + strlen(mangled) + 1, .cur = mangled });
	dem->opts = opts;
	dem_string_init(&dem->base_name);
	dem_string_init(&dem->suffix);
	dem_string_init(&dem->prefix);
	param_vec_init(&dem->func_params);
	return dem;
}

void cpdem_fini(CpDem *dem) {
	if (!dem) {
		return;
	}

	/* free all demstring and deinit qualifiers vector */
	vec_foreach_ptr_typed(&dem->qualifiers, DemString, q, { dem_string_deinit(q); });
	vec_deinit(&dem->qualifiers);

	// deinit all func params first
	param_vec_deinit(&dem->func_params);

	dem_string_deinit(&dem->base_name);
	dem_string_deinit(&dem->prefix);
	dem_string_deinit(&dem->suffix);
	dem_string_deinit(&dem->custom_operator);

	memset(dem, 0, sizeof(CpDem));
	return;
}
