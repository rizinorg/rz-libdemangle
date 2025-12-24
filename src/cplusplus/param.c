// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "param.h"

Param *param_append_to_dem_string(Param *p, DemString *ds) {
	if (!ds || !p) {
		return NULL;
	}

	if ((p)->prefix.len) {
		dem_string_concat((ds), &(p)->prefix);
		dem_string_append_char((ds), ' ');
	}
	dem_string_concat((ds), &(p)->name);
	if ((p)->suffix.len) {
		dem_string_append_char((ds), ' ');
		dem_string_concat((ds), &(p)->suffix);
	}

	return p;
}

ParamVec *param_vec_append_to_dem_string(ParamVec *pv, DemString *ds) {
	if (!ds || !pv) {
		return NULL;
	}

	if (pv->length) {
		bool is_first_param = true;
		vec_foreach_ptr(pv, param, {
			if (is_first_param) {
				is_first_param = false;
			} else {
				dem_string_append_n((ds), ", ", 2);
			}

			param_append_to_dem_string(param, ds);
		});
	} else {
		dem_string_append_n((ds), "void", 4);
	}

	return pv;
}
