// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

/* 
 * NOTE: Taken from old c++v3 demangler code
 * Some of these are tested, others are not encountered yet.
 *
 * <special-name> ::= TV <type>
		  ::= TT <type>
		  ::= TI <type>
		  ::= TS <type>
		  ::= TA <template-arg>
		  ::= GV <(object) name>
		  ::= T <call-offset> <(base) encoding>
		  ::= Tc <call-offset> <call-offset> <(base) encoding>
   Also g++ extensions:
		  ::= TC <type> <(offset) number> _ <(base) type>
		  ::= TF <type>
		  ::= TJ <type>
		  ::= GR <name>
		  ::= GA <encoding>
		  ::= Gr <resource name>
		  ::= GTt <encoding>
		  ::= GTn <encoding>
*/

DEFN_RULE (special_name, {
    MATCH (
        READ_STR ("Tc") && RULE (call_offset) && RULE (call_offset) && 
        RULE (encoding)
    );
    MATCH (
        READ_STR ("GR") && APPEND_STR ("reference temporary for ") && 
        RULE (name) && RULE (seq_id) && READ ('_')
    );
    MATCH (READ ('T') && RULE (call_offset) && RULE (encoding));
    MATCH (
        READ_STR ("GR") && APPEND_STR ("reference temporary for ") && 
        RULE (name) && READ ('_')
    );
    MATCH (READ_STR ("TV") && APPEND_STR ("vtable for ") && RULE (type));
    MATCH (READ_STR ("TT") && APPEND_STR ("VTT structure for ") && RULE (type));
    MATCH (READ_STR ("TI") && APPEND_STR ("typeinfo structure for ") && RULE (type));
    MATCH (READ_STR ("TS") && APPEND_STR ("typeinfo name for ") && RULE (type));
    MATCH (READ_STR ("GV") && APPEND_STR ("guard variable for ") && RULE (name));
    MATCH (READ_STR ("GTt") && RULE (encoding));
}); 