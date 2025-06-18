// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"

DEFN_RULE (operator_name, {
    MATCH (READ ('v') && RULE (digit) && RULE (source_name));
    MATCH (READ_STR ("cv") && APPEND_STR ("operator (") && RULE (type) && APPEND_STR (")"));
    MATCH (READ_STR ("nw") && APPEND_STR ("operator new"));
    MATCH (READ_STR ("na") && APPEND_STR ("operator new[]"));
    MATCH (READ_STR ("dl") && APPEND_STR ("operator delete"));
    MATCH (READ_STR ("da") && APPEND_STR ("operator delete[]"));
    MATCH (READ_STR ("aw") && APPEND_STR ("operator co_await"));
    MATCH (READ_STR ("ps") && APPEND_STR ("operator+"));
    MATCH (READ_STR ("ng") && APPEND_STR ("operator-"));
    MATCH (READ_STR ("ad") && APPEND_STR ("operator&"));
    MATCH (READ_STR ("de") && APPEND_STR ("operator*"));
    MATCH (READ_STR ("co") && APPEND_STR ("operator~"));
    MATCH (READ_STR ("pl") && APPEND_STR ("operator+"));
    MATCH (READ_STR ("mi") && APPEND_STR ("operator-"));
    MATCH (READ_STR ("ml") && APPEND_STR ("operator*"));
    MATCH (READ_STR ("dv") && APPEND_STR ("operator/"));
    MATCH (READ_STR ("rm") && APPEND_STR ("operator%"));
    MATCH (READ_STR ("an") && APPEND_STR ("operator&"));
    MATCH (READ_STR ("or") && APPEND_STR ("operator|"));
    MATCH (READ_STR ("eo") && APPEND_STR ("operator^"));
    MATCH (READ_STR ("aS") && APPEND_STR ("operator="));
    MATCH (READ_STR ("pL") && APPEND_STR ("operator+="));
    MATCH (READ_STR ("mI") && APPEND_STR ("operator-="));
    MATCH (READ_STR ("mL") && APPEND_STR ("operator*="));
    MATCH (READ_STR ("dV") && APPEND_STR ("operator/="));
    MATCH (READ_STR ("rM") && APPEND_STR ("operator%="));
    MATCH (READ_STR ("aN") && APPEND_STR ("operator&="));
    MATCH (READ_STR ("oR") && APPEND_STR ("operator|="));
    MATCH (READ_STR ("eO") && APPEND_STR ("operator^="));
    MATCH (READ_STR ("ls") && APPEND_STR ("operator<<"));
    MATCH (READ_STR ("rs") && APPEND_STR ("operator>>"));
    MATCH (READ_STR ("lS") && APPEND_STR ("operator<<="));
    MATCH (READ_STR ("rS") && APPEND_STR ("operator>>="));
    MATCH (READ_STR ("eq") && APPEND_STR ("operator=="));
    MATCH (READ_STR ("ne") && APPEND_STR ("operator!="));
    MATCH (READ_STR ("lt") && APPEND_STR ("operator<"));
    MATCH (READ_STR ("gt") && APPEND_STR ("operator>"));
    MATCH (READ_STR ("le") && APPEND_STR ("operator<="));
    MATCH (READ_STR ("ge") && APPEND_STR ("operator>="));
    MATCH (READ_STR ("ss") && APPEND_STR ("operator<=>"));
    MATCH (READ_STR ("nt") && APPEND_STR ("operator!"));
    MATCH (READ_STR ("aa") && APPEND_STR ("operator&&"));
    MATCH (READ_STR ("oo") && APPEND_STR ("operator||"));
    MATCH (READ_STR ("pp") && APPEND_STR ("operator++"));
    MATCH (READ_STR ("mm") && APPEND_STR ("operator--"));
    MATCH (READ_STR ("cm") && APPEND_STR ("operator,"));
    MATCH (READ_STR ("pm") && APPEND_STR ("operator->*"));
    MATCH (READ_STR ("pt") && APPEND_STR ("operator->"));
    MATCH (READ_STR ("cl") && APPEND_STR ("operator()"));

    /* will generate " (type)" */
    MATCH (READ_STR ("ix") && APPEND_STR ("operator[]"));

    /* operator-name ::= li <source-name>          # operator ""*/
    MATCH (
        READ_STR ("li") && RULE (source_name)
    ); // TODO(brightprogrammer): How to generate for this operator?

    MATCH (READ_STR ("qu") && APPEND_STR ("operator?"));
}); 