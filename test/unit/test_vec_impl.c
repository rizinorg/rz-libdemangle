// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz-minunit.h"
#include "../../src/demangler_util.h"
#include "../../src/cplusplus/vec.h"

// Define a simple type for testing
typedef int TestInt;
void TestInt_free(TestInt *i) { UNUSED(i); }
VecIMPL(TestInt, TestInt_free);

// Define a struct type for testing memory management
typedef struct {
    int *ptr;
} TestStruct;

void TestStruct_free(TestStruct *s) {
    if (s && s->ptr) {
        free(s->ptr);
        s->ptr = NULL;
    }
}
VecIMPL(TestStruct, TestStruct_free);

int test_vec_int_basic() {
    VecTestInt *v = VecF(TestInt, ctor)();
    mu_assert("ctor failed", v != NULL);
    mu_assert("should be empty", VecF(TestInt, empty)(v));
    mu_assert("len should be 0", VecF(TestInt, len)(v) == 0);
    mu_assert("cap should be 0", VecF(TestInt, cap)(v) == 0);

    TestInt val = 42;
    VecF(TestInt, append)(v, &val);
    mu_assert("len should be 1", VecF(TestInt, len)(v) == 1);
    mu_assert("cap should be >= 1", VecF(TestInt, cap)(v) >= 1);
    mu_assert("head should be 42", *VecF(TestInt, head)(v) == 42);
    mu_assert("tail should be 42", *VecF(TestInt, tail)(v) == 42);

    val = 100;
    VecF(TestInt, append)(v, &val);
    mu_assert("len should be 2", VecF(TestInt, len)(v) == 2);
    mu_assert("head should be 42", *VecF(TestInt, head)(v) == 42);
    mu_assert("tail should be 100", *VecF(TestInt, tail)(v) == 100);
    mu_assert("at(1) should be 100", *VecF(TestInt, at)(v, 1) == 100);

    TestInt *popped = VecF(TestInt, pop)(v);
    mu_assert("pop should return 100", *popped == 100);
    mu_assert("len should be 1", VecF(TestInt, len)(v) == 1);

    VecF(TestInt, dtor)(v);
    mu_end;
}

int test_vec_int_stack() {
    VecTestInt v;
    VecF(TestInt, init)(&v);
    mu_assert("should be empty", VecF(TestInt, empty)(&v));

    TestInt val = 1;
    VecF(TestInt, append)(&v, &val);
    mu_assert("len should be 1", VecF(TestInt, len)(&v) == 1);

    VecF(TestInt, deinit)(&v);
    mu_assert("data should be NULL after deinit", v.data == NULL);
    mu_assert("len should be 0 after deinit", v.length == 0);
    mu_end;
}

int test_vec_reserve_resize() {
    VecTestInt *v = VecF(TestInt, ctor)();
    
    mu_assert("reserve failed", VecF(TestInt, reserve)(v, 10));
    mu_assert("cap should be 10", VecF(TestInt, cap)(v) == 10);
    mu_assert("len should still be 0", VecF(TestInt, len)(v) == 0);

    mu_assert("resize failed", VecF(TestInt, resize)(v, 5));
    mu_assert("len should be 5", VecF(TestInt, len)(v) == 5);
    mu_assert("cap should be >= 5", VecF(TestInt, cap)(v) >= 5);
    // Check zero initialization
    for (int i = 0; i < 5; i++) {
        mu_assert("resized elements should be 0", *VecF(TestInt, at)(v, i) == 0);
    }

    VecF(TestInt, dtor)(v);
    mu_end;
}

int test_vec_concat() {
    VecTestInt *v1 = VecF(TestInt, ctor)();
    VecTestInt *v2 = VecF(TestInt, ctor)();

    TestInt val = 1;
    VecF(TestInt, append)(v1, &val);
    val = 2;
    VecF(TestInt, append)(v2, &val);

    VecF(TestInt, concat)(v1, v2);
    mu_assert("v1 len should be 2", VecF(TestInt, len)(v1) == 2);
    mu_assert("v1[0] should be 1", *VecF(TestInt, at)(v1, 0) == 1);
    mu_assert("v1[1] should be 2", *VecF(TestInt, at)(v1, 1) == 2);

    VecF(TestInt, dtor)(v1);
    VecF(TestInt, dtor)(v2);
    mu_end;
}

int test_vec_move() {
    VecTestInt *v1 = VecF(TestInt, ctor)();
    VecTestInt *v2 = VecF(TestInt, ctor)();

    TestInt val = 1;
    VecF(TestInt, append)(v2, &val);

    VecF(TestInt, move)(v1, v2);
    mu_assert("v1 len should be 1", VecF(TestInt, len)(v1) == 1);
    mu_assert("v1[0] should be 1", *VecF(TestInt, at)(v1, 0) == 1);
    mu_assert("v2 should be empty", VecF(TestInt, empty)(v2));
    mu_assert("v2 data should be NULL", v2->data == NULL);

    VecF(TestInt, dtor)(v1);
    VecF(TestInt, dtor)(v2);
    mu_end;
}

int test_vec_struct_memory() {
    VecTestStruct *v = VecF(TestStruct, ctor)();
    
    TestStruct s;
    s.ptr = malloc(sizeof(int));
    *s.ptr = 123;
    
    VecF(TestStruct, append)(v, &s);
    
    mu_assert("len should be 1", VecF(TestStruct, len)(v) == 1);
    mu_assert("value should be 123", *VecF(TestStruct, at)(v, 0)->ptr == 123);

    VecF(TestStruct, dtor)(v);
    // If double free occurs, test will crash.
    mu_end;
}

int all_tests() {
    mu_run_test(test_vec_int_basic);
    mu_run_test(test_vec_int_stack);
    mu_run_test(test_vec_reserve_resize);
    mu_run_test(test_vec_concat);
    mu_run_test(test_vec_move);
    mu_run_test(test_vec_struct_memory);
    return tests_passed != tests_run;
}

mu_main(all_tests);
