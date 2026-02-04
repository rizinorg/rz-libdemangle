#!/usr/bin/env python3
"""Extract and categorize C++ demangling tests from test files."""

import re
import csv
import os
from collections import defaultdict
from pathlib import Path

# Test file patterns
# Note: test_cxx.27.c exists but was NOT in original meson.build
# We include it anyway to expose previously untested code
TEST_FILES = [
    *[f"test/test_cxx.{i:02d}.c" for i in range(28)],  # 00-27
    "test/test_cxx_base.c",
    "test/test_cxx_gnu_v3_llvm.c",
    "test/test_cxx_gnu_v3_template.c",
    "test/test_cxx_gnu_v3_type.c",
]

# Category patterns (order matters - first match wins)
# Note: ctor_dtor is handled specially in categorize() function
CATEGORIES = [
    ("vtable", [r"\bvtable\b", r"\bVTT\b", r"\bconstruction vtable\b"]),
    ("typeinfo", [r"\btypeinfo\b", r"\btype_info\b"]),
    ("thunk", [r"\bthunk\b", r"\bcovariant return thunk\b"]),
    ("operator", [r"\boperator[^\w]", r"\boperator\s*[<>=+\-*/\[\]()]"]),
    ("lambda", [r"'lambda'", r"'unnamed", r"\$_\d+", r"block_invoke", r"'lambda\d*'"]),
    (
        "special",
        [r"\bguard variable\b", r"\bglobal constructors\b", r"\bglobal destructors\b"],
    ),
    ("template", [r"<.*>"]),
    ("method", [r"::\w+\("]),
    ("function", [r"^\w+\(", r"^[a-zA-Z_][\w:]*\("]),
]


def categorize(demangled):
    """Categorize a demangled symbol."""
    if not demangled or demangled == "(null)" or not demangled.strip():
        return "invalid"

    # Special check for constructors/destructors
    # Pattern: ClassName::ClassName(...) or ClassName::~ClassName(...)
    ctor_dtor_pattern = r"(\w+)::~?\1\s*\("
    if re.search(ctor_dtor_pattern, demangled):
        return "ctor_dtor"

    # Destructor with explicit ~
    if re.search(r"::~\w+\s*\(", demangled):
        return "ctor_dtor"

    for category, patterns in CATEGORIES:
        for pattern in patterns:
            if re.search(pattern, demangled, re.IGNORECASE):
                return category

    return "other"


def extract_tests_from_file(filepath):
    """Extract test cases from a C test file."""
    enabled_tests = []
    disabled_tests = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Match mu_demangle_test patterns
    # Pattern: mu_demangle_test("mangled", "demangled")
    # Can be commented with //
    pattern = r'(//[^\n]*)?mu_demangle_test\(\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\)'

    for match in re.finditer(pattern, content):
        comment = match.group(1) if match.group(1) else ""
        mangled = match.group(2)
        demangled = match.group(3)

        # Check if test is disabled (commented or marked as INCORRECT/TODO/etc)
        is_disabled = bool(match.group(1))  # Has // comment
        if not is_disabled:
            # Check if there's a comment marker before the mu_demangle_test on the same line
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_prefix = content[line_start : match.start()]
            if (
                "//" in line_prefix
                or "INCORRECT" in line_prefix
                or "TODO" in line_prefix
            ):
                is_disabled = True

        # Unescape the strings
        mangled = mangled.replace(r"\"", '"').replace(r"\\", "\\")
        demangled = demangled.replace(r"\"", '"').replace(r"\\", "\\")

        test_case = (mangled, demangled)

        if is_disabled:
            disabled_tests.append(test_case)
        else:
            enabled_tests.append(test_case)

    return enabled_tests, disabled_tests


def write_csv(filepath, tests):
    """Write tests to CSV file with proper escaping."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["mangled", "demangled"])

        for mangled, demangled in tests:
            writer.writerow([mangled, demangled])


def main():
    # Collect tests by category
    enabled_by_category = defaultdict(list)
    disabled_by_category = defaultdict(list)

    total_enabled = 0
    total_disabled = 0

    for test_file in TEST_FILES:
        if not os.path.exists(test_file):
            print(f"Warning: {test_file} not found")
            continue

        print(f"Processing {test_file}...")
        enabled, disabled = extract_tests_from_file(test_file)

        total_enabled += len(enabled)
        total_disabled += len(disabled)

        # Categorize enabled tests
        for mangled, demangled in enabled:
            category = categorize(demangled)
            enabled_by_category[category].append((mangled, demangled))

        # Categorize disabled tests
        for mangled, demangled in disabled:
            category = categorize(demangled)
            disabled_by_category[category].append((mangled, demangled))

    print(f"\nTotal enabled tests: {total_enabled}")
    print(f"Total disabled tests: {total_disabled}")

    # Write enabled tests
    print("\nWriting enabled test CSVs...")
    for category, tests in sorted(enabled_by_category.items()):
        csv_path = f"test/data/cxx_{category}.csv"
        write_csv(csv_path, tests)
        print(f"  {csv_path}: {len(tests)} tests")

    # Write disabled tests
    print("\nWriting disabled test CSVs...")
    for category, tests in sorted(disabled_by_category.items()):
        csv_path = f"test/data/cxx_{category}_disabled.csv"
        write_csv(csv_path, tests)
        print(f"  {csv_path}: {len(tests)} tests")

    print("\nCategory summary (enabled):")
    for category in sorted(enabled_by_category.keys()):
        count = len(enabled_by_category[category])
        print(f"  {category:15s}: {count:5d} tests")

    if disabled_by_category:
        print("\nCategory summary (disabled):")
        for category in sorted(disabled_by_category.keys()):
            count = len(disabled_by_category[category])
            print(f"  {category:15s}: {count:5d} tests")


if __name__ == "__main__":
    main()
