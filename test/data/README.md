# C++ Demangling Test Data

This directory contains CSV files with test data for C++ demangling tests.

## Structure

Each category has two CSV files:
- `cxx_<category>.csv` - Enabled tests that are expected to pass
- `cxx_<category>_disabled.csv` - Disabled tests (commented out or marked INCORRECT in original files)

## CSV Format

Standard CSV with two columns:
```csv
mangled,demangled
_Z3foov,foo()
"_ZeqRK7QStringS1_","operator==(QString const&, QString const&)"
```

- Fields with commas are enclosed in double quotes
- Quotes within fields are escaped as `""`
- Empty demangled field means the symbol should not demangle

## Categories

| Category | Tests | Description |
|----------|-------|-------------|
| `cxx_ctor_dtor` | 5,192 | Constructors and destructors |
| `cxx_method` | 13,385 | Class member functions |
| `cxx_template` | 6,218 | Template specializations |
| `cxx_other` | 2,072 | Miscellaneous symbols |
| `cxx_function` | 1,472 | Free functions |
| `cxx_vtable` | 1,490 | Virtual tables |
| `cxx_typeinfo` | 510 | RTTI typeinfo |
| `cxx_operator` | 304 | Operator overloads |
| `cxx_thunk` | 79 | Virtual thunks |
| `cxx_special` | 13 | Guard variables, etc. |
| `cxx_lambda` | 11 | Lambda expressions |

**Total: 30,746 enabled tests**

## Source Files

These CSV files were extracted from the original numbered test files:
- `test_cxx.{00-26}.c` (27 files from original meson.build)
- `test_cxx.27.c` (never in meson.build - contains C++20 module features)
- `test_cxx_base.c`
- `test_cxx_gnu_v3_llvm.c`
- `test_cxx_gnu_v3_template.c`
- `test_cxx_gnu_v3_type.c`

## Regenerating CSV Files

Use the `extract_tests.py` script in the repository root:

```bash
python3 extract_tests.py
```

This will re-extract all tests from the original C files (if they still exist in git history) and regenerate the CSV files.

## Known Test Failures

Some tests fail due to demangler limitations (not test infrastructure issues):

1. **noexcept support**: Missing `noexcept` in function pointers
2. **ABI tags**: Missing `[abi:X]` annotations
3. **C++20 modules**: Module name annotations like `@FOO` and `@Foo.Bar`
4. **Type aliases**: `int64_t` vs `long long` (semantically correct, different names)
5. **Advanced templates**: Parameter packs, complex substitutions

Most C++20 module failures come from `test_cxx.27.c` which was never enabled in the original build system.
