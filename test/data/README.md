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

| Category        | Tests  | Description                  |
|-----------------|--------|------------------------------|
| `cxx_ctor_dtor` | 5,192  | Constructors and destructors |
| `cxx_method`    | 13,385 | Class member functions       |
| `cxx_template`  | 6,218  | Template specializations     |
| `cxx_other`     | 2,072  | Miscellaneous symbols        |
| `cxx_function`  | 1,472  | Free functions               |
| `cxx_vtable`    | 1,490  | Virtual tables               |
| `cxx_typeinfo`  | 510    | RTTI typeinfo                |
| `cxx_operator`  | 304    | Operator overloads           |
| `cxx_thunk`     | 79     | Virtual thunks               |
| `cxx_special`   | 13     | Guard variables, etc.        |
| `cxx_lambda`    | 11     | Lambda expressions           |

**Total: 30,746 enabled tests**
