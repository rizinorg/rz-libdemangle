# Rizin libdemangle

This library contains all rizin demanglers and is linked statically in rizin to provide demangling support in rizin

## Run tests with asan

```
meson -Dbuildtype=debugoptimized -Db_sanitize=address,undefined build
ninja -C build test
```

## Build and install cli tool

This cli tool does not require rizin.

### Install

```
meson --prefix=/usr -Denable_cli=true build
ninja -C build install
```

### Usage

```
demangle -s pascal 'OUTPUT_$$_init'
```

## Install library in prefix path

```
meson --prefix=/usr -Dinstall_lib=true build
ninja -C build install
```

## Demangler

## Graphviz Tracing

The C++ demangler now supports visual tracing via Graphviz for debugging complex parsing scenarios. Instead of text-based trace logs, the system generates `.dot` files that can be rendered as visual graphs showing the parsing tree.

### Features

- **Visual parsing tree**: Each rule invocation becomes a node in the graph
- **Success/failure tracking**: Nodes are color-coded:
  - 🟢 **Green**: Successful rule matches
  - 🔴 **Red**: Failed rule matches  
  - 🟠 **Orange**: Backtracked attempts (dashed border)
  - 🔵 **Blue**: Currently running rules
- **Position tracking**: Shows parsing position and input snippets
- **Result display**: Successful nodes show their output
- **Parent-child relationships**: Edges show rule call hierarchy
- **Backtracking visualization**: Clearly shows which paths were abandoned

### Usage

Enable tracing by setting the `DEMANGLE_TRACE` environment variable:

```bash
export DEMANGLE_TRACE=1
./your_demangler _ZN4llvm8DenseMapIPKN5clang4DeclEPNS_6WeakVHEE
```

Or compile with `-DENABLE_GRAPHVIZ_TRACE` to always enable tracing.

This will generate a file like `demangle_trace__ZN4llvm8DenseMapIPKN5clang4DeclEPNS_6WeakVHE.dot`.

### Generating Images

Convert the `.dot` file to a visual format:

```bash
# PNG image
dot -Tpng demangle_trace.dot -o parsing_tree.png

# SVG (scalable)
dot -Tsvg demangle_trace.dot -o parsing_tree.svg

# PDF
dot -Tpdf demangle_trace.dot -o parsing_tree.pdf
```

### Graph Structure

The generated graph shows:
- **Root node**: The initial `mangled_name` rule
- **Child nodes**: All rules called during parsing
- **Edge colors**: Match the node status (green for success, red for failure, etc.)
- **Node labels**: Include rule name, position, input snippet, and result
- **Legend**: Explains the color coding

This visual representation makes it much easier to understand complex backtracking scenarios and identify where parsing issues occur.

## Building

```
meson -Dbuildtype=debugoptimized -Db_sanitize=address,undefined build
ninja -C build test
```
