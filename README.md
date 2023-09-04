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
