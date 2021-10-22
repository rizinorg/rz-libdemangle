# Rizin libdemangle

This library contains all rizin demanglers and is linked statically in rizin to provide demangling support in rizin

## Run tests with asan

```
meson -Dbuildtype=debugoptimized -Db_sanitize=address,undefined build
ninja -C build test
```
