# Rizin libdemangle

This library contains all rizin demanglers and is linked statically in rizin to provide demangling support in rizin

## Clone Repository

```
git clone https://github.com/rizinorg/rz-libdemangle.git
cd rz-libdemangle
```

## Build and install cli tool

This cli tool does not require rizin.

```
meson setup build --prefix=/usr -Denable_cli=true
meson compile -C build
sudo meson install -C build
```


### Usage

```
rz-demangle -s pascal 'OUTPUT_$$_init'
```


## Install Library

To install the library into the system prefix:


```
meson setup build --prefix=/usr -Dinstall_lib=true
meson compile -C build
sudo meson install -C build
```


## Development

### Debug Build with Sanitizers

```
meson setup build -Dbuildtype=debugoptimized -Db_sanitize=address,undefined
```

### Run Tests

```
meson test -C build
```
