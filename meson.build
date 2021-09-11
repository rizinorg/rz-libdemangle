project('libdemangle', 'c', meson_version: '>=0.46.0')

libdemangle_c_args = []
libdemangle_src = [
  'src/demangler_util.c',
  'src/demangler.c',
  'src/rust.c',
  'src/java.c',
  'src/microsoft_demangle.c',
  'src/msvc.c',
  'src/objc.c',
]

if get_option('use_gpl')
  libdemangle_src += 'src/cxx.c'
  libdemangle_src += 'src/cxx/cp-demangle.c'
  libdemangle_c_args += '-DWITH_GPL=1'
endif

if get_option('use_swift_demangler')
  libdemangle_src += 'src/swift.c'
  libdemangle_c_args += '-DWITH_SWIFT_DEMANGLER=1'
endif

libdemangle = library('demangle', libdemangle_src,
    c_args : libdemangle_c_args,
    dependencies: [],
    include_directories: include_directories('src'))

libdemangle_dep = declare_dependency(
    link_with: libdemangle,
    dependencies: [],
    include_directories: include_directories('.'),
)
