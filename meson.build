project('libdemangle', 'c', meson_version: '>=0.46.0')

libdemangle_c_args = []
libdemangle_src = [
  'src/demangler_util.c',
  'src/demangler.c',
  'src/java.c',
  'src/microsoft_demangle.c',
  'src/msvc.c',
  'src/objc.c',
]

tests = [
  'java',
  'msvc',
  'objc',
]

if get_option('use_gpl')
  libdemangle_src += 'src/cxx.c'
  libdemangle_src += 'src/cxx/cp-demangle.c'
  libdemangle_c_args += '-DWITH_GPL=1'
  tests += 'cxx'

  # rust tests depends on cxx
  tests += 'rust'
  libdemangle_src += 'src/rust.c'
endif

if get_option('use_swift_demangler')
  libdemangle_src += 'src/swift.c'
  libdemangle_c_args += '-DWITH_SWIFT_DEMANGLER=1'
  tests += 'swift'
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

foreach test : tests
  exe = executable('test_@0@'.format(test), 'test/test_@0@.c'.format(test),
    include_directories: include_directories(['.', 'test']),
    dependencies: [libdemangle_dep],
    c_args : libdemangle_c_args,
    install: false,
    install_rpath: '',
    implicit_include_directories: false
  )
  test(test, exe)
endforeach