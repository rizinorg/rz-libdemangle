project('libdemangle', 'c', meson_version: '>=0.49.0')

cc = meson.get_compiler('c')

common_c_args = []
libdemangle_c_args = []
libdemangle_src = [
  'src' / 'cxx.c',
  'src' / 'cxx' / 'borland.c',
  'src' / 'demangler.c',
  'src' / 'demangler_util.c',
  'src' / 'java.c',
  'src' / 'microsoft_demangle.c',
  'src' / 'msvc.c',
  'src' / 'objc.c',
  'src' / 'pascal' / 'pascal.c',
  'src' / 'rust.c',
]

tests = [
  'borland',
  'java',
  'msvc',
  'objc',
  'pascal',
  'rust',
]

if get_option('use_gpl')
  libdemangle_src += 'src' / 'cxx' / 'cp-demangle.c'
  common_c_args += '-DWITH_GPL=1'
  tests += 'cxx'
endif

if get_option('use_swift_demangler')
  libdemangle_src += 'src' / 'swift.c'
  common_c_args += '-DWITH_SWIFT_DEMANGLER=1'
  tests += 'swift'
endif

if get_option('default_library') == 'shared'
  if cc.has_argument('-fvisibility=hidden')
    libdemangle_c_args += '-fvisibility=hidden'
  endif
endif

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: 'c')
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: 'c')
endif

libdemangle = library('demangle', libdemangle_src,
    c_args : common_c_args + libdemangle_c_args,
    dependencies: [],
    implicit_include_directories: false,
    include_directories: include_directories(['include', 'src']))

libdemangle_dep = declare_dependency(
    link_with: libdemangle,
    dependencies: [],
    include_directories: include_directories('include'),
)

if get_option('enable_tests') and not meson.is_subproject()
  test_dependencies = [libdemangle_dep]
  if get_option('b_sanitize').contains('address')
    test_dependencies += cc.find_library('asan')
  endif
  if get_option('b_sanitize').contains('undefined')
    test_dependencies += cc.find_library('ubsan')
  endif
  foreach test : tests
    exe = executable('test_@0@'.format(test), 'test/test_@0@.c'.format(test),
      include_directories: include_directories(['include', 'test']),
      dependencies: test_dependencies,
      c_args : common_c_args,
      install: false,
      install_rpath: '',
      implicit_include_directories: false
    )
    test(test, exe)
  endforeach
endif