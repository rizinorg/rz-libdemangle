project('libdemangle', 'c', meson_version: '>=0.49.0')

cc = meson.get_compiler('c')

common_c_args = []
libdemangle_c_args = []
libdemangle_src = [
  'src' / 'cxx' / 'borland.c',
  'src' / 'cxx.c',
  'src' / 'demangler.c',
  'src' / 'demangler_util.c',
  'src' / 'java.c',
  'src' / 'microsoft_demangle.c',
  'src' / 'msvc.c',
  'src' / 'objc.c',
  'src' / 'pascal' / 'pascal.c',
  'src' / 'rust' / 'punycode.c',
  'src' / 'rust' / 'rust.c',
  'src' / 'rust' / 'rust_legacy.c',
  'src' / 'rust' / 'rust_v0.c',
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
  libdemangle_src += 'src' / 'gnu_v2' / 'cplus-dem.c'
  common_c_args += '-DWITH_GPL=1'

  tests += 'cxx.00'
  tests += 'cxx.01'
  tests += 'cxx.02'
  tests += 'cxx.03'
  tests += 'cxx.04'
  tests += 'cxx.05'
  tests += 'cxx.06'
  tests += 'cxx.07'
  tests += 'cxx.08'
  tests += 'cxx.09'
  tests += 'cxx.10'
  tests += 'cxx.11'
  tests += 'cxx.12'
  tests += 'cxx.13'
  tests += 'cxx.14'
  tests += 'cxx.15'
  tests += 'cxx.16'
  tests += 'cxx.17'
  tests += 'cxx.18'
  tests += 'cxx.19'
  tests += 'cxx.20'
  tests += 'cxx.21'
  tests += 'cxx.22'
  tests += 'cxx.23'
  tests += 'cxx.24'
  tests += 'cxx.25'
  tests += 'cxx.26'

  tests += 'cxx_base'
  tests += 'cxx_gnu_v2'
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
    install: get_option('install_lib'),
    include_directories: include_directories(['include', 'src']))

libdemangle_dep = declare_dependency(
    link_with: libdemangle,
    dependencies: [],
    include_directories: include_directories('include'),
)

if get_option('enable_cli')
  bin_demangle = [
    'bin' / 'demangle.c',
  ]
  executable('demangle', bin_demangle,
    c_args : common_c_args,
    dependencies: [libdemangle_dep],
    include_directories: include_directories(['include', 'src']),
    implicit_include_directories: false,
    install: true,
  )
endif

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
