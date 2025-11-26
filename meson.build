project('libdemangle', 'c', meson_version : '>=0.49.0')

cc = meson.get_compiler('c')

common_c_args = []
libdemangle_c_args = []
libdemangle_src = [
    'src' / 'borland.c',
    'src' / 'cxx.c',

    'src' / 'cplusplus' / 'demangle.c',
    'src' / 'cplusplus' / 'common.c',
    'src' / 'cplusplus' / 'param.c',
    'src' / 'cplusplus' / 'meta.c',
    'src' / 'cplusplus' / 'trace_graph.c',
    'src' / 'cplusplus' / 'parser_combinator.c',
    'src' / 'cplusplus' / 'v2.c',
    'src' / 'cplusplus' / 'v3.c',

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

    'cxx.00',
    'cxx.01',
    'cxx.02',
    'cxx.03',
    'cxx.04',
    'cxx.05',
    'cxx.06',
    'cxx.07',
    'cxx.08',
    'cxx.09',
    'cxx.10',
    'cxx.11',
    'cxx.12',
    'cxx.13',
    'cxx.14',
    'cxx.15',
    'cxx.16',
    'cxx.17',
    'cxx.18',
    'cxx.19',
    'cxx.20',
    'cxx.21',
    'cxx.22',
    'cxx.23',
    'cxx.24',
    'cxx.25',
    'cxx.26',

    'cxx_base',
    'cxx_gnu_v2',
    'cxx_gnu_v3_type',
    'cxx_gnu_v3_template',
    'cxx_gnu_v3_llvm',
]

unit_tests = [
    'cxx_rules'
]

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
    add_project_arguments('--std=gnu99', language : 'c')
elif cc.has_argument('--std=c99')
    add_project_arguments('--std=c99', language : 'c')
endif

libdemangle = both_libraries(
    'demangle',
    libdemangle_src,
    c_args : common_c_args + libdemangle_c_args,
    dependencies : [],
    implicit_include_directories : false,
    install : get_option('install_lib'),
    include_directories : include_directories(['include', 'src']),
)

libdemangle_dep = declare_dependency(
    link_with : libdemangle,
    dependencies : [],
    include_directories : include_directories('include'),
)

if get_option('enable_cli')
    bin_demangle = [
        'bin' / 'demangle.c',
    ]
    executable(
        'demangle',
        bin_demangle,
        c_args : common_c_args,
        dependencies : [libdemangle_dep],
        include_directories : include_directories(['include', 'src']),
        implicit_include_directories : false,
        install : true,
    )
endif

if get_option('enable_tests') and not meson.is_subproject()
    test_dependencies = []
    if get_option('b_sanitize').contains('address')
        unit_test_dependencies += cc.find_library('asan')
    endif
    if get_option('b_sanitize').contains('undefined')
        test_dependencies += cc.find_library('ubsan')
    endif
    foreach test : tests
        exe = executable(
            'test_@0@'.format(test),
            'test/test_@0@.c'.format(test),
            include_directories : include_directories(['include', 'test']),
            dependencies : test_dependencies + libdemangle_dep,
            c_args : common_c_args,
            install : false,
            install_rpath : '',
            implicit_include_directories : false,
        )
        test(test, exe)
    endforeach

    foreach test : unit_tests
        exe = executable(
            'test_@0@'.format(test),
            'test/unit/test_@0@.c'.format(test),
            link_whole : libdemangle.get_static_lib(),
            include_directories : include_directories(['include', 'test']),
            dependencies : test_dependencies,
            c_args : common_c_args,
            install : false,
            install_rpath : '',
            implicit_include_directories : false,
        )
        test(test, exe)
    endforeach
endif
