project('libdemangle', 'c', meson_version : '>=0.56.0')

cc = meson.get_compiler('c')

common_c_args = []
libdemangle_c_args = []
libdemangle_src = [
    'src' / 'borland.c',
    'src' / 'cxx.c',

    'src' / 'cplusplus' / 'demangle.c',
    'src' / 'cplusplus' / 'v2' / 'common.c',
    'src' / 'cplusplus' / 'v2' / 'param.c',
    'src' / 'cplusplus' / 'v2' / 'v2.c',
    'src' / 'cplusplus' / 'v3' / 'meta.c',
    'src' / 'cplusplus' / 'v3' / 'parser_combinator.c',
    'src' / 'cplusplus' / 'v3' / 'ast.c',
    'src' / 'cplusplus' / 'v3' / 'v3.c',

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

    'subs', # Substitution table tests

    # C++ demangling tests (organized by category)
    'cxx_ctor_dtor',
    'cxx_function',
    'cxx_lambda',
    'cxx_method',
    'cxx_operator',
    'cxx_other',
    'cxx_special',
    'cxx_template',
    'cxx_thunk',
    'cxx_typeinfo',
    'cxx_vtable',
    
    'cxx_gnu_v2',  # Keep GNU v2 separate (different ABI)
]

unit_tests = [
    'cxx_rules',
    'vec_impl'
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

# When used as a subproject with default_library=static (e.g., Rizin),
# prefer the static library. Otherwise, use the shared library by default.
if get_option('default_library') == 'static'
    libdemangle_link = libdemangle.get_static_lib()
elif get_option('default_library') == 'shared'
    libdemangle_link = libdemangle.get_shared_lib()
else
    # For 'both', prefer static for better compatibility as a subproject
    libdemangle_link = libdemangle.get_static_lib()
endif

libdemangle_dep = declare_dependency(
    link_with : libdemangle_link,
    dependencies : [],
    include_directories : include_directories('include'),
)

if get_option('enable_cli')
    bin_demangle = [
        'bin' / 'demangle.c',
    ]
    # Use 'rz-demangle' to avoid name conflicts with the library on MSVC
    executable(
        'rz-demangle',
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
        test_dependencies += cc.find_library('asan')
    endif
    if get_option('b_sanitize').contains('undefined')
        test_dependencies += cc.find_library('ubsan')
    endif
    
    # Tests that need longer timeout due to large number of test cases
    slow_tests = ['cxx_method', 'cxx_template', 'cxx_ctor_dtor']
    
    # Tests that use CSV data files and need SOURCE_ROOT defined
    csv_tests = [
        'cxx_ctor_dtor',
        'cxx_function',
        'cxx_lambda',
        'cxx_method',
        'cxx_operator',
        'cxx_other',
        'cxx_special',
        'cxx_template',
        'cxx_thunk',
        'cxx_typeinfo',
        'cxx_vtable',
    ]

    foreach test : tests
        test_c_args = common_c_args
        
        # Add SOURCE_ROOT for CSV-based tests
        if test in csv_tests
            test_c_args += '-DSOURCE_ROOT="@0@"'.format(meson.project_source_root())
        endif
        
        exe = executable(
            'test_@0@'.format(test),
            'test/test_@0@.c'.format(test),
            link_whole : libdemangle.get_static_lib(),
            include_directories : include_directories(['include', 'test', 'src']),
            dependencies : test_dependencies,
            c_args : test_c_args,
            install : false,
            install_rpath : '',
            implicit_include_directories : false,
        )
        if test in slow_tests
            test(test, exe, timeout : 120)
        else
            test(test, exe)
        endif
    endforeach
    foreach test : unit_tests
        exe = executable(
            'test_@0@'.format(test),
            'test/unit/test_@0@.c'.format(test),
            link_whole : libdemangle.get_static_lib(),
            include_directories : include_directories(['include', 'test', 'src']),
            dependencies : test_dependencies,
            c_args : common_c_args,
            install : false,
            install_rpath : '',
            implicit_include_directories : false,
        )
        test(test, exe)
    endforeach
endif
