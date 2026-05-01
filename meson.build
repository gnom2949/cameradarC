project ('cameradarC', 'c', 'cpp',
	version : '0.2.2-stable',
	default_options : ['c_std=c99', 'cpp_std=c++14', 'warning_level=2']
)

v_h = vcs_tag (
	input : 'src/version.h.in',
	output : 'version.h',
	fallback : '0.2.1-unstable'
)

confDt   = configuration_data()
confDt.set_quoted ('PROJECT_VERSION', meson.project_version())

configure_file(
	output: 'config.h',
	configuration : confDt
)

inc = include_directories ('.', 'src')

add_project_arguments('-D_GNU_SOURCE', language: 'c')
	
#deps
install_headers ('imm/IntMemoryManager.h', subdir: 'imm')

libimm = shared_library ('imm',
	'imm/IntMemoryManager.c',
	install: true,
	include_directories: include_directories('.')
)

imm = declare_dependency(
	link_with: libimm,
	include_directories: include_directories('.')
)
curl = dependency ('libcurl')
thread = dependency ('threads')
json = dependency ('json-c')
xml = dependency ('libxml-2.0')
gtest = dependency ('gtest', main : true, required : false)

sources = ['src/main.c', 'src/utils.c', 'src/nmap.c', 'src/runner.c', 'src/scanners.c', 'src/socks.c', 'src/dictionary.c', v_h]

executable ('cam',
	sources,
	dependencies : [curl, thread, json, xml, imm],
	include_directories : inc,
	install : true,
        link_args: ['-static'],
	c_args: ['-Wall', '-Wextra', '-Wno-unused-function']
)

test_sources = ['tests/test_mem.cpp', 'tests/testcam.cpp', 'src/nmap.c', 'src/utils.c', 'src/runner.c', 'src/socks.c', 'src/scanners.c', 'src/dictionary.c', v_h]

camtest = executable ('camt',
	test_sources,
	dependencies : [gtest, imm, thread, curl, json, xml],
	include_directories : include_directories('.'),
	link_args : ['-Wl,--wrap=spawnSock']
)

test ('intmemorymanager_allocator_test', camtest)

install_subdir ('src/brute', install_dir : get_option('datadir') / 'gnom2949')
