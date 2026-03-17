project ('cameradarC', 'c',
	version : '0.2.0-unstable',
	default_options : ['c_std=c99', 'warning_level=2']
)

v_h = vcs_tag (
	input : 'src/version.h.in',
	output : 'version.h',
	fallback : '0.2.0-unstable'
)

confDt = configuration_data()
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

sources = ['src/main.c', 'src/utils.c', 'src/nmap.c', v_h]

executable ('cam',
	sources,
	dependencies : [curl, thread, json, xml, imm],
	include_directories : inc,
	install : true,
	c_args: ['-Wall', '-Wextra', '-Wno-unused-function']
)