project ('cameradarC', 'c',
	version : '0.1',
	default_options : ['c_std=c99', 'warning_level=2'])
	
add_project_arguments('-D_GNU_SOURCE', language: 'c')
	
#deps
curl = dependency ('libcurl')
thread = dependency ('threads')
json = dependency ('json-c')

sources = ['main.c']

executable ('cam',
	sources,
	dependencies : [curl, thread, json],
	install : true)