project('connman_proxy', 'c',
        version : '1.0.0',
        license: 'LGPL2+',
        meson_version: '>=0.46'
    )
compiler = meson.get_compiler('c')

###############
# Directories #
###############

top_srcdir = meson.source_root()
includedir = include_directories('include')

###################
# End Directories #
###################

##################
# Module Imports #
##################

gnome = import('gnome')
pkgconfig = import('pkgconfig')

######################
# End Module Imports #
######################

#########################
# External Dependencies #
#########################

gio_dep = dependency('gio-2.0', version : '>= 2.26.0')
gio_unix_dep = dependency('gio-unix-2.0', version : '>= 2.26.0')

pthread_deps = declare_dependency(link_args : '-lpthread')

#############################
# End External Dependencies #
#############################

###############################
# Compiler and Linker options #
###############################

connman_proxy_compiler_flag  = ['-std=gnu99']
connman_proxy_compiler_flag += ['-rdynamic', '-fvisibility=hidden']
connman_proxy_compiler_flag += ['-Wall', '-Werror']
connman_proxy_compiler_flag += ['-Wfloat-equal', '-Wformat=2', '-Wunreachable-code', '-Wundef', '-Winline', '-Wconversion', '-Wswitch', '-Wcast-align', '-Wimplicit', '-Wmissing-prototypes', '-Wshadow']
connman_proxy_compiler_flag += ['-Wsign-conversion', '-Wimplicit-function-declaration', '-Wpointer-to-int-cast', '-Wint-to-pointer-cast']
if compiler.has_argument('-Wcast-function-type')
connman_proxy_compiler_flag += ['-Wcast-function-type']
endif

##### Developer Compiler flags #####
connman_proxy_compiler_flag += ['-g']
#connman_proxy_compiler_flag += ['-Wextra']

connman_proxy_compiler_flag += ['-DCONNMAN_LOG_LEVEL=CONN_LOG_INFO'] #Default Log level

connman_proxy_linker_flag = '-Wl,--as-needed'

add_project_arguments([connman_proxy_compiler_flag, connman_proxy_linker_flag], language : 'c')

###################################
# End compiler and Linker options #
###################################


#########
# Build #
#########

subdirs = [ 'dbus_xml', 'include', 'src', 'docs' ]

##### Conditional Builds #####
if get_option('examples')
subdirs += 'examples'
endif

foreach n : subdirs
    subdir(n)
endforeach

#############
# End Build #
#############

pkgconfig.generate(libraries : connman_proxy,
                    version : meson.project_version(),
                    name : 'connmanproxy',
                    filebase : 'connmanproxy',
                    description : 'A Library to communicate with connman daemon',
                    subdirs : 'connman_proxy')
