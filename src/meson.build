##### Generate libconnmanproxy.so
libconnmanproxy_sources = ['connman_proxy_main.c',
                           'connman_proxy_manager_interface.c',
                           'connman_proxy_service_interface.c',
                           'connman_proxy_technology_interface.c',
                           'connman_mgr_agent_interface.c',
                           'connman_proxy_utils.c',
                           generated_src]

lib_dep = [gio_dep, gio_unix_dep]
connman_proxy = shared_library('connmanproxy', libconnmanproxy_sources, include_directories : includedir, dependencies : lib_dep, install: true)
