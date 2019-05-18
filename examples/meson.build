
##### Generate connman_proxy_test #####
libconnmanproxy_deps = declare_dependency(include_directories : includedir, 
                                          link_with : connman_proxy)

connman_proxy_test_deps = [gio_dep, gio_unix_dep, pthread_deps, libconnmanproxy_deps]
connman_proxy_test_sources = [ 'connman_proxy_test.c',
                               'connman_proxy_test_kb.c',
                               generated_src[1]]
executable('connman_proxy_test', connman_proxy_test_sources, dependencies : connman_proxy_test_deps, install: false)
