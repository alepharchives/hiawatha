cmake_minimum_required(VERSION 2.8.4)
project(Hiawatha C)

# Compiler
set(CMAKE_C_FLAGS "-Wall -Wextra")
set(CMAKE_BUILD_TYPE "RelWithDebInfo")

# Options
option(ENABLE_CACHE    "Enable cache support in Hiawatha." on)
option(ENABLE_DEBUG    "Enable debug information (for development only)." off)
option(ENABLE_IPV6     "Enable IPv6 support in Hiawatha." on)
option(ENABLE_MONITOR  "Enable support for the Hiawatha Monitor." off)
option(ENABLE_RPROXY   "Enable reverse proxy support in Hiawatha." on)
option(ENABLE_SSL      "Enable SSL (PolarSSL) support in Hiawatha." on)
option(ENABLE_TOMAHAWK "Enable Tomahawk in Hiawatha" off)
option(ENABLE_TOOLKIT  "Enable the URL toolkit in Hiawatha" on)
option(ENABLE_XSLT     "Enable XSLT support in Hiawatha." on)

# Includes
include(CMakeFiles.txt)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(FindLibXml2)
include(FindLibXslt)
include(cmake/GNUInstallDirs.cmake)
include(cmake/CopyIfNotExists.cmake)

# Settings
set(HIAWATHA_VERSION_MAJOR 8)
set(HIAWATHA_VERSION_MINOR 6)
set(HIAWATHA_VERSION_PATCH 0)
string(TOLOWER ${CMAKE_PROJECT_NAME} PROJECT_NAME)
if(${HIAWATHA_VERSION_PATCH} EQUAL 0)
	set(HIAWATHA_VERSION "${HIAWATHA_VERSION_MAJOR}.${HIAWATHA_VERSION_MINOR}")
else()
	set(HIAWATHA_VERSION "${HIAWATHA_VERSION_MAJOR}.${HIAWATHA_VERSION_MINOR}.${HIAWATHA_VERSION_PATCH}")
endif()
if(EXISTS "/proc/loadavg")
	option(ENABLE_LOADCHECK "Enable the ability to check for server load." on)
endif()
set(CONFIG_DIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/hiawatha CACHE STRING "Configuration directory")
set(LOG_DIR ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/hiawatha CACHE STRING "Log directory")
set(PID_DIR ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run CACHE STRING "PID directory")
set(WEBROOT_DIR ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/www/hiawatha CACHE STRING "Webroot directory")
set(WORK_DIR ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/hiawatha CACHE STRING "Work directory")

# Compiler directives
check_include_file(crypt.h HAVE_CRYPT_H)
check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files("sys/types.h;netinet/in.h" HAVE_NETINET_IN_H)
check_include_files("sys/types.h;netinet/tcp.h" HAVE_NETINET_TCP_H)
check_include_file(rpcsvc/crypt.h HAVE_RPCSVC_CRYPT_H)

check_function_exists(setenv HAVE_SETENV)
check_function_exists(unsetenv HAVE_UNSETENV)
check_function_exists(clearenv HAVE_CLEARENV)
check_function_exists(strcasecmp HAVE_STRCASECMP)
check_function_exists(strncasecmp HAVE_STRNCASECMP)
check_function_exists(strnstr HAVE_STRNSTR)
check_function_exists(strcasestr HAVE_STRCASESTR)

check_library_exists(crypt crypt "" HAVE_CRYPT_LIBRARY)
check_library_exists(network socket "" HAVE_NETWORK_LIBRARY)
check_library_exists(z gzdopen "" HAVE_Z_LIBRARY)

if(HAVE_CRYPT_LIBRARY)
	set(CRYPT_LIBRARY "crypt")
endif()
if(HAVE_NETWORK_LIBRARY)
	set(NETWORK_LIBRARY "network")
endif()
if(HAVE_Z_LIBRARY)
	set(Z_LIBRARY "z")
endif()
if (APPLE OR CYGWIN)
	set(CIFS 1)
endif()

# CPack
set(CPACK_PACKAGE_VERSION_MAJOR ${HIAWATHA_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${HIAWATHA_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${HIAWATHA_VERSION_PATCH})
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${HIAWATHA_VERSION}")
set(CPACK_SOURCE_IGNORE_FILES "/build(/|_.*/)")
include(CPack)

# PolarSSL
if(ENABLE_SSL)
	option(USE_SHARED_POLARSSL_LIBRARY "Build PolarSSL as a shared library." ON)
	set(CMAKE_INSTALL_NAME_DIR ${CMAKE_INSTALL_FULL_LIBDIR}/hiawatha)
	set(LIB_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/hiawatha)
	add_subdirectory(polarssl)
	set(POLARSSL_LIBRARY "polarssl")
endif()

# Hiawatha
include_directories(${CMAKE_CURRENT_BINARY_DIR} polarssl/include)
if(ENABLE_XSLT)
	include_directories(${LIBXML2_INCLUDE_DIR} ${LIBXSLT_INCLUDE_DIR})
endif()

# Configure files
configure_file(config.h.in config.h)
foreach (configfile ${config_files_in})
	configure_file(${configfile}.in ${configfile} @ONLY)
endforeach()
foreach(manpage ${manual_pages_in})
	configure_file(${manpage}.in ${manpage})
endforeach()
configure_file(extra/logrotate.in logrotate.d/hiawatha)

# Binaries
add_executable(cgi-wrapper ${cgi_wrapper_src})
add_executable(hiawatha ${hiawatha_src})
add_executable(php-fcgi ${php_fcgi_src})
add_executable(ssi-cgi ${ssi_cgi_src})
add_executable(wigwam ${wigwam_src})
target_link_libraries(wigwam ${CRYPT_LIBRARY})
target_link_libraries(hiawatha ${CRYPT_LIBRARY} pthread ${Z_LIBRARY})
if(ENABLE_SSL)
	target_link_libraries(hiawatha ${POLARSSL_LIBRARY})
	set_target_properties(hiawatha PROPERTIES INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR}/hiawatha)
endif()
if(ENABLE_XSLT)
	target_link_libraries(hiawatha ${LIBXML2_LIBRARIES} ${LIBXSLT_LIBRARIES})
endif()

# Installation
install(TARGETS hiawatha php-fcgi wigwam DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(TARGETS cgi-wrapper DESTINATION ${CMAKE_INSTALL_SBINDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID)
install(TARGETS ssi-cgi DESTINATION ${CMAKE_INSTALL_BINDIR})

foreach(configfile ${config_files})
	install(CODE "copy_if_not_exists(\"${CMAKE_SOURCE_DIR}/${configfile}\" \"${CONFIG_DIR}\")")
endforeach()
foreach(configfile ${config_files_in})
	install(CODE "copy_if_not_exists(\"${CMAKE_CURRENT_BINARY_DIR}/${configfile}\" \"${CONFIG_DIR}\")")
endforeach()

install(FILES ${manual_pages} DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1)
foreach(manpage ${manual_pages_in})
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${manpage} DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1)
endforeach()

install(FILES extra/index.html DESTINATION ${WEBROOT_DIR})

# Create directories
install(DIRECTORY empty DESTINATION ${LOG_DIR} PATTERN "empty" EXCLUDE)
install(DIRECTORY empty DESTINATION ${PID_DIR} PATTERN "empty" EXCLUDE)
install(DIRECTORY empty DESTINATION ${WORK_DIR} PATTERN "empty" EXCLUDE)
