# Install script for directory: /home/hugo/projects/hiawatha/polarssl/library

# Set the install prefix
IF(NOT DEFINED CMAKE_INSTALL_PREFIX)
  SET(CMAKE_INSTALL_PREFIX "")
ENDIF(NOT DEFINED CMAKE_INSTALL_PREFIX)
STRING(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
IF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  IF(BUILD_TYPE)
    STRING(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  ELSE(BUILD_TYPE)
    SET(CMAKE_INSTALL_CONFIG_NAME "RelWithDebInfo")
  ENDIF(BUILD_TYPE)
  MESSAGE(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
ENDIF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)

# Set the component getting installed.
IF(NOT CMAKE_INSTALL_COMPONENT)
  IF(COMPONENT)
    MESSAGE(STATUS "Install component: \"${COMPONENT}\"")
    SET(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  ELSE(COMPONENT)
    SET(CMAKE_INSTALL_COMPONENT)
  ENDIF(COMPONENT)
ENDIF(NOT CMAKE_INSTALL_COMPONENT)

# Install shared libraries without execute permission?
IF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  SET(CMAKE_INSTALL_SO_NO_EXE "1")
ENDIF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  FOREACH(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/usr/lib/hiawatha/libpolarssl.so.1.2.5"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/usr/lib/hiawatha/libpolarssl.so.2"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/usr/lib/hiawatha/libpolarssl.so"
      )
    IF(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      FILE(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    ENDIF()
  ENDFOREACH()
  FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/lib/hiawatha" TYPE SHARED_LIBRARY PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE FILES
    "/home/hugo/projects/hiawatha/build/polarssl/library/libpolarssl.so.1.2.5"
    "/home/hugo/projects/hiawatha/build/polarssl/library/libpolarssl.so.2"
    "/home/hugo/projects/hiawatha/build/polarssl/library/libpolarssl.so"
    )
  FOREACH(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/usr/lib/hiawatha/libpolarssl.so.1.2.5"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/usr/lib/hiawatha/libpolarssl.so.2"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/usr/lib/hiawatha/libpolarssl.so"
      )
    IF(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      IF(CMAKE_INSTALL_DO_STRIP)
        EXECUTE_PROCESS(COMMAND "/usr/bin/strip" "${file}")
      ENDIF(CMAKE_INSTALL_DO_STRIP)
    ENDIF()
  ENDFOREACH()
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

