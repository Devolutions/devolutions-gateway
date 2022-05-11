
cmake_minimum_required(VERSION 3.8)

project(Jetify C)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION" VERSION_STRING)
string(STRIP "${VERSION_STRING}" VERSION_STRING)
string(REGEX REPLACE "([0-9]+).[0-9]+.[0-9]+" "\\1" JETIFY_VERSION_MAJOR ${VERSION_STRING})
string(REGEX REPLACE "[0-9]+.([0-9]+).[0-9]+" "\\1" JETIFY_VERSION_MINOR ${VERSION_STRING})
string(REGEX REPLACE "[0-9]+.[0-9]+.([0-9]+)" "\\1" JETIFY_VERSION_PATCH ${VERSION_STRING})
set(JETIFY_VERSION "${JETIFY_VERSION_MAJOR}.${JETIFY_VERSION_MINOR}.${JETIFY_VERSION_PATCH}")

message(STATUS "VERSION: ${JETIFY_VERSION}")

set(JETIFY_NAME "jetify")
set(JETIFY_VENDOR "Devolutions Inc.")
set(JETIFY_COPYRIGHT "Copyright 2022 ${JETIFY_VENDOR}")

if(WIN32)
    include(WindowsRC)
	include(MSVCRuntime)

	if(NOT DEFINED MSVC_RUNTIME)
		set(MSVC_RUNTIME "static")
	endif()

	configure_msvc_runtime()
endif()

if(WIN32)
	set(C_FLAGS "")
	set(C_FLAGS "${C_FLAGS} -D_UNICODE")
	set(C_FLAGS "${C_FLAGS} -D_CRT_SECURE_NO_WARNINGS")
	set(C_FLAGS "${C_FLAGS} -DWIN32_LEAN_AND_MEAN")
	set(C_FLAGS "${C_FLAGS} -D_WINSOCK_DEPRECATED_NO_WARNINGS")
	set(C_FLAGS "${C_FLAGS} -DWINVER=0x0602 -D_WIN32_WINNT=0x0602")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS}")
endif()

if(WIN32)
    set(DEPENDENCIES_DIR "${CMAKE_SOURCE_DIR}/dependencies")
    set(DETOURS_ROOT_DIR "${DEPENDENCIES_DIR}/detours")

    include_directories("${DETOURS_ROOT_DIR}/include")

    add_library(detours STATIC IMPORTED)

    if(CMAKE_GENERATOR_PLATFORM MATCHES "ARM64")
        set(MSVC_PLATFORM_TARGET "arm64")
    elseif(CMAKE_GENERATOR_PLATFORM MATCHES "Win32")
        set(MSVC_PLATFORM_TARGET "x86")
    else()
        set(MSVC_PLATFORM_TARGET "x64")
    endif()

    message(STATUS "MSVC_PLATFORM_TARGET: ${MSVC_PLATFORM_TARGET}")

    set_property(TARGET detours PROPERTY
        IMPORTED_LOCATION "${DETOURS_ROOT_DIR}/lib/${MSVC_PLATFORM_TARGET}/Release/detours.lib")
    set_property(TARGET detours PROPERTY
        IMPORTED_LOCATION_DEBUG "${DETOURS_ROOT_DIR}/lib/${MSVC_PLATFORM_TARGET}/Debug/detours.lib")
endif()

set(JETIFY_SOURCES
    Logger.c
    Logger.h
    Utils.c
    Utils.h
    WSMan.c
    WSMan.h
    Jetify.c
    Jetify.h)

if(WIN32)
    list(APPEND JETIFY_SOURCES
        ApiHooks.c
        ApiHooks.h)
endif()

set(JETIFY_RESOURCES
    jetify.rc)

windows_rc_generate_version_info(
    NAME "${JETIFY_NAME}" TYPE "DLL"
    VERSION "${JETIFY_VERSION}.0"
    FILENAME "${JETIFY_NAME}.dll"
    VENDOR "${JETIFY_VENDOR}"
    COPYRIGHT "${JETIFY_COPYRIGHT}"
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

source_group("Resources" FILES ${JETIFY_RESOURCES})

add_library(jetify SHARED
    ${JETIFY_SOURCES}
    ${JETIFY_RESOURCES})

if(WIN32)
    target_link_libraries(jetify detours)
    target_link_libraries(jetify winhttp.lib)
endif()
