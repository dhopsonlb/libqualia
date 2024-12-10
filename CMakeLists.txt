cmake_minimum_required(VERSION 3.5.0)
project("QualiaLib")

execute_process(COMMAND git rev-parse --short HEAD OUTPUT_VARIABLE REVISION_)
string(STRIP "${REVISION_}" REVISION)

if (EMBEDDED)
	set(DISABLE_PKG_CONFIG 1)
	set(USE_WOLFSSL 1)
	set(DISABLE_PYTHON 1)
	set(build_feature_flags ${build_feature_flags} -DQUALIA_EMBEDDED)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
	set(QUALIA_OPTIMIZE_OPTS "-Os")
else()
	set(QUALIA_OPTIMIZE_OPTS "-O0" "-g3" "-DQUALIA_DEBUG")
endif()


if (NOT DISABLE_PKG_CONFIG)
	set(CMAKE_INCLUDE_CURRENT_DIR ON)
	message("== Searching for pkg-config...")
	find_package(PkgConfig)
	message("== Ok, found pkg-config")
else()
	if (NOT DISABLE_TLS)
		message("== Forcing WolfSSL because pkg-config is disabled")
		set(USE_WOLFSSL 1)
	endif()

	set(DISABLE_PYTHON 1)
endif()

set(base_sourcefiles src/qualia.c)
set(sourcefiles ${base_sourcefiles})
set(build_feature_flags)

if (NOT DISABLE_TLS)
	set(sourcefiles ${sourcefiles} src/qualiatls.c)
		
	if (USE_WOLFSSL)
			include("${CMAKE_CURRENT_LIST_DIR}/wolfssl.cmake")
	else()
			include("${CMAKE_CURRENT_LIST_DIR}/openssl.cmake")
	endif()

else()
	set(build_feature_flags ${build_feature_flags} -DQUALIA_NO_TLS -DQUALIA_NO_OQS)
endif()

if (NOT DISABLE_PYTHON)
	set(sourcefiles ${sourcefiles} src/pyapi.cpp)
else()
	set(build_feature_flags ${build_feature_flags} -DQUALIA_NO_PYTHON)
endif()

add_library(libqualia_static STATIC EXCLUDE_FROM_ALL ${sourcefiles})
add_library(libqualia SHARED ${sourcefiles})

if (NOT DISABLE_TLS)
	if (SSL_ALREADY_INIT)
		target_compile_definitions(libqualia PUBLIC QUALIA_SSL_ALREADY_INIT=1)
		target_compile_definitions(libqualia_static PUBLIC QUALIA_SSL_ALREADY_INIT=1)
		message("== !! Assuming SSL library already initialized by a parent project !! ==")
	endif()
	
	if (USE_WOLFSSL)
		target_compile_definitions(libqualia PUBLIC QUALIA_USE_WOLFSSL=1)
		target_compile_definitions(libqualia_static PUBLIC QUALIA_USE_WOLFSSL=1)
	else()
		target_compile_definitions(libqualia PUBLIC QUALIA_USE_OPENSSL=1)
		target_compile_definitions(libqualia_static PUBLIC QUALIA_USE_OPENSSL=1)
	endif()
endif()

if (NOT DISABLE_PYTHON)
	message("== Searching for Python 3 devel...")
	pkg_check_modules(PYTHON3 REQUIRED python3-embed python3)
	message("== OK, found Python 3 devel.")
endif()

target_include_directories(libqualia PUBLIC "${TLS_INCLUDES}" "${PYTHON3_INCLUDE_DIRS}")
target_include_directories(libqualia_static PUBLIC $"{TLS_INCLUDES}" "${PYTHON3_INCLUDE_DIRS}")

target_compile_definitions(libqualia PUBLIC QUALIA_REVISION="${REVISION}")
target_compile_definitions(libqualia_static PUBLIC QUALIA_REVISION="${REVISION}" QUALIA_STATIC)

target_compile_options(libqualia PUBLIC ${QUALIA_OPTIMIZE_OPTS} -fno-strict-aliasing -pedantic -Wall -fPIC)
target_compile_options(libqualia PRIVATE ${build_feature_flags})
target_compile_options(libqualia PRIVATE $<$<COMPILE_LANGUAGE:C>:-Werror=incompatible-pointer-types -Werror=return-type -Werror=int-conversion>)

target_compile_options(libqualia_static PUBLIC ${QUALIA_OPTIMIZE_OPTS} -fno-strict-aliasing -pedantic -Wall -fPIC)
target_compile_options(libqualia_static PRIVATE ${build_feature_flags})
target_compile_options(libqualia_static PRIVATE $<$<COMPILE_LANGUAGE:C>:-Werror=incompatible-pointer-types -Werror=return-type -Werror=int-conversion>)


target_link_libraries(libqualia PUBLIC "${TLS_LIBS_SHARED}" "${PYTHON3_LIBRARIES}") #If either of those is not present, does nothing.
target_link_libraries(libqualia_static PUBLIC "${TLS_LIBS_STATIC}" "${PYTHON3_LIBRARIES}") #If either of those is not present, does nothing.
	
set_property(TARGET libqualia PROPERTY PREFIX "")
set_property(TARGET libqualia_static PROPERTY PREFIX "")

set_property(TARGET libqualia PROPERTY C_STANDARD 99) #Might not have a C11 compiler on some particularly shit platforms.
set_property(TARGET libqualia_static PROPERTY C_STANDARD 99) #Might not have a C11 compiler on some particularly shit platforms.

set_property(TARGET libqualia PROPERTY C_STANDARD_REQUIRED ON)
set_property(TARGET libqualia_static PROPERTY C_STANDARD_REQUIRED ON)

set_property(TARGET libqualia PROPERTY CXX_STANDARD 17) #If we have Sepples, we probably have something modern though, in my experience.
set_property(TARGET libqualia_static PROPERTY CXX_STANDARD 17) #If we have Sepples, we probably have something modern though, in my experience.

set_property(TARGET libqualia PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET libqualia_static PROPERTY CXX_STANDARD_REQUIRED ON)
