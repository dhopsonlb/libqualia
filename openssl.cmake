
if (DISABLE_PKGCONFIG)
	message(FATAL_ERROR "Trying to use OpenSSL but pkg-config is disabled!")
endif()

if (EMBEDDED)
	message(FATAL_ERROR "Use of embedded mode with OpenSSL is not supported!")
endif()

message("== Searching for OpenSSL...")
pkg_check_modules(OPENSSL REQUIRED openssl)
message("== OK, found OpenSSL.")
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(TLS_LIBS_SHARED "${OPENSSL_LIBRARIES}")
set(TLS_LIBS_STATIC "") #Because the host program will probably link OpenSSL for us when we're a static library.
set(TLS_INCLUDES "${OPENSSL_INCLUDE_DIRS}")
