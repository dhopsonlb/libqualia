
if (NOT ENABLE_OQS) #Turn off OQS by default
	set(DISABLE_OQS 1)
endif()

set(WOLFSSL_OPENSSLALL "yes" CACHE STRING "")
set(WOLFSSL_FILESYSTEM "no")
set(BUILD_SHARED_LIBS OFF)

if (NOT DISABLE_OQS)
	set(OQS_BUILD_ONLY_LIB ON)
	set(OQS_MINIMAL_BUILD " OQS_ENABLE_KEM_saber_saber;OQS_ENABLE_KEM_saber_lightsaber; "
		"OQS_ENABLE_KEM_saber_firesaber;OQS_ENABLE_KEM_kyber_1024; "
		"OQS_ENABLE_KEM_kyber_1024_90s;OQS_ENABLE_KEM_kyber_768; "
		"OQS_ENABLE_KEM_kyber_768_90s;OQS_ENABLE_KEM_kyber_512; "
		"OQS_ENABLE_KEM_kyber_512_90s;OQS_ENABLE_KEM_ntru_hps2048509; "
		"OQS_ENABLE_KEM_ntru_hps2048677;OQS_ENABLE_KEM_ntru_hps4096821; "
		"OQS_ENABLE_KEM_ntru_hrss701;OQS_ENABLE_SIG_falcon_1024; "
		"OQS_ENABLE_SIG_falcon_512;OQS_ENABLE_SIG_dilithium_2; "
		"OQS_ENABLE_SIG_dilithium_3;OQS_ENABLE_SIG_dilithium_5; "
		"OQS_ENABLE_SIG_dilithium_2_aes;OQS_ENABLE_SIG_dilithium_3_aes; "
		"OQS_ENABLE_SIG_dilithium_5_aes")
	set(OQS_USE_OPENSSL OFF)
	set(WOLFSSL_OQS "yes")
	set(OQS_LIBRARY oqs)
	set(OQS_INCLUDE_DIR  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/liboqs_build/include>)
	
	add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/3rdparty/liboqs/ ${CMAKE_CURRENT_BINARY_DIR}/liboqs_build EXCLUDE_FROM_ALL)
else()
	set(WOLFSSL_OQS "no")
	set(build_feature_flags ${build_feature_flags} -DQUALIA_NO_OQS)
endif()

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/3rdparty/wolfssl/ ${CMAKE_CURRENT_BINARY_DIR}/wolfssl_build EXCLUDE_FROM_ALL)

target_compile_options(wolfssl PUBLIC ${QUALIA_OPTIMIZE_OPTS} -fPIC)

if (NOT DISABLE_OQS)
	target_compile_options(oqs PUBLIC ${QUALIA_OPTIMIZE_OPTS} -fPIC)
endif()

set(TLS_INCLUDES "${CMAKE_CURRENT_LIST_DIR}/wolfssl")
set(TLS_LIBS_SHARED wolfssl) #Statically linked wolfssl for a statically linked lib.
set(TLS_LIBS_STATIC wolfssl)
