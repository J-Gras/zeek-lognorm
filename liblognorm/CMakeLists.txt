
cmake_minimum_required(VERSION 2.8)

project(Plugin)

include(BroPlugin)

find_package(Liblognorm)
find_package(LibJSON-C)

if ( LIBLOGNORM_FOUND AND LibJSON-C_FOUND )
	message(STATUS "Liblognorm header prefix : ${LIBLOGNORM_INCLUDE_DIR}")
	message(STATUS "Liblognorm library path  : ${LIBLOGNORM_LIBRARY}")
	message(STATUS "LibJSON-C header prefix  : ${LIBJSON_C_INCLUDE_DIR}")
	message(STATUS "LibJSON-C library path   : ${LIBJSON_C_LIBRARY}")

	bro_plugin_begin(Bro_Liblognorm Lognorm)
	bro_plugin_cc(src/Plugin.cc)
	bro_plugin_cc(src/LogNormalizer.cc)
	bro_plugin_bif(src/lognorm.bif)
	bro_plugin_dist_files(README CHANGES COPYING VERSION)
	bro_plugin_link_library(${LIBLOGNORM_LIBRARY})
	bro_plugin_link_library(${LIBJSON_C_LIBRARY})
	bro_plugin_end()
else ()
	if ( NOT LIBLOGNORM_FOUND )
		message(FATAL_ERROR "Liblognorm not found.")
	endif ()
	if ( NOT LibJSON-C_FOUND )
		message(FATAL_ERROR "LibJSON-C not found.")
	endif ()
endif ()
