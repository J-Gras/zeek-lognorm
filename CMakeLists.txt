
cmake_minimum_required(VERSION 2.8)

project(Plugin)

include(BroPlugin)

find_package(Liblognorm)
find_package(LibFastJSON)

if ( LIBLOGNORM_FOUND AND LibFastJSON_FOUND)
	message(STATUS "Liblognorm header prefix   : ${LIBLOGNORM_INCLUDE_DIR}")
	message(STATUS "Liblognorm library path    : ${LIBLOGNORM_LIBRARY}")
	message(STATUS "LibFastJSON header prefix  : ${LIBFASTJSON_INCLUDE_DIR}")
	message(STATUS "LibFastJSON library path   : ${LIBFASTJSON_LIBRARY}")

	include_directories(${LIBFASTJSON_INCLUDE_DIR})

	bro_plugin_begin(Bro Lognorm)
	bro_plugin_cc(src/Plugin.cc)
	bro_plugin_cc(src/LogNormalizer.cc)
	bro_plugin_bif(src/lognorm.bif)
	bro_plugin_dist_files(README CHANGES COPYING VERSION)
	bro_plugin_link_library(${LIBLOGNORM_LIBRARY})
	bro_plugin_link_library(${LIBFASTJSON_LIBRARY})
	bro_plugin_end()
else ()
	message(FATAL_ERROR "Build failed:")
	if ( NOT LIBLOGNORM_FOUND )
		message(FATAL_ERROR "Liblognorm not found.")
	endif ()
	if ( NOT LibFastJSON_FOUND )
		message(FATAL_ERROR "LibFastJSON not found.")
	endif ()
endif ()
