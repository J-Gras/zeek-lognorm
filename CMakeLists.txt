
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeelPluginLiblognorm)

include(ZeekPlugin)

find_package(Liblognorm)
find_package(LibFastJSON)

if ( LIBLOGNORM_FOUND AND LIBFASTJSON_FOUND)
	message(STATUS "Liblognorm header prefix   : ${LIBLOGNORM_INCLUDE_DIR}")
	message(STATUS "Liblognorm library path    : ${LIBLOGNORM_LIBRARY}")
	message(STATUS "LibFastJSON header prefix  : ${LIBFASTJSON_INCLUDE_DIR}")
	message(STATUS "LibFastJSON library path   : ${LIBFASTJSON_LIBRARY}")

	include_directories(${LIBLOGNORM_INCLUDE_DIR})
	include_directories(${LIBFASTJSON_INCLUDE_DIR})

	zeek_plugin_begin(Zeek Lognorm)
	zeek_plugin_cc(src/Plugin.cc)
	zeek_plugin_cc(src/LogNormalizer.cc)
	zeek_plugin_bif(src/lognorm.bif)
	zeek_plugin_dist_files(README CHANGES COPYING VERSION)
	zeek_plugin_link_library(${LIBLOGNORM_LIBRARY})
	zeek_plugin_link_library(${LIBFASTJSON_LIBRARY})
	zeek_plugin_end()
else ()
	message(FATAL_ERROR "Build failed:")
	if ( NOT LIBLOGNORM_FOUND )
		message(FATAL_ERROR "Liblognorm not found.")
	endif ()
	if ( NOT LIBFASTJSON_FOUND )
		message(FATAL_ERROR "LibFastJSON not found.")
	endif ()
endif ()
