# - Try to find libfastjson.
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LIBFASTJSON_INCLUDE_DIR     Set this variable to the root directory of
#                              libfastjson if the module has problems finding
#                              the proper path.
#
# Variables defined by this module:
#
#  LIBFASTJSON_FOUND          System has libfastjson libraries and headers.
#  LIBFASTJSON_LIBRARY        The libfastjson library
#  LIBFASTJSON_INCLUDE_DIR    The location of libfastjson headers

find_library(LIBFASTJSON_LIBRARY
    NAMES libfastjson.so libfastjson.dylib
    HINTS lib64
)

find_path(LIBFASTJSON_INCLUDE_DIR
    NAMES json.h
    HINTS include
    PATH_SUFFIXES libfastjson
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibFastJSON DEFAULT_MSG
    LIBFASTJSON_LIBRARY
    LIBFASTJSON_INCLUDE_DIR
)

mark_as_advanced(
    LIBFASTJSON_LIBRARY
    LIBFASTJSON_INCLUDE_DIR
)
