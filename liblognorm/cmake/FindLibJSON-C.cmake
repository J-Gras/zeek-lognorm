# - Try to find libjson-c.
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LIBJSON_C_INCLUDE_DIR     Set this variable to the root directory of
#                            libjson-c if the module has problems finding
#                            the proper path.
#
# Variables defined by this module:
#
#  LIBJSON_C_FOUND          System has libjson-c libraries and headers.
#  LIBJSON_C_LIBRARY        The libjson-c library
#  LIBJSON_C_INCLUDE_DIR    The location of libjson-c headers

find_library(LIBJSON_C_LIBRARY
    NAMES libjson-c.so
    HINTS lib64
)

find_path(LIBJSON_C_INCLUDE_DIR
    NAMES json.h
    HINTS include
    PATH_SUFFIXES json-c
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibJSON-C DEFAULT_MSG
    LIBJSON_C_LIBRARY
    LIBJSON_C_INCLUDE_DIR
)

mark_as_advanced(
    LIBJSON_C_LIBRARY
    LIBJSON_C_INCLUDE_DIR
)
