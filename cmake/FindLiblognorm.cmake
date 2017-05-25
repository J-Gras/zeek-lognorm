# - Try to find liblognorm.
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LIBLOGNORM_INCLUDE_DIR    Set this variable to the root directory of
#                            liblognorm if the module has problems finding
#                            the proper path.
#
# Variables defined by this module:
#
#  LIBLOGNORM_FOUND          System has liblognorm libraries and headers.
#  LIBLOGNORM_LIBRARY        The liblognorm library
#  LIBLOGNORM_INCLUDE_DIR    The location of liblognorm headers

find_library(LIBLOGNORM_LIBRARY
    NAMES liblognorm.so
    HINTS lib64
)

find_path(LIBLOGNORM_INCLUDE_DIR
    NAMES liblognorm.h
    HINTS include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Liblognorm DEFAULT_MSG
    LIBLOGNORM_LIBRARY
    LIBLOGNORM_INCLUDE_DIR
)

mark_as_advanced(
    LIBLOGNORM_LIBRARY
    LIBLOGNORM_INCLUDE_DIR
)
