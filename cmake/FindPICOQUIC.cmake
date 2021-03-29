# - Try to find Picoquic

find_path(PICOQUIC_INCLUDE_DIR
    NAMES picoquic.h)

find_library(PICOQUIC_CORE_LIBRARY picoquic-core)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set PICOQUIC_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(PICOQUIC REQUIRED_VARS
    PICOQUIC_CORE_LIBRARY
    PICOQUIC_INCLUDE_DIR)

if(PICOQUIC_FOUND)
    set(PICOQUIC_LIBRARIES ${PICOQUIC_CORE_LIBRARY})
    set(PICOQUIC_INCLUDE_DIRS ${PICOQUIC_INCLUDE_DIR})
endif()

mark_as_advanced(PICOQUIC_LIBRARIES PICOQUIC_INCLUDE_DIRS)
