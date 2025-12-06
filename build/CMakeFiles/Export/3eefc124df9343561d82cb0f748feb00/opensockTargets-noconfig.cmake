#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "opensock::opensock" for configuration ""
set_property(TARGET opensock::opensock APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(opensock::opensock PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "CXX"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libopensock.a"
  )

list(APPEND _cmake_import_check_targets opensock::opensock )
list(APPEND _cmake_import_check_files_for_opensock::opensock "${_IMPORT_PREFIX}/lib/libopensock.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
