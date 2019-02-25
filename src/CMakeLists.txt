configure_file(
  "${PROJECT_SOURCE_DIR}/include/nvtop/version.h.in"
  "${PROJECT_BINARY_DIR}/include/nvtop/version.h"
  IMMEDIATE @ONLY)

if(MINGW)
  add_executable(nvtop
    nvtop.c
    interface.c
    get_process_info_windows.c
    extract_gpuinfo.c)
else()
  add_executable(nvtop
    nvtop.c
    interface.c
    get_process_info_linux.c
    extract_gpuinfo.c)
endif()

target_include_directories(nvtop PRIVATE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)

set_property(TARGET nvtop PROPERTY C_STANDARD 11)

if(MINGW)
  target_link_libraries(nvtop
    PRIVATE nvml ncurses m)
else()
  target_link_libraries(nvtop
    PRIVATE nvml ncurses m "-Wl,-Bstatic")
endif()

install (TARGETS nvtop
  RUNTIME DESTINATION bin)
