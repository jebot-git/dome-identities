enable_language(C)
pkg_check_modules(DESKTOPMENU REQUIRED IMPORTED_TARGET gio-2.0 wayland-client)
if(XNEDIT_ENABLE_X11)
  pkg_check_modules(DESKTOPMENU_X11 REQUIRED IMPORTED_TARGET x11)
endif()
find_program(WAYLAND_SCANNER wayland-scanner REQUIRED)
set(menu_extensions_dir "${CMAKE_CURRENT_LIST_DIR}")
function(de_xr_desktop_menu target)
  add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/appmenu-client.h"
    COMMAND "${WAYLAND_SCANNER}" client-header "${menu_extensions_dir}/appmenu.xml" "${CMAKE_CURRENT_BINARY_DIR}/appmenu-client.h"
    DEPENDS "${menu_extensions_dir}/appmenu.xml")
  add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/appmenu-protocol.c"
    COMMAND "${WAYLAND_SCANNER}" private-code "${menu_extensions_dir}/appmenu.xml" "${CMAKE_CURRENT_BINARY_DIR}/appmenu-protocol.c"
    DEPENDS "${menu_extensions_dir}/appmenu.xml")
  target_sources(${target} PRIVATE "${menu_extensions_dir}/desktop-menu.cpp" "${CMAKE_CURRENT_BINARY_DIR}/appmenu-protocol.c" "${CMAKE_CURRENT_BINARY_DIR}/appmenu-client.h")
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_link_libraries(${target} PRIVATE PkgConfig::DESKTOPMENU)
  if(XNEDIT_ENABLE_X11)
    target_link_libraries(${target} PRIVATE PkgConfig::DESKTOPMENU_X11)
  endif()
endfunction()
