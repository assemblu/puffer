cmake_minimum_required(VERSION 3.15)
project(CS2EspOverlay LANGUAGES C CXX)

# Force 64‑bit build (CS2 is x64)
set(CMAKE_GENERATOR_PLATFORM x64)

# Include directories – ImGui headers and MinHook header are in this folder
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Source files for the DLL
set(SRC_FILES
    overlay.cpp
    imgui.cpp
    imgui_draw.cpp
    imgui_widgets.cpp
    imgui_tables.cpp
    imgui_demo.cpp
    backends/imgui_impl_win32.cpp
    backends/imgui_impl_dx11.cpp
    hook.c
    buffer.c
    trampoline.c
)

add_library(CS2EspOverlay SHARED ${SRC_FILES})

target_link_libraries(CS2EspOverlay PRIVATE d3d11 dxgi)

# Release optimisation
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(CS2EspOverlay PRIVATE /O2)
endif()
