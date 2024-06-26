﻿# CMakeList.txt : CMake project for libsyscall, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("libmmap" C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for executables")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")

# Add source to this project's executable.
add_library (mmap STATIC "src/mmap.cpp")
target_include_directories(mmap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(libassert)

add_executable (mmap_test mmap_test.cpp)
target_link_libraries(mmap_test mmap libassert::assert)

install(TARGETS mmap
        RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/sys DESTINATION "${INSTALL_INC_DIR}")
