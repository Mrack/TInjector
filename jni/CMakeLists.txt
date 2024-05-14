cmake_minimum_required(VERSION 3.22)
project(tinjector)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(core)
add_subdirectory(test)

add_library(local_dobby STATIC IMPORTED)
set_target_properties(local_dobby PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI}/libdobby.a)

add_executable(tinjector main.cpp)
target_link_libraries(tinjector dl log)