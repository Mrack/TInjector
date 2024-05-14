cmake_minimum_required(VERSION 3.18.4)


project(testso)

set(CMAKE_CXX_STANDARD 20)

include_directories(elfio)
include_directories(.)

add_library(local_dobby STATIC IMPORTED)
set_target_properties(local_dobby PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI}/libdobby.a)

add_library(tcore SHARED core.cpp utils.cpp)
find_library(
        log-lib
        log)

target_link_libraries(tcore ${log-lib} local_dobby)