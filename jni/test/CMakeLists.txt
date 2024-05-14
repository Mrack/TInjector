cmake_minimum_required(VERSION 3.18.4)

project(testso)

set(CMAKE_CXX_STANDARD 20)


add_library(testso SHARED testso.cpp utils.cpp)

add_library(local_dobby STATIC IMPORTED)
set_target_properties(local_dobby PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../core/${ANDROID_ABI}/libdobby.a)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../core)


find_library(
        log-lib
        log)

target_link_libraries(testso ${log-lib} local_dobby)

