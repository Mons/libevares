cmake_minimum_required(VERSION 2.8)

include_directories(src)

add_library(evares src/libevares.c)
target_link_libraries(evares cares)

add_executable(sample ex/sample.c)
target_link_libraries(sample ev evares cares)

