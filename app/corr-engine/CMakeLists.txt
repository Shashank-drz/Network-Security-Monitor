cmake_minimum_required(VERSION 3.10)
project(corr_engine)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(nlohmann_json REQUIRED)
find_package(yaml-cpp REQUIRED)

add_executable(corr_engine src/corr_engine.cpp)

target_link_libraries(corr_engine PRIVATE
    nlohmann_json::nlohmann_json
    yaml-cpp
)
