cmake_minimum_required(VERSION 3.10)
project(corr_engine)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find nlohmann/json for parsing EVE JSON alerts
find_package(nlohmann_json REQUIRED)

# Find YAML-CPP (using lowercase package name)
find_package(yaml-cpp REQUIRED)

# Define your executable (This should now be line 10 if you include blank lines as above)
add_executable(corr_engine src/corr_engine.cpp)

# Link against both libraries
# Using 'nlohmann_json::nlohmann_json' (namespaced)
# Using 'yaml-cpp' (NOT namespaced, as this seems to be the issue with 'yaml-cpp::yaml-cpp')
target_link_libraries(corr_engine PRIVATE
    nlohmann_json::nlohmann_json
    yaml-cpp
)
