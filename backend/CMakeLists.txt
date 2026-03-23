cmake_minimum_required(VERSION 3.20)
project(secure_message_backend LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.15.3
)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)

FetchContent_MakeAvailable(httplib nlohmann_json)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PQXX REQUIRED libpqxx)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(secure_message_backend
  src/main.cpp
)

target_link_libraries(secure_message_backend
  PRIVATE
    nlohmann_json::nlohmann_json
    ${PQXX_LIBRARIES}
    ${SODIUM_LIBRARIES}
)

target_include_directories(secure_message_backend
  PRIVATE
    ${httplib_SOURCE_DIR}
    ${PQXX_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)

