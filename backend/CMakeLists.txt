cmake_minimum_required(VERSION 3.20)
project(secure_message_backend LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# We vendor a couple of small, widely-used header-only libraries via FetchContent
# so the backend builds reproducibly in Docker/CI without requiring system packages.
include(FetchContent)

FetchContent_Declare(
  httplib
  # cpp-httplib provides a minimal HTTP server/client layer for our REST API.
  # It can also do HTTPS when built with OpenSSL, but we keep it lightweight here.
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.15.3
)

FetchContent_Declare(
  nlohmann_json
  # nlohmann/json is used for request/response parsing and emitting JSON payloads in C++.
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)

# Pin tags to avoid unplanned dependency changes (reproducible builds).
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
    # cpp-httplib is header-only; we include its source directory directly.
    ${httplib_SOURCE_DIR}
    ${PQXX_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)

