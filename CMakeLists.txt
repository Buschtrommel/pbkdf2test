project(pbkdf2test)

cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

set(PBKDF2TEST_VERSION_MAJOR "0")
set(PBKDF2TEST_VERSION_MINOR "1")
set(PBKDF2TEST_VERSION_PATCH "0")
set(PBKDF2TEST_VERSION "${PBKDF2TEST_VERSION_MAJOR}.${PBKDF2TEST_VERSION_MINOR}.${PBKDF2TEST_VERSION_PATCH}")

find_package(Qt5 5.1.0 REQUIRED COMPONENTS Core)
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
endif (OPENSSL_FOUND)

# Auto generate moc files
set(CMAKE_AUTOMOC ON)

# As moc files are generated in the binary dir, tell CMake
# to always look for includes there:
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Skaffari default install prefix" FORCE)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

set(CMAKE_INSTALL_BINDIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Directory to install pbkdf2test executable.")

# Enable C++11 features
add_definitions(-std=c++11)

add_definitions("-DPBKDF2TEST_VERSION=\"${PBKDF2TEST_VERSION}\"")

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

set(pbkdf2test_SRCS
    main.cpp
)

add_executable(pbkdf2test ${pbkdf2test_SRCS})

target_link_libraries(pbkdf2test
    Qt5::Core
    ${OPENSSL_LIBRARIES}
)


install(TARGETS pbkdf2test DESTINATION ${CMAKE_INSTALL_BINDIR})
