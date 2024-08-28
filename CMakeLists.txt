cmake_minimum_required(VERSION 3.12)
project(photoniq-auth-client VERSION 1.0.0 LANGUAGES CXX)

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# Options
option(BUILD_TESTS "Build the tests" ON)  # Default is ON when building only the library
option(USE_EXTERNAL_LIBS "Use external libraries (velocypack, pulsar, cpr)" ON)  # Default is ON when building only the library

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
if(ADDITIONAL_INCLUDE_DIR)
    include_directories(${ADDITIONAL_INCLUDE_DIR})
endif()


# External dependencies
if(USE_EXTERNAL_LIBS)
    include(${CMAKE_SOURCE_DIR}/cmake/external-projects.cmake)
endif()

# Add the source files
file(GLOB_RECURSE LIBRARY_SOURCES ${CMAKE_SOURCE_DIR}/src/*.cpp)


# Create the library
add_library(${PROJECT_NAME} STATIC ${LIBRARY_SOURCES})

# Link external libraries if requested
if(USE_EXTERNAL_LIBS)
    # Assuming cpr, velocypack, and pulsar libraries are built and available
    target_link_libraries(${PROJECT_NAME} PRIVATE cpr pulsar velocypack)
endif()

# Ensure that external projects are built before building your library
if(USE_EXTERNAL_LIBS)
    add_dependencies(${PROJECT_NAME} externalCprCurlForPeople externalPulsarCppClient externalVelocyPack)
endif()



# Testing
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# Installation
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/ DESTINATION include)

# Export the library for other projects
export(EXPORT ${PROJECT_NAME}Targets
    FILE "${CMAKE_BINARY_DIR}/${PROJECT_NAME}Targets.cmake"
    NAMESPACE ${PROJECT_NAME}::
)

# Package configuration
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}  # Use the project version here
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_SOURCE_DIR}/cmake/Config.cmake.in"
    "${CMAKE_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION lib/cmake/${PROJECT_NAME}
)

install(EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION lib/cmake/${PROJECT_NAME}
)

install(FILES
    "${CMAKE_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION lib/cmake/${PROJECT_NAME}
)
