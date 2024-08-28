set(EXTERNAL_PROJECTS_PREFIX ${CMAKE_BINARY_DIR})
set(EXTERNAL_PROJECTS_INSTALL_PREFIX ${EXTERNAL_PROJECTS_PREFIX})

include(GNUInstallDirs)

link_directories(${EXTERNAL_PROJECTS_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
include_directories($<BUILD_INTERFACE:${EXTERNAL_PROJECTS_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}>)

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.0
)

FetchContent_GetProperties(googletest)

if(NOT googletest_POPULATED)
  FetchContent_Populate(googletest)
  add_subdirectory(
    ${googletest_SOURCE_DIR}
    ${googletest_BINARY_DIR}
    )
endif()

#FetchContent_Declare(
#  velocypack
#  GIT_REPOSITORY https://github.com/arangodb/velocypack.git
#  GIT_TAG main
#)

#FetchContent_GetProperties(velocypack)

#if(NOT velocypack_POPULATED)
#  set(BuildVelocyPackExamples OFF)
#  set(BuildTools OFF)
#  FetchContent_Populate(velocypack)
#  add_subdirectory(
#    ${velocypack_SOURCE_DIR}
#    ${velocypack_BINARY_DIR}
#    )
#endif()


include(ExternalProject)

ExternalProject_Add(externalVelocyPack
    PREFIX "${EXTERNAL_PROJECTS_PREFIX}"
    GIT_REPOSITORY "https://github.com/arangodb/velocypack.git"
    GIT_TAG "main"
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${EXTERNAL_PROJECTS_INSTALL_PREFIX}
        -DBuildVelocyPackExamples=OFF
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    )

ExternalProject_Add(externalCprCurlForPeople
    PREFIX "${EXTERNAL_PROJECTS_PREFIX}"
    GIT_REPOSITORY "https://github.com/whoshuu/cpr.git"
    GIT_TAG "1.10.4"
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${EXTERNAL_PROJECTS_INSTALL_PREFIX}
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_CPR_TESTS=0
    )

ExternalProject_Add(externalPulsarCppClient
    PREFIX "${EXTERNAL_PROJECTS_PREFIX}"
    GIT_REPOSITORY "https://github.com/apache/pulsar-client-cpp"
    GIT_TAG "v3.1.1"
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${EXTERNAL_PROJECTS_INSTALL_PREFIX}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DBUILD_TESTS=OFF
        -DOPENSSL_ROOT_DIR=/home/manoj/code/others/openssl/openssl-1.1.1 -DOPENSSL_LIBRARIES=/home/manoj/code/others/openssl/openssl-1.1.1/lib -DOPENSSL_INCLUDE_DIR=/home/manoj/code/others/openssl/openssl-1.1.1/include
    )
