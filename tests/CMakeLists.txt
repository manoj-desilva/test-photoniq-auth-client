
set(PTQ_AUTH_CLIENT_TESTS ptq_auth_client_tests)

file(GLOB PTQ_AUTH_CLIENT_TESTS_SOURCES
     "*.cpp"
)

add_executable(
  ${PTQ_AUTH_CLIENT_TESTS}
  ${PTQ_AUTH_CLIENT_TESTS_SOURCES}
  main.cpp
)

target_link_libraries(${PTQ_AUTH_CLIENT_TESTS}
  ${PROJECT_NAME}
  gtest_main
  gmock_main
  pthread
  z
  cpr
  velocypack
)

target_include_directories(${PTQ_AUTH_CLIENT_TESTS} PRIVATE
  ${INCLUDE_DIRECTORIES}
)
