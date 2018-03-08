set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/test_bin)

addtest(regression_test regression_test.cpp)

target_include_directories(regression_test PUBLIC ${PROJECT_SOURCE_DIR}/test)

target_link_libraries(regression_test
    application
    integration_framework
    )
