file(GLOB HEADERS "*.h")
# 第一个测试程序：TestSDF（使用TestSDF.cpp）
add_executable(test-sdf-crypto TestSDF.cpp ${HEADERS})
target_link_libraries(test-sdf-crypto PUBLIC sdf-crypto pthread ${CMAKE_DL_LIBS})
target_link_directories(test-sdf-crypto PUBLIC ${CMAKE_BINARY_DIR}/output)

# 第二个测试程序：test-verify-hash（使用testVerifyAndHash.cpp）
add_executable(test-verify-hash testVerifyAndHash.cpp ${HEADERS})
target_link_libraries(test-verify-hash PUBLIC sdf-crypto pthread ${CMAKE_DL_LIBS})
target_link_directories(test-verify-hash PUBLIC ${CMAKE_BINARY_DIR}/output)

