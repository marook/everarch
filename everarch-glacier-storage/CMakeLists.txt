cmake_minimum_required(VERSION 2.8.11)
project(everarch-glacier-storage C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "-std=c99 -Wall -Werror -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

include(CheckCCompilerFlag)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")

# https://github.com/private-octopus/picoquic
find_package(PICOQUIC REQUIRED)

# https://github.com/DaveGamble/cJSON
find_package(cJSON REQUIRED)

find_package(SQLite3 REQUIRED)

find_package(Threads REQUIRED)

include_directories(
  ${PICOQUIC_INCLUDE_DIRS}
  ${cJSON_INCLUDE_DIRS}
  ${SQLite3_INCLUDE_DIRS}
  ${Threads_INCLUDE_DIRS}
  )

add_executable(evr-glacier-storage
  src/configuration.c
  src/dynamic_array.c
  src/evr-glacier-storage.c
  src/files.c)
target_link_libraries(evr-glacier-storage
  ${PICOQUIC_LIBRARIES}
  ${CJSON_LIBRARIES}
  )

add_executable(dynamic_array-test
  src/assert.c
  src/dynamic_array.c
  src/dynamic_array-test.c
  )
target_link_libraries(dynamic_array-test)
add_test(dynamic_array-test ./dynamic_array-test)

add_executable(files-test
  src/assert.c
  src/files-test.c
  src/dynamic_array.c
  src/files.c
  )
target_link_libraries(files-test
  ${CJSON_LIBRARIES}
  )
add_test(files-test ./files-test)

add_executable(configuration-test
  src/assert.c
  src/configuration.c
  src/configuration-test.c
  src/dynamic_array.c
  src/files.c
  )
target_link_libraries(configuration-test
  ${CJSON_LIBRARIES}
  )
add_test(configuration-test ./configuration-test)

add_executable(glacier-test
  src/assert.c
  src/configuration.c
  src/configuration-testutil.c
  src/glacier.c
  src/glacier-test.c
  src/dynamic_array.c
  src/files.c
  )
target_link_libraries(glacier-test
  ${CJSON_LIBRARIES}
  ${SQLite3_LIBRARIES}
  )
add_test(glacier-test ./glacier-test)
