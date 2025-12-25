project(cve-database-creation)

SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include SQLiteCpp library and build it
option(SQLITECPP_RUN_CPPLINT OFF)
include_directories(SQLiteCpp/include)
add_subdirectory(SQLiteCpp)

# Include mariadb-connector-cpp library
set(CONC_WITH_UNIT_TESTS OFF)
set(CMAKE_BUILD_TYPE "RelWithDebInfo")
set(WITH_UNIT_TESTS OFF CACHE INTERNAL "")
include_directories(mariadb-connector-cpp/include)
# workaround until mariadb fix issue in test/CMakeLists.txt
include_directories("${CMAKE_BINARY_DIR}/mariadb-connector-cpp/test")
add_subdirectory(mariadb-connector-cpp)

# Include Json C++ file
include_directories(json/single_include)

SET_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

ADD_EXECUTABLE(create_db create_db.cpp database_wrapper.cpp prepared_statement.cpp)
TARGET_LINK_LIBRARIES(create_db SQLiteCpp sqlite3 pthread mariadbcpp)
if (NOT APPLE)
    TARGET_LINK_LIBRARIES(create_db dl)
endif()