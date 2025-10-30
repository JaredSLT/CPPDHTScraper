cmake_minimum_required(VERSION 3.15)
project(CPPDHTScraper)

# Use a supported standard (C++20). Change to 17 if your compiler is older.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(CPPDHTScraper main.cpp)

# Link pthreads (cross-platform) and Winsock on Windows
find_package(Threads REQUIRED)
target_link_libraries(CPPDHTScraper PRIVATE Threads::Threads)

if (WIN32)
    # Ensure modern Windows APIs (inet_pton) are exposed
    target_compile_definitions(CPPDHTScraper PRIVATE _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN)
    target_link_libraries(CPPDHTScraper PRIVATE ws2_32)
endif()
