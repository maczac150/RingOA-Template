# build example executable
add_executable(example main.cpp)

# link with RingOA
target_link_libraries(example PRIVATE RingOA::RingOA)
