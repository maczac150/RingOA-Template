# =========================
# Example
# =========================

set(TEST_SOURCES
  pdte.cpp
  main.cpp
)

add_executable(pdte ${TEST_SOURCES})

# Inherit RingOA's compile definitions (LOG_LEVEL / USE_FIXED_RANDOM_SEED)
target_link_libraries(pdte PRIVATE RingOA::RingOA)

# Per-config compile options for the pdte target itself
target_compile_options(pdte PRIVATE
  $<$<CONFIG:Debug>:-Og -g -Wall -Wextra>
  $<$<CONFIG:RelWithDebInfo>:-O2 -g -fno-omit-frame-pointer -march=native>
  $<$<CONFIG:Release>:-O2 -march=native -flto -funroll-loops>
)

message(STATUS "[RingOA Settings]")
message(STATUS "  LOG_LEVEL                 : ${RingOA_LOG_LEVEL}")
message(STATUS "  USE_FIXED_RANDOM_SEED     : ${RingOA_USE_FIXED_RANDOM_SEED}")
message(STATUS "--------------------------------------------")
