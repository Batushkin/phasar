cmake_minimum_required(VERSION 3.12)

project(spm)

# include yaml-cpp
include(FetchContent)
FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG yaml-cpp-0.7.0 # Can be a tag (yaml-cpp-x.x.x), a commit hash, or a branch name (master)
)
FetchContent_GetProperties(yaml-cpp)

if(NOT yaml-cpp_POPULATED)
  message(STATUS "Fetching yaml-cpp...")
  FetchContent_Populate(yaml-cpp)
  add_subdirectory(${yaml-cpp_SOURCE_DIR} ${yaml-cpp_BINARY_DIR})
endif()

#find_package(phasar REQUIRED)

#add_executable(se spm.cpp)

include_directories(
  ${PROJECT_SOURCE_DIR}
)

# Build the Symbolic Executor
file(GLOB CPP_SOURCE
    "spm.cpp"
    "lib/*.cpp"    
)

if(PHASAR_IN_TREE)
  add_phasar_executable(se
    ${CPP_SOURCE}
  )
else()
  add_executable(se
    ${CPP_SOURCE}
  )
endif()

target_link_libraries(se
  LINK_PUBLIC
    phasar
    z3
    phasar_llvm_pathsensitivity
    phasar_config
    phasar_controller
    phasar_llvm_controlflow
    phasar_llvm_utils
    phasar_analysis_strategy
    phasar_llvm_ifdside
    phasar_utils
    phasar_mono
    phasar_llvm_db
    phasar_passes
    phasar_llvm_pointer
    phasar_llvm
    phasar_llvm_typehierarchy
    yaml-cpp::yaml-cpp
)

#install(TARGETS se
#  RUNTIME DESTINATION bin
#)