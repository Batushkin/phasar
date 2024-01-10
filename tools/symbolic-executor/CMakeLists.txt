cmake_minimum_required(VERSION 3.12)

project(SymbolicExecutor)

# Build the Symbolic Executor
if(PHASAR_IN_TREE)
  add_phasar_executable(se
    SymbolicExecutor.cpp
  )
else()
  add_executable(se
    SymbolicExecutor.cpp
  )
endif()

#find_package(phasar REQUIRED)

#add_executable(se SymbolicExecutor.cpp)

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
    
)

#install(TARGETS se
#  RUNTIME DESTINATION bin
#)