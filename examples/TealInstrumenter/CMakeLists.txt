set(MODULE TRUE)

set( LLVM_USED_LIBS
  clangFrontend
  clangAST
  )

set( LLVM_LINK_COMPONENTS support mc)

add_clang_library(TealInstrumenter
    Instrumentation.cpp
    TealInstrumenter.cpp
    )

set_target_properties(TealInstrumenter
  PROPERTIES
  LINKER_LANGUAGE CXX
  PREFIX "")
