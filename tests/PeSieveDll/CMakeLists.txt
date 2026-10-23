cmake_minimum_required(VERSION 3.15)
project(NativeMirrorDllContract LANGUAGES CXX)
add_executable(NativeMirrorDllContract contract.cpp)
target_compile_features(NativeMirrorDllContract PRIVATE cxx_std_17)
target_include_directories(NativeMirrorDllContract SYSTEM PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../pe-sieve-master/pe-sieve-master/include")
if(MSVC)
  target_compile_options(NativeMirrorDllContract PRIVATE /W4 /WX)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PE_SIEVE_MACHINE X64)
  else()
    set(PE_SIEVE_MACHINE X86)
  endif()
  set(PE_SIEVE_IMPORT "${CMAKE_CURRENT_BINARY_DIR}/pe-sieve.lib")
  add_custom_command(OUTPUT "${PE_SIEVE_IMPORT}"
    COMMAND "${CMAKE_AR}" /nologo
      "/def:${CMAKE_CURRENT_SOURCE_DIR}/../../tools/NativeMirrorDll/pe-sieve.def"
      "/machine:${PE_SIEVE_MACHINE}" "/out:${PE_SIEVE_IMPORT}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/NativeMirrorDll/pe-sieve.def")
  add_custom_target(PeSieveImportLibrary DEPENDS "${PE_SIEVE_IMPORT}")
  add_executable(NativeMirrorDllImportContract import_contract.cpp)
  target_compile_options(NativeMirrorDllImportContract PRIVATE /W4 /WX)
  target_include_directories(NativeMirrorDllImportContract SYSTEM PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../pe-sieve-master/pe-sieve-master/include")
  target_link_libraries(NativeMirrorDllImportContract PRIVATE "${PE_SIEVE_IMPORT}")
  add_dependencies(NativeMirrorDllImportContract PeSieveImportLibrary)
  add_library(NativeMirrorVersionFixture SHARED version_fixture.cpp
    "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/NativeMirrorDll/pe-sieve.def")
  target_include_directories(NativeMirrorVersionFixture SYSTEM PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../pe-sieve-master/pe-sieve-master/include")
  target_compile_options(NativeMirrorVersionFixture PRIVATE /W4 /WX)
  set_target_properties(NativeMirrorVersionFixture PROPERTIES OUTPUT_NAME pe-sieve
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/version-fixture"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/version-fixture")
endif()
