cmake_minimum_required(VERSION 3.21)
project(FuriousWfpService LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The Furious WFP service can only be built on Windows.")
endif()

add_library(FuriousWfpServiceCore STATIC
    WfpEngine.cpp
    WfpEngine.h
    WfpPolicyCompiler.h
)
target_compile_features(FuriousWfpServiceCore PUBLIC cxx_std_17)
target_compile_definitions(FuriousWfpServiceCore PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)
target_link_libraries(FuriousWfpServiceCore PUBLIC fwpuclnt)
if(MSVC)
    target_compile_options(FuriousWfpServiceCore PRIVATE /W4 /WX /permissive-)
endif()

add_executable(FuriousWfpService
    WfpServiceMain.cpp
    WfpPipeServer.cpp
    WfpPipeServer.h
    WfpIpcDispatcher.h
)
target_compile_features(FuriousWfpService PRIVATE cxx_std_17)
target_compile_definitions(FuriousWfpService PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)
target_link_libraries(FuriousWfpService PRIVATE FuriousWfpServiceCore advapi32)
if(MSVC)
    target_compile_options(FuriousWfpService PRIVATE /W4 /WX /permissive-)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(FuriousWfpIpcProtocolTests tests/IpcProtocolTests.cpp)
    target_compile_features(FuriousWfpIpcProtocolTests PRIVATE cxx_std_17)
    target_compile_definitions(FuriousWfpIpcProtocolTests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
    target_link_libraries(FuriousWfpIpcProtocolTests PRIVATE fwpuclnt)

    if(MSVC)
        target_compile_options(FuriousWfpIpcProtocolTests PRIVATE /W4 /WX /permissive-)
    endif()
    add_test(NAME FuriousWfpIpcProtocolTests COMMAND FuriousWfpIpcProtocolTests)

    add_executable(FuriousWfpNamedPipeIntegrationTests
        tests/NamedPipeIntegrationTests.cpp
        WfpPipeServer.cpp
        WfpPipeServer.h
        WfpIpcDispatcher.h
    )
    target_compile_features(FuriousWfpNamedPipeIntegrationTests PRIVATE cxx_std_17)
    target_compile_definitions(FuriousWfpNamedPipeIntegrationTests PRIVATE
        WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
    )
    target_link_libraries(FuriousWfpNamedPipeIntegrationTests PRIVATE advapi32 fwpuclnt)
    if(MSVC)
        target_compile_options(FuriousWfpNamedPipeIntegrationTests PRIVATE /W4 /WX /permissive-)
    endif()
    add_test(NAME FuriousWfpNamedPipeIntegrationTests
        COMMAND FuriousWfpNamedPipeIntegrationTests)
    set_tests_properties(FuriousWfpNamedPipeIntegrationTests PROPERTIES TIMEOUT 10)
endif()
