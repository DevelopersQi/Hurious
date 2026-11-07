cmake_minimum_required(VERSION 3.21)
project(FuriousWfpService LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The Furious WFP service can only be built on Windows.")
endif()

add_library(FuriousWfpTcpBroker STATIC
    ../broker/WfpTcpRedirect.cpp
    ../broker/WfpSocks5Udp.cpp
    ../broker/WfpSocks5UdpControl.cpp
    ../broker/WfpSocks5UdpAssociation.cpp
    ../broker/WfpSocks5UdpAssociationManager.cpp
    ../broker/WfpSocks5UdpSocket.cpp
    ../broker/WfpSocks5UdpRedirectRecord.cpp
    ../broker/WfpUdpFlowManager.cpp
    ../broker/WfpSocks5UdpAssociationClient.cpp
    ../broker/WfpTcpRedirect.h
    ../broker/WfpTcpBrokerServer.cpp
    ../broker/WfpTcpBrokerServer.h
)
target_compile_features(FuriousWfpTcpBroker PUBLIC cxx_std_17)
target_compile_definitions(FuriousWfpTcpBroker PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_link_libraries(FuriousWfpTcpBroker PUBLIC ws2_32)
if(MSVC)
    target_compile_options(FuriousWfpTcpBroker PRIVATE /W4 /WX /permissive-)
endif()

add_library(FuriousWfpServiceCore STATIC
    WfpEngine.cpp
    WfpEngine.h
    WfpPolicyCompiler.h
    WfpDriverLifecycle.cpp
    WfpDriverLifecycle.h
)
target_compile_features(FuriousWfpServiceCore PUBLIC cxx_std_17)
target_compile_definitions(FuriousWfpServiceCore PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)
target_link_libraries(FuriousWfpServiceCore PUBLIC fwpuclnt advapi32 rpcrt4 FuriousWfpTcpBroker)
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
    target_link_libraries(FuriousWfpIpcProtocolTests PRIVATE FuriousWfpServiceCore)

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
    target_link_libraries(FuriousWfpNamedPipeIntegrationTests PRIVATE advapi32 FuriousWfpServiceCore)
    if(MSVC)
        target_compile_options(FuriousWfpNamedPipeIntegrationTests PRIVATE /W4 /WX /permissive-)
    endif()
    add_test(NAME FuriousWfpNamedPipeIntegrationTests
        COMMAND FuriousWfpNamedPipeIntegrationTests)
    set_tests_properties(FuriousWfpNamedPipeIntegrationTests PROPERTIES TIMEOUT 10)

    # Exercise the TCP redirect metadata and broker lifecycle in the same
    # Windows CI job that builds the service. The standalone broker project
    # already defines these tests, but the service workflow previously only
    # compiled the broker library without running them.
    add_executable(FuriousWfpTcpBrokerTests
        ../broker/tests/WfpTcpRedirectTests.cpp
        ../broker/tests/WfpTcpBrokerServerTests.cpp
    )
    target_compile_features(FuriousWfpTcpBrokerTests PRIVATE cxx_std_17)
    target_compile_definitions(FuriousWfpTcpBrokerTests PRIVATE
        WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
    )
    target_link_libraries(FuriousWfpTcpBrokerTests PRIVATE FuriousWfpTcpBroker)
    if(MSVC)
        # Keep assertions active in Release CI builds; otherwise these
        # regression executables would silently skip their checks under NDEBUG.
        target_compile_options(FuriousWfpTcpBrokerTests PRIVATE /W4 /WX /permissive- /UNDEBUG)
    endif()
    add_test(NAME FuriousWfpTcpBrokerTests COMMAND FuriousWfpTcpBrokerTests)
    set_tests_properties(FuriousWfpTcpBrokerTests PROPERTIES TIMEOUT 15)
endif()
