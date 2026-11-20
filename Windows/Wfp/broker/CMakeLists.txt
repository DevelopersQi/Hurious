cmake_minimum_required(VERSION 3.21)
project(FuriousWfpTcpBroker LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The WFP broker is Windows-only.")
endif()

add_library(FuriousWfpTcpBroker STATIC
    WfpTcpRedirect.cpp
    WfpSocks5Udp.cpp
    WfpSocks5UdpControl.cpp
    WfpSocks5UdpAssociation.cpp
    WfpSocks5UdpAssociationManager.cpp
    WfpSocks5UdpSocket.cpp
    WfpSocks5UdpRedirectRecord.cpp
    WfpUdpFlowManager.cpp
    WfpSocks5UdpAssociationClient.cpp
    WfpSocks5UdpRelayTransport.cpp
    WfpSocks5UdpFlowRelay.cpp
    WfpUdpFlowRelayRegistry.cpp
    WfpUdpBrokerServer.cpp
    WfpTcpRedirect.h
    WfpTcpBrokerServer.cpp
    WfpTcpBrokerServer.h
    WfpUdpBrokerServer.h
)
target_compile_features(FuriousWfpTcpBroker PUBLIC cxx_std_17)
target_compile_definitions(FuriousWfpTcpBroker PUBLIC
    WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)
target_link_libraries(FuriousWfpTcpBroker PUBLIC ws2_32)
if(MSVC)
    target_compile_options(FuriousWfpTcpBroker PRIVATE /W4 /WX /permissive-)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(FuriousWfpTcpBrokerTests
        tests/WfpTcpRedirectTests.cpp
        tests/WfpTcpBrokerServerTests.cpp
    )
    add_executable(FuriousWfpSocks5UdpTests
        tests/WfpSocks5UdpTests.cpp
    )
    add_executable(FuriousWfpUdpBrokerServerTests
        tests/WfpUdpBrokerServerTests.cpp
    )

    foreach(test_target IN ITEMS
            FuriousWfpTcpBrokerTests
            FuriousWfpSocks5UdpTests
            FuriousWfpUdpBrokerServerTests)
        target_compile_features(${test_target} PRIVATE cxx_std_17)
        target_link_libraries(${test_target} PRIVATE FuriousWfpTcpBroker)
        if(MSVC)
            # Keep assert-based checks active in Release CI builds.
            target_compile_options(${test_target} PRIVATE /W4 /WX /permissive- /UNDEBUG)
        endif()
    endforeach()

    add_test(NAME FuriousWfpTcpBrokerTests COMMAND FuriousWfpTcpBrokerTests)
    add_test(NAME FuriousWfpSocks5UdpTests COMMAND FuriousWfpSocks5UdpTests)
    add_test(NAME FuriousWfpUdpBrokerServerTests COMMAND FuriousWfpUdpBrokerServerTests)
endif()
