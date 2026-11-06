cmake_minimum_required(VERSION 3.21)
project(FuriousWfpTcpBroker LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The WFP TCP broker is Windows-only.")
endif()

add_library(FuriousWfpTcpBroker STATIC
    WfpTcpRedirect.cpp
    WfpTcpRedirect.h
)
target_compile_features(FuriousWfpTcpBroker PUBLIC cxx_std_17)
target_compile_definitions(FuriousWfpTcpBroker PUBLIC
    WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)
target_link_libraries(FuriousWfpTcpBroker PUBLIC ws2_32)
if(MSVC)
    target_compile_options(FuriousWfpTcpBroker PRIVATE /W4 /WX /permissive-)
endif()
