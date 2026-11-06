cmake_minimum_required(VERSION 3.21)
project(FuriousWfpServiceCore LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The Furious WFP service core can only be built on Windows.")
endif()

add_library(FuriousWfpServiceCore STATIC
    WfpEngine.cpp
    WfpEngine.h
)

target_compile_features(FuriousWfpServiceCore PUBLIC cxx_std_17)
target_compile_definitions(FuriousWfpServiceCore PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_link_libraries(FuriousWfpServiceCore PUBLIC fwpuclnt)

if(MSVC)
    target_compile_options(FuriousWfpServiceCore PRIVATE /W4 /WX /permissive-)
endif()
