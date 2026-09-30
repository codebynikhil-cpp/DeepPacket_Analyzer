cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Source files
set(SOURCES
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/packet_source.cpp
    src/live_capture_source.cpp
    src/sni_extractor.cpp
    src/dns_parser.cpp
    src/http_parser.cpp
    src/types.cpp
    src/fast_path.cpp
    src/dpi_engine.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/stats_collector.cpp
    src/traffic_analytics.cpp
    src/wfp_enforcement.cpp
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create the executable
add_executable(PacketInspector ${SOURCES})

# Find pcap library if available
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PCAP libpcap)
    if(PCAP_FOUND)
        include_directories(${PCAP_INCLUDE_DIRS})
        target_link_libraries(PacketInspector ${PCAP_LIBRARIES})
    endif()
endif()

if(WIN32)
    # Link Windows socket, concurrency, and WFP libraries
    target_link_libraries(PacketInspector ws2_32 fwpuclnt)
endif()
