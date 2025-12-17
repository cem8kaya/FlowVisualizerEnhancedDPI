# Common utilities library
add_library(callflow_common STATIC
    common/logger.cpp
    common/types.cpp
    common/utils.cpp
    common/config_loader.cpp
)
target_include_directories(callflow_common PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(callflow_common PUBLIC
    nlohmann_json::nlohmann_json
    Threads::Threads
    fmt::fmt
)

# PCAP ingestion library
add_library(pcap_ingest STATIC
    pcap_ingest/pcap_reader.cpp
    pcap_ingest/pcapng_reader.cpp
    pcap_ingest/multi_interface_reader.cpp
    pcap_ingest/format_detector.cpp
    pcap_ingest/packet_queue.cpp
)
target_include_directories(pcap_ingest PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIR}
)
target_link_libraries(pcap_ingest PUBLIC
    callflow_common
    ${PCAP_LIBRARY}
)

# nDPI engine wrapper
if(NOT NEED_NDPI_BUILD)
    add_library(ndpi_engine STATIC
        ndpi_engine/ndpi_wrapper.cpp
        ndpi_engine/ndpi_flow_cache.cpp
        ndpi_engine/flow_classifier.cpp
    )
    target_include_directories(ndpi_engine PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${NDPI_INCLUDE_DIR}
    )
    target_link_libraries(ndpi_engine PUBLIC
        callflow_common
        ${NDPI_LIBRARY}
    )
endif()

# Flow manager library
add_library(flow_manager STATIC
    flow_manager/flow_tracker.cpp
    flow_manager/session_correlator.cpp
)
target_include_directories(flow_manager PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(flow_manager PUBLIC
    callflow_common
)

# Transport layer library
add_library(transport STATIC
    transport/sctp_reassembler.cpp
    transport/sctp_parser.cpp
)
target_include_directories(transport PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(transport PUBLIC
    callflow_common
)

# Protocol parsers library
add_library(protocol_parsers STATIC
    protocol_parsers/sip_parser.cpp
    protocol_parsers/rtp_parser.cpp
    protocol_parsers/gtp_parser.cpp
    protocol_parsers/gtpv1_parser.cpp
    protocol_parsers/diameter_parser.cpp
    protocol_parsers/http2_parser.cpp
)
target_include_directories(protocol_parsers PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(protocol_parsers PUBLIC
    callflow_common
    transport
)

# Event extractor library
add_library(event_extractor STATIC
    event_extractor/event_builder.cpp
    event_extractor/json_exporter.cpp
)
target_include_directories(event_extractor PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(event_extractor PUBLIC
    callflow_common
    protocol_parsers
)

# Persistence library (SQLite3)
if(SQLite3_FOUND)
    add_library(persistence STATIC
        persistence/database.cpp
    )
    target_include_directories(persistence PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${SQLite3_INCLUDE_DIRS}
    )
    target_link_libraries(persistence PUBLIC
        callflow_common
        ${SQLite3_LIBRARIES}
    )
endif()

# API server library (optional)
if(BUILD_API_SERVER)
    add_library(api_server STATIC
        api_server/http_server.cpp
        api_server/websocket_handler.cpp
        api_server/routes.cpp
        api_server/job_manager.cpp
        api_server/rate_limiter.cpp
        api_server/input_validator.cpp
        api_server/auth_manager.cpp
        api_server/auth_middleware.cpp
        api_server/auth_routes.cpp
        api_server/analytics_manager.cpp
        api_server/analytics_routes.cpp
    )
    target_include_directories(api_server PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    )
    target_link_libraries(api_server PUBLIC
        callflow_common
        pcap_ingest
        flow_manager
        protocol_parsers
        event_extractor
        httplib::httplib
    )
    target_compile_definitions(api_server PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
    )
    # Link OpenSSL for HTTPS support and JWT signing
    if(ENABLE_TLS)
        target_link_libraries(api_server PUBLIC
            OpenSSL::SSL
            OpenSSL::Crypto
        )
    endif()

    # Link jwt-cpp for JWT authentication
    target_link_libraries(api_server PUBLIC jwt-cpp::jwt-cpp)

    # Link persistence for auth manager (if available)
    if(SQLite3_FOUND)
        target_link_libraries(api_server PUBLIC persistence)
    endif()
endif()

# Main CLI executable
add_executable(callflowd
    cli/main.cpp
    cli/cli_parser.cpp
)

target_link_libraries(callflowd PRIVATE
    callflow_common
    pcap_ingest
    flow_manager
    protocol_parsers
    event_extractor
)

if(NOT NEED_NDPI_BUILD)
    target_link_libraries(callflowd PRIVATE ndpi_engine)
endif()

if(BUILD_API_SERVER)
    target_link_libraries(callflowd PRIVATE api_server)
    target_compile_definitions(callflowd PRIVATE BUILD_API_SERVER)
endif()

if(SQLite3_FOUND)
    target_link_libraries(callflowd PRIVATE persistence)
    target_compile_definitions(callflowd PRIVATE ENABLE_DATABASE_PERSISTENCE)

    # Create admin user tool (requires persistence and auth)
    if(BUILD_API_SERVER)
        add_executable(create_admin
            cli/create_admin.cpp
        )
        target_link_libraries(create_admin PRIVATE
            callflow_common
            persistence
            api_server
        )
    endif()
endif()
