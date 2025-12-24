# Common utilities library
add_library(callflow_common STATIC
    common/logger.cpp
    common/types.cpp
    common/utils.cpp
    common/config_loader.cpp
    common/crypto_utils.cpp
    common/nas_security_context.cpp
    common/packet_filter.cpp
)
target_include_directories(callflow_common PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(callflow_common PUBLIC
    nlohmann_json::nlohmann_json
    Threads::Threads
    fmt::fmt
    OpenSSL::Crypto
)

# Config manager library
add_library(config_manager STATIC
    config/config_manager.cpp
)
target_include_directories(config_manager PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(config_manager PUBLIC
    callflow_common
    yaml-cpp
)

# Session correlation library
add_library(session_correlation STATIC
    session/session_types.cpp
    session/session_correlator.cpp
)
target_include_directories(session_correlation PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(session_correlation PUBLIC
    callflow_common
)

# Identity correlation library
add_library(identity_correlation STATIC
    correlation/identity/subscriber_identity.cpp
    correlation/identity/msisdn_normalizer.cpp
    correlation/identity/imsi_normalizer.cpp
    correlation/identity/imei_normalizer.cpp
    correlation/identity/guti_parser.cpp
    correlation/identity/identity_matcher.cpp
    correlation/identity/subscriber_context_manager.cpp
)
target_include_directories(identity_correlation PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(identity_correlation PUBLIC
    callflow_common
)

# SIP correlation library
add_library(sip_correlation STATIC
    correlation/sip/sip_types.cpp
    correlation/sip/sip_message.cpp
    correlation/sip/sip_transaction.cpp
    correlation/sip/sip_dialog.cpp
    correlation/sip/sip_call_detector.cpp
    correlation/sip/sip_session.cpp
    correlation/sip/sip_correlator.cpp
)
target_include_directories(sip_correlation PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(sip_correlation PUBLIC
    callflow_common
    identity_correlation
)

# Diameter correlation library
add_library(diameter_correlation STATIC
    correlation/diameter/diameter_types.cpp
    correlation/diameter/diameter_message.cpp
    correlation/diameter/diameter_session.cpp
    correlation/diameter/diameter_correlator.cpp
)
target_include_directories(diameter_correlation PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(diameter_correlation PUBLIC
    callflow_common
    identity_correlation
    protocol_parsers
)

# GTPv2 correlation library
add_library(gtpv2_correlation STATIC
    correlation/gtpv2/gtpv2_types.cpp
    correlation/gtpv2/gtpv2_message.cpp
    correlation/gtpv2/gtpv2_bearer.cpp
    correlation/gtpv2/gtpv2_session.cpp
    correlation/gtpv2/gtpv2_fteid_manager.cpp
    correlation/gtpv2/gtpv2_correlator.cpp
)
target_include_directories(gtpv2_correlation PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(gtpv2_correlation PUBLIC
    callflow_common
    identity_correlation
    protocol_parsers
)

# Procedure state machines library
add_library(procedure_correlation STATIC
    correlation/procedure_state_machine.cpp
    correlation/lte_attach_machine.cpp
    correlation/x2_handover_machine.cpp
    correlation/volte_call_machine.cpp
    correlation/fiveg_registration_machine.cpp
    correlation/procedure_detector.cpp
    correlation/keepalive_aggregator.cpp
    correlation/tunnel_manager.cpp
    correlation/handover_detector.cpp
    correlation/ladder_types.cpp
    correlation/participant_detector.cpp
    correlation/ladder_diagram_generator.cpp
    correlation/subscriber_context.cpp
    correlation/volte_call.cpp
)
target_include_directories(procedure_correlation PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(procedure_correlation PUBLIC
    callflow_common
    session_correlation
    protocol_parsers
    identity_correlation
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

# ASN.1 wrapper library for S1AP
add_library(asn1_wrapper STATIC
    ${PROJECT_SOURCE_DIR}/thirdparty/asn1c/s1ap_asn1_wrapper.cpp
)
target_include_directories(asn1_wrapper PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/thirdparty
)
target_link_libraries(asn1_wrapper PUBLIC
    callflow_common
)

# Protocol parsers library
add_library(protocol_parsers STATIC
    protocol_parsers/sip_parser.cpp
    protocol_parsers/sip_3gpp_parser.cpp
    protocol_parsers/rtp_parser.cpp
    protocol_parsers/gtp_parser.cpp
    protocol_parsers/gtpv1_parser.cpp
    protocol_parsers/gtp/gtpv2_types.cpp
    protocol_parsers/gtp/gtpv2_ie_parser.cpp
    protocol_parsers/gtp/gtp_teid_manager.cpp
    protocol_parsers/pfcp_parser.cpp
    protocol_parsers/diameter_parser.cpp
    protocol_parsers/diameter_s6a_parser.cpp
    protocol_parsers/diameter/diameter_types.cpp
    protocol_parsers/diameter/diameter_base.cpp
    protocol_parsers/diameter/diameter_avp_parser.cpp
    protocol_parsers/diameter/diameter_session_manager.cpp
    protocol_parsers/diameter/diameter_policy_types.cpp
    protocol_parsers/diameter/diameter_gx_parser.cpp
    protocol_parsers/diameter/diameter_rx_parser.cpp
    protocol_parsers/diameter/diameter_gy_parser.cpp
    protocol_parsers/diameter/policy_rule_parser.cpp
    protocol_parsers/diameter/ims_types.cpp
    protocol_parsers/diameter/diameter_cx_parser.cpp
    protocol_parsers/diameter/diameter_sh_parser.cpp
    protocol_parsers/http2_parser.cpp
    protocol_parsers/fiveg_sba_parser.cpp
    protocol_parsers/x2ap_parser.cpp
    protocol_parsers/ngap_parser.cpp
    protocol_parsers/nas5g_parser.cpp
    protocol_parsers/nas_parser.cpp
    protocol_parsers/s1ap/s1ap_parser.cpp
    protocol_parsers/s1ap/s1ap_ie_parser.cpp

)
target_include_directories(protocol_parsers PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/thirdparty
)
target_link_libraries(protocol_parsers PUBLIC
    callflow_common
    transport
    asn1_wrapper
)

# PCAP ingestion library (Depends on protocol_parsers)
add_library(pcap_ingest STATIC
    pcap_ingest/pcap_reader.cpp
    pcap_ingest/pcapng_reader.cpp
    pcap_ingest/multi_interface_reader.cpp
    pcap_ingest/interface_detector.cpp
    pcap_ingest/format_detector.cpp
    pcap_ingest/packet_queue.cpp
    pcap_ingest/link_layer_parser.cpp
    pcap_ingest/ip_reassembler.cpp
    pcap_ingest/tcp_reassembler.cpp
    pcap_ingest/tcp_state_machine.cpp
    pcap_ingest/sip_framer.cpp
    pcap_ingest/diameter_framer.cpp
    pcap_ingest/http2_framer.cpp
    pcap_ingest/packet_processor.cpp
)
target_include_directories(pcap_ingest PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIR}
)
target_link_libraries(pcap_ingest PUBLIC
    callflow_common
    session_correlation
    protocol_parsers
    ${PCAP_LIBRARY}
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
    session_correlation
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
        config_manager
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
        target_compile_definitions(api_server PUBLIC ENABLE_DATABASE_PERSISTENCE)
    endif()
endif()

# Main CLI executable
add_executable(callflowd
    cli/main.cpp
    cli/cli_parser.cpp
    cli/cli_parser.cpp
)

target_compile_options(callflowd PRIVATE -fno-lto)
target_link_options(callflowd PRIVATE -fno-lto)

target_link_libraries(callflowd PRIVATE
    procedure_correlation
    event_extractor
    session_correlation
    flow_manager
    pcap_ingest
    protocol_parsers
    config_manager
    callflow_common
)

if(NOT NEED_NDPI_BUILD)
    target_link_libraries(callflowd PRIVATE ndpi_engine)
    target_compile_definitions(callflowd PRIVATE ENABLE_NDPI)
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
