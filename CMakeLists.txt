project(pcap-sflow-sampler)

set (SOURCE_FILES find_payload.c)
add_executable (find_payload ${SOURCE_FILES})

target_link_libraries(find_payload -lpcap)
