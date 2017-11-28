project(pcap-sflow-sampler)

set (SOURCE_FILES pcap2sflow.c)
add_executable (pcap2sflow ${SOURCE_FILES})

target_link_libraries(pcap2sflow -lpcap)
