project(pcap-sflow-sampler)

set (SOURCE_FILES_pcap2sflow pcap2sflow.c )
add_executable (pcap2sflow ${SOURCE_FILES_pcap2sflow} )

target_link_libraries(pcap2sflow -lpcap)
