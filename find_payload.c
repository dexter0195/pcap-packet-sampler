
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

struct capture {
    int start;
    int stop;
    int curr_sample;
    int s;
    int n;
};

typedef struct capture cap_stat;

void select_random (cap_stat *stat) {
    //seleziona il prossimo pacchetto in modo random partendo dall'ultima finestra considerata
    srand ( time(NULL) ) ;
    int x = rand();
    stat->s = stat->start + ( x % stat->n ) ;
    return;
}

void next_window (cap_stat *stat){
    //analizza la successiva finestra di pacchetti
    stat->start = stat->stop + 1;
    stat->stop = stat->stop + 1 + stat->n;
    select_random(stat);
}

bool to_sample ( cap_stat *sampler_info ) {
    //controlla se il pacchetto corrente deve essere campionato o meno

    if (sampler_info->curr_sample < sampler_info->start) {
        //se sono andato avanti con la window ma il cursore e` ancora indietro questo pacchetto sara` sicuramente da scartare
        sampler_info->curr_sample++;
        return false;
    }

    if (sampler_info->curr_sample == sampler_info->s) {
        //se il pacchetto corrente e` quello designato per essere campionato avanza e rispondi true
        sampler_info->curr_sample++;
        next_window(sampler_info);
        return true;
    }
    else {
        sampler_info->curr_sample++;
        return false;
    }
}

/* Finds the payload of a TCP/IP packet */
void my_packet_handler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    cap_stat *sampler_info;
    sampler_info = (cap_stat *) args;

    int curr = sampler_info->curr_sample;
    bool skip = ! (to_sample(sampler_info));
    if ( skip ) {
        return;
    }


    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
                     (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    printf("packet:%d \n", packet);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    /*
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */

    return;
}

int main(int argc, char **argv) {


    if (argc < 3) {
        printf("missing arguments");
        return 1;
    }
    cap_stat info = { 0, 0, 0, 0, strtol(argv[2], NULL, 10) };

    select_random(&info);
    info.stop = info.n;

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */
    /* End the loop after this many packets are captured */
    int total_packet_count = 200;
    u_char *my_arguments = (u_char*) &info;


    handle = pcap_open_offline(argv[1], error_buffer);

    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    pcap_close(handle);

    return 0;
}
