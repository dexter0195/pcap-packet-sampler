
#define _GNU_SOURCE
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <dnet.h>
#include "uthash.h"
#include <pcap/pcap.h>
#include <zconf.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

#define DEFAULT_SLEEP_COUNTDOWN 100

/*
 * Linux Socket Cooked Capture header - a pseudo header as DL substitute
 */

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

struct capture {
    int start;
    int stop;
    int curr_sample;
    int s;
    int n;
    pcap_dumper_t *pdumper;
    int truncate_b;
    bool dlt_raw;
    bool use_blacklist;
    int sleeping_timeout;
};
struct blacklist_item {
    char ip[256];            /* we'll use this field as the key */
    int id;
    UT_hash_handle hh; /* makes this structure hashable */
};

struct blacklist_item *black_list = NULL;

typedef struct capture cap_stat;

void select_random (cap_stat *stat) {
    //seleziona il prossimo pacchetto in modo random partendo dall'ultima finestra considerata
    //TODO srand alimentato con time potrebbe essere poco casuale se viene aggiornato spesso!
    srand ( time(NULL) ) ;
    int x = rand();
    stat->s = stat->start + ( x % stat->n ) ;
}

void next_window (cap_stat *stat){
    //analizza la successiva finestra di pacchetti
    stat->start = stat->stop + 1;
    stat->stop = stat->stop + 1 + stat->n;
    select_random(stat);
}

bool to_sample ( cap_stat *sampler_info ) {

    //se n == 1 allora disattiva il campionamento e salva tutti i pacchetti
    if (sampler_info->n == 1) return true;

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

void save_packet (cap_stat *s, const struct pcap_pkthdr *header, const u_char *packet){

    if (s->truncate_b == 0) {
        //0 viene considerato come valore di default per "salva tutto il pacchetto"
        pcap_dump((u_char *)s->pdumper, header, packet);
        return;
    }
    if (header->caplen > s->truncate_b) {
        u_char *new_packet = malloc(s->truncate_b);
        memcpy(new_packet,packet,s->truncate_b);
        pcap_dump((u_char *)s->pdumper, header, new_packet);
        free(new_packet);
    }
    else {
        pcap_dump((u_char *)s->pdumper, header, packet);
    }

}
/* Finds the payload of a TCP/IP packet */
void my_packet_handler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    cap_stat *sampler_info;
    sampler_info = (cap_stat *) args;

    if (sampler_info->sleeping_timeout-- == 0){
        const struct timespec timer = {
                .tv_sec = 0,
                .tv_nsec = 5000000
        };
        struct timespec s;
//        printf("simulating real traffic... sleeping\n");
        sampler_info->sleeping_timeout = DEFAULT_SLEEP_COUNTDOWN;
        nanosleep(&timer, &s);
    }


    const struct sniff_ip *ip; /* The IP header */
    if (sampler_info->dlt_raw) {
        /* First, lets make sure we have an IP packet */
        ip = (struct sniff_ip*)(packet);
    }
    else {
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    }

    if (sampler_info->use_blacklist == true){
        //check if the address is blacklisted
        struct blacklist_item *tmp = NULL;
        HASH_FIND_STR(black_list, inet_ntoa(ip->ip_src), tmp);
        if (tmp != NULL) {
            //if it is blacklisted sample no matters the sampling rate
//        printf("address %s is blacklisted\n", tmp->ip );
            save_packet(sampler_info,header,packet);
            return;
        }
    }

    bool skip = ! (to_sample(sampler_info));
    if ( skip ) {
        return;
    }
    else {
        save_packet(sampler_info,header,packet);
        return;
    }


}

void usage(char *argv1){
    printf("usage: %s --infile <input_file.pcap> --outfile <output_file.pcap>\n\n"
                   "options:\n"
                   "-t\t--trunkate-pkts <bytes>\t\ttruncate packet size to (bytes) size\n"
                   "-n\t--no-truncate-pkts\t\tdo not truncate packets\n"
                   "-s\t--sample-n <N>\t\t\tsample 1 every N packets seen\n"
                   "-r\t\t\t\tuse dlt raw format\n"
                   "-b\t\t\t\tuse blacklist to further analyze suspected sources\n"
                   "-N\t--no-sample\t\t\tdo not sample every N packets, take them all!\n"
                   "-h\t--help\t\t\tshow this help\n"
                   "\n" ,argv1);
}

void load_blacklist(){
    char blacklist_filename [4096] = "/tmp/pcap2sflow-blacklist";
    char buff [256];
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    FILE *fp;

    fp = fopen(blacklist_filename, "r");
    int id = 0;
    if (fp == NULL) {
        perror("no blacklist_file provided");
        exit(EXIT_FAILURE);
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        //reads all the lines and add them to the hashtable of blacklisted ip
        if ((line)[read - 1] == '\n') {
            //strip the newline char
            (line)[read - 1] = '\0';
        }
        if (strcmp(line, "") == 0 ){

        }
        struct blacklist_item *s;
        s = (struct blacklist_item*)malloc(sizeof(struct blacklist_item));
        s->id = id++;
        strncpy(s->ip, line, 256);
        HASH_ADD_STR(black_list, ip , s);
    }

//    struct blacklist_item *s = NULL;

//    printf("Blacklisted IPs:\n");
//    for(s=black_list; s != NULL; s=s->hh.next) {
//        printf("id %d: ip %s\n", s->id, s->ip);
//    }

    fclose(fp);

}

void reload_blacklist(int signo){
    if (signo != SIGUSR1) {
        return;
    }
    HASH_CLEAR(hh, black_list);
    black_list = NULL;
    load_blacklist();

}

int main(int argc, char **argv) {


    int truncate_bytes = 0;
    int sample_n = 1;
    char in_filename[4096] = "";
    char out_filename[4096] = "";
    bool dlt_raw_ip = false;
    bool use_blacklist = false;

    FILE *pid_fd = fopen("/tmp/pcap2sflow.pid", "w+");
    fprintf(pid_fd, "%d", getpid());
    fclose(pid_fd);


/* Flag set by ‘--verbose’. */
//    static int verbose_flag;
    static int raw_ip;
    static int use_blist;


    int c;

    while (1) {
        static struct option long_options[] =
                {
                        {"truncate-pkts",     required_argument,       0,             't'},
                        {"help",     no_argument,       0,             'h'},
                        {"sample-n",  required_argument, 0,             's'},
                        {"dlt-raw",  no_argument, &raw_ip,             'r'},
                        {"blacklist",  no_argument, &use_blist,             'b'},
                        {"infile",    required_argument, 0,             'i'},
                        {"outfile",    required_argument, 0,             'o'},
                        {0, 0,                         0,             0}
                };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "t:s:i:o:hrb",
                        long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 0:
                /* If this option set a flag, do nothing else now. */
                if (long_options[option_index].flag != 0)
                    break;
//                printf("option %s", long_options[option_index].name);
                if (optarg)
//                    printf(" with arg %s", optarg);
//                printf("\n");
                break;

            case 'i':
                strncpy(in_filename,optarg,4096);
//                printf("filename: %s\n", in_filename);
                break;

            case 'o':
                strncpy(out_filename,optarg,4096);
//                printf("filename: %s\n", out_filename);
                break;

            case 't':
//                printf("truncate to option -d with value `%s'\n", optarg);
                truncate_bytes = atoi(optarg);
                break;
            case 'b':
//                printf("truncate to option -d with value `%s'\n", optarg);
                use_blacklist = true;
                break;
            case 'r':
//                printf("truncate to option -d with value `%s'\n", optarg);
                dlt_raw_ip = true;
                break;

            case 's':
//                printf("sample every N option -f with value `%s'\n", optarg);
                sample_n = atoi(optarg);
                break;

            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                usage(argv[0]);
                abort();
        }
    }

    //files are mandatory!!
    if ( strcmp("", in_filename) == 0 ) {
        usage(argv[0]);
        abort();
    }
    if ( strcmp("", out_filename) == 0 ) {
        usage(argv[0]);
        abort();
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    if (use_blacklist == true) {
        load_blacklist();
        if (signal(SIGUSR1, reload_blacklist) == SIG_ERR)
            printf("\ncan't catch SIGUSR1\n");
    }
    handle = pcap_open_offline(in_filename, error_buffer);

    cap_stat info = {0, sample_n, 0, 0, sample_n, NULL, truncate_bytes, dlt_raw_ip , use_blacklist, DEFAULT_SLEEP_COUNTDOWN};
    select_random(&info);

    info.pdumper = pcap_dump_open(handle, out_filename);
    u_char *my_arguments = (u_char*) &info;
    pcap_loop(handle, 0, my_packet_handler, my_arguments);

    pcap_close(handle);

    return 0;
}
