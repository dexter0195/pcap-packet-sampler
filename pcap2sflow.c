
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <string.h>

struct capture {
    int start;
    int stop;
    int curr_sample;
    int s;
    int n;
    pcap_dumper_t *pdumper;
    int truncate_b;
    bool only_ip_pkts;
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

    if (header->caplen > s->truncate_b) {
        u_char *new_packet = malloc(s->truncate_b);
        memcpy(new_packet,packet,s->truncate_b);
        pcap_dump((u_char *)s->pdumper, header, new_packet);
        free(new_packet);
    }
    else {
        pcap_dump((u_char *)s->pdumper, header, packet);
    }

    return;
}
/* Finds the payload of a TCP/IP packet */
void my_packet_handler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    cap_stat *sampler_info;
    sampler_info = (cap_stat *) args;

    if (sampler_info->only_ip_pkts) {
        /* First, lets make sure we have an IP packet */
        struct ether_header *eth_header;
        eth_header = (struct ether_header *) packet;
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            printf("Not an IP packet. Skipping...\n\n");
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

    //TODO predisporre il troncamento del pacchetto

}

void usage(char *argv1){
    printf("usage: %s --infile <input_file.pcap> --outfile <output_file.pcap>\n\n"
                   "options:\n"
                   "-t\t--trunkate-pkts <bytes>\t\ttruncate packet size to (bytes) size\n"
                   "-n\t--no-truncate-pkts\t\tdo not truncate packets\n"
                   "-s\t--sample-n <N>\t\t\tsample 1 every N packets seen\n"
                   "-N\t--no-sample\t\t\tdo not sample every N packets, take them all!\n"
                   "-h\t--help\t\t\tshow this help\n"
                   "\n" ,argv1);
}

int main(int argc, char **argv) {


    int truncate_bytes = 0;
    int sample_n = 1;
    char in_filename[4096] = "";
    char out_filename[4096] = "";
    bool only_ip_pkts = false;


/* Flag set by ‘--verbose’. */
    static int verbose_flag;
    static int no_truncate;
    static int no_sample;
    static int only_ip;

    int c;

    while (1) {
        static struct option long_options[] =
                {
                        /* These options set a flag. */
                        {"verbose", no_argument,       &verbose_flag, 1},
                        /* These options don’t set a flag.
                           We distinguish them by their indices. */
                        {"truncate-pkts",     required_argument,       0,             't'},
                        {"help",     no_argument,       0,             'h'},
                        {"no-truncate-pkts",  no_argument,       &no_truncate,             'n'},
                        {"sample-n",  required_argument, 0,             's'},
                        {"no-sample",  no_argument, &no_sample,             'N'},
                        {"only-ip-pkts",  no_argument, &only_ip,             'p'},
                        {"infile",    required_argument, 0,             'i'},
                        {"outfile",    required_argument, 0,             'o'},
                        {0, 0,                         0,             0}
                };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "t:ns:Ni:o:hp",
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
            case 'p':
//                printf("truncate to option -d with value `%s'\n", optarg);
                only_ip_pkts = true;
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


    /* Instead of reporting ‘--verbose’
       and ‘--brief’ as they are encountered,
       we report the final status resulting from them. */
    if (verbose_flag)
        puts("verbose flag is set");

//    /* Print any remaining command line arguments (not options). */
//    if (optind < argc) {
//        printf("non-option ARGV-elements: ");
//        while (optind < argc)
//            printf("%s ", argv[optind++]);
//        putchar('\n');
//    }

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
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    handle = pcap_open_offline(in_filename, error_buffer);

    cap_stat info = {0, sample_n, 0, 0, sample_n, NULL, truncate_bytes, only_ip_pkts};
    select_random(&info);

    info.pdumper = pcap_dump_open(handle, out_filename);
    u_char *my_arguments = (u_char*) &info;
    pcap_loop(handle, 0, my_packet_handler, my_arguments);

    pcap_close(handle);

    return 0;
}
