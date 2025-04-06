#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

     
        if (ip->iph_protocol == IPPROTO_TCP) {

            // Ethernet Header 출력
            printf("=== Ethernet Header ===\n");
            printf("Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP Header 출력
            printf("=== IP Header ===\n");
            printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            // IP Header 길이 
            int ip_header_len = ip->iph_ihl * 4;

            // TCP Header 접근
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

            // TCP Header 길이 계산
            int tcp_header_len = TH_OFF(tcp) * 4;

            // TCP Header 출력
            printf("=== TCP Header ===\n");
            printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %u\n", ntohs(tcp->tcp_dport));

            // Message 출력 
            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = header->caplen - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);
            
            printf("=== Payload ===\n");
            int print_len = payload_len < 20 ? payload_len : 20; // 최대 20 bytes
            for(int i = 0; i < print_len; i++) {
                printf("%02X ", payload[i]);
            }
            printf("\n\n");
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; 
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap open fail!: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "filter compile fail!: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "filter compile fail!: %s\n", pcap_geterr(handle));
        return 1;
    }


    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
