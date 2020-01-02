#include <dirent.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#define LINE_LEN 1024
#define MAX_PACKET 1024

typedef struct satis{
    char source_ip[20];
    char destination_ip[20];
    int num;
}Satis;


char* make_address(struct in_addr IPv4){
    char *res = (char *)malloc(sizeof(char) * 20);
    unsigned ip1, ip2, ip3, ip4;
    ip4 = ((IPv4.s_addr) >> 24) & (0xff);
    ip3 = ((IPv4.s_addr) >> 16) & (0xff);
    ip2 = ((IPv4.s_addr) >> 8) & (0xff);
    ip1 = ((IPv4.s_addr) >> 0) & (0xff);
    sprintf(res, "%u.%u.%u.%u", ip1, ip2, ip3, ip4);
    return res;
}
int check_packet(struct ip *IP,Satis ip_packet_satis[],int ip_packet_num){
    int res=0;
    for(int i=0;i<ip_packet_num;i++){
        int des_flag=strcmp(make_address(IP->ip_dst),ip_packet_satis[i].destination_ip);
        int src_flag=strcmp(make_address(IP->ip_src),ip_packet_satis[i].source_ip);
        if(des_flag==0 && src_flag==0){
            res=1;
            ip_packet_satis[i].num++;
            break;
        }
    }
    return res;
}
char *TCPorUCP(struct ip *IP){
    char *res = (char *)malloc(sizeof(char) * 100);
}
int main(int argc, char *argv[]){
    if (argc != 3){
        fprintf(stderr, "Command Error! Cannot find the object.\n");
        exit(1);
    }
    else if (strcmp(argv[1], "-r") != 0){
        fprintf(stderr, "Command Error! Command is not \"-r\".\n");
        exit(1);
    }
    pcap_t *fp;
    char error_buffer[PCAP_ERRBUF_SIZE];
    if ((fp = pcap_open_offline(argv[2], error_buffer)) == NULL){
        fprintf(stderr, "\n");
        exit(1);
    }
    struct pcap_pkthdr *header = NULL;
    const u_char *content = NULL;
    int ret;
    int ip_packet_num=0;
    Satis ip_packet_satis[MAX_PACKET];
    while ((ret = pcap_next_ex(fp, &header, &content)) != -2){
        if (ret == -1){
            fprintf(stderr, "Cannot get next %s\n", pcap_geterr(fp));
            exit(1);
        }
        if (ret != 1)
            break;
        struct tm *ltime;
        char timestr[100];
        time_t local_tv_sec;

        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%Y/%m/%d %H:%M:%S ", ltime);

        //print header
        printf("Time: %s.%.6d\n",timestr,(int)header->ts.tv_usec);
        printf("Length: %d bytes\n", header->len);
        printf("Capture length: %d bytes\n", header->caplen);

        //print packet in hex dump
        for (int i = 0; i < header->caplen; i++){
            printf("%02x ", content[i]);
        } //end for
        printf("\n\n");

        struct ether_header *eptr;
        eptr = (struct ehter_header *)content;
        u_char *ptr = eptr->ether_dhost;
        int i = ETHER_ADDR_LEN;
        printf("Destiantion MAC Address: ");
        do{
            printf("%s%x", (i == ETHER_ADDR_LEN) ? "" : ":", *ptr++);
        } while (--i > 0);
        printf("\n");
        *ptr = eptr->ether_shost;
        i = ETHER_ADDR_LEN;
        printf("Source MAC Address: ");
        do{
            printf("%s%x", (i == ETHER_ADDR_LEN) ? "" : ":", *ptr++);
        } while (--i > 0);
        printf("\n");

        //Read the source and destination
        if (ntohs(eptr->ether_type) == ETHERTYPE_IP){
            
            printf("Ethernet is IP packet : %d\n", ntohs(eptr->ether_type));
            struct ip *IP = (struct ip *)(content + sizeof(struct ether_header));

            if(!check_packet(IP,ip_packet_satis,ip_packet_num)){
                strcpy(ip_packet_satis[ip_packet_num].destination_ip,make_address(IP->ip_dst));
                strcpy(ip_packet_satis[ip_packet_num].source_ip,make_address(IP->ip_src));
                ip_packet_satis[ip_packet_num].num=1;
                ip_packet_num++;
            }

            printf("Destination IP Address is : %s\n", make_address(IP->ip_dst));
            printf("Source IP Address is : %s\n", make_address(IP->ip_src));
            if (IP->ip_p == 6){
                struct tcphdr *TCP = (struct tcphdr *)(content + sizeof(struct ether_header) + sizeof(struct ip));
                printf("Is TCP protocol\n");
                printf("Destination port is : %d\n", ntohs(TCP->th_dport));
                printf("Source port is : %d\n", ntohs(TCP->th_sport));
            }
            else if (IP->ip_p == 17){
                struct udphdr *UDP = (struct udphdr *)(content + sizeof(struct ether_header) + sizeof(struct ip));
                printf("Is UDP protocol\n");
                printf("Destination port is : %d\n", ntohs(UDP->uh_dport));
                printf("Source port is : %d\n", ntohs(UDP->uh_sport));
            }
        }
        printf("\n\n");
    }
    printf("---------Statistics---------\n");
    if(ip_packet_num==0){
        printf("Didn't get any IP packet.\n");
    }
    for(int i=0;i<ip_packet_num;i++){
        printf("The number of this pair packet is %d\n",ip_packet_satis[i].num);
        printf("The Destination IP is %s\n",ip_packet_satis[i].destination_ip);
        printf("The Source IP is %s\n",ip_packet_satis[i].source_ip);
        printf("\n\n");
    }
}
