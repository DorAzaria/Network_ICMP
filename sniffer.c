/*****************************************************************************/
/****************************  sniffer.c   ***********************************/
/***  Requirements:                                                        ***/
/***                                                                       ***/
/***  sniffing ICMP traffic in your network and will display               ***/
/***  the following fields:                                                ***/
/***  -> IP_SRC                                                            ***/
/***  -> IP_DST                                                            ***/
/***  -> TYPE                                                              ***/
/***  -> CODE                                                              ***/
/***  For each relevant packet from your network.                          ***/
/***                                                                       ***/
/*****************************************************************************/
/*****************************************************************************/

/**********************************************
 * A Promiscuous Mode:
 *   is a mode for a wired network interface controller (NIC)
 *   or wireless network interface controller (WNIC) that causes the controller
 *   to pass all traffic it receives to the central processing unit (CPU) rather
 *   than passing only the frames that the controller is specifically programmed
 *   to receive.
 *   This mode is normally used for packet sniffing that takes place on a router
 *   or on a computer connected to a wired network or one being part of a wireless LAN.
 *   Interfaces are placed into promiscuous mode by software bridges often used with hardware
 *   virtualization.
 **********************************************/
/**********************************************
* A compiled BPF code:
*   if the driver for the network interface supports promiscuous mode,
*   it allows the interface to be put into that mode so that all packets
*   on the network can be received, even those destined to other hosts.
*   BPF allows a user-program to attach a filter to the socket,
*   which tells the kernel to discard unwanted packets.
**********************************************/
/**********************************************
 * Packet Capturing using raw PCAP library:
 * -> It still uses raw sockets internally,
 *    but its API is standard across all platforms.
 *    OS specifics are hidden by PCAP’s implementation.
 * -> Allows programmers to specify filtering rules using
 *    human readable Boolean expressions.
 **********************************************/
/**********************************************
 * Implementation:
 **********************************************/
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <pcap.h>
#define ICMP_HDR_LEN 4

void print_icmp_packet(char* , int);
int icmp=0;
/**********************************************
 * Get captured packet
 **********************************************/
int main() {
    int PACKET_LEN = IP_MAXPACKET;
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create the raw socket
    // * htons(ETH_P_ALL) -> Capture all types of packets
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        printf("socket() failed with error");
        printf("To create a raw socket, the process needs to be run by Admin/root user (sudo).\n\n");
        return -1;
    }

    // Turn on the promiscuous mode.
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    // Getting captured packets
    char buffer[IP_MAXPACKET];
    socklen_t len;
    while (1) {
        bzero(buffer,IP_MAXPACKET);
        len = sizeof(saddr);
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, &len);
        if (data_size >= 0){
            print_icmp_packet(buffer, data_size);
        }
    }
    close(sock);
    return 0;
}

void print_icmp_packet(char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;

    if (iph->protocol == IPPROTO_ICMP) {
        printf("============================================");
        printf("\nICMP packet %d, data size: %d \n", ++icmp, size);

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        printf("|-IP Header\n");
        printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
        printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

        int iphdrlen = iph->ihl * ICMP_HDR_LEN;
        struct icmphdr *icmph = (struct icmphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));
        printf("|-ICMP Header\n");
        printf("   |-Type             : %d\n", (unsigned int)(icmph->type));
        printf("   |-Code             : %d\n", icmph->code);

    }

}

//
//int main() {
//    pcap_t *handle;
//    pcap_if_t *alldevsp , *device;
//    char errbuf[PCAP_ERRBUF_SIZE];
//    struct bpf_program fp;
//    char filter_exp[] = "ip proto icmp";
//    bpf_u_int32 net;
//
//    char *devname , devs[100][100];
//    int count = 1 , n;
//
//    //First get the list of available devices
//    printf("Finding available devices ... ");
//    if( pcap_findalldevs( &alldevsp , errbuf) )
//    {
//        printf("Error finding devices : %s" , errbuf);
//        exit(1);
//    }
//    printf("Done");
//
//    //Print the available devices
//    printf("\nAvailable Devices are :\n");
//    for(device = alldevsp ; device != NULL ; device = device->next)
//    {
//        printf("%d. %s - %s\n" , count , device->name , device->description);
//        if(device->name != NULL)
//        {
//            strcpy(devs[count] , device->name);
//        }
//        count++;
//    }
//
//    //Ask user which device to sniff
//    printf("Enter the number of the device you want to sniff : ");
//    scanf("%d" , &n);
//    devname = devs[n];
//    // Step 1: Open live pcap session on NIC with name eth3
//    handle = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuf);
//
//    if(handle == NULL) {
//        printf("Couldn't open device.\n");
//        return -1;
//    }
//    // Step 2: Compile filter_exp into BPF psuedo-code
//    pcap_setfilter(handle, &fp);
//
//    // Step 3: Capture packets
//    pcap_loop(handle, -1, print_icmp_packet, NULL);
//
//    pcap_close(handle);   //Close the handle
//    return 0;
//}
//void print_icmp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
//    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
//    struct sockaddr_in source, dest;
//
//    if (iph->protocol == IPPROTO_ICMP) {
//        printf("============================================");
//        printf("\nICMP packet %d, data size: %d \n", ++icmp, header->len);
//
//        memset(&source, 0, sizeof(source));
//        source.sin_addr.s_addr = iph->saddr;
//
//        memset(&dest, 0, sizeof(dest));
//        dest.sin_addr.s_addr = iph->daddr;
//
//        printf("|-IP Header\n");
//        printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
//        printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
//
//        int iphdrlen = iph->ihl * ICMP_HDR_LEN;
//        struct icmphdr *icmph = (struct icmphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));
//        printf("|-ICMP Header\n");
//        printf("   |-Type             : %d\n", (unsigned int)(icmph->type));
//        printf("   |-Code             : %d\n", (unsigned int)(icmph->code));
//
//    }
//}
