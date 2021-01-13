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
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

/**********************************************
 * Implementation:
 **********************************************/
int count=0;
void got_packet(unsigned char* , int );

int main(int argc, char *argv[]) {

    printf("\n######################################################\n");
    printf("   Welcome!, please wait for new ICMP packets...\n");
    printf("######################################################\n\n");

    int PACKET_LEN = IP_MAXPACKET;
    struct packet_mreq mr;

/**********************************************
 * Create the raw socket
 * -> htons(ETH_P_ALL): Capture all types of packets
 **********************************************/
    int raw_socket;
    if ((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("listener: socket");
        return -1;
    }

/**********************************************
 * Turn on the promiscuous mode
 **********************************************/
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(raw_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

/**********************************************
 * Get captured packet
 **********************************************/
    char buffer[PACKET_LEN];
    while(1) {
        bzero(buffer,PACKET_LEN);
        int received = recvfrom(raw_socket, buffer, ETH_FRAME_LEN, 0, NULL, NULL);

        unsigned char* hex= ((unsigned char*)buffer);
        unsigned char* packet= (unsigned char *)malloc(received);

        for (int i =14,j=0; i < received-4;i++,j++) {
            packet[j]=hex[i];
        }

        got_packet(packet, received);
    }
}

void got_packet(unsigned char* buffer, int size) {

    struct iphdr *iph = (struct iphdr*)buffer;

/**********************************************
* Check if it's a ICMP protocol.
**********************************************/
    if (iph->protocol == 1) {

        unsigned short iphdrlen = iph->ihl*4;
        struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);

/**********************************************
* If the IP Destination is known,
* then print the data.
**********************************************/
        if((unsigned int)(icmph->type) != 96) {

            struct sockaddr_in source,dest;
            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph->saddr;

            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = iph->daddr;

            printf("*********************** ICMP Packet No. %d *************************\n",++count);
            printf("\nIP Header\n");
            printf("---> Source IP        : %s\n",inet_ntoa(source.sin_addr));
            printf("---> Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
            printf("\nICMP Header\n");
            printf("---> Type : %d\n", (unsigned int) (icmph->type));
            printf("---> Code : %d\n", (unsigned int) (icmph->code));

        }
    }
}





