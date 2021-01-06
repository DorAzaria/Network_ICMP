//
// Created by dor on 05/01/2021.
//

/*****************************************************************************/
/****************************  myping.cpp  ***********************************/
/***                                                                       ***/
/***  1) To be able to read from the raw socket the reply, use instead     ***/
/***     of IPPROTO_RAW - IPPROTO_ICMP:                                    ***/
/***     socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);                         ***/
/***                                                                       ***/
/***  2) Do not "cook" IP-header - delete that code.                       ***/
/***     Thus, with IPPROTO_ICMP the application is in charge only for     ***/
/***     ICMP packet, header and data, not for the IP-header.              ***/
/***                                                                       ***/
/***  3) "Cook" and add only ICMP, whereas kernel will add IPv4 header     ***/
/***     by itself.                                                        ***/
/***                                                                       ***/
/***  4) Remove setsockopt() IP_HDRINCL since we are not "cooking" the     ***/
/***     IP-header.                                                        ***/
/***                                                                       ***/
/***  5) When receiving, though, we are getting the whole IP packet and    ***/
/***     must extract the ICMP reply.                                      ***/
/***                                                                       ***/
/***  6) Note, that you get a copy of all ICMP packets sent to the host    ***/
/***     and should filter the relevant.                                   ***/
/***                                                                       ***/
/***  7) Check the sent ICMP packet in Wireshark.                          ***/
/***     If the checksum is not correct (zero), you missed to remove       ***/
/***     IP-header offset in ICMP-header checksum copying or calculations. ***/
/*****************************************************************************/
/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()

// IPv4 header len without options
#define IP4_HDRLEN 20
// ICMP header len for echo req
#define ICMP_HDRLEN 8
#define SOURCE_IP "127.0.0.1"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "192.168.1.1"
#define PCKT_LEN 1024

// Checksum algorithm
unsigned short calculate_checksum(unsigned short * paddress, int len);

int main() {
/*--------------------------------------------------------------------*/
/*--- ICMP header                                                  ---*/
/*--------------------------------------------------------------------*/
    struct icmp icmphdr; // ICMP-header

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // ICMP header.
    memcpy (packet, &icmphdr, ICMP_HDRLEN);

    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;

    // ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) packet, ICMP_HDRLEN + datalen);
    memcpy (packet, &icmphdr, ICMP_HDRLEN);

/*--------------------------------------------------------------------*/
/*--- Create Raw Socket                                            ---*/
/*--------------------------------------------------------------------*/
    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket for IP-ICMP
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

/*--------------------------------------------------------------------*/
/*--- Send the ICMP ECHO request packet                            ---*/
/*--------------------------------------------------------------------*/
    // Send the packet using sendto() for sending Datagrams.
    int sent_size  = sendto(sock, packet,  ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in));
    if (sent_size == -1) {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("Sent one packet. \nsent: %d \n",sent_size);

/*--------------------------------------------------------------------*/
/*--- Receive the ICMP-ECHO-REPLY packet                           ---*/
/*--------------------------------------------------------------------*/
    bzero(packet,IP_MAXPACKET);
    socklen_t len = sizeof(dest_in);
    int get_size = -1;
    while (1) {
        get_size = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *) &dest_in, &len);
        if (get_size > 0) {
            printf("Get one packet.\nget: %d \n",get_size);
            break;
        }
    }

    // Close the raw socket descriptor.
    close(sock);

    return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short * w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

