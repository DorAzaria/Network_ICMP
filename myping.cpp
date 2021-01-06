#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8
#define SOURCE_IP "127.0.0.1"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "192.168.1.1"

/*****************************************************************************/
/****************************  myping.cpp  ***********************************/
/***  Requirements:                                                        ***/
/***                                                                       ***/
/***  1) myping.cpp sends ICMP ECHO REQUEST and receives                   ***/
/***     ICMP-ECHO-REPLY (one time is enough).                             ***/
/***                                                                       ***/
/***  2) myping.cpp calculates the RTT time in milliseconds and            ***/
/***     microseconds.                                                     ***/
/***                                                                       ***/
/*****************************************************************************/
/*****************************************************************************/

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
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user (sudo).\n\n");
        return -1;
    }

/*--------------------------------------------------------------------*/
/*--- Send the ICMP ECHO REQUEST packet                            ---*/
/*--------------------------------------------------------------------*/

    struct timeval start, end;
    gettimeofday(&start, NULL);

    // Send the packet using sendto() for sending Datagrams.
    int sent_size  = sendto(sock, packet,  ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in));
    if (sent_size == -1) {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("\nSent one packet. \nsent: %d \n\n",sent_size);

/*--------------------------------------------------------------------*/
/*--- Receive the ICMP ECHO REPLY packet                           ---*/
/*--------------------------------------------------------------------*/
    bzero(packet,IP_MAXPACKET);
    socklen_t len = sizeof(dest_in);
    int get_size = -1;
    while (1) {
        get_size = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *) &dest_in, &len);
        if (get_size > 0) {
            printf("Get one packet.\nget: %d (+ IP4_HDRLEN) \n\n",get_size);
            break;
        }
    }

    gettimeofday(&end, NULL);

    char reply[IP_MAXPACKET];
    memcpy(reply, packet + ICMP_HDRLEN + IP4_HDRLEN, datalen);
    printf("ICMP reply: %s \n", reply);

    float milliseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
    unsigned long microseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec);
    printf("RTT time in milliseconds: %f \n", milliseconds);
    printf("RTT time in microseconds: %ld\n\n", microseconds );


    // Close the raw socket descriptor.
    close(sock);

    return 0;
}

/*--------------------------------------------------------------------*/
/*--- Checksum - Calculate the ICMP header checksum                ---*/
/*--------------------------------------------------------------------*/
unsigned short calculate_checksum(unsigned short * paddress, int len) {
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

