#define __FAVOR_BSD

#include <stdio.h> 
#include <sys/ioctl.h> 
#include <sys/socket.h> 
#include <sys/time.h> 
#include <sys/errno.h> 
#include <net/if.h> 
#include <net/ppp_defs.h> 
#include <arpa/inet.h> 

#include <net/if_ppp.h> 
#include <netinet/if_ether.h> 

#include <netinet/ip.h>
//#include <linux/ip.h> 
#include <linux/tcp.h> 
#include <linux/udp.h> 
#include <linux/icmp.h> 

#include <features.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h> 
#include <net/if_arp.h> 

#include "capture.h"

struct s_packet_hdr *  sock_capture_init()
{
    struct s_packet_hdr * s_packet;
    int fd;
    
    s_packet = calloc( 1, sizeof( struct s_packet_hdr ) );
    
    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
	perror("socket");
	exit(0);
    }
    
    s_packet->sock = fd; 
    
    return s_packet;
}


int sock_capture( struct s_packet_hdr * s_packet )
{
    unsigned int fromlen=sizeof( struct sockaddr );
    struct sockaddr_ll fromaddr;

    if(( s_packet->packet_size = recvfrom( s_packet->sock, s_packet->packet_data, 1500,0,(struct sockaddr *) &fromaddr, &fromlen))<=0){
	return 0;
    }
    
    switch (fromaddr.sll_hatype) {
	case ARPHRD_ETHER:
		s_packet->ip  = &s_packet->packet_data[14];
		s_packet->tcp = &s_packet->packet_data[14+sizeof( struct ip)];
		
		return 14;
	break;    
	case ARPHRD_LOOPBACK:
		s_packet->ip = &s_packet->packet_data[14];
		s_packet->tcp = &s_packet->packet_data[14+sizeof( struct ip)];
		return 14;
	break;
	case ARPHRD_PPP:
		s_packet->ip = &s_packet->packet_data[0];
		s_packet->tcp = &s_packet->packet_data[0+sizeof( struct ip)];
		return 0;
	break;
	default:
		s_packet->ip = &s_packet->packet_data[0];
	break;
    }

    return 1;
}

