#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>


struct tcp_pseudo {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned char dummy;
    unsigned char proto;
    unsigned short length;
};

struct packet_checksum {		
    struct tcp_pseudo pseudo;
    struct tcphdr tcp;
    char data[1024];
};
unsigned short in_cksum(unsigned short *addr, int len)
{
    register int nleft = len;
    register unsigned short *w = addr;
    register int sum = 0;
    unsigned short answer = 0;

    while (nleft > 1) {
	sum += *w++;
	nleft -= 2;
    }
    if (nleft == 1) {
	*(u_char *) (&answer) = *(u_char *) w;

	sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}
int socket_send_raw(int socket, struct ip *s_ip, struct tcphdr *s_tcp, char * data, int data_size )
{
    char packet[1500];

    struct sockaddr_in sin;

    struct ip *ip = (struct ip *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
    struct packet_checksum s_cksum;
    
    memset( &sin, 0x00, sizeof( struct sockaddr_in ));
    
    memcpy(ip, s_ip, sizeof(struct ip));
    memcpy(tcp, s_tcp, sizeof(struct tcphdr));
    memcpy(&packet[sizeof( struct ip )+ sizeof( struct tcphdr)], data, data_size);

    memset(&s_cksum, 0x00, sizeof(struct packet_checksum));

    s_cksum.pseudo.src_addr = ip->ip_src.s_addr;
    s_cksum.pseudo.dst_addr = ip->ip_dst.s_addr;
    s_cksum.pseudo.dummy = 0;
    s_cksum.pseudo.proto = IPPROTO_TCP;
    s_cksum.pseudo.length = htons(sizeof(struct tcphdr)+data_size);

    if( data && data_size ){
        memcpy( &s_cksum.data, data, data_size);
    }
    memcpy( &s_cksum.tcp, tcp, sizeof( struct tcphdr ));
    

    tcp->th_sum = in_cksum((unsigned short *) &s_cksum, sizeof(struct tcp_pseudo) + sizeof(struct tcphdr)+data_size);

    ip->ip_sum = in_cksum((unsigned short *) ip, sizeof(struct ip));

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip->ip_dst.s_addr;
    sin.sin_port = tcp->th_dport;

    sendto(socket, packet, sizeof(struct ip) + sizeof(struct tcphdr)+data_size, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));
}

int send_syn(int socket, char *source, char *dest, unsigned long seq, int sport, int dport)
{
    struct ip ip;
    struct tcphdr tcp;
    char option[] = { 0x02, 0x04, 0x05, 0xb4,
    		      0x04, 0x02,
    		      0x08, 0x0a, 0x01, 0xbc, 0x12, 0x95, 0x00, 0x00, 0x00, 0x00,
    		      0x01,
    		      0x03, 0x03, 0x00 };
    		      

    ip.ip_hl = 5;
    ip.ip_v = 4;
    ip.ip_tos = 0x10;
    ip.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + 20);
    ip.ip_id = htons(32433);
    ip.ip_off = 0x40;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0;
    ip.ip_src.s_addr = inet_addr(source);;
    ip.ip_dst.s_addr = inet_addr(dest);

    memset(&tcp, 0x00, sizeof(struct tcphdr));

    tcp.th_sport = htons(sport);
    tcp.th_dport = htons(dport);

    tcp.th_seq = htonl(seq);
    tcp.th_ack = htonl(0);
    tcp.th_flags = 0x02;
    tcp.th_win = 0xd016;
    tcp.th_off = 10;


    socket_send_raw(socket, &ip, &tcp, option, sizeof( option ));

    return 1;
}
int send_ack(int socket, char *source, char *dest, int sport, int dport, unsigned long seq,unsigned long ack )
{
    struct ip ip;
    struct tcphdr tcp;

    ip.ip_hl = 5;
    ip.ip_v = 4;
    ip.ip_tos = 0;
    ip.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip.ip_id = htons(629);
    ip.ip_off = 0;
    ip.ip_ttl = 255;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0;
    ip.ip_src.s_addr = inet_addr(source);;
    ip.ip_dst.s_addr = inet_addr(dest);

    memset(&tcp, 0x00, sizeof(struct tcphdr));

    tcp.th_sport = htons(sport);
    tcp.th_dport = htons(dport);

    tcp.th_seq = htonl( seq );
    tcp.th_ack = htonl( ack );
    tcp.th_flags = 0x10;
    tcp.th_win = htons(0x7c00);
    tcp.th_off = 5;
    socket_send_raw(socket, &ip, &tcp, NULL, 0 );

    return 1;
}
int i_send_ack(int socket, unsigned long source, unsigned long dest, int sport, int dport, unsigned long seq,unsigned long ack )
{
    struct ip ip;
    struct tcphdr tcp;

    ip.ip_hl = 5;
    ip.ip_v = 4;
    ip.ip_tos = 0;
    ip.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip.ip_id = htons(629);
    ip.ip_off = 0;
    ip.ip_ttl = 255;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0;
    ip.ip_src.s_addr = source;
    ip.ip_dst.s_addr = dest;

    memset(&tcp, 0x00, sizeof(struct tcphdr));

    tcp.th_sport = htons(sport);
    tcp.th_dport = htons(dport);

    tcp.th_seq = htonl( seq );
    tcp.th_ack = htonl( ack );
    tcp.th_flags = 0x10;
    tcp.th_win = htons(0x7c00);
    tcp.th_off = 5;
    socket_send_raw(socket, &ip, &tcp, NULL, 0 );

    return 1;
}
int send_data(int socket, char *source, char *dest, int sport, int dport, unsigned long seq,unsigned long ack, char *data, int data_size )
{
    struct ip ip;
    struct tcphdr tcp;

    ip.ip_hl = 5;
    ip.ip_v = 4;
    ip.ip_tos = 0;
    ip.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr)+data_size);
    ip.ip_id = htons(629);
    ip.ip_off = 0;
    ip.ip_ttl = 255;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0;
    ip.ip_src.s_addr = inet_addr(source);;
    ip.ip_dst.s_addr = inet_addr(dest);

    memset(&tcp, 0x00, sizeof(struct tcphdr));

    tcp.th_sport = htons(sport);
    tcp.th_dport = htons(dport);

    tcp.th_seq = htonl( seq );
    tcp.th_ack = htonl( ack );
    tcp.th_flags = 0x18;
    tcp.th_win = htons(0x7c00);
    tcp.th_off = 5;
    socket_send_raw(socket, &ip, &tcp, data, data_size);

    return 1;
}
int i_send_data(int socket, unsigned long source, unsigned long dest, int sport, int dport, unsigned long seq,unsigned long ack, char *data, int data_size )
{
    struct ip ip;
    struct tcphdr tcp;

    ip.ip_hl = 5;
    ip.ip_v = 4;
    ip.ip_tos = 0;
    ip.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr)+data_size);
    ip.ip_id = htons(629);
    ip.ip_off = 0;
    ip.ip_ttl = 255;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0;
    ip.ip_src.s_addr = source;
    ip.ip_dst.s_addr = dest;

    memset(&tcp, 0x00, sizeof(struct tcphdr));

    tcp.th_sport = htons(sport);
    tcp.th_dport = htons(dport);

    tcp.th_seq = htonl( seq );
    tcp.th_ack = htonl( ack );
    tcp.th_flags = 0x18;
    tcp.th_win = htons(0x7c00);
    tcp.th_off = 5;
    socket_send_raw(socket, &ip, &tcp, data, data_size);

    return 1;
}
