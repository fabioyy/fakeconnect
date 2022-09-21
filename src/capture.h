struct s_packet_hdr {
    int sock;
    
    char packet_data[1500];
    int  packet_size;

    struct tcphdr * tcp;
    struct ip * ip;
};
