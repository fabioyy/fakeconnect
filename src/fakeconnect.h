struct s_queue_hdr {
	unsigned long s_addr;
	unsigned long d_addr;
	int sport;
	int dport;
	unsigned long seq;
	unsigned long ack;
	int status;
	
	
	struct s_queue_hdr * s_right;
	struct s_queue_hdr * s_left;
};
struct s_queue {
	struct s_queue_hdr * s_first;
	struct s_queue_hdr * s_last;
};

