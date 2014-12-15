#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <hiredis/hiredis.h>

#define PORT_FILTER_HEADER			"port "
#define PORT_FILTER_HEADER_LENGTH	5

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

char *program_name;

void error(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void) fputc('\n', stderr);
	}

	exit(1);
}

void filter_handler(u_char *user, 
	const struct pcap_pkthdr *h, const u_char *bytes)
{

	const struct sniff_ip *ip = NULL;
	int size_ethernet = sizeof(struct sniff_ethernet);
	
	ip = (struct sniff_ip *)(bytes + size_ethernet);

	//char *inet_ntoa(struct in_addr inaddr);
	char *ip_src = NULL;
	char *ip_dst = NULL;
	int ip_total_len = 0;

	ip_src = inet_ntoa(ip->ip_src);
	ip_dst = inet_ntoa(ip->ip_dst);
	ip_total_len = ntohs(ip->ip_len);
	
	
	printf("ip_src: %s, ip_dst: %s, ip_len: %d\n", ip_src, ip_dst, ip_total_len);
}

int main(int argc, char **argv)
{
	int opt;
	char *optstring = "i:p:c:";
	char *device = NULL;
	char port_filter[16] = PORT_FILTER_HEADER;
	int filter_number = -1;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	char err_buf[PCAP_ERRBUF_SIZE];
	pcap_t *p_handle = NULL;
	struct bpf_program filter;

	program_name = argv[0];

	while ((opt = getopt(argc, argv, optstring)) != -1) {
		switch (opt) {
			case 'i':
				device = optarg;
				break;
			case 'p':
				strcat(&port_filter[PORT_FILTER_HEADER_LENGTH], 
						optarg);
				break;
			case 'c':
				filter_number = atoi(optarg);
				break;
			default:
				break;
		}
	}

	if (device == NULL) {
		device = pcap_lookupdev(err_buf);
		if (device == NULL) {
			error("Invalid network interface");
		}
	}

	pcap_lookupnet(device, &net, &mask, err_buf);
	p_handle = pcap_open_live(device, 65535, 0, 0, err_buf);

	if (strlen(port_filter) > PORT_FILTER_HEADER_LENGTH) {
		pcap_compile(p_handle, &filter, port_filter, 0, net);
		pcap_setfilter(p_handle, &filter);
	}

	pcap_loop(p_handle, filter_number, filter_handler, NULL);

	pcap_close(p_handle);

	return 0;
}
