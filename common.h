#ifndef _COMMON_H_
#define _COMMON_H_

#define SUCCESS		0
#define FAILURE		-1

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define SNIFF_BUFF_MAX_LENGTH	65535
#define VERSION		"1.0.0"

#define MAXINUM_SNAPLEN		262144
#define DEFAULT_SNAPLEN		MAXINUM_SNAPLEN
#define MAXINUM_ADDR_LENGTH		16

#define BUFF_SIZE	128

struct sniff_iphdr {
	struct in_addr src;
	struct in_addr dst;
	uint32_t len;
};

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

#endif
