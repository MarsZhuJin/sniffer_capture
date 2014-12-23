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
#include <pthread.h>
#include "common.h"
#include "sniffer_list.h"

#define PORT_FILTER_HEADER			"port "
#define PORT_FILTER_HEADER_LENGTH	5

#define BUFF_SIZE	128

struct sniff_list sniffer_list;
const char *program_name;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

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

/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
char *copy_argv(register char **argv)
{
	register char **p;
	register u_int len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL)
		error("copy_argv: malloc");

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}

void *redis_handler(void *arg)
{
	char bytes[SNIFF_BUFF_MAX_LENGTH];
	int size_ethernet = sizeof(struct sniff_ethernet);
	const struct sniff_ip *ip = NULL;
	char *ip_src = NULL;
	char *ip_dst = NULL;
	char ip_total_num[BUFF_SIZE];
	char redis_key[BUFF_SIZE];
	char redis_cmd[BUFF_SIZE];
	redisContext *c = NULL;
	int ret = 0;

	/* Initialize redis client */
	c = redisConnect("127.0.0.1", 6379);
	if (c->err) {
		error("Connect to redis server failed.\n");
	}

	while (1) {
		ret = sniff_list_pull(bytes);
		if (ret < 0) {
			memset(bytes, 0, SNIFF_BUFF_MAX_LENGTH);
			continue;
		}

		ip = (struct sniff_ip *) (bytes + size_ethernet);
		
		ip_src = inet_ntoa(ip->ip_src);
		ip_dst = inet_ntoa(ip->ip_dst);

		memset(redis_key, 0, BUFF_SIZE);
		memset(redis_cmd, 0, BUFF_SIZE);
		memset(ip_total_num, 0, BUFF_SIZE);

		sprintf(ip_total_num, " %d", ntohs(ip->ip_len));

		strcat(redis_key, "ip_src:");
		strcat(redis_key, ip_src);
		strcat(redis_key, ",ip_dst:");
		strcat(redis_key, ip_dst);

		strcat(redis_cmd, "incrby ");
		strcat(redis_cmd, redis_key);
		strcat(redis_cmd, ip_total_num);

		redisReply *r = (redisReply *)redisCommand(c, redis_cmd);
		if (r == NULL) {
			error("execute %s failed.\n", redis_cmd);
		}
		freeReplyObject(r);
	}

	redisFree(c);

	fprintf(stderr, "redis command: %s\n", redis_cmd);

	pthread_exit(NULL);
}

void sniffer_handler(u_char *user, 
	const struct pcap_pkthdr *h, const u_char *bytes)
{
	sniff_list_push(bytes, h->caplen);
}

int main(int argc, char **argv)
{
	int opt;
	char *optstring = "i:p:c:";
	char *cmd_buf = NULL;
	char *device = NULL;
	int filter_number = -1;
	bpf_u_int32 localnet = 0, netmask = 0;
	struct bpf_program fcode;
	pcap_t *handler = NULL;
	char err_buf[PCAP_ERRBUF_SIZE];
	int cpu_num = 0;

	program_name = argv[0];
	cpu_num = sysconf(_SC_NPROCESSORS_ONLN);

	while ((opt = getopt(argc, argv, optstring)) != -1) {
		switch (opt) {
			case 'i':
				device = optarg;
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
			error("%s", err_buf);
		}
	}

	handler = pcap_open_live(device, 65535, 0, 0, err_buf);

	if (pcap_lookupnet(device, &localnet, &netmask, err_buf) < 0) {
		error("%s", err_buf);
	}

	cmd_buf = copy_argv(&argv[optind]);
	if (pcap_compile(handler, &fcode, cmd_buf, 1, netmask) < 0)
		error("%s", pcap_geterr(handler));

	if (pcap_setfilter(handler, &fcode) < 0) {
		error("%s", pcap_geterr(handler));
	}

	pcap_loop(handler, filter_number, sniffer_handler, NULL);

	pcap_close(handler);

	return 0;
}
