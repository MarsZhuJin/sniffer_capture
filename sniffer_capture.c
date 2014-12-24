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
#include <errno.h>
#include <string.h>
#include "common.h"
#include "sniffer_list.h"

#define PORT_FILTER_HEADER			"port "
#define PORT_FILTER_HEADER_LENGTH	5
#define MAXINUM_SNAPLEN		262144
#define DEFAULT_SNAPLEN		MAXINUM_SNAPLEN

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

void warning(const char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: WARNING: ", program_name);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
}

static void print_version(void)
{
	(void) fprintf(stderr, "%s version %s\n", program_name, VERSION);
	(void) fprintf(stderr, "%s\n", pcap_lib_version());
}

static void print_usage(void)
{
	print_version();
	(void) fprintf(stderr, 
		"Usage: %s [-hv] [-c count]\n"
		"\t\t[-i interface]\n", program_name);
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
	u_short total_length = 0;
	redisContext *c = NULL;
	int ret = 0;

	/* Initialize redis client */
	c = redisConnect("127.0.0.1", 6379);
	if (c->err) {
		error("Connect to redis server failed.\n");
	}

	while (1) {
		memset(bytes, 0, SNIFF_BUFF_MAX_LENGTH);
		ret = sniff_list_pull(bytes);
		if (ret < 0) {
			continue;
		}

		ip = (struct sniff_ip *) (bytes + size_ethernet);
		
		ip_src = inet_ntoa(ip->ip_src);
		ip_dst = inet_ntoa(ip->ip_dst);
		total_length = ntohs(ip->ip_len);

		fprintf(stderr, "ip_src: %s, ip_dst: %s, total_length: %hd\n", ip_src, ip_dst, total_length);

		redisReply *r = 
			(redisReply *)redisCommand(c, "INCRBY %s,%s %u", ip_src, ip_dst, total_length);
		if (r == NULL) {
			error("execute redis command failed.\n");
		}
		freeReplyObject(r);
	}

	redisFree(c);

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
	char *optstring = "i:p:c:hv";
	char *cmd_buf = NULL, *device = NULL, *cp = NULL;
	int filter_number = -1;
	bpf_u_int32 localnet = 0, netmask = 0;
	struct bpf_program fcode;
	pcap_t *handler = NULL;
	char err_buf[PCAP_ERRBUF_SIZE];
	int cpu_num = 0;
	int i = 0;
	pthread_t *pthr = NULL;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	while ((opt = getopt(argc, argv, optstring)) != -1) {
		switch (opt) {
			case 'i':
				device = optarg;
				break;
			case 'c':
				filter_number = atoi(optarg);
				break;
			case 'h':
				print_usage();
				exit(0);
				break;
			case 'v':
				print_version();
				exit(0);
				break;
			default:
				break;
		}
	}

	cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
	pthr = (pthread_t *) malloc(cpu_num * sizeof(pthread_t));
	if (pthr == NULL) {
		error("%s", strerror(errno));
	}

	for (i = 0; i < cpu_num; i++) {
		pthread_create(&pthr[i], NULL, redis_handler, NULL);
	}


	if (device == NULL) {
		device = pcap_lookupdev(err_buf);
		if (device == NULL) {
			error("%s", err_buf);
		}
	}

	handler = pcap_open_live(device, DEFAULT_SNAPLEN, 0, 0, err_buf);
	if (handler == NULL) 
        error("%s", err_buf);
	else if (*err_buf)
		warning("%s", err_buf);

	if (pcap_lookupnet(device, &localnet, &netmask, err_buf) < 0) {
		error("%s", err_buf);
	}

	if (pcap_datalink(handler) != DLT_EN10MB) {
		error("Device %s doesn't provide Ethernet headers - not supported\n", device);
	}

	cmd_buf = copy_argv(&argv[optind]);
	if (pcap_compile(handler, &fcode, cmd_buf, 1, netmask) < 0)
		error("%s", pcap_geterr(handler));

	if (pcap_setfilter(handler, &fcode) < 0) {
		error("%s", pcap_geterr(handler));
	}

	pcap_loop(handler, filter_number, sniffer_handler, NULL);

	#if 0

	for (i = 0; i < cpu_num; i++) {
		pthread_join(pthr[i], NULL);
	}
	#endif

	if (pthr != NULL) {
        free(pthr);
        pthr = NULL;
	}

	pcap_close(handler);

	return 0;
}
