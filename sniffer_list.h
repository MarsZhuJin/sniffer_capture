#ifndef _SNIFFER_LIST_H_
#define _SNIFFER_LIST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

struct sniff_list {
	struct sniff_iphdr *list;
	uint32_t total_length;
	uint32_t current;
};

#define SNIFFER_LENGTH	128

extern struct sniff_list sniffer_list;
static pthread_mutex_t sniff_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline int sniff_list_init(void)
{
	sniffer_list.total_length = SNIFFER_LENGTH;
	sniffer_list.current = 0;
	sniffer_list.list  = (struct sniff_iphdr *) malloc(SNIFFER_LENGTH * sizeof(struct sniff_iphdr));
	if (sniffer_list.list == NULL) {
		fprintf(stderr, "malloc failed.\n");
		return FAILURE;
	}

	memset(sniffer_list.list, 0, SNIFFER_LENGTH * sizeof(struct sniff_iphdr));

	return SUCCESS;
}

static inline int sniff_list_push(struct sniff_iphdr ip_info)
{
	uint32_t current = 0;
	
	pthread_mutex_lock(&sniff_mutex);
	current = sniffer_list.current;

	if (current >= sniffer_list.total_length) {
		sniffer_list.list = 
						(struct sniff_iphdr *) realloc(sniffer_list.list, 
								(sniffer_list.total_length + SNIFFER_LENGTH) * sizeof(struct sniff_iphdr));
		if (sniffer_list.list == NULL) {
			fprintf(stderr, "realloc failed.\n");
			return FAILURE;
		}

		sniffer_list.total_length += SNIFFER_LENGTH;
	}

	sniffer_list.list[current].src = ip_info.src;
	sniffer_list.list[current].dst = ip_info.dst;
	sniffer_list.list[current].len = ip_info.len;
	sniffer_list.current++;

	pthread_mutex_unlock(&sniff_mutex);

	return SUCCESS;
}

static inline int sniff_list_pull(struct sniff_iphdr *data)
{
	uint32_t current = 0;
	uint32_t len = 0;

	pthread_mutex_lock(&sniff_mutex);
	current = sniffer_list.current - 1;
	if (current == -1) {
		pthread_mutex_unlock(&sniff_mutex);
		return FAILURE;
	}

	data->src = sniffer_list.list[current].src;
	data->dst = sniffer_list.list[current].dst;
	data->len = sniffer_list.list[current].len;

	sniffer_list.current--;
	pthread_mutex_unlock(&sniff_mutex);

	return SUCCESS;
}

static inline int sniff_list_destroy(void)
{
	uint32_t current = sniffer_list.current;
	int i = 0; 

	if (sniffer_list.list != NULL) {
		free(sniffer_list.list);
		sniffer_list.list = NULL;
	}
		
	return 0;
}

#endif
