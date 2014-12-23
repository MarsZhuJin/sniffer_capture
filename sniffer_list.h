#ifndef _SNIFFER_LIST_H_
#define _SNIFFER_LIST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

struct sniff_list {
	sniff_str_t *list;
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
	sniffer_list.list  = (sniff_str_t *) malloc(SNIFFER_LENGTH * sizeof(sniff_str_t));
	if (sniffer_list.list == NULL) {
		fprintf(stderr, "malloc failed.\n");
		return FAILURE;
	}

	memset(sniffer_list.list, 0, SNIFFER_LENGTH * sizeof(sniff_str_t));

	return SUCCESS;
}

static inline int sniff_list_push(const u_char *sniff_data, uint32_t sniff_data_len)
{
	uint32_t current = 0;
	
	pthread_mutex_lock(&sniff_mutex);
	current = sniffer_list.current;

	if (current >= sniffer_list.total_length) {
		sniffer_list.list = 
						(sniff_str_t *) realloc(sniffer_list.list, 
								(sniffer_list.total_length + SNIFFER_LENGTH) * sizeof(sniff_str_t));
		if (sniffer_list.list == NULL) {
			fprintf(stderr, "realloc failed.\n");
			return FAILURE;
		}

		sniffer_list.total_length += SNIFFER_LENGTH;
	}

	sniffer_list.list[current].data = (u_char *) malloc(sniff_data_len);
	if (sniffer_list.list[current].data == NULL) {
		fprintf(stderr, "malloc failed.\n");
		return FAILURE;
	}
	memcpy(sniffer_list.list[current].data, sniff_data, sniff_data_len);
	sniffer_list.list[current].len = sniff_data_len;
	sniffer_list.current++;
	pthread_mutex_unlock(&sniff_mutex);

	return SUCCESS;
}

static inline int sniff_list_pull(u_char *sniff_data)
{
	uint32_t current = 0;
	u_char *data = NULL;
	uint32_t len = 0;

	pthread_mutex_lock(&sniff_mutex);
	current = sniffer_list.current - 1;
	if (current == -1) {
		pthread_mutex_unlock(&sniff_mutex);
		return FAILURE;
	}

	data = sniffer_list.list[current].data;
	len = sniffer_list.list[current].len;
	memcpy(sniff_data, data, len);

	free(data);
	sniffer_list.list[current].len = 0;
	sniffer_list.current--;
	pthread_mutex_unlock(&sniff_mutex);

	return SUCCESS;
}

static inline int sniff_list_destroy(void)
{
	uint32_t current = sniffer_list.current;
	int i = 0; 

	for (i = 0; i < current; i++) {
		free(sniffer_list.list[i].data);
		sniffer_list.list[i].len = 0;
	}

	free(sniffer_list.list);

	return 0;
}

#endif
